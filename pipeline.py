"""Vendor-shaped JSON -> validated OCSF projections -> DuckDB evidence bundles."""
import json
from datetime import datetime
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
from jsonschema import Draft202012Validator
from ocsf_json_schema import OcsfJsonSchemaEmbedded, get_ocsf_schema

from fixture_factory import generate
from ingestion import ingest, landed_path
from methodology import reference_disposition

ROOT = Path(__file__).resolve().parent
OCSF_VERSION = '1.8.0'
OCSF = OcsfJsonSchemaEmbedded(get_ocsf_schema(version=OCSF_VERSION))
VALIDATORS = {name: Draft202012Validator(OCSF.get_class_schema(name)) for name in ('authentication', 'account_change', 'http_activity')}


def epoch_ms(value):
    return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp() * 1000)


def rows(path):
    with path.open(encoding='utf-8') as handle:
        for number, line in enumerate(handle, 1):
            yield number, json.loads(line)


def metadata(vendor, product, uid):
    return {'version': OCSF_VERSION, 'product': {'vendor_name': vendor, 'name': product}, 'original_event_uid': uid}


def map_okta(raw):
    for field in ('uuid', 'published', 'eventType', 'outcome', 'target', '_collection'):
        if field not in raw:
            raise ValueError(f'missing {field}')
    user = next((x for x in raw['target'] if x.get('type') == 'User'), None)
    app = next((x for x in raw['target'] if x.get('type') == 'AppInstance'), None)
    if not user or not user.get('id') or not user.get('alternateId'):
        raise ValueError('missing stable user identity')
    base = {'category_uid': 3, 'metadata': metadata('Okta', 'System Log', raw['uuid']), 'severity_id': 1,
            'time': epoch_ms(raw['published']), 'status_id': 1 if raw['outcome']['result'] == 'SUCCESS' else 2,
            'user': {'uid': user['id'], 'name': user['alternateId']},
            'class_name': '', 'activity_name': '', 'type_name': ''}
    if raw['eventType'] == 'user.lifecycle.deactivate':
        event = dict(base, activity_id=5, activity_name='Disable', class_uid=3001, class_name='Account Change',
                     type_uid=300105, type_name='Account Change: Disable')
        class_name = 'account_change'
    elif raw['eventType'] == 'user.authentication.sso' and app:
        event = dict(base, activity_id=1, activity_name='Logon', class_uid=3002, class_name='Authentication',
                     type_uid=300201, type_name='Authentication: Logon', service={'uid': app['id'], 'name': app['alternateId']})
        class_name = 'authentication'
    else:
        raise ValueError('unsupported Okta event type or missing application')
    return event, class_name, {'user_uid': user['id'], 'user_name': user['alternateId'],
                               'service_uid': app.get('id') if app else None, 'hostname': None,
                               'collection_batch': raw['_collection']['batch_id']}


def map_zscaler(raw):
    for field in ('event_id', 'datetime', 'login', 'hostname', 'url', 'requestmethod', 'action', '_collection'):
        if field not in raw:
            raise ValueError(f'missing {field}')
    method = raw['requestmethod'].upper()
    activities = {'CONNECT': 1, 'DELETE': 2, 'GET': 3, 'HEAD': 4, 'OPTIONS': 5, 'POST': 6, 'PUT': 7, 'TRACE': 8, 'PATCH': 9}
    if method not in activities:
        raise ValueError('unsupported HTTP method')
    activity = activities[method]
    event = {'activity_id': activity, 'activity_name': method.title(), 'category_uid': 4, 'category_name': 'Network Activity',
             'class_uid': 4002, 'class_name': 'HTTP Activity', 'type_uid': 400200 + activity,
             'type_name': f'HTTP Activity: {method.title()}', 'severity_id': 1, 'time': epoch_ms(raw['datetime']),
             'metadata': metadata('Zscaler', 'NSS', raw['event_id']),
             'src_endpoint': {'ip': raw.get('ClientIP'), 'owner': {'name': raw['login']}},
             'dst_endpoint': {'hostname': raw['hostname']},
             'http_request': {'http_method': method, 'url': {'url_string': raw['url']}}}
    return event, 'http_activity', {'user_uid': None, 'user_name': raw['login'], 'service_uid': None,
                                    'hostname': raw['hostname'], 'collection_batch': raw['_collection']['batch_id'],
                                    'source_action': raw['action'].lower()}


def build_warehouse(root=None, force=False):
    root = Path(root or ROOT)
    fixture_manifest = generate(root)
    ingestion = ingest(root)
    normalized_dir = root / 'data' / 'normalized'; normalized_dir.mkdir(parents=True, exist_ok=True)
    output = normalized_dir / 'ocsf_events.parquet'
    quality = normalized_dir / 'quarantine.parquet'
    if output.exists() and quality.exists() and not force:
        cached = json.loads((normalized_dir / 'pipeline_manifest.json').read_text(encoding='utf-8'))
        if cached.get('mapping_version') == '4' and cached.get('ingestion_run_id') == ingestion['run_id']:
            return cached
    events, quarantine = [], []
    sources = [('okta', landed_path(root, ingestion, 'okta'), map_okta),
               ('zscaler', landed_path(root, ingestion, 'zscaler'), map_zscaler)]
    class_counts = {}
    for source, path, mapper in sources:
        for line, raw in rows(path):
            try:
                event, class_name, index = mapper(raw)
                errors = list(VALIDATORS[class_name].iter_errors(event))
                if errors:
                    raise ValueError('OCSF validation: ' + errors[0].message)
                class_counts[class_name] = class_counts.get(class_name, 0) + 1
                events.append({'source': source, 'source_action': None, 'evidence_id': event['metadata']['original_event_uid'],
                               'event_time': event['time'], 'class_uid': event['class_uid'], 'activity_id': event['activity_id'],
                               **index, 'ocsf_json': json.dumps(event, separators=(',', ':'))})
            except (ValueError, KeyError, TypeError) as exc:
                quarantine.append({'source': source, 'line': line, 'reason': str(exc)[:300],
                                   'raw_json': json.dumps(raw, separators=(',', ':'))})
    pq.write_table(pa.Table.from_pylist(events), output, compression='zstd')
    pq.write_table(pa.Table.from_pylist(quarantine), quality, compression='zstd')
    hr = [row for _, row in rows(landed_path(root, ingestion, 'hr'))]
    services = json.loads(landed_path(root, ingestion, 'business_services').read_text(encoding='utf-8'))
    pq.write_table(pa.Table.from_pylist(hr), normalized_dir / 'hr_context.parquet', compression='zstd')
    pq.write_table(pa.Table.from_pylist(services), normalized_dir / 'business_context.parquet', compression='zstd')
    result = {'mapping_version': '4', 'ingestion_run_id': ingestion['run_id'],
              'ingestion_registry_version': ingestion['registry_version'],
              'ingestion_ready_for': ingestion['ready_for'],
              'ocsf_version': OCSF_VERSION, 'raw_counts': ingestion['counts'], 'normalized_events': len(events),
              'quarantined': len(quarantine), 'class_counts': class_counts,
              'validation': 'Every emitted event passed the packaged OCSF 1.8.0 JSON Schema for its class.',
              'provenance': {'raw': ingestion['source_kind'],
                             'normalized': 'OCSF projection plus query index columns',
                             'context': 'user-supplied context' if fixture_manifest.get('fixture') is False else 'fictional HR and business-service enrichment'}}
    (normalized_dir / 'pipeline_manifest.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def correlate(batch, root=None):
    root = Path(root or ROOT)
    manifest = build_warehouse(root)
    con = duckdb.connect()
    try:
        con.read_parquet(str(root / 'data/normalized/ocsf_events.parquet')).create_view('events')
        con.read_parquet(str(root / 'data/normalized/hr_context.parquet')).create_view('workers')
        con.read_parquet(str(root / 'data/normalized/business_context.parquet')).create_view('services')
        workers = con.execute("SELECT worker_id, primary_email, identity_uid, termination_time, expected_service_id, evidence_id FROM workers WHERE employment_status='terminated' ORDER BY worker_id").fetchall()
        findings, bundles, clusters = [], [], []
        for worker_id, email, identity_uid, terminated, service_id, hr_evidence in workers:
            service = con.execute("SELECT app_uid, hostname, service_name, objective_id, business_objective, data_classification, owner FROM services WHERE service_id=?", [service_id]).fetchone()
            app_uid, hostname, service_name, objective_id, objective, classification, owner = service
            identities = con.execute("SELECT DISTINCT user_uid FROM events WHERE collection_batch=? AND user_name=? AND user_uid IS NOT NULL ORDER BY user_uid", [batch, email]).fetchall()
            disabled = con.execute("SELECT evidence_id, event_time, ocsf_json FROM events WHERE collection_batch=? AND user_name=? AND class_uid=3001 AND activity_id=5", [batch, email]).fetchall()
            auth = con.execute("SELECT evidence_id, event_time, ocsf_json FROM events WHERE collection_batch=? AND user_name=? AND class_uid=3002 AND activity_id=1 AND service_uid=?", [batch, email, app_uid]).fetchall()
            web = con.execute("SELECT evidence_id, event_time, ocsf_json FROM events WHERE collection_batch=? AND user_name=? AND class_uid=4002 AND activity_id=3 AND hostname=?", [batch, email, hostname]).fetchall()
            scenario_id = f'leaver-access:{worker_id}:{service_id}'
            cutoff = epoch_ms(terminated)
            auth = [x for x in auth if x[1] > cutoff and json.loads(x[2]).get('status_id') == 1]
            allowed_ids = {x[0] for x in con.execute("SELECT evidence_id FROM events WHERE source_action='allowed'").fetchall()}
            web = [x for x in web if x[1] > cutoff and x[0] in allowed_ids]
            disabled = [x for x in disabled if x[1] > cutoff and json.loads(x[2]).get('status_id') == 1]
            disabled.sort(key=lambda x: (x[1], x[0]))
            auth.sort(key=lambda x: (x[1], x[0]))
            web.sort(key=lambda x: (x[1], x[0]))
            evidence_ids = [hr_evidence] + [x[0] for x in disabled + auth + web]
            if len(identities) > 1:
                state, reason = 'unknown', 'Multiple identity UIDs share the same login; exact identity resolution abstained.'
            elif disabled and not (auth and web):
                state, reason = 'not-supported', 'A disable event is present in this collection window; this narrow condition is not supported.'
            elif auth and web:
                state, reason = 'supported', 'Post-termination authentication and allowed web activity correlate to the same business service.'
            else:
                state, reason = 'unknown', 'The collection window lacks a complete correlated authentication-and-web evidence pair.'
            finding = {'scenario_id': scenario_id, 'person_id': worker_id, 'service_id': service_id, 'state': state,
                       'reason': reason, 'evidence_ids': evidence_ids, 'collection_batch': batch}
            findings.append(finding)
            evidence_records = [{'evidence_id': hr_evidence, 'source': 'hr', 'observed_fact':
                                     f'{worker_id} has employment_status=terminated at {terminated}; HR expects identity_uid={identity_uid}.'}]
            for evidence_id, _, event_json in sorted(disabled + auth + web, key=lambda x: (x[1], x[0])):
                event = json.loads(event_json)
                if event['class_uid'] == 3001:
                    fact = (f"Okta recorded {event['activity_name']} for {event['user']['name']} "
                            f"at {event['time']} with status_id={event['status_id']}.")
                elif event['class_uid'] == 3002:
                    fact = (f"Okta recorded {event['activity_name']} for {event['user']['name']} "
                            f"to {event['service']['name']} at {event['time']} with status_id={event['status_id']}.")
                else:
                    fact = (f"Zscaler recorded {event['activity_name']} by {event['src_endpoint']['owner']['name']} "
                            f"to {event['dst_endpoint']['hostname']} at {event['time']} with source_action=allowed.")
                if event['class_uid'] in (3001, 3002):
                    fact += f" Observed identity_uid={event['user']['uid']}."
                evidence_records.append({'evidence_id': evidence_id, 'source': event['metadata']['product']['vendor_name'],
                                         'ocsf_class': event['class_name'], 'observed_fact': fact})
            times = [x[1] for x in disabled + auth + web] or [cutoff]
            cluster = {'cluster_id': scenario_id, 'scenario_id': scenario_id, 'person_id': worker_id,
                       'service_id': service_id, 'collection_batch': batch, 'termination_time': terminated,
                       'identity_uids': [x[0] for x in identities], 'expected_identity_uid': identity_uid,
                       'termination_ms': cutoff, 'authentication_times': [x[1] for x in auth],
                       'web_times': [x[1] for x in web], 'disable_times': [x[1] for x in disabled],
                       'authentication_events': len(auth), 'web_events': len(web), 'disable_events': len(disabled),
                       'first_activity_ms': min(times), 'last_activity_ms': max(times),
                       'service_name': service_name, 'objective_id': objective_id,
                       'business_objective': objective, 'data_classification': classification,
                       'service_owner': owner, 'profile_outcome': 'PR.AA-05',
                       'context_origin': manifest['provenance']['context'], 'evidence_ids': evidence_ids,
                       'evidence_records': evidence_records}
            clusters.append(cluster)
            disposition = reference_disposition(cluster)
            state = {'candidate-submitted': 'supported', 'contradicted': 'not-supported',
                     'ambiguous': 'unknown', 'insufficient-evidence': 'unknown'}[disposition]
            reason = {
                'candidate-submitted': 'Successful authentication and allowed web activity follow termination and any observed disable event.',
                'contradicted': 'A successful disable event is present with no later qualifying activity in this window; this does not establish global revocation.',
                'ambiguous': 'Observed identity UIDs are multiple or conflict with the HR identity; exact identity resolution abstained.',
                'insufficient-evidence': 'The collection lacks resolved identity evidence or a complete activity pair after termination and any disable.',
            }[disposition]
            finding.update(state=state, reason=reason, disposition=disposition)
            if state == 'supported':
                bundles.append({**cluster, **finding,
                                'identity_uid': identities[0][0] if identities else identity_uid})
        relevant = con.execute("SELECT count(*) FROM events WHERE collection_batch=? AND user_name IN (SELECT primary_email FROM workers WHERE employment_status='terminated')", [batch]).fetchone()[0]
    finally:
        con.close()
    return {'batch': batch, 'manifest': manifest, 'stage_counts': {'raw_records': sum(manifest['raw_counts'].values()),
             'normalized_events': manifest['normalized_events'], 'quarantined': manifest['quarantined'],
             'relevant_terminated_user_events': relevant, 'investigation_clusters': len(clusters),
             'supported_evidence_bundles': len(bundles)},
            'findings': findings, 'clusters': clusters, 'bundles': bundles}


if __name__ == '__main__':
    build_warehouse(force=True)
    for batch in (1, 2):
        result = correlate(batch)
        print(batch, result['stage_counts'], [(x['person_id'], x['state']) for x in result['findings']])
