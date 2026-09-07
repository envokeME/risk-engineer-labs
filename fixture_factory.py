"""Generate deterministic, vendor-shaped telemetry for the learning lab."""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 41
BASE = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def iso(value):
    return value.isoformat().replace('+00:00', 'Z')


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(json.dumps(row, separators=(',', ':')) for row in rows) + '\n', encoding='utf-8')


def okta_event(uid, published, event_type, user_uid, email, service, app_uid, batch, result='SUCCESS'):
    return {
        'uuid': uid,
        'published': iso(published),
        'eventType': event_type,
        'outcome': {'result': result},
        'actor': {'id': user_uid, 'type': 'User', 'alternateId': email, 'displayName': email.split('@')[0]},
        'client': {'ipAddress': f'198.51.100.{int(user_uid[-3:].replace("A", "1").replace("B", "2")) % 250 + 1}'},
        'target': [
            {'id': user_uid, 'type': 'User', 'alternateId': email, 'displayName': email.split('@')[0]},
            {'id': app_uid, 'type': 'AppInstance', 'alternateId': service, 'displayName': service.replace('-', ' ').title()},
        ],
        '_collection': {'batch_id': batch, 'source': 'okta-system-log', 'complete': True},
    }


def zscaler_event(uid, observed, email, hostname, batch, action='Allowed'):
    return {
        'datetime': iso(observed),
        'event_id': uid,
        'action': action,
        'user': email,
        'login': email,
        'url': f'https://{hostname}/records',
        'urlcategory': 'Business Use',
        'hostname': hostname,
        'ClientIP': f'203.0.113.{int(email[4:8]) % 250 + 1}',
        'requestmethod': 'GET',
        'product': 'NSS',
        'vendor': 'Zscaler',
        '_collection': {'batch_id': batch, 'source': 'zscaler-nss-web', 'complete': True},
    }


def generate(root=None, force=False):
    root = Path(root or Path(__file__).resolve().parent)
    raw = root / 'data' / 'raw'
    marker = raw / 'manifest.json'
    if marker.exists() and not force:
        return json.loads(marker.read_text(encoding='utf-8'))
    rng = random.Random(SEED)

    services = []
    names = [('support', 'Customer support platform', 'customer-information'),
             ('finance', 'Financial reporting workspace', 'financial-reporting'),
             ('engineering', 'Engineering delivery platform', 'software-delivery')]
    for i in range(200):
        service_id, name, objective = names[i] if i < 3 else (f'service-{i:03}', f'Business service {i:03}', f'objective-{i:03}')
        services.append({'service_id': service_id, 'app_uid': f'0oa{i:05}', 'hostname': f'{service_id}.apps.example.test',
                         'service_name': name, 'objective_id': f'OBJ-{i + 1:03}', 'business_objective': objective,
                         'data_classification': 'customer-confidential' if i == 0 else 'internal',
                         'owner': f'Business owner {i:03}', 'context_origin': 'fictional lab context'})

    special_service = {1: 'support', 2: 'support', 3: 'support', 4: 'support', 5: 'finance', 6: 'engineering'}
    workers = []
    for i in range(1, 1001):
        person = f'P{i:04}'
        workers.append({'evidence_id': f'HR-{i:04}', 'worker_id': person, 'identity_uid': f'00u{i:04}',
                        'primary_email': f'user{i:04}@corp.example.test',
                        'employment_status': 'terminated' if i <= 6 else 'active',
                        'termination_time': iso(BASE - timedelta(hours=4)) if i <= 6 else None,
                        'expected_service_id': special_service.get(i), 'observed_at': iso(BASE),
                        'source': 'hris-worker-snapshot', 'source_kind': 'mock record shaped like an HR export'})

    okta = []
    for i in range(7990):
        person_n = 10 + (i % 991)
        service = services[i % len(services)]
        batch = 1 if i % 2 == 0 else 2
        at = BASE + timedelta(hours=batch - 1, minutes=(i // 2) % 60, seconds=i % 60)
        email = f'user{person_n:04}@corp.example.test'
        okta.append(okta_event(f'OKTA-N-{i:05}', at, 'user.authentication.sso', f'00u{person_n:04}', email,
                                service['service_id'], service['app_uid'], batch))
    by_id = {s['service_id']: s for s in services}
    def add_okta(uid, minute, person, service_id, batch=1, event='user.authentication.sso', identity=None):
        service = by_id[service_id]
        okta.append(okta_event(uid, BASE + timedelta(hours=batch - 1, minutes=minute), event,
                                identity or f'00u{person:04}', f'user{person:04}@corp.example.test',
                                service_id, service['app_uid'], batch))
    add_okta('OKTA-P1', 12, 1, 'support')
    add_okta('OKTA-P2A', 15, 2, 'support', identity='00u0002A')
    add_okta('OKTA-P2B', 16, 2, 'support', identity='00u0002B')
    add_okta('OKTA-P3-DISABLE', -235, 3, 'support', event='user.lifecycle.deactivate')
    add_okta('OKTA-P4', 18, 4, 'support')
    add_okta('OKTA-P5', 20, 5, 'finance')
    add_okta('OKTA-P6', 22, 6, 'engineering')
    add_okta('OKTA-P1-DISABLE', 1, 1, 'support', batch=2, event='user.lifecycle.deactivate')
    add_okta('OKTA-P6-B2', 10, 6, 'engineering', batch=2)
    okta.append({'published': iso(BASE), 'eventType': 'user.authentication.sso', '_collection': {'batch_id': 1, 'source': 'okta-system-log', 'complete': True}})

    zscaler = []
    for i in range(39994):
        person_n = 10 + (i % 991)
        service = services[i % len(services)]
        batch = 1 if i % 2 == 0 else 2
        at = BASE + timedelta(hours=batch - 1, minutes=(i // 2) % 60, seconds=i % 60)
        zscaler.append(zscaler_event(f'ZIA-N-{i:05}', at, f'user{person_n:04}@corp.example.test', service['hostname'], batch))
    def add_zia(uid, minute, person, service_id, batch=1):
        zscaler.append(zscaler_event(uid, BASE + timedelta(hours=batch - 1, minutes=minute),
                                     f'user{person:04}@corp.example.test', by_id[service_id]['hostname'], batch))
    add_zia('ZIA-P1', 14, 1, 'support')
    add_zia('ZIA-P2', 17, 2, 'support')
    add_zia('ZIA-P5', 21, 5, 'finance')
    add_zia('ZIA-P6', 23, 6, 'engineering')
    add_zia('ZIA-P6-B2', 11, 6, 'engineering', batch=2)
    zscaler.append({'datetime': iso(BASE), 'action': 'Allowed', '_collection': {'batch_id': 1, 'source': 'zscaler-nss-web', 'complete': True}})

    assert len(workers) == 1000 and len(okta) == 8000 and len(zscaler) == 40000 and len(services) == 200
    write_jsonl(raw / 'hr_workers.jsonl', workers)
    write_jsonl(raw / 'okta_system_log.jsonl', okta)
    write_jsonl(raw / 'zscaler_nss_web.jsonl', zscaler)
    context = root / 'data' / 'context' / 'business_services.json'
    context.parent.mkdir(parents=True, exist_ok=True)
    context.write_text(json.dumps(services, indent=2), encoding='utf-8')
    manifest = {'seed': SEED, 'source_kind': 'deterministic mock data shaped like documented vendor exports',
                'counts': {'hr': 1000, 'okta': 8000, 'zscaler': 40000, 'business_services': 200},
                'batches': [1, 2], 'generated_for': 'risk.engineer Lab 01; not production telemetry'}
    marker.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


if __name__ == '__main__':
    print(json.dumps(generate(force=True), indent=2))
