import json
import tempfile
import unittest
from copy import deepcopy
from jsonschema import ValidationError
from contracts import evidence_bundle, validate_contract
from import_exports import import_exports
from ingestion import ingest
from pathlib import Path

import duckdb

from engine import run, validate_candidate
from evaluation import evaluate
from methodology import reference_disposition
from pipeline import ROOT, VALIDATORS, correlate


def fake_reasoner(pipeline):
    candidates = []
    dispositions = []
    findings = {item['scenario_id']: item for item in pipeline['findings']}
    for bundle in pipeline['clusters']:
        state = findings[bundle['scenario_id']]['state']
        if state != 'supported':
            disposition = reference_disposition(bundle)
            dispositions.append({'cluster_id': bundle['cluster_id'], 'disposition': disposition,
                                 'rationale': findings[bundle['scenario_id']]['reason'], 'evidence_ids': bundle['evidence_ids']})
            continue
        args = {
            'cluster_id': bundle['cluster_id'],
            'observed_condition': 'Post-termination successful authentication and allowed web activity reached the expected service.',
            'statement': (f"If an unauthorized actor uses the observed post-termination access path to {bundle['service_name']}, "
                          f"then information or service integrity may be affected, affecting {bundle['business_objective']}."),
            'threat_event': 'Unauthorized use of a retained account',
            'potential_consequence': 'Loss of information or service integrity',
            'assumptions': ['The correlated account belongs to the terminated worker.'],
            'open_questions': ['Did the service owner approve any continued access?'],
            'evidence_ids': bundle['evidence_ids'],
        }
        candidates.append(validate_candidate(args, bundle))
        dispositions.append({'cluster_id': bundle['cluster_id'], 'disposition': 'candidate-submitted',
                             'rationale': 'The evidence pair and context support a candidate.', 'evidence_ids': bundle['evidence_ids']})
    return {'candidates': candidates, 'dispositions': dispositions, 'trace': [], 'usage': {}, 'model': 'offline-test', 'response_id': None}


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.batch1 = correlate(1)
        cls.batch2 = correlate(2)

    def test_realistic_fixture_volume_and_reduction(self):
        self.assertEqual(self.batch1['stage_counts']['raw_records'], 49200)
        self.assertEqual(self.batch1['stage_counts']['normalized_events'], 47998)
        self.assertEqual(self.batch1['stage_counts']['quarantined'], 2)
        self.assertEqual(self.batch1['stage_counts']['relevant_terminated_user_events'], 11)
        self.assertEqual(len(self.batch1['bundles']), 3)
        self.assertEqual(len(self.batch2['bundles']), 1)

    def test_risk_contracts_and_forbidden_assessment_field(self):
        bundle = evidence_bundle(self.batch1['clusters'][0])
        validate_contract('RiskEvidenceBundle', bundle)
        candidate = fake_reasoner(self.batch1)['candidates'][0]['risk_scenario']
        validate_contract('CandidateRiskScenario', candidate)
        with self.assertRaises(ValidationError):
            validate_contract('CandidateRiskScenario', {**candidate, 'likelihood': 5})
        no_hr = deepcopy(bundle)
        no_hr['evidence'] = [e for e in no_hr['evidence'] if e['source'] != 'hr']
        no_hr['derived_conditions'] = []
        validate_contract('RiskEvidenceBundle', no_hr)

    def test_import_preserves_sources_and_refuses_existing_target(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'imported'
            import_exports(ROOT / 'data', destination)
            original = ROOT / 'data/raw/okta_system_log.jsonl'
            self.assertEqual(original.read_bytes(), (destination / 'data/raw/okta_system_log.jsonl').read_bytes())
            receipt = json.loads((destination / 'data/landing/ingestion_receipt.json').read_text(encoding='utf-8'))
            self.assertEqual(sum(receipt['counts'].values()), 49200)
            self.assertEqual(receipt['ready_for'], ['leaver-access-v1'])
            with self.assertRaises(ValueError):
                import_exports(ROOT / 'data', destination)

    def test_ingestion_is_content_addressed_and_reports_envelope_quality(self):
        first = ingest(ROOT)
        second = ingest(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(len(first['sources']), 4)
        self.assertEqual(sum(first['counts'].values()), 49200)
        okta = next(item for item in first['sources'] if item['adapter'] == 'okta')
        zscaler = next(item for item in first['sources'] if item['adapter'] == 'zscaler')
        self.assertEqual(okta['batch_counts'], {'1': 4003, '2': 3997})
        self.assertEqual(zscaler['batch_counts'], {'1': 20002, '2': 19998})
        self.assertEqual(okta['records_missing_id'], 1)
        self.assertEqual(zscaler['records_missing_id'], 1)
        self.assertEqual(okta['transport_status'], 'accepted-with-envelope-warnings')
        self.assertTrue((ROOT / okta['landing_path']).exists())

    def test_representative_events_pass_official_ocsf_schemas(self):
        con = duckdb.connect()
        try:
            con.read_parquet(str(ROOT / 'data/normalized/ocsf_events.parquet')).create_view('events')
            rows = con.execute("SELECT class_uid, any_value(ocsf_json) FROM events GROUP BY class_uid ORDER BY class_uid").fetchall()
        finally:
            con.close()
        names = {3001: 'account_change', 3002: 'authentication', 4002: 'http_activity'}
        self.assertEqual({row[0] for row in rows}, set(names))
        for class_uid, event_json in rows:
            errors = list(VALIDATORS[names[class_uid]].iter_errors(json.loads(event_json)))
            self.assertEqual(errors, [])

    def test_correlation_abstains_when_identity_is_ambiguous(self):
        p2 = next(item for item in self.batch1['findings'] if item['person_id'] == 'P0002')
        self.assertEqual(p2['state'], 'unknown')
        self.assertIn('identity', p2['reason'].lower())

    def test_collection_batches_change_evidence_state(self):
        states1 = {item['person_id']: item['state'] for item in self.batch1['findings']}
        states2 = {item['person_id']: item['state'] for item in self.batch2['findings']}
        self.assertEqual((states1['P0001'], states2['P0001']), ('supported', 'not-supported'))
        self.assertEqual((states1['P0005'], states2['P0005']), ('supported', 'unknown'))
        self.assertEqual((states1['P0006'], states2['P0006']), ('supported', 'supported'))

    def test_statement_rejects_false_citations_and_assessment(self):
        bundle = self.batch1['clusters'][0]
        base = {
            'cluster_id': bundle['cluster_id'],
            'observed_condition': 'Post-termination activity reached the expected service.',
            'statement': 'If an unauthorized actor uses retained access, then customer information may be affected.',
            'threat_event': 'Unauthorized use',
            'potential_consequence': 'Customer information exposure',
            'assumptions': ['The account maps to the worker.'],
            'open_questions': ['Was access approved?'],
            'evidence_ids': bundle['evidence_ids'],
        }
        with self.assertRaisesRegex(ValueError, 'exactly match'):
            validate_candidate({**base, 'evidence_ids': ['made-up-id', *bundle['evidence_ids']]}, bundle)
        with self.assertRaisesRegex(ValueError, 'assessment language'):
            validate_candidate({**base, 'statement': base['statement'] + ' Likelihood is high.'}, bundle)

    def test_replay_is_idempotent_and_scenario_ids_are_stable(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / 'history.sqlite'
            first = run(1, db_path=db, reasoner=fake_reasoner)
            second = run(1, db_path=db, reasoner=lambda _: (_ for _ in ()).throw(AssertionError('cache missed')))
        self.assertEqual(first, second)
        self.assertEqual(
            [item['scenario_id'] for item in first['pipeline']['bundles']],
            [item['scenario_id'] for item in self.batch1['bundles']],
        )

    def test_synthetic_evaluation_scorecard(self):
        with tempfile.TemporaryDirectory() as folder:
            results = [run(batch, db_path=Path(folder) / 'history.sqlite', reasoner=fake_reasoner) for batch in (1, 2)]
        scorecard = evaluate(results, require_trace=False)
        self.assertTrue(scorecard['passed'])
        self.assertFalse(evaluate(results)['passed'], 'Offline substitute cannot pass live trace verification')
        self.assertEqual(scorecard['cases'], 12)
        self.assertEqual(scorecard['candidate_precision'], 1)

    def test_missing_identity_is_not_replaced_by_hr(self):
        cluster = next(c for c in self.batch2['clusters'] if c['person_id'] == 'P0005')
        self.assertEqual(evidence_bundle(cluster)['scope']['identity_ids'], [])
        self.assertEqual(reference_disposition(cluster), 'insufficient-evidence')

    def test_disable_does_not_erase_later_activity(self):
        cluster = deepcopy(self.batch1['clusters'][0])
        cluster['disable_times'] = [cluster['first_activity_ms'] - 1]
        self.assertEqual(reference_disposition(cluster), 'candidate-submitted')
        cluster['disable_times'] = [cluster['last_activity_ms'] + 1]
        self.assertEqual(reference_disposition(cluster), 'contradicted')
        cluster['web_times'] = [cluster['last_activity_ms'] + 2]
        self.assertEqual(reference_disposition(cluster), 'insufficient-evidence')
        cluster['identity_uids'] = ['a-different-identity']
        self.assertEqual(reference_disposition(cluster), 'ambiguous')

    def test_model_sees_no_reference_label(self):
        for cluster in self.batch1['clusters']:
            bundle = evidence_bundle(cluster)
            self.assertEqual(bundle['derived_conditions'], [])
            self.assertNotIn('disposition', bundle)

    def test_failed_model_does_not_lock_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / 'history.sqlite'
            with self.assertRaisesRegex(RuntimeError, 'intentional'):
                run(1, db_path=db, reasoner=lambda _: (_ for _ in ()).throw(RuntimeError('intentional')))
            self.assertEqual(len(run(1, db_path=db, reasoner=fake_reasoner)['reasoning']['candidates']), 3)


if __name__ == '__main__':
    unittest.main()
