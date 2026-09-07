"""Experimental identification contracts; OCSF remains the event authority."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

SCHEMAS = Path(__file__).parent / 'schemas'


def validate_contract(name, value):
    schema = json.loads((SCHEMAS / f'{name}.schema.json').read_text(encoding='utf-8'))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    return value


def evidence_bundle(bundle):
    identity_ids = bundle['identity_uids']
    condition = []
    if bundle.get('reason'):
        condition = [{'description': bundle['reason'], 'rule_id': 'leaver-access-v1',
                      'evidence_ids': bundle['evidence_ids']}]
    return validate_contract('RiskEvidenceBundle', {
        'schema_version': '1.0.0',
        'bundle_id': bundle.get('cluster_id', bundle['scenario_id']),
        'collection_batch': bundle['collection_batch'],
        'scope': {'identity_ids': identity_ids, 'service_ids': [bundle['service_id']],
                  'start_ms': bundle['first_activity_ms'], 'end_ms': bundle['last_activity_ms']},
        'evidence': bundle['evidence_records'],
        'derived_conditions': condition,
        'business_context': {'objective_id': bundle['objective_id'], 'objective': bundle['business_objective'],
                             'service': bundle['service_name'], 'owner': bundle['service_owner'],
                             'data_classification': bundle['data_classification'],
                             'target_profile_outcomes': [bundle['profile_outcome']], 'origin': bundle['context_origin']},
        'limitations': ['Activity does not establish authorization, malicious intent, or business loss.',
                        'Identity IDs are observed in the current window; an empty list means unresolved, even when HR supplies an expected ID.',
                        'Web activity is joined by login and service; this is not proof of a shared authenticated session.',
                        'Source availability and event absence are not proof of complete collection or globally revoked access.',
                        'The cluster is a bounded investigation lead, not a risk determination.'],
    })


def candidate_scenario(candidate, bundle):
    value = {
        'schema_version': '1.0.0', 'scenario_id': candidate['scenario_id'], 'bundle_id': bundle['bundle_id'],
        'collection_batch': bundle['collection_batch'], 'observed_condition': candidate['observed_condition'],
        'threat_event': candidate['threat_event'], 'potential_consequence': candidate['potential_consequence'],
        'risk_statement': candidate['statement'], 'business_context': bundle['business_context'],
        'evidence_ids': candidate['evidence_ids'], 'assumptions': candidate['assumptions'],
        'open_questions': candidate['open_questions'], 'review_status': 'candidate-human-review-required',
        'origin': 'model-generated',
    }
    validate_contract('CandidateRiskScenario', value)
    available = {e['evidence_id'] for e in bundle['evidence']}
    if set(value['evidence_ids']) != available:
        raise ValueError('Candidate citations must match the inspected evidence bundle')
    return value
