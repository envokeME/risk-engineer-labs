"""Manifest-driven, content-addressed file ingestion before OCSF mapping."""
from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent


def nested(record, dotted_path):
    value = record
    for part in dotted_path.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def load_records(path, file_format):
    if file_format == 'jsonl':
        records = []
        with path.open(encoding='utf-8') as handle:
            for line_number, line in enumerate(handle, 1):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f'{path.name}:{line_number} is not valid JSON') from exc
        return records
    records = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(records, list):
        raise ValueError(f'{path.name} must contain a JSON array')
    return records


def ingest(root=None, registry_path=None):
    """Land registered files once by digest and issue a validated receipt.

    This boundary checks transport integrity and provenance. Vendor semantics and
    OCSF validation happen later, so malformed source records remain observable.
    """
    root = Path(root or ROOT).resolve()
    registry_file = Path(registry_path or (root / 'config/source_registry.json'))
    if not registry_file.exists():
        registry_file = ROOT / 'config/source_registry.json'
    registry = json.loads(registry_file.read_text(encoding='utf-8'))
    raw_manifest_path = root / 'data/raw/manifest.json'
    raw_manifest = json.loads(raw_manifest_path.read_text(encoding='utf-8')) if raw_manifest_path.exists() else {}
    receipts, counts, required_scenarios = [], {}, []

    for source in registry['sources']:
        source_path = root / 'data' / source['relative_path']
        if not source_path.exists():
            raise FileNotFoundError(f"Required registered source is missing: {source['source_id']} ({source_path})")
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        landing_path = root / 'data/landing' / source['source_id'] / digest[:16] / source_path.name
        if not landing_path.exists():
            landing_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, landing_path)
        elif hashlib.sha256(landing_path.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f'Content-addressed landing collision for {source["source_id"]}')

        records = load_records(landing_path, source['format'])
        if not records:
            raise ValueError(f"Registered source is empty: {source['source_id']}")
        ids = [nested(record, source['record_id_path']) for record in records]
        present_ids = [str(value) for value in ids if value not in (None, '')]
        duplicate_count = sum(count - 1 for count in Counter(present_ids).values() if count > 1)
        batch_counts = Counter()
        if source.get('batch_path'):
            for record in records:
                batch = nested(record, source['batch_path'])
                if batch is not None:
                    batch_counts[str(batch)] += 1
        missing = len(records) - len(present_ids)
        status = 'accepted-with-envelope-warnings' if missing or duplicate_count else 'accepted'
        receipt = {
            'source_id': source['source_id'], 'label': source['label'], 'role': source['role'],
            'adapter': source['adapter'], 'format': source['format'],
            'source_path': source_path.relative_to(root).as_posix(),
            'landing_path': landing_path.relative_to(root).as_posix(),
            'sha256': digest, 'bytes': source_path.stat().st_size, 'record_count': len(records),
            'records_with_id': len(present_ids), 'records_missing_id': missing,
            'duplicate_ids': duplicate_count, 'batch_counts': dict(sorted(batch_counts.items())),
            'transport_status': status,
        }
        receipts.append(receipt)
        counts[source['count_key']] = len(records)
        required_scenarios.extend(source.get('required_for', []))

    ready_for = []
    for scenario in sorted(set(required_scenarios)):
        needed = {s['source_id'] for s in registry['sources'] if scenario in s.get('required_for', [])}
        present = {r['source_id'] for r in receipts}
        if needed <= present:
            ready_for.append(scenario)
    run_material = ''.join(item['sha256'] for item in receipts) + registry['registry_version']
    result = {
        'schema_version': '1.0.0', 'registry_version': registry['registry_version'],
        'run_id': hashlib.sha256(run_material.encode()).hexdigest()[:16],
        'source_kind': raw_manifest.get('source_kind', 'registered file drop'),
        'counts': counts, 'sources': receipts,
        'ready_for': ready_for,
    }
    schema = json.loads((ROOT / 'schemas/IngestionReceipt.schema.json').read_text(encoding='utf-8'))
    Draft202012Validator(schema).validate(result)
    receipt_path = root / 'data/landing/ingestion_receipt.json'
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def landed_path(root, receipt, adapter):
    source = next(item for item in receipt['sources'] if item['adapter'] == adapter)
    return Path(root).resolve() / source['landing_path']


if __name__ == '__main__':
    from fixture_factory import generate
    generate(ROOT)
    print(json.dumps(ingest(ROOT), indent=2))
