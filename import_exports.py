"""Copy a user-supplied export set into a fresh lab workspace; never call an LLM."""
import argparse
import json
import shutil
from pathlib import Path
from ingestion import ingest

REQUIRED = ['raw/okta_system_log.jsonl', 'raw/zscaler_nss_web.jsonl',
            'raw/hr_workers.jsonl', 'context/business_services.json']


def import_exports(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError('Choose a new destination directory to preserve previous evidence')
    counts = {}
    for relative, name in zip(REQUIRED, ['okta', 'zscaler', 'hr', 'business_services']):
        path = source / relative
        if relative.endswith('.jsonl'):
            with path.open(encoding='utf-8') as handle:
                records = [json.loads(line) for line in handle if line.strip()]
        else:
            records = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(records, list) or not records:
            raise ValueError(f'{relative} must contain a nonempty record collection')
        if name in ('okta', 'zscaler'):
            for row in records:
                if not isinstance(row.get('_collection', {}).get('batch_id'), int):
                    raise ValueError(f'{relative} requires _collection.batch_id on each event')
        counts[name] = len(records)
    for relative in REQUIRED:
        target = destination / 'data' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
    (destination / 'data/raw/manifest.json').write_text(json.dumps({
        'counts': counts, 'source_kind': 'user-supplied exports', 'fixture': False,
    }, indent=2), encoding='utf-8')
    ingest(destination)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(import_exports(args.source, args.destination))
