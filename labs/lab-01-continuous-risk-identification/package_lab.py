"""Explicit public-artifact allowlist. Never include runtime or credentials."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import re

root = Path(__file__).resolve().parent
names = ['contracts.py', 'ingestion.py', 'import_exports.py', 'config/source_registry.json', 'schemas/IngestionReceipt.schema.json', 'schemas/RiskEvidenceBundle.schema.json', 'schemas/CandidateRiskScenario.schema.json', 'fixture_factory.py', 'pipeline.py', 'methodology.py', 'exercise.py', 'engine.py', 'evaluation.py', 'evals/ground_truth.json', 'evals/scorecard.json', 'visuals.py', 'test_engine.py', 'test_connector.py', 'connectors/README.md', 'connectors/okta_system_log.py', 'build_notebook.py', 'execute_notebook.py',
         'package_lab.py', 'requirements.txt', 'Dockerfile', 'compose.yaml', '.dockerignore',
         'README.md', 'SPEC.md', 'VALIDATION.md', 'SEMANTIC-REVIEW.md',
         'lab-01-continuous-risk-identification.ipynb',
         'examples/batch-1.json', 'examples/batch-2.json', 'assets/source-volume.png',
         'assets/pipeline-funnel.png', 'assets/agent-investigation.png', 'assets/candidate-risk-register.png', 'assets/evidence-to-statement.png', 'assets/evidence-history.png']
for name in names:
    path = root / name
    if path.suffix != '.png':
        content = path.read_text(encoding='utf-8')
        if re.search(r'sk-(?:proj-)?[A-Za-z0-9_-]{24,}', content):
            raise RuntimeError('Potential credential pattern; packaging stopped')
with ZipFile(root / 'risk-engineer-lab-01.zip', 'w', ZIP_DEFLATED) as archive:
    for name in names:
        archive.write(root / name, 'risk-engineer-lab-01/' + name)
    archive.write(root.parent.parent / 'LICENSE', 'risk-engineer-lab-01/LICENSE')
print(f'Packaged {len(names)} allowlisted files; no runtime, environment files or credentials included')
