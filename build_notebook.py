"""Build the learner-facing Jupyter lab."""
from pathlib import Path
import nbformat as n

ROOT = Path(__file__).resolve().parent
cells = []
def md(text): cells.append(n.v4.new_markdown_cell(text))
def code(text): cells.append(n.v4.new_code_cell(text))

md('''# Lab 01 · Continuous risk identification
**risk.engineer · Risk engineering lifecycle, step 1**

A security tool produces events. A business system supplies context. Neither produces a risk statement by itself.

In this lab, you will run a repeatable data pipeline that turns **49,200 vendor-shaped mock records** into a small set of cited candidate risk statements:

`Okta + Zscaler → validation → OCSF → business context → bounded clusters → agent investigation → human review`

The pipeline identifies plausible scenarios. It does **not** score likelihood, rate impact, prioritize, recommend treatment, or accept risk.

**Time:** 45–60 minutes · **Cost:** $0 in replay mode; variable in live mode · **Prerequisites:** basic Python/JSON and either Python 3.12 or Docker

**Learning objectives**

1. Land and receipt multiple changing sources without losing provenance.
2. Map vendor fields to validated OCSF events while keeping business context separate.
3. Use an agent to investigate every bounded cluster and abstain when the evidence is incomplete, contradictory, or ambiguous.
4. Validate citations and measure the workflow against known synthetic cases.

**Expected output:** a visual candidate-risk register, an evidence graph, batch history, the full agent tool trace, and a machine-readable evaluation scorecard.''')

code('''import json
from pathlib import Path
import duckdb
from IPython.display import display, Markdown
from fixture_factory import generate
from ingestion import ingest
from pipeline import build_warehouse, correlate
from engine import run, VERSION
from evaluation import evaluate
from visuals import show_volume, show_funnel, show_evidence, show_investigation_board, show_register, show_history

ROOT = Path.cwd()
LIVE = False  # True makes paid API calls using OPENAI_API_KEY. False replays saved real model traces.
display(Markdown("**Mode:** " + ("live bounded model run" if LIVE else "saved real model output over regenerated mock evidence")))''')

md('''## 1 · Begin with the objective, not the alert

The fictional organization needs former-worker access removed so customer information, financial reporting, and software delivery remain protected. NIST CSF outcome **PR.AA-05** supplies target-profile context: access permissions are managed, enforced, and reviewed.

This is not a maturity score. It tells us which desired outcome may be affected. The security evidence still has to support a condition, and a plausible threat event still has to connect that condition to a potential consequence.''')

code('''manifest = generate(ROOT)
manifest''')

md('''## 2 · Register, land and receipt every source

The fixture factory stands in for upstream collectors. It produces deterministic JSON shaped like records teams receive from Okta System Log and Zscaler NSS. HR and the service catalog provide separate context. These are mock records—no vendor tenant or real person is represented.

Ingestion is a separate boundary. A source registry declares the role, format, adapter, identity field and batch field for every feed. The ingestor copies each file into a content-addressed landing path, calculates a SHA-256 checksum, counts records and batches, reports missing or duplicate source IDs, and issues a validated receipt. Reprocessing the same files produces the same receipt and does not duplicate the landed object.

This stage does not decide whether a security record is meaningful or ask an LLM to repair it. A valid JSON record may still fail vendor mapping or OCSF validation later.

At this volume, the lesson is visible: sending every event to a model would be expensive, hard to audit, and unnecessary.''')

code('''receipt = ingest(ROOT)
show_volume({'pipeline': {'manifest': {'raw_counts': receipt['counts']}}})
display([{
    'source': source['label'], 'role': source['role'], 'records': source['record_count'],
    'batches': source['batch_counts'] or 'snapshot', 'status': source['transport_status'],
    'sha256': source['sha256'][:12] + '…'
} for source in receipt['sources']])

def first_jsonl(path):
    with path.open(encoding='utf-8') as handle:
        return json.loads(next(handle))

display({'Okta source record': first_jsonl(ROOT / 'data/raw/okta_system_log.jsonl')})
display({'Zscaler source record': first_jsonl(ROOT / 'data/raw/zscaler_nss_web.jsonl')})
print('Ingestion run:', receipt['run_id'], '· ready for:', receipt['ready_for'])''')

md('''## 3 · Validate and normalize landed telemetry to OCSF

The pipeline reads the landed copies referenced by the receipt. It rejects malformed source rows into quarantine. Valid Okta and Zscaler records are mapped to OCSF 1.8.0 classes and checked against the packaged OCSF JSON Schema before they are written to Parquet.

- Okta authentication → **Authentication [3002]**
- Okta account deactivation → **Account Change [3001]**
- Zscaler web request → **HTTP Activity [4002]**

HR and business-service data remain enrichment. Forcing them into a security-event schema would erase useful meaning.''')

md('''### The adapter is an explicit field contract

| Source field | OCSF / query projection | Why it survives |
|---|---|---|
| Okta `published` | `time` | orders identity activity |
| Okta `uuid` | `metadata.original_event_uid` | preserves source provenance |
| Okta target user | `user` | supports identity joins |
| Okta target app | `service` | connects access to a business service |
| Okta `outcome.result` | `status_id` | distinguishes successful activity |
| Zscaler `datetime` | `time` | aligns web and identity timelines |
| Zscaler `event_id` | `metadata.original_event_uid` | preserves source provenance |
| Zscaler `login` | `src_endpoint.owner.name` | supports identity correlation |
| Zscaler `hostname` | `dst_endpoint.hostname` | resolves the destination service |
| Zscaler `url` / `requestmethod` | `http_request` | retains the observed request |

The normalized event is not invented by the model. An adapter performs this mapping and OCSF Schema validation determines whether the result is accepted.''')

code('''warehouse = build_warehouse(ROOT)
display(warehouse)

con = duckdb.connect()
try:
    con.read_parquet(str(ROOT / 'data/normalized/ocsf_events.parquet')).create_view('events')
    sample = con.execute("SELECT source, evidence_id, class_uid, activity_id, ocsf_json FROM events WHERE evidence_id='OKTA-P1'").fetchone()
finally:
    con.close()
display({'source': sample[0], 'evidence_id': sample[1], 'class_uid': sample[2], 'activity_id': sample[3], 'ocsf_event': json.loads(sample[4])})''')

md('''## 4 · Form an investigation queue

DuckDB groups observations by worker login and expected service, retaining all observed identity UIDs. A login match is a lead; a unique identity consistent with HR is required before supporting this scenario.

Our reference method requires successful authentication and allowed web activity after termination and after the latest observed disable, if present. Multiple or conflicting identities mean ambiguity; no observed identity means insufficient evidence. A disable with no later qualifying activity contradicts the narrow condition for this window only.

These conditions define one scenario family. The method is visible in code for comparison, while the agent receives the facts without the reference labels.''')

code('''pipelines = [correlate(1, ROOT), correlate(2, ROOT)]
display([{k: c[k] for k in ('person_id', 'service_id', 'identity_uids', 'evidence_ids')} for c in pipelines[0]['clusters']])''')

md('''**Learner checkpoint — predict before revealing batch 2:**

- P0001 has a supported trail in batch 1. What should happen if a successful disable event appears in batch 2?
- P0002 resolves to two identity UIDs in batch 1. Should the system guess?
- P0004 has only part of the required event pair. Is absence of evidence proof that no risk exists?

Run the later history visual to test your answers. Consider what each result tells you, and what it cannot establish.''')

md('''## 5 · Investigate six bounded clusters with a constrained agent

Code reduces 49,200 records to six terminated-worker investigation clusters. It does **not** tell the model which ones are supported. Each cluster contains neutral observed facts, stable identifiers, and the exact evidence IDs available for citation.

The bounded agent can only list clusters, inspect a timeline, look up business context, submit a candidate, and close a cluster. It has no raw-file access and no arbitrary SQL. Code rejects invented citations, assessment language, oversized statements, and decisions made before inspection. Every cluster must end as `candidate-submitted`, `insufficient-evidence`, `contradicted`, or `ambiguous`.''')

code('''results = []
for batch in (1, 2):
    if LIVE:
        results.append(run(batch))
    else:
        saved = ROOT / f'examples/batch-{batch}.json'
        result = json.loads(saved.read_text(encoding='utf-8'))
        assert result['version'] == VERSION, 'Saved traces are from a different engine revision.'
        assert result['pipeline']['clusters'] == pipelines[batch-1]['clusters'], 'Saved evidence differs from local input. Use live mode for changed inputs.'
        results.append(result)

show_funnel(results[0])
display([{'cluster_id': c['cluster_id'], 'records': len(c['evidence_records'])} for c in results[0]['pipeline']['clusters']])
print('Model:', results[0]['reasoning']['model'])
for event in results[0]['reasoning']['trace']:
    target = event['arguments'].get('cluster_id', 'pipeline')
    print(f"turn {event['turn']:>2} · {event['tool']:<25} · {target:<35} · accepted={event['accepted']}")''')

md('''## 6 · Review the identified scenarios and their history

The risk statement follows a reviewable structure:

> If a plausible threat event acts through the observed condition, then a potential business consequence may occur, affecting an objective.

The event records support account activity, not the identity of the person operating the account, malicious intent, compromise or loss. A second collection may strengthen, weaken or remove evidence support while the stable scenario ID preserves history.

**Review the model, too:** several saved statements attribute activity to the departed worker when the records only identify the account. Business consequences are broad hypotheses. SEMANTIC-REVIEW.md records these limitations and a more careful editorial formulation; exact model outputs remain visible below.''')

code('''show_investigation_board(results[0])
show_evidence(results[0])
show_register(results[0])
show_history(results)

display({'batch_1': results[0]['pipeline']['stage_counts'], 'batch_2': results[1]['pipeline']['stage_counts']})''')

md('''### Evaluate the workflow, not the prose

The included benchmark contains twelve author-labeled synthetic cases across two collection batches. It tests candidate precision/recall, abstention and contradiction decisions, citation sets, the identification-only boundary, and tool-budget compliance. This is a regression harness—not independent evidence that the approach works on a real enterprise estate.''')
code('''scorecard = evaluate(results)
display(scorecard)
assert scorecard['passed'], 'Review the failed metric before treating this run as validated.' ''')

md('''### Change the input and prove the difference

P0001's second collection contains a disable. Predict what happens if successful authentication and allowed web activity arrive **after** that disable.

The next cell creates an isolated fixture workspace, appends two vendor JSON records, and reruns ingestion, normalization and the reference method. The content hash must change and the same scenario must return to candidate support. This exercise is deterministic and makes no model call. Open exercise.py to change the two timestamps and test the opposite ordering.''')
code('''from exercise import run_exercise
exercise_result = run_exercise()
display(exercise_result)
assert exercise_result['before'] == 'contradicted'
assert exercise_result['after'] == 'candidate-submitted' ''')

md('''### Inspect the risk-identification contracts

OCSF describes events. Our experimental `RiskEvidenceBundle` links those events to scope, derived conditions, business context, and limitations before the LLM sees them. `CandidateRiskScenario` validates the resulting hypothesis, citations, assumptions, and review status.

These are versioned lab contracts, not an industry standard. HR is optional in the contract; the current offboarding adapter needs HR to establish termination. The current rule selects this scenario family before model reasoning.''')
code('''from contracts import evidence_bundle, validate_contract
bundle = evidence_bundle(pipelines[0]['clusters'][0])
display(bundle)
scenario = results[0]['reasoning']['candidates'][0]['risk_scenario']
validate_contract('CandidateRiskScenario', scenario)
display(scenario)''')

md('''## What you built

You built the first step of a risk engineering lifecycle: continuous identification from changing system evidence. The separation of responsibilities is deliberate:

1. schemas make records interoperable;
2. deterministic code validates, joins, reduces, and abstains;
3. the LLM expresses a bounded scenario from cited evidence and business context;
4. a human decides whether the candidate is useful enough to enter a governed risk process.

### References

- [OCSF schema](https://github.com/ocsf/ocsf-schema) — vendor-neutral security-event structure.
- [Okta System Log](https://developer.okta.com/docs/reference/system-log-query/) — vendor source shape and polling model.
- [NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) — target-profile outcome context.
- [NIST SP 800-30 Rev. 1](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-30r1.pdf) — threat-event and predisposing-condition concepts; this lab is not a full assessment.

**Cleanup:** stop Jupyter, or run `docker compose down`. Add `-v` only if you intentionally want to delete generated data and history. Never place an API key in this notebook or repository.''')

notebook = n.v4.new_notebook(cells=cells, metadata={
    'kernelspec': {'display_name': 'Python 3', 'language': 'python', 'name': 'python3'},
    'language_info': {'name': 'python', 'version': '3.12'},
})
n.write(notebook, ROOT / 'lab-01-continuous-risk-identification.ipynb')
