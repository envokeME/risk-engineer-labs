"""Small, transparent evaluation harness for the synthetic Lab 01 cases."""
import json
import re
from pathlib import Path
from methodology import reference_disposition

ROOT = Path(__file__).resolve().parent
ASSESSMENT_LANGUAGE = re.compile(r"\b(likelihood|probability|severity|risk score|priority|treatment|acceptance)\b", re.I)


def evaluate(results, ground_truth_path=None, require_trace=True):
    truth = json.loads(Path(ground_truth_path or ROOT / "evals/ground_truth.json").read_text(encoding="utf-8"))
    expected = {}
    for batch, rows in truth["batches"].items():
        expected.update({(int(batch), sid): disposition for sid, disposition in rows.items()})
    observed, candidates, evidence, baseline = {}, {}, {}, {}
    trace_count = 0
    citations_valid = True
    trace_valid = True
    unique_records = True
    seen_batches = set()
    for result in results:
        batch = result["batch"]
        unique_records &= batch not in seen_batches
        seen_batches.add(batch)
        evidence.update({(batch, c["cluster_id"]): set(c["evidence_ids"]) for c in result["pipeline"]["clusters"]})
        baseline.update({(batch, c["cluster_id"]): reference_disposition(c) for c in result["pipeline"]["clusters"]})
        for row in result["reasoning"]["dispositions"]:
            key = (batch, row["cluster_id"])
            unique_records &= key not in observed
            observed[key] = row["disposition"]
            citations_valid &= (key in evidence and set(row["evidence_ids"]) == evidence[key]
                                and len(row["evidence_ids"]) == len(set(row["evidence_ids"])))
        for row in result["reasoning"]["candidates"]:
            key = (batch, row["cluster_id"])
            unique_records &= key not in candidates
            candidates[key] = row
        trace = result["reasoning"]["trace"]
        trace_count += len(trace)
        timelines, contexts, submitted, closed = set(), set(), set(), set()
        listed, inspected = False, False
        for event in trace:
            if not event["accepted"]:
                continue
            tool = event["tool"]
            sid = event["arguments"].get("cluster_id")
            if tool == "inspect_pipeline":
                inspected = True
            elif tool == "list_evidence_clusters":
                trace_valid &= inspected
                listed = True
            elif tool == "inspect_entity_timeline":
                trace_valid &= listed
                timelines.add(sid)
            elif tool == "lookup_business_context":
                trace_valid &= listed
                contexts.add(sid)
            elif tool in ("submit_statement", "close_cluster"):
                trace_valid &= sid in timelines and sid in contexts and sid not in closed
                if tool == "submit_statement":
                    submitted.add(sid)
                else:
                    trace_valid &= ((event["arguments"]["disposition"] == "candidate-submitted") == (sid in submitted))
                    closed.add(sid)
        expected_ids = {c["cluster_id"] for c in result["pipeline"]["clusters"]}
        trace_valid &= bool(trace) and closed == expected_ids and submitted == {c["cluster_id"] for c in result["reasoning"]["candidates"]}
    expected_candidates = {key for key, value in expected.items() if value == "candidate-submitted"}
    predicted_candidates = set(candidates)
    tp = len(expected_candidates & predicted_candidates)
    precision = tp / len(predicted_candidates) if predicted_candidates else 1.0
    recall = tp / len(expected_candidates) if expected_candidates else 1.0
    citations_valid &= all(key in evidence and set(row["evidence_ids"]) == evidence[key]
                           and len(row["evidence_ids"]) == len(set(row["evidence_ids"])) for key, row in candidates.items())
    assessment_leakage = sum(bool(ASSESSMENT_LANGUAGE.search(" ".join([
        row["observed_condition"], row["statement"], row["threat_event"], row["potential_consequence"]]))) for row in candidates.values())
    correct = sum(observed.get(key) == value for key, value in expected.items())
    scorecard = {
        "benchmark": truth["description"],
        "cases": len(expected), "correct_dispositions": correct,
        "observed_cases_match_benchmark": set(observed) == set(expected) and unique_records,
        "disposition_accuracy": round(correct / len(expected), 3),
        "candidate_precision": round(precision, 3), "candidate_recall": round(recall, 3),
        "unsupported_candidates": len(predicted_candidates - expected_candidates),
        "citation_sets_valid": citations_valid, "assessment_language_violations": assessment_leakage,
        "tool_calls": trace_count, "tool_budget_respected": all(len(r["reasoning"]["trace"]) <= 40 for r in results),
        "agent_trace_verified": bool(trace_valid),
        "baseline_correct_dispositions": sum(baseline.get(key) == value for key, value in expected.items()),
        "model_additional_correct_dispositions": correct - sum(baseline.get(key) == value for key, value in expected.items()),
        "models": sorted({r["reasoning"]["model"] for r in results}),
        "interpretation": "This benchmark tests known-case behavior. It does not establish model superiority or semantic correctness of business consequences.",
    }
    scorecard["passed"] = (scorecard["disposition_accuracy"] == 1 and precision == 1 and recall == 1
                           and citations_valid and assessment_leakage == 0 and scorecard["tool_budget_respected"]
                           and scorecard["observed_cases_match_benchmark"] and (trace_valid or not require_trace)
                           and {key for key, value in observed.items() if value == "candidate-submitted"} == predicted_candidates)
    return scorecard


if __name__ == "__main__":
    results = [json.loads((ROOT / f"examples/batch-{batch}.json").read_text(encoding="utf-8")) for batch in (1, 2)]
    scorecard = evaluate(results)
    (ROOT / "evals/scorecard.json").write_text(json.dumps(scorecard, indent=2), encoding="utf-8")
    print(json.dumps(scorecard, indent=2))
