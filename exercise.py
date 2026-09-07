"""Change fixture JSON in an isolated workspace and rerun local transformations."""
import json
import tempfile
from datetime import timedelta
from pathlib import Path

from fixture_factory import BASE, generate, okta_event, zscaler_event, write_jsonl
from pipeline import correlate, rows
from methodology import reference_disposition


def run_exercise():
    """Append source events after a disable; original learner files stay intact."""
    with tempfile.TemporaryDirectory(prefix="risk-lab-exercise-") as folder:
        root = Path(folder)
        generate(root)
        before = correlate(2, root)
        okta_path = root / "data/raw/okta_system_log.jsonl"
        web_path = root / "data/raw/zscaler_nss_web.jsonl"
        okta = [row for _, row in rows(okta_path)]
        web = [row for _, row in rows(web_path)]
        okta.append(okta_event("EXERCISE-AUTH-P1", BASE + timedelta(hours=1, minutes=15),
                              "user.authentication.sso", "00u0001", "user0001@corp.example.test",
                              "support", "0oa00000", 2))
        web.append(zscaler_event("EXERCISE-WEB-P1", BASE + timedelta(hours=1, minutes=16),
                                "user0001@corp.example.test", "support.apps.example.test", 2))
        write_jsonl(okta_path, okta)
        write_jsonl(web_path, web)
        after = correlate(2, root)
        first = next(c for c in before["clusters"] if c["person_id"] == "P0001")
        second = next(c for c in after["clusters"] if c["person_id"] == "P0001")
        assert before["manifest"]["ingestion_run_id"] != after["manifest"]["ingestion_run_id"]
        assert reference_disposition(first) == "contradicted"
        assert reference_disposition(second) == "candidate-submitted"
        return {
            "mode": "local deterministic exercise; no LLM call",
            "scenario_id": second["scenario_id"],
            "before": reference_disposition(first), "after": reference_disposition(second),
            "new_evidence_ids": ["EXERCISE-AUTH-P1", "EXERCISE-WEB-P1"],
            "before_ingestion_id": before["manifest"]["ingestion_run_id"],
            "after_ingestion_id": after["manifest"]["ingestion_run_id"],
            "after_evidence": second["evidence_records"],
            "lesson": "A disable event does not erase subsequent access. Changed source bytes invalidate the warehouse cache.",
        }


if __name__ == "__main__":
    print(json.dumps(run_exercise(), indent=2))
