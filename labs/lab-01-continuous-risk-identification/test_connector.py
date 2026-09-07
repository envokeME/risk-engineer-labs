import json
import tempfile
import unittest
from pathlib import Path

from connectors.okta_system_log import collect


class OktaConnectorTests(unittest.TestCase):
    def test_collects_pages(self):
        calls = []

        def fake_transport(url, token):
            calls.append((url, token))
            if len(calls) == 1:
                return ([{"uuid": "one"}], {"Link": '<https://tenant.okta.com/api/v1/logs?after=one>; rel="next"'})
            return ([{"uuid": "two"}], {})

        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "raw" / "okta_system_log.jsonl"
            result = collect("https://tenant.okta.com", "private-token", "2026-09-01T00:00:00Z",
                             "2026-09-02T00:00:00Z", 7, output, transport=fake_transport)
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(result["records"], 2)
        self.assertEqual([row["uuid"] for row in rows], ["one", "two"])
        self.assertTrue(all(row["_collection"]["batch_id"] == 7 for row in rows))
        self.assertTrue(all(token == "private-token" for _, token in calls))

    def test_rejects_cross_origin_pagination(self):
        def fake_transport(url, token):
            return ([{"uuid": "one"}], {"Link": '<https://attacker.example/logs>; rel="next"'})

        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "different origin"):
                collect("https://tenant.okta.com", "private-token", "a", "b", 1,
                        Path(folder) / "records.jsonl", transport=fake_transport)


if __name__ == "__main__":
    unittest.main()
