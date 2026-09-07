"""Collect Okta System Log pages into Lab 01's registered raw JSONL contract.

Release validation uses an injected fake transport. A live tenant is not required.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def _next_link(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        sections = [item.strip() for item in part.split(";")]
        if len(sections) > 1 and sections[1] == 'rel="next"':
            return sections[0].strip("<>")
    return None


def _validate_origin(expected: str, candidate: str) -> None:
    expected_url = urllib.parse.urlsplit(expected)
    candidate_url = urllib.parse.urlsplit(candidate)
    if expected_url.scheme != "https" or candidate_url.scheme != "https":
        raise ValueError("Okta collection requires HTTPS")
    if (expected_url.scheme, expected_url.netloc) != (candidate_url.scheme, candidate_url.netloc):
        raise ValueError("Refusing to forward credentials to a different origin")


def _http_get(url: str, token: str) -> tuple[list[dict], dict[str, str]]:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"SSWS {token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read()), dict(response.headers.items())


def collect(
    domain: str,
    token: str,
    since: str,
    until: str,
    batch_id: int,
    output: Path | str,
    *,
    max_pages: int = 100,
    max_records: int = 100_000,
    transport=_http_get,
) -> dict:
    """Collect bounded, paginated records and atomically publish one JSONL file."""
    domain = domain.rstrip("/")
    query = urllib.parse.urlencode({"since": since, "until": until, "limit": 1000})
    url = f"{domain}/api/v1/logs?{query}"
    _validate_origin(domain, url)
    records: list[dict] = []
    pages = 0
    collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    while url:
        if pages >= max_pages:
            raise RuntimeError("Okta page limit reached before collection completed")
        _validate_origin(domain, url)
        page, headers = transport(url, token)
        if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
            raise ValueError("Okta response must be a JSON array of objects")
        for record in page:
            enriched = dict(record)
            enriched["_collection"] = {
                "source_id": "okta-system-log",
                "batch_id": batch_id,
                "collected_at": collected_at,
                "window_start": since,
                "window_end": until,
            }
            records.append(enriched)
            if len(records) > max_records:
                raise RuntimeError("Okta record limit reached before collection completed")
        pages += 1
        link = next((value for key, value in headers.items() if key.lower() == "link"), None)
        url = _next_link(link)

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, delete=False) as handle:
        temporary = Path(handle.name)
        for record in records:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")
    temporary.replace(destination)
    return {"source_id": "okta-system-log", "pages": pages, "records": len(records), "output": str(destination)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect bounded Okta System Log evidence for Lab 01")
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--batch-id", required=True, type=int)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--max-records", type=int, default=100_000)
    args = parser.parse_args()
    domain = os.environ.get("OKTA_DOMAIN", "")
    token = os.environ.get("OKTA_API_TOKEN", "")
    if not domain or not token:
        raise SystemExit("Set OKTA_DOMAIN and OKTA_API_TOKEN outside the repository")
    print(collect(domain, token, args.since, args.until, args.batch_id, args.output,
                  max_pages=args.max_pages, max_records=args.max_records))
