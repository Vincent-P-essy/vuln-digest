"""Unit tests for the CISA KEV collector."""

from datetime import datetime, timedelta, timezone

import responses as responses_lib
from requests.exceptions import ConnectionError

from collectors.cisa_kev import CISA_KEV_URL, CISAKEVCollector


def _make_entry(cve_id: str, date_added: str) -> dict:
    return {
        "cveID": cve_id,
        "vendorProject": "Microsoft",
        "product": "Windows Server",
        "vulnerabilityName": f"Test vuln {cve_id}",
        "dateAdded": date_added,
        "shortDescription": "A critical vulnerability.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-02-01",
    }


@responses_lib.activate
def test_fetch_all_parses_catalogue():
    payload = {
        "vulnerabilities": [
            _make_entry("CVE-2024-0010", "2024-01-10"),
            _make_entry("CVE-2024-0011", "2024-01-12"),
        ]
    }
    responses_lib.add(responses_lib.GET, CISA_KEV_URL, json=payload, status=200)
    results = CISAKEVCollector().fetch_all()

    assert len(results) == 2
    assert results[0]["cve_id"] == "CVE-2024-0010"
    assert results[0]["vendor"] == "Microsoft"
    assert results[0]["is_exploited"] is True
    assert results[0]["source"] == "cisa_kev"


@responses_lib.activate
def test_fetch_recent_filters_by_date():
    today = datetime.now(tz=timezone.utc)
    recent_date = (today - timedelta(days=3)).strftime("%Y-%m-%d")
    old_date = (today - timedelta(days=30)).strftime("%Y-%m-%d")

    payload = {
        "vulnerabilities": [
            _make_entry("CVE-2024-0020", recent_date),
            _make_entry("CVE-2024-0021", old_date),
        ]
    }
    responses_lib.add(responses_lib.GET, CISA_KEV_URL, json=payload, status=200)
    results = CISAKEVCollector().fetch_recent(days_back=7)

    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2024-0020"


@responses_lib.activate
def test_fetch_all_returns_empty_on_error():
    responses_lib.add(responses_lib.GET, CISA_KEV_URL, body=ConnectionError())
    assert CISAKEVCollector().fetch_all() == []
