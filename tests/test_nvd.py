"""Unit tests for the NVD collector."""

import pytest
import responses as responses_lib
from requests.exceptions import ConnectionError

from collectors.nvd import NVD_BASE_URL, NVDCollector


@pytest.fixture
def nvd_response():
    return {
        "totalResults": 2,
        "resultsPerPage": 2000,
        "startIndex": 0,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-15T10:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "A critical RCE in Apache Log4j allows remote code execution."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"value": "CWE-502"}]}
                    ],
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-0002",
                    "published": "2024-01-15T11:00:00.000",
                    "descriptions": [
                        {"lang": "fr", "value": "Vulnérabilité SSH critique"},
                        {"lang": "en", "value": "Critical SSH vulnerability in OpenSSH."},
                    ],
                    "metrics": {
                        "cvssMetricV30": [
                            {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                        ]
                    },
                    "weaknesses": [],
                    "references": [],
                }
            },
        ],
    }


@responses_lib.activate
def test_fetch_recent_parses_cves(nvd_response):
    responses_lib.add(
        responses_lib.GET,
        NVD_BASE_URL,
        json=nvd_response,
        status=200,
    )
    collector = NVDCollector(api_key=None)
    results = collector.fetch_recent(days_back=1)

    assert len(results) == 2
    cve1 = results[0]
    assert cve1["cve_id"] == "CVE-2024-0001"
    assert cve1["cvss_v3_score"] == 9.8
    assert cve1["cvss_v3_severity"] == "CRITICAL"
    assert "CWE-502" in cve1["cwe"]
    assert cve1["source"] == "nvd"
    assert "Apache Log4j" in cve1["description"]


@responses_lib.activate
def test_fetch_recent_english_description_preferred(nvd_response):
    responses_lib.add(responses_lib.GET, NVD_BASE_URL, json=nvd_response, status=200)
    collector = NVDCollector()
    results = collector.fetch_recent(days_back=1)
    assert results[1]["description"] == "Critical SSH vulnerability in OpenSSH."


@responses_lib.activate
def test_fetch_recent_returns_empty_on_connection_error():
    responses_lib.add(
        responses_lib.GET,
        NVD_BASE_URL,
        body=ConnectionError("Network unreachable"),
    )
    collector = NVDCollector()
    results = collector.fetch_recent(days_back=1)
    assert results == []


@responses_lib.activate
def test_fetch_recent_returns_empty_on_http_error():
    responses_lib.add(responses_lib.GET, NVD_BASE_URL, status=403)
    collector = NVDCollector()
    results = collector.fetch_recent(days_back=1)
    assert results == []
