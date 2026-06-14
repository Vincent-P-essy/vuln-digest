"""NVD REST API v2 collector for recent CVEs."""

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000


class NVDCollector:
    """Collects CVE data from the National Vulnerability Database REST API v2."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
        # NVD rate limits: 5 req/30s without key, 50 req/30s with key
        self._sleep_between_calls = 0.05 if self.api_key else 0.6

    def fetch_recent(self, days_back: int = 1) -> list[dict]:
        """Fetch CVEs published in the last N days.

        Args:
            days_back: Number of days to look back (max 120 per NVD API limits).

        Returns:
            List of vulnerability dicts with standardised fields.
        """
        now = datetime.now(tz=timezone.utc)
        start = now - timedelta(days=days_back)

        pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": 0,
        }

        all_vulns: list[dict] = []
        while True:
            try:
                time.sleep(self._sleep_between_calls)
                response = self.session.get(NVD_BASE_URL, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.ConnectionError:
                logger.warning("Cannot connect to NVD API. Returning empty list.")
                return []
            except requests.exceptions.Timeout:
                logger.warning("NVD API request timed out. Returning empty list.")
                return []
            except requests.exceptions.RequestException as exc:
                logger.warning("NVD API error: %s. Returning empty list.", exc)
                return []

            total = data.get("totalResults", 0)
            items = data.get("vulnerabilities", [])
            parsed = [self._parse_item(item) for item in items]
            all_vulns.extend(parsed)

            logger.debug(
                "NVD: fetched %d/%d CVEs (startIndex=%d)",
                len(all_vulns),
                total,
                params["startIndex"],
            )

            if len(all_vulns) >= total or not items:
                break
            params["startIndex"] += RESULTS_PER_PAGE

        logger.info("NVD: collected %d CVEs for the last %d day(s).", len(all_vulns), days_back)
        return all_vulns

    @staticmethod
    def _parse_item(item: dict) -> dict:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description (English preferred)
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS v3 score
        metrics = cve.get("metrics", {})
        cvss_v3_score: Optional[float] = None
        cvss_v3_severity: Optional[str] = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_severity = cvss_data.get("baseSeverity")
                break

        # CWE
        weaknesses = cve.get("weaknesses", [])
        cwe_list: list[str] = []
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val and val != "NVD-CWE-Other":
                    cwe_list.append(val)

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])]

        return {
            "source": "nvd",
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_severity": cvss_v3_severity,
            "cwe": cwe_list,
            "references": refs[:5],  # cap at 5
            "published": cve.get("published", ""),
        }
