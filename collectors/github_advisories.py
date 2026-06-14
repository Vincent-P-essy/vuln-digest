"""GitHub Security Advisories collector via GraphQL API."""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

_QUERY = """
query($after: String, $publishedSince: DateTime!) {
  securityAdvisories(
    first: 100
    after: $after
    publishedSince: $publishedSince
    classifications: [GENERAL, MALWARE]
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      ghsaId
      summary
      severity
      publishedAt
      cvss {
        score
        vectorString
      }
      identifiers {
        type
        value
      }
      vulnerabilities(first: 5) {
        nodes {
          package {
            name
            ecosystem
          }
          firstPatchedVersion {
            identifier
          }
        }
      }
    }
  }
}
"""


class GitHubAdvisoriesCollector:
    """Collects security advisories from the GitHub GraphQL API."""

    def __init__(self, token: Optional[str] = None) -> None:
        self.token = token or os.getenv("GITHUB_TOKEN")
        if not self.token:
            logger.warning(
                "GITHUB_TOKEN not set. GitHub Advisories collector will return an empty list."
            )
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def fetch_recent(self, days_back: int = 1) -> list[dict]:
        """Fetch HIGH/CRITICAL security advisories published in the last N days.

        Args:
            days_back: Number of days to look back.

        Returns:
            List of advisory dicts, or empty list if token is missing.
        """
        if not self.token:
            return []

        since = datetime.now(tz=timezone.utc) - timedelta(days=days_back)
        published_since = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        all_advisories: list[dict] = []
        cursor: Optional[str] = None

        while True:
            variables = {"publishedSince": published_since, "after": cursor}
            try:
                response = self.session.post(
                    GITHUB_GRAPHQL_URL,
                    json={"query": _QUERY, "variables": variables},
                    timeout=30,
                )
                response.raise_for_status()
                body = response.json()
            except requests.exceptions.ConnectionError:
                logger.warning("Cannot connect to GitHub API. Returning empty list.")
                return []
            except requests.exceptions.Timeout:
                logger.warning("GitHub API request timed out. Returning empty list.")
                return []
            except requests.exceptions.RequestException as exc:
                logger.warning("GitHub API error: %s. Returning empty list.", exc)
                return []

            if "errors" in body:
                logger.error("GitHub GraphQL errors: %s", body["errors"])
                return []

            data = body.get("data", {}).get("securityAdvisories", {})
            nodes = data.get("nodes", [])
            # Filter to HIGH/CRITICAL only
            for node in nodes:
                if node.get("severity") in ("HIGH", "CRITICAL"):
                    all_advisories.append(self._parse_node(node))

            page_info = data.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

        logger.info(
            "GitHub Advisories: collected %d HIGH/CRITICAL advisories for the last %d day(s).",
            len(all_advisories),
            days_back,
        )
        return all_advisories

    @staticmethod
    def _parse_node(node: dict) -> dict:
        cve_ids = [
            i["value"]
            for i in node.get("identifiers", [])
            if i.get("type") == "CVE"
        ]
        packages = [
            {
                "name": v["package"]["name"],
                "ecosystem": v["package"]["ecosystem"],
                "patched_version": (
                    v.get("firstPatchedVersion", {}) or {}
                ).get("identifier"),
            }
            for v in node.get("vulnerabilities", {}).get("nodes", [])
        ]
        return {
            "source": "github_advisories",
            "ghsa_id": node.get("ghsaId", ""),
            "cve_id": cve_ids[0] if cve_ids else "",
            "cve_ids": cve_ids,
            "summary": node.get("summary", ""),
            "severity": node.get("severity", ""),
            "cvss_score": (node.get("cvss") or {}).get("score"),
            "published_at": node.get("publishedAt", ""),
            "affected_packages": packages,
        }
