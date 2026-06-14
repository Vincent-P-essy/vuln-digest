"""CISA Known Exploited Vulnerabilities collector."""

import logging
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class CISAKEVCollector:
    """Collects entries from the CISA Known Exploited Vulnerabilities catalogue."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "vuln-digest/1.0"})

    def fetch_all(self) -> list[dict]:
        """Download the full CISA KEV catalogue.

        Returns:
            List of vulnerability dicts.
        """
        try:
            response = self.session.get(CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.ConnectionError:
            logger.warning("Cannot connect to CISA KEV feed. Returning empty list.")
            return []
        except requests.exceptions.Timeout:
            logger.warning("CISA KEV request timed out. Returning empty list.")
            return []
        except requests.exceptions.RequestException as exc:
            logger.warning("CISA KEV error: %s. Returning empty list.", exc)
            return []

        vulns = data.get("vulnerabilities", [])
        logger.info("CISA KEV: fetched %d total entries.", len(vulns))
        return [self._parse_item(v) for v in vulns]

    def fetch_recent(self, days_back: int = 7) -> list[dict]:
        """Return only KEV entries added within the last N days.

        Args:
            days_back: Number of days to look back.

        Returns:
            Filtered list of recently-added KEV entries.
        """
        all_entries = self.fetch_all()
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days_back)
        recent = []
        for entry in all_entries:
            date_added_str = entry.get("date_added", "")
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                if date_added >= cutoff:
                    recent.append(entry)
            except ValueError:
                continue

        logger.info(
            "CISA KEV: %d entries added in the last %d day(s).", len(recent), days_back
        )
        return recent

    @staticmethod
    def _parse_item(v: dict) -> dict:
        return {
            "source": "cisa_kev",
            "cve_id": v.get("cveID", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "short_description": v.get("shortDescription", ""),
            "required_action": v.get("requiredAction", ""),
            "due_date": v.get("dueDate", ""),
            # Mark as actively exploited
            "is_exploited": True,
        }
