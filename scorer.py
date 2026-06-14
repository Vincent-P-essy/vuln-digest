"""CVSS v3 + banking-context vulnerability scorer."""

import logging

logger = logging.getLogger(__name__)

# Keywords indicating relevance to financial/banking infrastructure
BANKING_KEYWORDS = [
    "swift",
    "banking",
    "financial",
    "payment",
    "atm",
    "card",
    "pos",
    "trading",
    "oracle",
    "java",
    "apache",
    "ssl",
    "tls",
    "openssl",
    "ssh",
    "rdp",
    "citrix",
    "sap",
    "windows server",
    "active directory",
    "ldap",
    "exchange",
    "sharepoint",
    "cisco",
    "vmware",
    "spring",
    "log4j",
    "weblogic",
    "jboss",
    "struts",
]

# CVSS severity → numeric baseline (used when score is missing)
_SEVERITY_BASELINE = {
    "CRITICAL": 9.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    None: 0.0,
}


class VulnScorer:
    """Scores vulnerabilities with a business-context-aware priority."""

    def score(self, vuln: dict) -> dict:
        """Add business_score, priority, and is_banking_relevant to a vuln dict.

        Scoring formula:
          base   = CVSS v3 base score (or severity baseline if score missing)
          +2.0   if in CISA KEV (actively exploited in the wild)
          +1.5   if any banking keyword matches description/vendor/product
          → capped at 10.0

        Priority thresholds:
          ≥ 9.0 → CRITICAL
          ≥ 7.0 → HIGH
          ≥ 4.0 → MEDIUM
          < 4.0 → LOW

        Args:
            vuln: Vulnerability dict from any collector.

        Returns:
            Same dict with added keys: business_score, priority, is_banking_relevant.
        """
        # Base score from CVSS or inferred from severity label
        cvss = vuln.get("cvss_v3_score") or vuln.get("cvss_score")
        if cvss is None:
            severity_label = (
                vuln.get("cvss_v3_severity") or vuln.get("severity", "")
            ).upper()
            cvss = _SEVERITY_BASELINE.get(severity_label, 0.0)

        business_score = float(cvss)

        # Bonus: actively exploited (CISA KEV)
        if vuln.get("is_exploited"):
            business_score += 2.0

        # Bonus: banking-relevant keywords
        text_to_search = " ".join(
            str(vuln.get(field, ""))
            for field in (
                "description",
                "short_description",
                "summary",
                "vendor",
                "product",
                "vulnerability_name",
            )
        ).lower()

        is_banking_relevant = any(kw in text_to_search for kw in BANKING_KEYWORDS)
        if is_banking_relevant:
            business_score += 1.5

        business_score = min(round(business_score, 2), 10.0)

        # Priority label
        if business_score >= 9.0:
            priority = "CRITICAL"
        elif business_score >= 7.0:
            priority = "HIGH"
        elif business_score >= 4.0:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        return {
            **vuln,
            "business_score": business_score,
            "priority": priority,
            "is_banking_relevant": is_banking_relevant,
        }

    def rank(self, vulns: list[dict]) -> list[dict]:
        """Score and sort vulnerabilities by business_score descending.

        Args:
            vulns: List of raw vulnerability dicts.

        Returns:
            List of scored dicts sorted by business_score (highest first).
        """
        scored = [self.score(v) for v in vulns]
        scored.sort(key=lambda v: v["business_score"], reverse=True)
        logger.info(
            "Ranked %d vulnerabilities. Top priority: %s",
            len(scored),
            scored[0].get("cve_id") if scored else "N/A",
        )
        return scored
