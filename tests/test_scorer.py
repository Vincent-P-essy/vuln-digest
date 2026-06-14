"""Unit tests for the VulnScorer."""

from scorer import BANKING_KEYWORDS, VulnScorer


def _vuln(cvss=None, severity=None, exploited=False, description=""):
    return {
        "cve_id": "CVE-2024-9999",
        "source": "nvd",
        "cvss_v3_score": cvss,
        "cvss_v3_severity": severity,
        "is_exploited": exploited,
        "description": description,
    }


def test_score_uses_cvss_score():
    scorer = VulnScorer()
    result = scorer.score(_vuln(cvss=7.5))
    assert result["business_score"] == 7.5
    assert result["priority"] == "HIGH"


def test_score_falls_back_to_severity_label():
    scorer = VulnScorer()
    result = scorer.score(_vuln(severity="CRITICAL"))
    assert result["business_score"] == 9.0
    assert result["priority"] == "CRITICAL"


def test_score_exploited_adds_bonus():
    scorer = VulnScorer()
    result = scorer.score(_vuln(cvss=7.0, exploited=True))
    assert result["business_score"] == 9.0
    assert result["priority"] == "CRITICAL"


def test_score_banking_keyword_adds_bonus():
    scorer = VulnScorer()
    result = scorer.score(_vuln(cvss=7.0, description="Critical Apache SSL certificate bypass"))
    assert result["is_banking_relevant"] is True
    assert result["business_score"] == 8.5


def test_score_capped_at_10():
    scorer = VulnScorer()
    result = scorer.score(_vuln(cvss=9.8, exploited=True, description="Swift payment TLS RCE"))
    assert result["business_score"] == 10.0


def test_score_no_data():
    scorer = VulnScorer()
    result = scorer.score({"cve_id": "CVE-2024-0000", "source": "nvd"})
    assert result["priority"] == "LOW"
    assert result["is_banking_relevant"] is False


def test_rank_sorts_descending():
    scorer = VulnScorer()
    vulns = [
        _vuln(cvss=5.0, description="medium issue"),
        _vuln(cvss=9.8, description="critical apache ssl"),
        _vuln(cvss=3.0, description="low"),
    ]
    ranked = scorer.rank(vulns)
    scores = [v["business_score"] for v in ranked]
    assert scores == sorted(scores, reverse=True)
    assert ranked[0]["cvss_v3_score"] == 9.8


def test_banking_keywords_present():
    assert "swift" in BANKING_KEYWORDS
    assert "apache" in BANKING_KEYWORDS
    assert "ssl" in BANKING_KEYWORDS
