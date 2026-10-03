# vuln-digest

![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/domain-cybersecurity-red)

**Daily vulnerability digest with banking-context scoring — automated collection from NVD, CISA KEV, and GitHub Advisories.**

Security analysts at financial institutions spend significant time every morning manually reading CVE feeds from NVD, CISA, and GitHub. `vuln-digest` automates this entirely: it collects the day's bulletins, scores them using CVSS v3 enriched with banking-specific context, and delivers a clean HTML + JSON report — ready before the morning stand-up.

---

## Why this project?

| Manual process | With vuln-digest |
|---|---|
| Analyst reads 3+ feeds manually | Automated collection at 07:00 |
| No priority filter | CVSS + banking-context scoring |
| Plain CVE IDs only | Vendor/product/action context |
| No CISA KEV correlation | Actively-exploited flag (+2 score) |
| Ad-hoc email/Slack | HTML report + JSON for dashboards |

Banking-relevant keywords (Oracle, Apache, SSL/TLS, Swift, SAP, Citrix, Windows Server…) add a scoring bonus to surface infrastructure CVEs that matter to a financial institution.

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                       main.py / scheduler.py           │
│          (CLI + APScheduler — daily at 07:00 UTC)      │
└───────────┬──────────────────────┬─────────────────────┘
            │                      │
     ┌──────▼──────┐        ┌──────▼──────┐
     │  collectors/ │        │  scorer.py  │
     │  ├ nvd.py   │        │             │
     │  ├ cisa_    │──────▶ │ CVSS v3     │
     │  │  kev.py  │        │ + KEV bonus │
     │  └ github_  │        │ + banking   │
     │    advisories│        │   keywords  │
     └─────────────┘        └──────┬──────┘
                                   │
                            ┌──────▼──────┐
                            │  digest.py  │
                            │             │
                            │ HTML report │
                            │ JSON report │
                            └─────────────┘
                                   │
                         reports/YYYY-MM-DD/
                         ├── digest.html
                         └── digest.json
```

### Data sources

| Source | What it provides | Update frequency |
|---|---|---|
| **NVD REST API v2** | All public CVEs with CVSS v3 scores | Continuous |
| **CISA KEV** | CVEs actively exploited in the wild | Weekly |
| **GitHub Advisories** | OSS package vulnerabilities (HIGH/CRITICAL) | Continuous |

### Scoring formula

```
business_score = cvss_v3_base_score
               + 2.0  (if CISA KEV — actively exploited)
               + 1.5  (if any banking keyword in description/vendor/product)
               capped at 10.0

Priority:
  ≥ 9.0 → CRITICAL
  ≥ 7.0 → HIGH
  ≥ 4.0 → MEDIUM
  < 4.0 → LOW
```

---

## Installation

```bash
git clone https://github.com/vincent-p-essy/vuln-digest.git
cd vuln-digest
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env to add NVD_API_KEY and GITHUB_TOKEN
```

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `NVD_API_KEY` | — | NVD API key (optional, increases rate limit) |
| `GITHUB_TOKEN` | — | GitHub token for Advisories GraphQL API |
| `OUTPUT_DIR` | `./reports` | Where HTML/JSON reports are written |
| `COLLECT_DAYS_BACK` | `1` | Days to look back for new CVEs |
| `SCHEDULE_HOUR` | `7` | UTC hour for daily run |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key  
GitHub token (no special scopes needed): https://github.com/settings/tokens

---

## Usage

### One-shot run

```bash
# Collect today's CVEs and generate reports
python main.py --run-now

# Look back 7 days, NVD and CISA only
python main.py --run-now --days-back 7 --sources nvd,cisa

# Print top-20 scored CVEs to stdout (no files written)
python main.py --run-now --json-only | head -100

# Custom output directory
python main.py --run-now --output-dir /var/vuln-reports
```

### Daily scheduler (07:00 UTC)

```bash
python scheduler.py
# Output:
# 2024-01-15T07:00:00 [INFO] Starting vulnerability collection (days_back=1)...
# 2024-01-15T07:00:12 [INFO] NVD: 47 CVEs collected.
# 2024-01-15T07:00:14 [INFO] CISA KEV: 3 entries collected.
# 2024-01-15T07:00:15 [INFO] GitHub: 12 advisories collected.
# 2024-01-15T07:00:15 [INFO] Digest generated — total=62 critical=5 high=18 banking=9 exploited=3
# 2024-01-15T07:00:15 [INFO] HTML report: reports/2024-01-15/digest.html
```

### Sample console output

```
============================================================
  vuln-digest summary
============================================================
  Total CVEs collected : 62
  CRITICAL             : 5
  HIGH                 : 18
  MEDIUM               : 31
  Banking-relevant     : 9
  Actively exploited   : 3
============================================================
  HTML  → reports/2024-01-15/digest.html
  JSON  → reports/2024-01-15/digest.json
============================================================
```

---

## Report format

### HTML report

A self-contained dark-themed HTML page with:
- Summary cards (CRITICAL / HIGH / MEDIUM / Banking-relevant / Exploited)
- Table of CRITICAL vulnerabilities with CVE IDs, descriptions, business scores
- Table of HIGH vulnerabilities
- Banking-relevant highlights section
- Color-coded severity badges

### JSON report

```json
{
  "generated_at": "2024-01-15T07:00:15+00:00",
  "date": "2024-01-15",
  "stats": {
    "total": 62,
    "by_priority": {"CRITICAL": 5, "HIGH": 18, "MEDIUM": 31, "LOW": 8},
    "banking_relevant": 9,
    "actively_exploited": 3,
    "by_source": {"nvd": 47, "cisa_kev": 3, "github_advisories": 12}
  },
  "vulnerabilities": [
    {
      "source": "nvd",
      "cve_id": "CVE-2024-0001",
      "cvss_v3_score": 9.8,
      "business_score": 10.0,
      "priority": "CRITICAL",
      "is_banking_relevant": true,
      "is_exploited": true,
      ...
    }
  ]
}
```

---

## Testing

```bash
pip install pytest responses
pytest tests/ -v
```

Tests cover: NVD response parsing, CISA KEV date filtering, scoring logic (CVSS baselines, bonus stacking, cap at 10.0), error handling on HTTP failures.

---

## Integration

`vuln-digest` feeds into [`cyber-dashboard`](https://github.com/vincent-p-essy/cyber-dashboard) which reads the JSON reports to display:
- Count of CRITICAL unpatched CVEs
- Banking-relevant CVE highlights

```
vuln-digest → reports/YYYY-MM-DD/digest.json → cyber-dashboard
```

---

## Roadmap

- [ ] Email delivery of the HTML report via SMTP/SendGrid
- [ ] Slack/Teams webhook notification for CRITICAL CVEs
- [ ] Deduplication across sources (same CVE in NVD + CISA + GitHub)
- [ ] Historical trending charts (CRITICAL count per day over 30 days)
- [ ] NVD CPE matching against an internal asset inventory
- [ ] EPSS score integration (Exploit Prediction Scoring System)
- [ ] Docker image for containerised deployment

---

## Author

**Vincent Plessy** — [GitHub](https://github.com/Vincent-P-essy)
Part of the [cyber-portfolio](https://github.com/vincent-p-essy) project ecosystem.
