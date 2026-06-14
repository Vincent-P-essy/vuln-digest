#!/usr/bin/env python3
"""vuln-digest: Daily vulnerability bulletin aggregator with banking-context scoring."""

import argparse
import json
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()


def setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="vuln-digest: aggregate CVE bulletins and generate a daily digest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --run-now
  python main.py --run-now --days-back 7 --sources nvd,cisa
  python main.py --run-now --output-dir /var/reports
        """,
    )
    parser.add_argument(
        "--run-now",
        action="store_true",
        help="Run the full collection + scoring + digest pipeline immediately.",
    )
    parser.add_argument(
        "--days-back",
        type=int,
        default=1,
        metavar="N",
        help="Number of days to look back when fetching CVEs (default: 1).",
    )
    parser.add_argument(
        "--sources",
        default="nvd,cisa,github",
        help="Comma-separated list of sources: nvd, cisa, github (default: all).",
    )
    parser.add_argument(
        "--output-dir",
        default=os.getenv("OUTPUT_DIR", "./reports"),
        metavar="DIR",
        help="Directory to write HTML and JSON reports (default: ./reports).",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print the JSON digest to stdout instead of writing files.",
    )
    return parser.parse_args()


def main() -> int:
    setup_logging()
    args = parse_args()
    logger = logging.getLogger(__name__)

    if not args.run_now:
        logger.info("No action specified. Use --run-now to collect and generate a digest.")
        logger.info("Use scheduler.py to run on a daily schedule.")
        return 0

    # Import here to allow --help without requiring dependencies
    from collectors.cisa_kev import CISAKEVCollector
    from collectors.github_advisories import GitHubAdvisoriesCollector
    from collectors.nvd import NVDCollector
    from digest import DigestGenerator
    from scorer import VulnScorer

    sources = [s.strip().lower() for s in args.sources.split(",")]
    all_vulns: list[dict] = []

    if "nvd" in sources:
        logger.info("Fetching from NVD (days_back=%d)...", args.days_back)
        nvd_vulns = NVDCollector().fetch_recent(days_back=args.days_back)
        logger.info("NVD: %d CVEs collected.", len(nvd_vulns))
        all_vulns.extend(nvd_vulns)

    if "cisa" in sources:
        cisa_days = max(args.days_back, 7)
        logger.info("Fetching from CISA KEV (days_back=%d)...", cisa_days)
        cisa_vulns = CISAKEVCollector().fetch_recent(days_back=cisa_days)
        logger.info("CISA KEV: %d entries collected.", len(cisa_vulns))
        all_vulns.extend(cisa_vulns)

    if "github" in sources:
        logger.info("Fetching from GitHub Advisories (days_back=%d)...", args.days_back)
        github_vulns = GitHubAdvisoriesCollector().fetch_recent(days_back=args.days_back)
        logger.info("GitHub: %d advisories collected.", len(github_vulns))
        all_vulns.extend(github_vulns)

    if not all_vulns:
        logger.warning("No vulnerabilities collected. Check source availability and credentials.")
        return 0

    logger.info("Scoring and ranking %d vulnerabilities...", len(all_vulns))
    scorer = VulnScorer()
    ranked = scorer.rank(all_vulns)

    if args.json_only:
        print(json.dumps(ranked[:20], indent=2))
        return 0

    logger.info("Generating digest reports in %s...", args.output_dir)
    result = DigestGenerator().generate(ranked, output_dir=args.output_dir)
    stats = result["stats"]

    # Console summary table
    print("\n" + "=" * 60)
    print(f"  vuln-digest summary")
    print("=" * 60)
    print(f"  Total CVEs collected : {stats['total']}")
    print(f"  CRITICAL             : {stats['by_priority']['CRITICAL']}")
    print(f"  HIGH                 : {stats['by_priority']['HIGH']}")
    print(f"  MEDIUM               : {stats['by_priority']['MEDIUM']}")
    print(f"  Banking-relevant     : {stats['banking_relevant']}")
    print(f"  Actively exploited   : {stats['actively_exploited']}")
    print("=" * 60)
    print(f"  HTML  → {result['html_path']}")
    print(f"  JSON  → {result['json_path']}")
    print("=" * 60 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
