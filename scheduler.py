"""APScheduler-based daily digest scheduler."""

import logging
import os
import signal
import sys

from dotenv import load_dotenv

load_dotenv()

from apscheduler.schedulers.blocking import BlockingScheduler

from collectors.cisa_kev import CISAKEVCollector
from collectors.github_advisories import GitHubAdvisoriesCollector
from collectors.nvd import NVDCollector
from digest import DigestGenerator
from scorer import VulnScorer

logger = logging.getLogger(__name__)


def run_pipeline() -> None:
    """Collect vulnerabilities from all sources, score them, and generate a digest."""
    days_back = int(os.getenv("COLLECT_DAYS_BACK", "1"))
    output_dir = os.getenv("OUTPUT_DIR", "./reports")

    logger.info("Starting vulnerability collection (days_back=%d)...", days_back)

    nvd = NVDCollector()
    cisa = CISAKEVCollector()
    github = GitHubAdvisoriesCollector()

    nvd_vulns = nvd.fetch_recent(days_back=days_back)
    cisa_vulns = cisa.fetch_recent(days_back=max(days_back, 7))
    github_vulns = github.fetch_recent(days_back=days_back)

    all_vulns = nvd_vulns + cisa_vulns + github_vulns
    logger.info(
        "Collected %d total vulnerabilities (NVD=%d, CISA=%d, GitHub=%d).",
        len(all_vulns),
        len(nvd_vulns),
        len(cisa_vulns),
        len(github_vulns),
    )

    scorer = VulnScorer()
    ranked = scorer.rank(all_vulns)

    generator = DigestGenerator()
    result = generator.generate(ranked, output_dir=output_dir)

    stats = result["stats"]
    logger.info(
        "Digest generated — total=%d critical=%d high=%d banking=%d exploited=%d",
        stats["total"],
        stats["by_priority"]["CRITICAL"],
        stats["by_priority"]["HIGH"],
        stats["banking_relevant"],
        stats["actively_exploited"],
    )
    logger.info("HTML report: %s", result["html_path"])
    logger.info("JSON report: %s", result["json_path"])


def main() -> None:
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    schedule_hour = int(os.getenv("SCHEDULE_HOUR", "7"))
    schedule_minute = int(os.getenv("SCHEDULE_MINUTE", "0"))

    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(
        run_pipeline,
        trigger="cron",
        hour=schedule_hour,
        minute=schedule_minute,
        id="daily_digest",
    )

    def _shutdown(signum, frame):
        logger.info("Received signal %d — shutting down scheduler.", signum)
        scheduler.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info(
        "Scheduler started — digest will run daily at %02d:%02d UTC.", schedule_hour, schedule_minute
    )
    scheduler.start()


if __name__ == "__main__":
    main()
