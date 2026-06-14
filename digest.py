"""Daily digest report generator (HTML + JSON)."""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


class DigestGenerator:
    """Generates dated HTML and JSON reports from a list of scored vulnerabilities."""

    def __init__(self, templates_dir: Path = TEMPLATES_DIR) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(
        self,
        vulns: list[dict],
        output_dir: str = "reports",
    ) -> dict:
        """Generate HTML and JSON reports for today's vulnerability digest.

        Args:
            vulns: Ranked, scored vulnerability dicts.
            output_dir: Base directory for reports (subdirectory per date is created).

        Returns:
            Dict with html_path, json_path, and stats summary.
        """
        today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        report_dir = Path(output_dir) / today
        report_dir.mkdir(parents=True, exist_ok=True)

        stats = self._compute_stats(vulns)

        # --- JSON report ---
        json_payload = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "date": today,
            "stats": stats,
            "vulnerabilities": vulns,
        }
        json_path = report_dir / "digest.json"
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(json_payload, fh, indent=2, ensure_ascii=False)
        logger.info("JSON report written to %s", json_path)

        # --- HTML report ---
        template = self.env.get_template("digest.html.j2")
        html_content = template.render(
            date=today,
            stats=stats,
            vulns=vulns,
            critical_vulns=[v for v in vulns if v.get("priority") == "CRITICAL"],
            high_vulns=[v for v in vulns if v.get("priority") == "HIGH"],
            banking_vulns=[v for v in vulns if v.get("is_banking_relevant")],
        )
        html_path = report_dir / "digest.html"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        logger.info("HTML report written to %s", html_path)

        return {
            "html_path": str(html_path),
            "json_path": str(json_path),
            "stats": stats,
        }

    @staticmethod
    def _compute_stats(vulns: list[dict]) -> dict:
        total = len(vulns)
        by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        banking_count = 0
        exploited_count = 0
        sources: dict[str, int] = {}

        for v in vulns:
            priority = v.get("priority", "LOW")
            by_severity[priority] = by_severity.get(priority, 0) + 1
            if v.get("is_banking_relevant"):
                banking_count += 1
            if v.get("is_exploited"):
                exploited_count += 1
            src = v.get("source", "unknown")
            sources[src] = sources.get(src, 0) + 1

        top5 = [
            {"cve_id": v.get("cve_id"), "score": v.get("business_score"), "priority": v.get("priority")}
            for v in vulns[:5]
        ]

        return {
            "total": total,
            "by_priority": by_severity,
            "banking_relevant": banking_count,
            "actively_exploited": exploited_count,
            "by_source": sources,
            "top5": top5,
        }
