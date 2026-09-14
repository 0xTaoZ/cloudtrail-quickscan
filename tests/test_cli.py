import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from cloudtrail_quickscan.cli import print_json_report, print_report
from cloudtrail_quickscan.models import Finding


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CliTest(unittest.TestCase):
    def test_module_entrypoint_runs_summary_report(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT / "src")

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "cloudtrail_quickscan",
                str(PROJECT_ROOT / "samples" / "cloudtrail_sample.json"),
                "--summary-only",
            ],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        self.assertIn("CloudTrail Quickscan", result.stdout)
        self.assertIn("Events checked: 14", result.stdout)

    def test_summary_orders_severity_by_priority(self):
        findings = [
            Finding(
                "LOW",
                "Uncommon region",
                "ListBuckets",
                "student",
                "198.51.100.2",
                "ap-south-1",
                "2026-06-28T09:30:00Z",
                "Low note",
            ),
            Finding(
                "MED",
                "IAM change",
                "CreateAccessKey",
                "student",
                "198.51.100.1",
                "us-east-1",
                "2026-06-28T08:18:00Z",
                "Med note",
            ),
            Finding(
                "HIGH",
                "Root activity",
                "DeleteTrail",
                "root",
                "192.0.2.50",
                "us-east-1",
                "2026-06-28T10:11:00Z",
                "High note",
            ),
        ]
        output = StringIO()

        with redirect_stdout(output):
            print_report(events_count=3, findings=findings, summary_only=True)

        self.assertIn("Severity: HIGH=1, MED=1, LOW=1", output.getvalue())

    def test_summary_shows_top_source_ips_and_users(self):
        findings = [
            Finding(
                "MED",
                "IAM change",
                "CreateAccessKey",
                "student",
                "198.51.100.1",
                "us-east-1",
                "2026-06-28T08:18:00Z",
                "note",
            ),
            Finding(
                "MED",
                "Access key deactivated",
                "UpdateAccessKey",
                "student",
                "198.51.100.1",
                "us-east-1",
                "2026-06-28T08:20:00Z",
                "note",
            ),
            Finding(
                "HIGH",
                "Root activity",
                "ListBuckets",
                "root",
                "192.0.2.50",
                "us-east-1",
                "2026-06-28T10:11:00Z",
                "note",
            ),
        ]
        output = StringIO()

        with redirect_stdout(output):
            print_report(events_count=3, findings=findings, summary_only=True)

        text = output.getvalue()
        self.assertIn("Top source IPs: 198.51.100.1=2, 192.0.2.50=1", text)
        self.assertIn("Top users: student=2, root=1", text)

    def test_json_report_includes_summary_counts(self):
        findings = [
            Finding(
                "MED",
                "IAM change",
                "CreateAccessKey",
                "student",
                "198.51.100.1",
                "us-east-1",
                "2026-06-28T08:18:00Z",
                "note",
            ),
            Finding(
                "HIGH",
                "Root activity",
                "ListBuckets",
                "root",
                "192.0.2.50",
                "us-east-1",
                "2026-06-28T10:11:00Z",
                "note",
            ),
        ]
        output = StringIO()

        with redirect_stdout(output):
            print_json_report(events_count=2, findings=findings)

        report = json.loads(output.getvalue())
        self.assertEqual(
            report["summary"]["source_ips"],
            {"198.51.100.1": 1, "192.0.2.50": 1},
        )
        self.assertEqual(report["summary"]["users"], {"student": 1, "root": 1})


if __name__ == "__main__":
    unittest.main()
