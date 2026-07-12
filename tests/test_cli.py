import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from cloudtrail_quickscan.cli import print_report
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
        self.assertIn("Events checked: 7", result.stdout)

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


if __name__ == "__main__":
    unittest.main()
