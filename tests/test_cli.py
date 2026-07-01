import os
import subprocess
import sys
import unittest
from pathlib import Path


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
        self.assertIn("Events checked: 5", result.stdout)


if __name__ == "__main__":
    unittest.main()
