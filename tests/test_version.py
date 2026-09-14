import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_cli_version(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "apollo.py"), "--version"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "Apollo Command Module 0.91.0",
        )


if __name__ == "__main__":
    unittest.main()
