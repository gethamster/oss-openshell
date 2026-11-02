#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
# SPDX-License-Identifier: Apache-2.0

"""Verify download fallback and fail-closed checksum handling without network."""

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

INSTALLER = Path(__file__).with_name("install-helm-unittest.sh")
FAKE_CURL = """#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
printf '%s\\n' "$url" >> "$URL_LOG"
case "$url" in
  *unavailable*) exit 28 ;;
  *corrupt*) printf 'corrupt' > "$output" ;;
  *) cp "$FIXTURE" "$output" ;;
esac
"""


class HelmDownloadTests(unittest.TestCase):
    def download(self, urls):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            fixture.write_bytes(b"verified release bytes")
            (root / "curl").write_text(FAKE_CURL)
            (root / "curl").chmod(0o755)
            env = dict(
                os.environ,
                PATH=f"{root}:{os.environ['PATH']}",
                FIXTURE=str(fixture),
                URL_LOG=str(root / "urls"),
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; shift; download_verified "$@"',
                    "test",
                    str(INSTALLER),
                    str(root / "archive"),
                    hashlib.sha256(fixture.read_bytes()).hexdigest(),
                    *urls,
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            return result, (root / "urls").read_text().splitlines()

    def test_primary_verified_download(self):
        result, urls = self.download(
            ["https://api.test/asset", "https://fallback.test/asset"]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(urls, ["https://api.test/asset"])

    def test_transport_failure_uses_verified_fallback(self):
        result, urls = self.download(
            ["https://api.test/unavailable", "https://fallback.test/asset"]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(urls), 2)

    def test_checksum_mismatch_never_installs_or_falls_back(self):
        result, urls = self.download(
            ["https://api.test/corrupt", "https://fallback.test/asset"]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(urls, ["https://api.test/corrupt"])

    def test_all_transports_failing_is_an_error(self):
        result, urls = self.download(
            ["https://api.test/unavailable", "https://fallback.test/unavailable"]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(urls), 2)


if __name__ == "__main__":
    unittest.main()
