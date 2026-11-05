# SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
# SPDX-License-Identifier: Apache-2.0

"""The release stamp must not resolve or change external dependencies."""
import importlib.util
import io
import subprocess
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('recipe', Path(__file__).with_name('release.py'))
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


class VersionTests(unittest.TestCase):
    def test_stamp_preserves_external_pins_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, OPENSHELL_VERSION='0.1.6-system.3'):
            before = Path.cwd()
            try:
                os.chdir(temporary)
                Path('crates/cli').mkdir(parents=True)
                Path('Cargo.toml').write_text('[workspace]\nmembers = ["crates/*"]\n[workspace.package]\nversion = "0.0.0"\n')
                Path('crates/cli/Cargo.toml').write_text('[package]\nname = "openshell-cli"\nversion.workspace = true\n')
                external = '\nname = "dependency"\nversion = "0.0.0"\nsource = "registry+https://example.invalid"\nchecksum = "pinned"\n'
                Path('Cargo.lock').write_text('version = 4\n[[package]]\nname = "openshell-cli"\nversion = "0.0.0"\n[[package]]' + external)
                recipe.prepare()
                once = Path('Cargo.lock').read_bytes()
                recipe.prepare()
                self.assertEqual(Path('Cargo.lock').read_bytes(), once)
                self.assertIn(external.encode(), once)
                self.assertIn(b'version = "0.1.6-system.3"', once)
            finally:
                os.chdir(before)


class DiagnosticTests(unittest.TestCase):
    def test_failed_check_keeps_the_compiler_output(self):
        result = subprocess.CompletedProcess(['cargo', 'test'], 101, stdout='specific compiler failure\n')
        output = io.StringIO()
        with patch.object(recipe.subprocess, 'run', return_value=result), patch('sys.stdout', output):
            with self.assertRaises(subprocess.CalledProcessError):
                recipe.test('x86_64-unknown-linux-gnu')
        self.assertIn('specific compiler failure', output.getvalue())


if __name__ == '__main__':
    unittest.main()
