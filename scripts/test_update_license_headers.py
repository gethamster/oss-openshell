#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
# SPDX-License-Identifier: Apache-2.0

"""Keep the SPDX gate strict while recognizing the fork's copyright owner."""

import runpy
import unittest
from pathlib import Path

has_header = runpy.run_path(str(Path(__file__).with_name("update_license_headers.py")))[
    "has_header"
]


class LicenseHeaderTests(unittest.TestCase):
    def test_recognized_owners_require_apache(self):
        for owner in (
            "NVIDIA CORPORATION & AFFILIATES. All rights reserved.",
            "Hamster",
            "Hamster. All rights reserved.",
        ):
            with self.subTest(owner=owner):
                copyright_line = (
                    f"// SPDX-FileCopyrightText: Copyright (c) 2026 {owner}"
                )
                self.assertTrue(
                    has_header(
                        [copyright_line, "// SPDX-License-Identifier: Apache-2.0"]
                    )
                )
                self.assertFalse(
                    has_header([copyright_line, "// SPDX-License-Identifier: GPL-3.0"])
                )

    def test_missing_or_unrecognized_copyright_fails(self):
        license_line = "# SPDX-License-Identifier: Apache-2.0"
        self.assertFalse(has_header([license_line]))
        for owner in ("Unknown", "Hamster Impersonator", "Hamster-MIT"):
            self.assertFalse(
                has_header(
                    [
                        f"# SPDX-FileCopyrightText: Copyright (c) 2026 {owner}",
                        license_line,
                    ]
                )
            )

    def test_header_must_be_near_the_start(self):
        self.assertFalse(
            has_header(
                ["" for _ in range(10)]
                + [
                    "# SPDX-FileCopyrightText: Copyright (c) 2026 Hamster",
                    "# SPDX-License-Identifier: Apache-2.0",
                ]
            )
        )


if __name__ == "__main__":
    unittest.main()
