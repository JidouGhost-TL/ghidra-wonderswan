# SPDX-License-Identifier: MIT OR Apache-2.0
import unittest
from unittest.mock import Mock, patch

import rehearse


class ReleasePinTest(unittest.TestCase):
    def test_published_input_pins_are_sha256(self):
        rehearse.validate_pins()

    def test_extra_gradle_checksum_suffix_refused_before_preparation(self):
        output = Mock()
        diagnostic = Mock()
        old_pin = rehearse.pins["gradle_sha256"] + "26"
        with patch.dict(rehearse.pins, gradle_sha256=old_pin):
            with self.assertRaisesRegex(RuntimeError, "64 lowercase hexadecimal"):
                rehearse.prepare(output, "Darwin-arm64", None, diagnostic)
        output.mkdir.assert_not_called()
        diagnostic.begin.assert_called_once_with("validate_release_pins")


if __name__ == "__main__":
    unittest.main()
