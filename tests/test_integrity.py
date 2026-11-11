from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.main import hash_file


class IntegrityTest(unittest.TestCase):
    def test_hash_changes_when_evidence_is_modified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.bin"
            path.write_bytes(b"original evidence")
            reference_hash, reference_root = hash_file(path)

            path.write_bytes(b"modified evidence")
            current_hash, current_root = hash_file(path)

        self.assertNotEqual(reference_hash, current_hash)
        self.assertNotEqual(reference_root, current_root)

    def test_hash_is_repeatable_for_unchanged_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.bin"
            path.write_bytes(b"stable evidence")
            first = hash_file(path)
            second = hash_file(path)

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
