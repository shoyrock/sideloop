import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from sideloop import ipa


class SigningArchiveTests(unittest.TestCase):
    def make_upload(self, folder, size=980):
        with zipfile.ZipFile(folder / "app.ipa", "w") as z:
            z.writestr("Payload/Test.app/Test", b"x" * size)
            z.writestr("Payload/Test.app/PlugIns/Widget.appex/Info.plist", b"extension")

    def test_near_classic_limit_does_not_reserve_zip64_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            self.make_upload(folder)
            with patch.object(ipa, "CLASSIC_LIMIT", 1000):
                result = ipa.signing_copy(folder)
            with zipfile.ZipFile(result) as z:
                entry = z.getinfo("Payload/Test.app/Test")
                self.assertEqual(z.read(entry), b"x" * 980)
                self.assertLess(entry.extract_version, 45)
                self.assertEqual(entry.extra, b"")
            self.assertNotIn(b"PK\x06\x06", result.read_bytes())

    def test_size_overflow_leaves_no_partial_copy_and_restores_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            self.make_upload(folder, 1001)
            limit = zipfile.ZIP64_LIMIT
            with patch.object(ipa, "CLASSIC_LIMIT", 1000):
                with self.assertRaises(zipfile.LargeZipFile):
                    ipa.signing_copy(folder)
            self.assertEqual(zipfile.ZIP64_LIMIT, limit)
            self.assertEqual(sorted(p.name for p in folder.iterdir()), ["app.ipa"])

    def test_entry_count_overflow_cannot_generate_zip64_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            self.make_upload(folder)
            with zipfile.ZipFile(folder / "app.ipa", "a") as z:
                z.writestr("Payload/Test.app/Info.plist", b"plist")
            with patch.object(zipfile, "ZIP_FILECOUNT_LIMIT", 1):
                with self.assertRaises(zipfile.LargeZipFile):
                    ipa.signing_copy(folder)
            self.assertFalse((folder / "app-noext.ipa").exists())
            self.assertFalse((folder / "app-noext.tmp").exists())


if __name__ == "__main__":
    unittest.main()
