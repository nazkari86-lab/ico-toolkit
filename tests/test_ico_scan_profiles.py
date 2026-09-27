from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ico_scan_core import Classification, CommandResult
from ico_scan_profiles import ArchiveExtractor, ToolProfile, filter_profiles_for_mode, is_archive, profiles_for


class FakeRunner:
    def __init__(self, listing: str, returncode: int = 0) -> None:
        self.listing = listing
        self.returncode = returncode
        self.calls = []

    def run(self, args, *, cwd, timeout, log_name):
        self.calls.append((list(args), cwd, timeout, log_name))
        if list(args[:3]) == ["7zz", "l", "-slt"]:
            return CommandResult(args=list(args), returncode=self.returncode, stdout=self.listing)
        return CommandResult(args=list(args), returncode=0, stdout="Everything is Ok")


class ProfileTests(unittest.TestCase):
    def test_png_profile_includes_zsteg_before_pngcheck(self):
        classification = Classification("image/png", "PNG image", "png", ".png")
        names = [profile.name for profile in profiles_for(classification)]
        self.assertLess(names.index("zsteg"), names.index("pngcheck"))

    def test_utf16_strings_are_not_run_with_nonportable_macos_flag(self):
        classification = Classification("application/octet-stream", "data", "data", ".bin")
        for profile in profiles_for(classification):
            self.assertFalse(profile.name == "strings-utf16le")
            self.assertNotEqual(profile.args_for(Path("evidence.bin"))[:2], ["strings", "-el"])

    def test_metadata_profile_is_limited_to_metadata_formats(self):
        data_profiles = {profile.name for profile in profiles_for(Classification("application/octet-stream", "data", "data", ".tmp"))}
        image_profiles = {profile.name for profile in profiles_for(Classification("image/png", "PNG image", "png", ".png"))}
        self.assertNotIn("metadata", data_profiles)
        self.assertIn("metadata", image_profiles)

    def test_fast_mode_keeps_only_cheap_profiles(self):
        classification = Classification("image/png", "PNG image", "png", ".png")
        fast = {profile.name for profile in filter_profiles_for_mode(profiles_for(classification), "fast")}
        self.assertIn("strings-ascii", fast)
        self.assertNotIn("zsteg", fast)
        self.assertNotIn("binwalk-signatures", fast)

    def test_unknown_profile_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            filter_profiles_for_mode([], "turbo")

    def test_memory_profile_is_offline(self):
        classification = Classification("application/octet-stream", "Windows memory dump", "memory", ".dmp")
        profiles = profiles_for(classification)
        commands = [profile.args_for(Path("capture.dmp")) for profile in profiles if profile.name.startswith("volatility-")]
        self.assertEqual(len(commands), 2)
        self.assertTrue(all("--offline" in command for command in commands))

    def test_archive_detection_uses_mime(self):
        classification = Classification("application/zip", "Zip archive data", "data", ".bin")
        self.assertTrue(is_archive(classification))

    def test_archive_expansion_limit_refuses_large_listing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sample.zip"
            archive.write_bytes(b"invalid archive bytes")
            classification = Classification("application/zip", "Zip archive data", "archive", ".zip")
            runner = FakeRunner(
                "Archive = sample.zip\nType = zip\n\n----------\n"
                "Path = nested.txt\nSize = 999999999\nFolder = -\n"
            )
            result = ArchiveExtractor(runner, max_bytes=1024).extract(archive, classification, root / "out")
        self.assertEqual(result.refused_reason, "no safe archive members fit the extraction limits")
        self.assertEqual(result.skipped_entries[0]["reason"], "member exceeds byte limit")
        self.assertTrue(result.partial)
        self.assertFalse(result.extracted)

    def test_archive_extract_discovers_files_inside_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sample.zip"
            archive.write_bytes(b"not used by fake runner")
            destination = root / "out"
            destination.mkdir()
            (destination / "nested.txt").write_text("CTF{nested}", encoding="utf-8")
            classification = Classification("application/zip", "Zip archive data", "archive", ".zip")
            listing = (
                "Archive = sample.zip\nType = zip\n\n----------\n"
                "Path = nested.txt\nSize = 10\nFolder = -\n"
            )
            result = ArchiveExtractor(FakeRunner(listing), max_bytes=1024).extract(archive, classification, destination)
        self.assertTrue(result.extracted)
        self.assertEqual([path.name for path in result.discovered], ["nested.txt"])

    def test_archive_selects_safe_members_within_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sample.7z"
            archive.write_bytes(b"not used by fake runner")
            destination = root / "out"
            destination.mkdir()
            nested = destination / "safe" / "note.txt"
            nested.parent.mkdir()
            nested.write_text("ICO{local_candidate}", encoding="utf-8")
            listing = (
                "Archive = sample.7z\nType = 7z\nSolid = +\n\n----------\n"
                "Path = huge.img\nSize = 2048\nFolder = -\n\n"
                "Path = safe/note.txt\nSize = 19\nFolder = -\n\n"
                "Path = ../outside.txt\nSize = 5\nFolder = -\n\n"
                "Path = link.txt\nSize = 5\nFolder = -\nAttributes = A lrwxrwxrwx\nSymbolic Link = safe/note.txt\n"
            )
            runner = FakeRunner(listing)
            result = ArchiveExtractor(runner, max_bytes=32, max_files=2).extract(
                archive,
                Classification("application/x-7z-compressed", "7-zip archive data", "archive", ".7z"),
                destination,
                timeout=17,
            )

        self.assertTrue(result.extracted)
        self.assertTrue(result.partial)
        self.assertEqual([entry.path for entry in result.selected_entries], ["safe/note.txt"])
        self.assertEqual(
            [entry["reason"] for entry in result.skipped_entries],
            ["member exceeds byte limit", "parent traversal in member path", "link entry"],
        )
        extraction_call = runner.calls[1]
        self.assertEqual(extraction_call[0][-1], "safe/note.txt")
        self.assertEqual(extraction_call[2], 17)


if __name__ == "__main__":
    unittest.main()
