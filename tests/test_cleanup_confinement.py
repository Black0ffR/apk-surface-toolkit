"""TEST-01 cross-cutting: cleanup must stay confined to its designated root.

The only destructive operation in the toolkit is wiping a stale
``.manifest-only`` decode tree (apktools.reset_stale_decode). These tests
use temporary synthetic directories to prove it never targets paths
outside the designated root and never removes unrelated files.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from triagekit.apktools import reset_stale_decode


def make_tree(base: str, name: str, *, marker: bool = False,
              files: tuple[str, ...] = ()) -> str:
    path = os.path.join(base, name)
    os.makedirs(path, exist_ok=True)
    if marker:
        with open(os.path.join(path, ".manifest-only"), "w", encoding="utf-8") as f:
            f.write("manifest-only fallback")
    for rel in files:
        full = os.path.join(path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write("data")
    return path


class TestCleanupConfinement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "ws")
        os.makedirs(self.root)
        self.addCleanup(self.tmp.cleanup)

    def test_wipes_stale_tree_inside_root(self):
        out = make_tree(self.root, "apktool", marker=True,
                        files=("AndroidManifest.xml",))
        wiped, detail = reset_stale_decode(out, root=self.root)
        self.assertTrue(wiped)
        self.assertFalse(os.path.exists(out))

    def test_refuses_path_outside_root(self):
        outside = make_tree(self.tmp.name, "evil", marker=True,
                            files=("keep.txt",))
        wiped, detail = reset_stale_decode(outside, root=self.root)
        self.assertFalse(wiped)
        self.assertIn("refused", detail)
        self.assertTrue(os.path.isfile(os.path.join(outside, "keep.txt")))

    def test_nothing_removed_without_marker(self):
        out = make_tree(self.root, "apktool", files=("AndroidManifest.xml",))
        wiped, detail = reset_stale_decode(out, root=self.root)
        self.assertFalse(wiped)
        self.assertIn("no stale", detail)
        self.assertTrue(os.path.isfile(os.path.join(out, "AndroidManifest.xml")))

    def test_symlink_escape_is_refused(self):
        outside = make_tree(self.tmp.name, "outside", marker=True,
                            files=("keep.txt",))
        link = os.path.join(self.root, "sneaky")
        os.symlink(outside, link)
        wiped, detail = reset_stale_decode(link, root=self.root)
        self.assertFalse(wiped)
        self.assertIn("refused", detail)
        self.assertTrue(os.path.isfile(os.path.join(outside, "keep.txt")))

    def test_sibling_prefix_directory_is_not_inside_root(self):
        sibling = make_tree(os.path.dirname(self.root), "wsX", marker=True)
        wiped, _ = reset_stale_decode(sibling, root=self.root)
        self.assertFalse(wiped)
        self.assertTrue(os.path.exists(sibling))

    def test_unrelated_project_files_survive_cleanup(self):
        out = make_tree(self.root, "apktool", marker=True)
        keep = make_tree(self.root, "project", files=("README.md", "rules.json"))
        wiped, _ = reset_stale_decode(out, root=self.root)
        self.assertTrue(wiped)
        self.assertTrue(os.path.isfile(os.path.join(keep, "README.md")))
        self.assertTrue(os.path.isfile(os.path.join(keep, "rules.json")))

    def test_root_itself_is_not_deleted(self):
        wiped, detail = reset_stale_decode(self.root, root=self.root)
        self.assertFalse(wiped)          # no marker at root
        self.assertTrue(os.path.isdir(self.root))


if __name__ == "__main__":
    unittest.main()
