"""Tests for build_lists.py. Run from this folder: python3 -I -m unittest"""

import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "build_lists.py")
# Made up: the real name is never written into this public repository.
PRIVATE = "example/private-indicators"
BARE = "private-indicators"

INDICATORS = (
    "# private-indicators indicator database\n"
    "#   Each line: type | value | severity | label\n"
    "\n"
    "sha256 | 0000000000000000000000000000000000000000000000000000000000000001 | critical | made-up payload  \n"
    "   # an indented comment\n"
    "\n"
    "\n"
    "\n"
    "pkgname | made-up-package | critical | made up for these tests\n"
    "# a closing comment\n"
    "domain | c2.example.invalid | warn | made-up host\n"
    "\n"
)


def osv_zip(path, ecosystem, extra=()):
    """1,000 made-up records, then one for each name in `extra`."""
    names = ["made-up-%d" % number for number in range(1000)] + list(extra)
    with zipfile.ZipFile(path, "w") as archive:
        for number, name in enumerate(names):
            record = {"id": "MAL-2026-%d" % (number + 1),
                      "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                                    "versions": ["1.0.%d" % number]}]}
            archive.writestr("MAL-2026-%d.json" % (number + 1), json.dumps(record))


class BuildListsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.npm = os.path.join(self.dir.name, "npm.zip")
        self.pypi = os.path.join(self.dir.name, "pypi.zip")
        osv_zip(self.npm, "npm")
        osv_zip(self.pypi, "PyPI")
        self.iocs = os.path.join(self.dir.name, "iocs")
        os.makedirs(self.iocs)
        self.write("example.ioc", INDICATORS)
        self.out = os.path.join(self.dir.name, "site")

    def write(self, name, text, folder=None):
        with open(os.path.join(folder or self.iocs, name), "w", encoding="utf-8", newline="") as handle:
            handle.write(text)

    def run_script(self, *extra, repository=PRIVATE):
        env = {k: v for k, v in os.environ.items() if k != "INDICATOR_REPOSITORY"}
        if repository is not None:
            env["INDICATOR_REPOSITORY"] = repository
        return subprocess.run(
            [sys.executable, "-I", SCRIPT, "--npm", self.npm, "--pypi", self.pypi, "--indicators", self.iocs,
             "--out", self.out, "--seq", "7", "--created", "2026-11-23T00:00:00Z", *extra],
            capture_output=True, text=True, env=env)

    def published(self, role):
        with open(os.path.join(self.out, "manifest.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
        names = [f["name"] for f in manifest["files"] if f["role"] == role]
        self.assertEqual(len(names), 1, manifest)
        with open(os.path.join(self.out, names[0]), "rb") as handle:
            return handle.read()

    def test_comment_lines_are_left_out_and_indicator_lines_are_unchanged(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        text = self.published("indicators").decode("utf-8")
        self.assertNotIn("private-indicators", text)
        self.assertFalse([line for line in text.split("\n") if line.lstrip().startswith("#")], text)
        kept = [line for line in INDICATORS.split("\n") if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual([line for line in text.split("\n") if line.strip()], kept, "byte for byte, in order")
        self.assertEqual(text, kept[0] + "\n\n" + kept[1] + "\n" + kept[2] + "\n", "blank lines run together")

    def test_a_file_with_nothing_but_comments_is_published_empty(self):
        self.write("example.ioc", "# only a comment\n\n# and another\n")
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.published("indicators"), b"")

    def test_the_build_stops_if_a_published_file_still_names_the_private_repository(self):
        self.write("example.ioc", INDICATORS + "string | x | critical | first seen by Private-Indicators\n")
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("refusing to publish an indicator file", done.stderr)
        self.assertNotIn("example.ioc", done.stderr, "which file is not said either")
        self.assertFalse(os.path.exists(os.path.join(self.out, "manifest.json")))

    def test_the_rule_file_and_notice_are_held_to_the_same(self):
        rules = os.path.join(self.dir.name, "rules.yar")
        self.write("rules.yar", "/* from example/private-indicators */\nrule a { condition: true }\n", folder=self.dir.name)
        done = self.run_script("--rules", rules)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("rules", done.stderr)

        self.write("rules.yar", "rule a { condition: true }\n", folder=self.dir.name)
        notice = os.path.join(self.dir.name, "NOTICE.txt")
        self.write("NOTICE.txt", "Indicators from Example/Private-Indicators.\n", folder=self.dir.name)
        done = self.run_script("--rules", rules, "--notice", notice)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("NOTICE.txt", done.stderr)

    def test_the_bare_name_is_looked_for_only_in_what_comes_from_the_private_repository(self):
        # Anyone can publish a package under the bare name. Listed by OSV, it must not stop the night's lists.
        osv_zip(self.npm, "npm", extra=[BARE])
        osv_zip(self.pypi, "PyPI", extra=[BARE])
        rules = os.path.join(self.dir.name, "rules.yar")
        self.write("rules.yar", "rule %s { condition: true }\n" % BARE.replace("-", "_"), folder=self.dir.name)
        notice = os.path.join(self.dir.name, "NOTICE.txt")
        self.write("NOTICE.txt", "Packages such as %s are listed.\n" % BARE, folder=self.dir.name)
        done = self.run_script("--rules", rules, "--notice", notice)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn((BARE + "\t").encode(), gzip.decompress(self.published("malicious-npm")))
        self.assertIn((BARE + "\t").encode(), gzip.decompress(self.published("malicious-pypi")))

        # The same name on an indicator line, which comes from that repository, still stops it.
        self.write("example.ioc", INDICATORS + "pkgname | %s | warn | made up\n" % BARE)
        self.out = os.path.join(self.dir.name, "site-2")
        done = self.run_script("--rules", rules, "--notice", notice)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("refusing to publish an indicator file", done.stderr)
        self.assertNotIn("example.ioc", done.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.out, "manifest.json")))

        # And the full name, in any file published, stops it too.
        self.write("example.ioc", INDICATORS)
        osv_zip(self.npm, "npm", extra=["@" + PRIVATE])
        self.out = os.path.join(self.dir.name, "site-3")
        done = self.run_script("--rules", rules, "--notice", notice)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("npm list", done.stderr)

    def test_without_the_name_the_build_says_it_could_not_look(self):
        done = self.run_script(repository=None)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("INDICATOR_REPOSITORY", done.stderr)
        self.assertNotIn("#", self.published("indicators").decode("utf-8"))

    def test_rules_are_published_with_their_role(self):
        rules = os.path.join(self.dir.name, "rules.yar")
        self.write("rules.yar", "rule a { condition: true }\n", folder=self.dir.name)
        done = self.run_script("--rules", rules)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(self.published("rules").startswith(b"\x1f\x8b"))


if __name__ == "__main__":
    unittest.main()
