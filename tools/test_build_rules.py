"""Tests for build_rules.py. Run from this folder: python3 -I -m unittest"""

import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_rules  # noqa: E402

SCRIPT = os.path.join(HERE, "build_rules.py")


def block(name, licence_lines, rules):
    head = [
        "/*",
        " * YARA Rule Set",
        " * Repository Name: %s" % name,
        " * Repository: https://example.invalid/%s/" % name.lower(),
        " * Retrieval Date: 2026-11-22",
        " * Number of Rules: %d" % len(rules),
        " *",
        " * ",
        " * LICENSE",
        " * ",
    ]
    first, rest = licence_lines[0], licence_lines[1:]
    head.append(" * " + first)
    head.extend(rest)
    head.append(" */")
    return "\n".join(head) + "\n" + "\n".join(rules) + "\n"


def rule(name, tags="FILE", condition='$a', extra_strings='', body_comment=''):
    return (
        "rule %s : %s\n{\n\tmeta:\n\t\tauthor = \"Someone <s@example.invalid>\"\n"
        "\t\tscore = 75\n\t\tlicense = \"Test licence\"\n\n"
        "\tstrings:\n\t\t$a = \"SMARTSORT-TEST-%s\"\n%s\n\tcondition:\n%s\t\t%s\n}"
        % (name, tags, name, extra_strings, body_comment, condition)
    )


MIT = ["MIT License", "", "Copyright (c) 2021 Example One", "", "Permission is hereby granted, free of charge."]
BSD = ["BSD 2-Clause License", "", "Copyright (c) 2023, Example Two", "", "Redistributions of source code must retain it."]
DRL = ["# Detection Rule License (DRL) 1.1", "", "Permission is hereby granted, free of charge, to any person."]
GPL = ["Example is licensed under the following GNU General Public License version 3.", "",
       "                    GNU GENERAL PUBLIC LICENSE", "", "may be combined with the Apache License, Version 2.0."]

MIT_KEEP = rule("EXAMPLE_Mit_Keep")
MIT_HASH = rule("EXAMPLE_Mit_Hash", condition='$a and hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"')
BSD_KEEP = rule("EXAMPLE_Bsd_Keep", condition="$a and filesize < 1MB")
BSD_WIN = rule("EXAMPLE_Bsd_Windows_Only", condition="uint16( 0 ) == 0x5A4D and $a")
BSD_WIN_NAME = rule("EXAMPLE_Win_Named")
BSD_PE = rule("EXAMPLE_Bsd_Pe", condition="pe.is_dll() and $a")
BSD_PE_SIG = rule("EXAMPLE_Bsd_PeSig", condition="uint32(uint32(0x3C)) == 0x00004550 and $a")
BSD_MEM = rule("EXAMPLE_Bsd_Memory", tags="MEMORY")
BSD_MEM_FILE = rule("EXAMPLE_Bsd_MemoryAndFile", tags="MEMORY FILE")
BSD_MODULE = rule("EXAMPLE_Bsd_Magic", condition='magic.type() contains "ELF"')
BSD_NOT_WIN = rule("EXAMPLE_Bsd_Winner", condition="$a")        # "Winner" is not the token "Win"
BSD_PE_IN_TEXT = rule("EXAMPLE_Bsd_PeInText", condition='$a and "pe.exe" != "x" // pe.is_dll() in a comment')
NOLIC_RULE = rule("EXAMPLE_NoLicence")
GPL_RULE = rule("EXAMPLE_Gpl")


def package_text():
    header = "/*\n * YARA-Forge YARA Rule Package\n * Name: core\n */\n\nimport \"dotnet\"\nimport \"hash\"\nimport \"pe\"\n\n\n"
    return (
        header
        + block("Mit-Source", MIT, [MIT_KEEP, MIT_HASH])
        + block("Bsd-Source", BSD, [BSD_KEEP, BSD_WIN, BSD_WIN_NAME, BSD_PE, BSD_PE_SIG, BSD_MEM, BSD_MEM_FILE,
                                    BSD_MODULE, BSD_NOT_WIN, BSD_PE_IN_TEXT])
        + block("Nolicence-Source", ["NO LICENSE SET"], [NOLIC_RULE])
        + block("Gpl-Source", GPL, [GPL_RULE])
        + block("Drl-Source", DRL, [rule("EXAMPLE_Drl_Keep")])
    )


def needs_yara_x(test):
    try:
        import yara_x  # noqa: F401
    except ImportError:
        test.skipTest("yara_x is not installed")


class BuildRulesTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.zip = os.path.join(self.dir.name, "pkg.zip")
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("packages/core/yara-rules-core.yar", package_text())
        # The repository's own denylist names real rules; these tests use their own.
        self.denylist = os.path.join(self.dir.name, "denylist.txt")
        self.write_denylist("")

    def write_denylist(self, text):
        with open(self.denylist, "w", encoding="utf-8") as handle:
            handle.write(text)

    def write_package(self, text):
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("a.yar", text)

    def run_script(self, *extra, out="rules.yar"):
        out_path = os.path.join(self.dir.name, out)
        done = subprocess.run(
            [sys.executable, "-I", SCRIPT, "--forge", self.zip, "--out", out_path, "--denylist", self.denylist, *extra],
            capture_output=True, text=True)
        return done, out_path

    def build(self, *extra):
        done, out_path = self.run_script("--min-rules", "1", "--forge-release", "20261122", *extra)
        self.assertEqual(done.returncode, 0, done.stderr)
        with open(out_path, encoding="utf-8") as handle:
            return handle.read(), done.stderr

    def test_keeps_exactly_the_right_rules(self):
        text, _ = self.build()
        kept = [n for n in ("EXAMPLE_Mit_Keep", "EXAMPLE_Mit_Hash", "EXAMPLE_Bsd_Keep", "EXAMPLE_Bsd_MemoryAndFile",
                            "EXAMPLE_Bsd_Winner", "EXAMPLE_Bsd_PeInText", "EXAMPLE_Drl_Keep")]
        for name in kept:
            self.assertIn("rule %s " % name, text)
        for name in ("EXAMPLE_Bsd_Windows_Only", "EXAMPLE_Win_Named", "EXAMPLE_Bsd_Pe ", "EXAMPLE_Bsd_PeSig",
                     "EXAMPLE_Bsd_Memory ", "EXAMPLE_Bsd_Magic", "EXAMPLE_NoLicence", "EXAMPLE_Gpl"):
            self.assertNotIn("rule %s" % name, text)
        self.assertEqual(sum(1 for line in text.split("\n") if line.startswith("rule ")), len(kept))

    def test_licence_texts_and_counts_are_written(self):
        text, _ = self.build()
        head = text.split("rule EXAMPLE_Mit_Keep", 1)[0]
        self.assertIn(" * Built for SmartSort from YARA Forge core (release 20261122).\n", head)
        self.assertNotRegex(head, r"[0-9]{4}-[0-9]{2}-[0-9]{2}", "no build date: the same release gives the same bytes")
        self.assertIn("Source: Mit-Source", head)
        self.assertIn("Repository: https://example.invalid/mit-source/", head)
        self.assertIn("Licence: MIT", head)
        self.assertIn("Copyright (c) 2021 Example One", head)
        self.assertIn("Licence: BSD 2-Clause", head)
        self.assertIn("Copyright (c) 2023, Example Two", head)
        self.assertIn("Licence: Detection Rule License 1.1", head)
        self.assertIn("Rules kept: 2\n", head)       # the MIT source
        self.assertIn("Rules kept: 4\n", head)       # the BSD source
        self.assertNotIn("Nolicence-Source", head)
        self.assertNotIn("Gpl-Source", head)

    def test_only_needed_imports(self):
        text, _ = self.build()
        imports = [l for l in text.split("\n") if l.startswith("import ")]
        self.assertEqual(imports, ['import "hash"'])

    def test_no_imports_when_no_module_is_used(self):
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("a.yar", block("Mit-Source", MIT, [MIT_KEEP]))
        text, _ = self.build()
        self.assertNotIn("import ", text)

    def test_rule_text_is_unchanged_byte_for_byte(self):
        text, _ = self.build()
        for original in (MIT_KEEP, MIT_HASH, BSD_KEEP, BSD_MEM_FILE, BSD_NOT_WIN, BSD_PE_IN_TEXT):
            self.assertIn("\n\n" + original + "\n\n", "\n\n" + text.replace("\n\n", "\n\n", 1))
        # In package order.
        order = [text.index("rule " + n + " ") for n in ("EXAMPLE_Mit_Keep", "EXAMPLE_Mit_Hash", "EXAMPLE_Bsd_Keep",
                                                          "EXAMPLE_Drl_Keep")]
        self.assertEqual(order, sorted(order))

    def test_refuses_below_minimum_and_writes_nothing(self):
        done, out_path = self.run_script("--min-rules", "500")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("refusing", done.stderr)
        self.assertFalse(os.path.exists(out_path))

    def test_same_input_gives_same_bytes(self):
        first, _ = self.build()
        done, out2 = self.run_script("--min-rules", "1", "--forge-release", "20261122", out="again.yar")
        self.assertEqual(done.returncode, 0, done.stderr)
        with open(out2, encoding="utf-8") as handle:
            self.assertEqual(first, handle.read())

    def test_summary_counts_drops_by_reason(self):
        _, stderr = self.build()
        self.assertIn("dropped for licence 2, windows 4, memory 1, module 1, compile 0", stderr)

    def test_release_tag_that_could_end_a_comment_is_refused(self):
        done, _ = self.run_script("--min-rules", "1", "--forge-release", "x*/y")
        self.assertNotEqual(done.returncode, 0)

    def test_licence_classes(self):
        classify = build_rules.classify_licence
        self.assertEqual(classify("\n".join(DRL)), "Detection Rule License 1.1")
        self.assertEqual(classify("MIT License\nPermission is hereby granted"), "MIT")
        self.assertEqual(classify("Apache License\nVersion 2.0, January 2004"), "Apache License 2.0")
        self.assertEqual(classify("Redistribution. 2-Clause BSD"), "BSD 2-Clause")
        self.assertIsNone(classify("NO LICENSE SET"))
        self.assertIsNone(classify("Copyright. All rights reserved."))
        self.assertIsNone(classify("Creative Commons Attribution 4.0"))
        self.assertIsNone(classify("\n".join(GPL)))

    def test_check_drops_a_rule_that_does_not_compile(self):
        needs_yara_x(self)
        broken = rule("EXAMPLE_Mit_Broken", condition="$nope")
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("a.yar", block("Mit-Source", MIT, [MIT_KEEP, broken, MIT_HASH]))
        text, stderr = self.build("--check")
        self.assertNotIn("EXAMPLE_Mit_Broken", text)
        self.assertIn("dropping EXAMPLE_Mit_Broken", stderr)
        self.assertIn("compile 1", stderr)
        self.assertIn("rule EXAMPLE_Mit_Hash ", text)
        self.assertIn("Rules kept: 2\n", text)

    def test_rules_needing_modules_outside_the_engines_six_are_dropped(self):
        rules = [rule("EXAMPLE_Mit_Lnk", condition="lnk.is_lnk and $a"),
                 rule("EXAMPLE_Mit_Dex", condition="dex.header.magic == \"x\" and $a"),
                 rule("EXAMPLE_Mit_Macho", condition="macho.number_of_segments > 0 and $a"),
                 rule("EXAMPLE_Mit_Range", condition="for any i in (0..pe.number_of_sections) : (true) and $a"),
                 rule("EXAMPLE_Mit_MathRange", condition="$a and (0..math.entropy(0, 10)) == 1")]
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("a.yar", block("Mit-Source", MIT, rules))
        text, stderr = self.build()
        self.assertNotIn("EXAMPLE_Mit_Lnk", text)
        self.assertNotIn("EXAMPLE_Mit_Dex", text)
        self.assertNotIn("EXAMPLE_Mit_Range", text)
        self.assertIn("rule EXAMPLE_Mit_Macho ", text)
        self.assertIn("rule EXAMPLE_Mit_MathRange ", text)
        self.assertIn("module 2", stderr)       # lnk, dex
        self.assertIn("windows 1", stderr)      # the pe range
        imports = [l for l in text.split("\n") if l.startswith("import ")]
        self.assertEqual(imports, ['import "math"', 'import "macho"'])

    def test_check_refuses_a_module_the_text_scan_does_not_know(self):
        needs_yara_x(self)
        from unittest import mock
        source = build_rules.Source("Mit-Source", "https://example.invalid/x/", "MIT", "MIT License")
        lnk = build_rules.parse_rule(source, rule("EXAMPLE_Mit_Lnk", condition="lnk.is_lnk and $a"))
        keep = build_rules.parse_rule(source, rule("EXAMPLE_Mit_Keep"))
        source.rules = [lnk, keep]
        dropped = {"module": 0, "compile": 0}
        # Blind the text scan, so only the compile step can notice the module.
        with mock.patch.object(build_rules, "KNOWN_MODULES", set()):
            self.assertEqual(build_rules.used_modules(lnk), set())
            kept = build_rules.compile_check([source], [lnk, keep], None, dropped)
        self.assertEqual([r.name for r in kept], ["EXAMPLE_Mit_Keep"])
        self.assertEqual(dropped["module"], 1)

    # A zero byte ends C text early, so the app refuses rule text that holds one.

    def test_a_rule_with_a_zero_byte_is_dropped_and_the_others_kept(self):
        zero = rule("EXAMPLE_Mit_Zero").replace("SMARTSORT-TEST-EXAMPLE_Mit_Zero", "SMARTSORT-TEST-\x00-ZERO")
        self.write_package(block("Mit-Source", MIT, [MIT_KEEP, zero, MIT_HASH]))
        text, stderr = self.build()
        self.assertNotIn("EXAMPLE_Mit_Zero", text)
        self.assertNotIn("\x00", text)
        self.assertIn("rule EXAMPLE_Mit_Keep ", text)
        self.assertIn("rule EXAMPLE_Mit_Hash ", text)
        self.assertIn("zero byte 1", stderr)

    def test_a_zero_byte_with_check_is_dropped_before_compiling(self):
        needs_yara_x(self)
        zero = rule("EXAMPLE_Mit_Zero").replace("SMARTSORT-TEST-EXAMPLE_Mit_Zero", "SMARTSORT-TEST-\x00-ZERO")
        self.write_package(block("Mit-Source", MIT, [MIT_KEEP, zero]))
        text, stderr = self.build("--check")
        self.assertNotIn("\x00", text)
        self.assertIn("zero byte 1", stderr)
        self.assertIn("compile 0", stderr)

    def test_a_zero_byte_outside_any_rule_stops_the_build(self):
        self.write_package(block("Mit-Source", MIT[:-1] + ["Permission is hereby granted.\x00"], [MIT_KEEP]))
        done, out_path = self.run_script("--min-rules", "1")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("zero byte", done.stderr)
        self.assertFalse(os.path.exists(out_path))

    # Text from the package that would end the header comment.

    def test_a_licence_text_that_would_end_the_comment_stops_the_build(self):
        self.write_package(block("Mit-Source", MIT + ["Keep this notice. */ rule Injected { condition: true } /*"],
                                 [MIT_KEEP]))
        done, out_path = self.run_script("--min-rules", "1")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("*/", done.stderr)
        self.assertFalse(os.path.exists(out_path))

    # The denylist: rules pulled by hand.

    def test_denylisted_rules_are_dropped_and_a_name_no_longer_there_is_warned_about(self):
        self.write_denylist("# Pulled by hand.\n\nEXAMPLE_Mit_Hash   matches something ordinary\n"
                            "  EXAMPLE_Gone_Away  no longer in the package\n")
        text, stderr = self.build()
        self.assertNotIn("EXAMPLE_Mit_Hash", text)
        self.assertNotIn('import "hash"', text, "only the dropped rule used it")
        self.assertIn("rule EXAMPLE_Mit_Keep ", text)
        self.assertIn("denylist 1", stderr)
        self.assertIn("EXAMPLE_Gone_Away", stderr)
        self.assertNotIn("EXAMPLE_Mit_Hash is not in", stderr)

    def test_a_denylist_entry_without_a_reason_is_refused(self):
        self.write_denylist("EXAMPLE_Mit_Hash\n")
        done, out_path = self.run_script("--min-rules", "1")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("reason", done.stderr)
        self.assertFalse(os.path.exists(out_path))

    def test_the_repositorys_denylist_reads(self):
        entries = build_rules.read_denylist(os.path.join(HERE, "rules-denylist.txt"))
        self.assertTrue(all(reason for reason in entries.values()))

    # The ordinary-file gate in --check.

    def test_check_drops_rules_that_match_ordinary_files(self):
        needs_yara_x(self)
        ordinary = os.path.join(self.dir.name, "ordinary")
        os.makedirs(os.path.join(ordinary, "deep"))
        with open(os.path.join(ordinary, "deep", "tool"), "wb") as handle:
            handle.write(b"an ordinary program that happens to hold SMARTSORT-TEST-EXAMPLE_Mit_Keep")
        # Passed over: a link (to a file outside that matches), and a file over 64 MB.
        outside = os.path.join(self.dir.name, "outside")
        with open(outside, "wb") as handle:
            handle.write(b"SMARTSORT-TEST-EXAMPLE_Mit_Hash")
        os.symlink(outside, os.path.join(ordinary, "link"))
        with open(os.path.join(ordinary, "huge"), "wb") as handle:
            handle.write(b"SMARTSORT-TEST-EXAMPLE_Drl_Keep")
            handle.truncate((64 << 20) + 1)
        user = rule("EXAMPLE_Mit_User", condition="EXAMPLE_Mit_Keep and filesize > 100MB")
        self.write_package(block("Mit-Source", MIT, [MIT_KEEP, user, MIT_HASH])
                           + block("Drl-Source", DRL, [rule("EXAMPLE_Drl_Keep")]))
        text, stderr = self.build("--check", "--benign", ordinary)
        self.assertNotIn("EXAMPLE_Mit_Keep", text)
        self.assertNotIn("EXAMPLE_Mit_User", text, "it used the dropped rule")
        self.assertIn("rule EXAMPLE_Mit_Hash ", text)
        self.assertIn("rule EXAMPLE_Drl_Keep ", text)
        self.assertIn("dropping EXAMPLE_Mit_Keep (Mit-Source): matches ordinary files, such as "
                      + os.path.join(ordinary, "deep", "tool"), stderr)
        self.assertIn("matches ordinary files 1", stderr)
        self.assertIn("compile 1", stderr)

    def test_check_drops_a_rule_that_used_a_dropped_one(self):
        needs_yara_x(self)
        broken = rule("EXAMPLE_Mit_Broken", condition="$nope")
        user = rule("EXAMPLE_Mit_User", condition="EXAMPLE_Mit_Broken")
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("a.yar", block("Mit-Source", MIT, [MIT_KEEP, broken, user]))
        text, _ = self.build("--check")
        self.assertNotIn("EXAMPLE_Mit_User", text)
        self.assertIn("rule EXAMPLE_Mit_Keep ", text)


if __name__ == "__main__":
    unittest.main()
