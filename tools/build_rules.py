#!/usr/bin/env python3
"""Build SmartSort's malware rule file from YARA Forge's "core" package.

    build_rules.py --forge yara-forge-rules-core.zip --out rules.yar
                   [--forge-release TAG] [--check [--benign DIR ...]] [--min-rules 500]
                   [--denylist FILE]

The package holds one `.yar` file: a header, then one block per source
repository. Each block starts with a comment naming the source and giving its
licence, followed by that source's rules.

What is kept:

  * Only blocks whose licence text is the Detection Rule License 1.1, BSD
    2-Clause, Apache 2.0 or MIT. Every other block is left out whole.
  * Only rules the app's engine can run: not rules that only work on Windows
    programs, not rules for memory alone, and not rules that need a module the
    engine was built without (it has hash, math, string, time, elf and macho).
  * No rule holding a zero byte: the app reads rule text as C text, which
    ends at one, so it refuses the whole file.
  * No rule named in the denylist (tools/rules-denylist.txt), which is how a
    rule is pulled by hand.

Kept rules are copied unchanged, in package order. The file starts with a
comment giving the release, then each source's name, address, licence text and
rule count. Nothing else changes from one build to the next, so the same
release always gives the same bytes.

With --check the whole file is compiled with the yara_x package, and any rule
that does not compile is dropped (and so, in turn, any rule that used it).
With --benign DIR as well, the compiled rules are run over the ordinary files
in DIR, and any rule that matches one is dropped as well, then the rest are
compiled again.

The standard library does the work; yara_x is needed only for --check.
Nothing is uploaded anywhere.
"""

import argparse
import os
import re
import stat
import sys
import zipfile

# The modules the app's engine is built with.
ENGINE_MODULES = ("hash", "math", "string", "time", "elf", "macho")
# Every module YARA-X 1.24.0 has (lib/src/modules/ in its source, tests aside).
# A rule using one that is not an engine module cannot run in the app, and the
# app compiles all rules as one set, so one such rule would sink them all.
KNOWN_MODULES = {
    "console", "crx", "cuckoo", "dex", "dotnet", "elf", "hash", "lnk", "macho", "magic",
    "math", "msi", "olecf", "pe", "string", "time", "vba", "vt", "zip",
}
WINDOWS_NAME_TOKENS = {"win", "windows", "win32", "win64"}
DEFAULT_DENYLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules-denylist.txt")
RULE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Every reason a rule can be left out for, in the order the summary gives them.
DROP_REASONS = ("licence", "windows", "memory", "module", "compile", "zero byte", "denylist", "ordinary")
# How much of the ordinary files under --benign is scanned.
BENIGN_FILE_LIMIT = 64 << 20
BENIGN_TOTAL_LIMIT = 2 << 30
BENIGN_FILES_LIMIT = 20_000

BLOCK_START = re.compile(r"^/\*\n \* YARA Rule Set\n", re.M)
RULE_START = re.compile(r"^(?:private |global )?rule ")
NAME_IN_HEADER = re.compile(r"^(?:(?:private|global) )*rule\s+([A-Za-z_][A-Za-z0-9_]*)")
CONDITION = re.compile(r"^\s*condition\s*:", re.M)
# A test of the first bytes of the file for "MZ", or of the PE signature.
PE_HEADER_TESTS = (
    re.compile(r"uint16\s*\(\s*0\s*\)\s*==\s*0x5a4d", re.I),
    re.compile(r"uint16be\s*\(\s*0\s*\)\s*==\s*0x4d5a", re.I),
    re.compile(r"uint32\s*\(\s*uint32\s*\(\s*0x3c\s*\)\s*\)\s*==\s*0x0*4550\b", re.I),
)
STRIP = re.compile(
    r'"(?:\\.|[^"\\\n])*"'            # string literal
    r"|//[^\n]*"                      # line comment
    r"|/\*.*?\*/"                     # block comment
    r"|(?<=matches)\s*/(?:\\.|[^/\\\n])+/[a-z]*",  # regex literal after "matches"
    re.S,
)
# A module name starts a field path: not part of a longer name or path, but a
# range such as (0..pe.number_of_sections) puts one right after "..".
DOTTED = re.compile(r"(?:(?<=\.\.)|(?<![A-Za-z0-9_$#@!.]))([A-Za-z_][A-Za-z0-9_]*)\s*\.")


class Source:
    def __init__(self, name, address, licence, license_text):
        self.name = name
        self.address = address
        self.licence = licence          # short name, or None when not accepted
        self.licence_text = license_text
        self.rules = []                 # kept: Rule objects
        self.licence_dropped = 0


class Rule:
    def __init__(self, source, text, name, tags):
        self.source = source
        self.text = text
        self.name = name
        self.tags = tags
        self.modules = set()


def classify_licence(text):
    """Decide from the licence text itself. DRL is checked first: its text also
    begins "Permission is hereby granted". A GNU licence is refused before
    anything else: CAPE's GPL text mentions the Apache licence, and the rules
    under it are not ours to publish."""
    if re.search(r"GNU\s+(?:Lesser\s+|Affero\s+)?(?:General\s+Public\s+License)", text, re.I):
        return None
    if "Detection Rule License" in text and "1.1" in text:
        return "Detection Rule License 1.1"
    if "BSD 2-Clause" in text or "2-Clause BSD" in text:
        return "BSD 2-Clause"
    if "Apache License" in text and "Version 2.0" in text:
        return "Apache License 2.0"
    if "MIT License" in text:
        return "MIT"
    return None


def read_package(path):
    with zipfile.ZipFile(path) as archive:
        yars = [e for e in archive.infolist() if e.filename.endswith(".yar") and not e.is_dir()]
        if len(yars) != 1:
            sys.exit("expected one .yar file in %s, found %d" % (path, len(yars)))
        if yars[0].file_size > 200_000_000:
            sys.exit("the rule file is far larger than expected")
        data = archive.read(yars[0])
    return data.decode("utf-8").replace("\r\n", "\n")


def parse_blocks(text):
    """Return a Source for each block, with its rule texts attached as raw
    (name, tags, text) tuples under `.raw`."""
    starts = [m.start() for m in BLOCK_START.finditer(text)]
    sources = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        block = text[start:end]
        lines = block.split("\n")
        try:
            close = lines.index(" */")
        except ValueError:
            sys.exit("a block header in the package is never closed")
        header = lines[:close]
        name = address = None
        licence_start = None
        for number, line in enumerate(header):
            if line.startswith(" * Repository Name:"):
                name = line[len(" * Repository Name:"):].strip()
            elif line.startswith(" * Repository:"):
                address = line[len(" * Repository:"):].strip()
            elif line.strip() == "* LICENSE" and licence_start is None:
                licence_start = number
        if not name or not address or licence_start is None:
            sys.exit("a block header lacks its name, address or licence")
        # The text after the "LICENSE" line, as the package gives it. Drop only
        # the blank " * " line that follows the word.
        licence_lines = header[licence_start + 1:]
        if licence_lines and licence_lines[0].strip() == "*":
            licence_lines = licence_lines[1:]
        licence_text = "\n".join(licence_lines)
        licence_text = re.sub(r"^ \* ?", "", licence_text, count=1)
        licence_text = licence_text.strip("\n")
        source = Source(name, address, classify_licence(licence_text), licence_text)
        source.raw = split_rules("\n".join(lines[close + 1:]))
        sources.append(source)
    return sources


def split_rules(body):
    found = []
    current = None
    for line in body.split("\n"):
        if current is None:
            if RULE_START.match(line):
                current = [line]
        else:
            current.append(line)
            if line == "}":
                found.append("\n".join(current))
                current = None
    if current is not None:
        sys.exit("a rule in the package is never closed")
    return found


def header_of(text):
    """The text of the rule up to its opening brace."""
    return text.split("{", 1)[0]


def parse_rule(source, text):
    head = header_of(text)
    match = NAME_IN_HEADER.match(head)
    if not match:
        sys.exit("cannot read a rule name from: %r" % head[:80])
    tags = set()
    if ":" in head:
        tags = set(head.split(":", 1)[1].split())
    rule = Rule(source, text, match.group(1), tags)
    return rule


def condition_text(text):
    match = CONDITION.search(text)
    if not match:
        return ""
    return STRIP.sub(lambda m: " " if not m.group(0).startswith('"') else '""', text[match.end():])


def used_modules(rule):
    return {m for m in DOTTED.findall(condition_text(rule.text)) if m in KNOWN_MODULES}


def windows_reason(rule, modules):
    tokens = {t.lower() for t in rule.name.split("_")}
    if tokens & WINDOWS_NAME_TOKENS:
        return "name says Windows"
    # The header test is looked for with comments removed but strings kept, so a
    # test written inside the condition is found whatever its spacing.
    stripped = condition_text(rule.text)
    if any(p.search(stripped) for p in PE_HEADER_TESTS):
        return "tests the PE header"
    if modules & {"pe", "dotnet"}:
        return "uses the pe or dotnet module"
    return None


def drop_reason(rule, denylist=None):
    """Return (category, detail) or None to keep."""
    if "\x00" in rule.text:
        return "zero byte", "holds a zero byte"
    if denylist and rule.name in denylist:
        return "denylist", denylist[rule.name]
    modules = used_modules(rule)
    detail = windows_reason(rule, modules)
    if detail:
        return "windows", detail
    if "MEMORY" in rule.tags and "FILE" not in rule.tags:
        return "memory", "memory-only"
    lacking = sorted(modules - set(ENGINE_MODULES))
    if lacking:
        return "module", "uses " + ", ".join(lacking)
    rule.modules = modules & set(ENGINE_MODULES)
    return None


def read_denylist(path):
    """Rule name -> why it is left out. One per line, the name and then the
    reason; `#` starts a comment line. An entry with no reason is refused."""
    entries = {}
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if not RULE_NAME.fullmatch(parts[0]):
                sys.exit("%s line %d: %r is not a rule name" % (path, number, parts[0]))
            if len(parts) < 2 or not parts[1].strip():
                sys.exit("%s line %d: give a reason after the rule's name" % (path, number))
            entries[parts[0]] = parts[1].strip()
    return entries


def select(sources, denylist=None):
    dropped = dict.fromkeys(DROP_REASONS, 0)
    for source in sources:
        if source.licence is None:
            source.licence_dropped = len(source.raw)
            dropped["licence"] += len(source.raw)
            continue
        for text in source.raw:
            rule = parse_rule(source, text)
            reason = drop_reason(rule, denylist)
            if reason:
                dropped[reason[0]] += 1
                if reason[0] in ("zero byte", "denylist"):
                    print("%s: dropping %s (%s): %s" % (reason[0], rule.name, source.name, reason[1]), file=sys.stderr)
            else:
                source.rules.append(rule)
    return dropped


def names_in_package(sources):
    """Every rule name in the package, whatever its source's licence."""
    found = set()
    for source in sources:
        for text in source.raw:
            match = NAME_IN_HEADER.match(header_of(text))
            if match:
                found.add(match.group(1))
    return found


def header_comment(sources, release):
    kept = [s for s in sources if s.rules]
    # The text comes from the package and goes inside one comment: anything
    # that would end it early, or end the app's reading of it, stops the build.
    for s in kept:
        for what, text in (("name", s.name), ("address", s.address), ("licence text", s.licence_text)):
            if "*/" in text:
                sys.exit("the %s of %s holds */, which would end the comment it is written in" % (what, s.name))
            if "\x00" in text:
                sys.exit("the %s of %s holds a zero byte, so the app would refuse the file" % (what, s.name))
    lines = ["/*"]
    built = "Built for SmartSort from YARA Forge core"
    if release:
        built += " (release %s)" % release
    lines.append(" * %s." % built)
    lines.append(" *")
    lines.append(" * Each source below is kept under its own licence. Every rule keeps its")
    lines.append(" * author, score and licence fields.")
    for s in kept:
        lines.append(" *")
        lines.append(" * Source: %s" % s.name)
        lines.append(" * Repository: %s" % s.address)
        lines.append(" * Licence: %s" % s.licence)
        lines.append(" * Rules kept: %d" % len(s.rules))
        lines.append(" * Licence text:")
        lines.append(" *")
        lines.append(s.licence_text)
    lines.append(" */")
    return "\n".join(lines)


def assemble(sources, rules, release):
    """The file text and, for each rule, the first line it sits on."""
    used = set()
    for rule in rules:
        used |= rule.modules
    parts = [header_comment(sources, release)]
    imports = ["import \"%s\"" % m for m in ENGINE_MODULES if m in used]
    if imports:
        parts.append("\n".join(imports))
    text = "\n\n".join(parts) + "\n\n"
    starts = []
    line = text.count("\n") + 1
    chunks = [text]
    for rule in rules:
        starts.append(line)
        chunks.append(rule.text + "\n\n")
        line += rule.text.count("\n") + 2
    return "".join(chunks).rstrip("\n") + "\n", starts


def error_line(message):
    match = re.search(r"-->\s*(?:\S*:)?(\d+):\d+", message)
    return int(match.group(1)) if match else None


def ordinary_files(folders):
    """The files under these folders the rules are run over: regular files
    only (a link is never followed), each at most 64 MB, and at most 20,000
    files and 2 GB in all, in the same order every time."""
    found = []
    total = 0
    for folder in folders:
        for root, dirs, names in os.walk(folder):
            dirs.sort()
            for name in sorted(names):
                path = os.path.join(root, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_size > BENIGN_FILE_LIMIT:
                    continue
                if len(found) == BENIGN_FILES_LIMIT or total + info.st_size > BENIGN_TOTAL_LIMIT:
                    print("check: stopped at %d ordinary files, %d MB, before %s" % (len(found), total >> 20, path),
                          file=sys.stderr)
                    return found
                found.append(path)
                total += info.st_size
    print("check: %d ordinary files, %d MB" % (len(found), total >> 20), file=sys.stderr)
    return found


def ordinary_matches(compiled, paths):
    """Each rule that matches one of these files, and the first file it matched."""
    import yara_x

    scanner = yara_x.Scanner(compiled)
    scanner.set_timeout(60)
    first = {}
    for path in paths:
        try:
            with open(path, "rb") as handle:
                data = handle.read(BENIGN_FILE_LIMIT)
            results = scanner.scan(data)
        except OSError:
            continue
        except (yara_x.TimeoutError, yara_x.ScanError) as error:
            print("check: could not scan %s: %s" % (path, error), file=sys.stderr)
            continue
        for match in results.matching_rules:
            first.setdefault(match.identifier, path)
    return first


def compile_check(sources, rules, release, dropped, benign=(), rounds=300):
    import yara_x

    # Compile as the app does: only the engine's modules. The Python package has
    # more, so the others are set to be ignored, and a rule that needed one
    # comes back missing from the compiled set.
    banned = sorted((KNOWN_MODULES | set(yara_x.module_names())) - set(ENGINE_MODULES))
    # Files no rule should match: a rule that does would flag them in the app.
    paths = ordinary_files(benign) if benign else []

    for number in range(1, rounds + 1):
        text, starts = assemble(sources, rules, release)
        try:
            compiler = yara_x.Compiler()
            for module in banned:
                compiler.ignore_module(module)
            compiler.add_source(text)
            compiled = compiler.build()
        except yara_x.CompileError as error:
            message = str(error)
            line = error_line(message)
            if line is None or not starts or line < starts[0]:
                sys.exit("compile error outside any rule:\n" + message)
            index = max(i for i, s in enumerate(starts) if s <= line)
            rule = rules[index]
            summary = message.split("\n", 1)[0]
            print("check: dropping %s (%s): %s" % (rule.name, rule.source.name, summary), file=sys.stderr)
            dropped["compile"] += 1
            rule.source.rules.remove(rule)
            rules = rules[:index] + rules[index + 1:]
            continue
        built = {r.identifier for r in compiled}
        missing = [r for r in rules if r.name not in built]
        if missing:
            for rule in missing:
                print("check: dropping %s (%s): needs a module the app lacks" % (rule.name, rule.source.name),
                      file=sys.stderr)
                dropped["module"] += 1
                rule.source.rules.remove(rule)
            rules = [r for r in rules if r.name in built]
            continue
        matched = ordinary_matches(compiled, paths) if paths else {}
        flagged = [r for r in rules if r.name in matched]
        if flagged:
            # Then compiled again: a rule that used one of these goes too.
            for rule in flagged:
                print("check: dropping %s (%s): matches ordinary files, such as %s"
                      % (rule.name, rule.source.name, matched[rule.name]), file=sys.stderr)
                dropped["ordinary"] += 1
                rule.source.rules.remove(rule)
            rules = [r for r in rules if r.name not in matched]
            continue
        print("check: compiles after %d round(s)" % number, file=sys.stderr)
        return rules
    sys.exit("still not compiling after %d rounds" % rounds)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--forge", required=True, help="yara-forge-rules-core.zip")
    parser.add_argument("--out", required=True)
    parser.add_argument("--forge-release", help="the package's release tag")
    parser.add_argument("--check", action="store_true", help="compile with yara_x and drop what fails")
    parser.add_argument("--benign", action="append", default=[], metavar="DIR",
                        help="with --check: drop any rule that matches a file in DIR (may be given more than once)")
    parser.add_argument("--denylist", default=DEFAULT_DENYLIST, help="rule names to leave out, each with a reason")
    parser.add_argument("--min-rules", type=int, default=500)
    args = parser.parse_args()

    # The tag comes from a download and ends up inside a comment.
    if args.forge_release is not None and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", args.forge_release):
        sys.exit("--forge-release may only hold letters, digits, dot, dash and underscore")
    if args.benign and not args.check:
        sys.exit("--benign needs --check")
    for folder in args.benign:
        if not os.path.isdir(folder):
            sys.exit("--benign %s: no such folder" % folder)
    denylist = read_denylist(args.denylist)
    sources = parse_blocks(read_package(args.forge))
    dropped = select(sources, denylist)
    for name in sorted(set(denylist) - names_in_package(sources)):
        print("denylist: %s is not in the package any more" % name, file=sys.stderr)
    rules = [r for s in sources for r in s.rules]
    if args.check:
        rules = compile_check(sources, rules, args.forge_release, dropped, args.benign)

    print("kept per source:", file=sys.stderr)
    for s in sources:
        if s.licence is None:
            print("  %-22s left out (licence not accepted): %d rules" % (s.name, s.licence_dropped), file=sys.stderr)
        else:
            print("  %-22s %-27s %d" % (s.name, s.licence, len(s.rules)), file=sys.stderr)
    print("kept %d rules; dropped for licence %d, windows %d, memory %d, module %d, compile %d, zero byte %d, "
          "denylist %d, matches ordinary files %d"
          % (len(rules), dropped["licence"], dropped["windows"], dropped["memory"], dropped["module"],
             dropped["compile"], dropped["zero byte"], dropped["denylist"], dropped["ordinary"]), file=sys.stderr)

    if len(rules) < args.min_rules:
        sys.exit("refusing to write a rule file with only %d rules (minimum %d)" % (len(rules), args.min_rules))

    text, _ = assemble(sources, rules, args.forge_release)
    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


if __name__ == "__main__":
    main()
