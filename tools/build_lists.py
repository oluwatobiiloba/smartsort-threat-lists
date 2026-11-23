#!/usr/bin/env python3
"""Build SmartSort's threat lists.

Reads OSV's public exports (npm and PyPI), keeps the malicious-package records
that have not been withdrawn, and writes one sorted text list per ecosystem,
gzip-compressed, plus the curated indicator files and a manifest that names
every file with its size and SHA-256.

Only the Python standard library is used. Nothing is uploaded anywhere.

    build_lists.py --npm npm.zip --pypi pypi.zip --indicators DIR --out DIR
                   [--rules FILE] [--seq N] [--created ISO8601]

List lines, sorted by the bytes of the name:

    name                                  every version is malicious
    name<TAB>1.0.0,1.0.1                  those versions
    name<TAB>>=2.0.0                      that version and later
    name<TAB>>=1.0.0<1.2.0                from the first up to, not including, the second

A third tab-separated field names the advisory (the lowest id when several).
"""

import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import sys
import zipfile

FORMAT = 1
# Indicator files that must never be published: they describe one person's Mac.
PRIVATE_INDICATORS = {"allowlist.local.ioc"}
# Always used with fullmatch: "$" would also accept a trailing newline, and a
# newline in a name or version would start a line of its own in the list.
NAME_OK = re.compile(r"[^\s\x00-\x20\x7f]+")
VERSION_OK = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_~!-]*")
ID_OK = re.compile(r"MAL-[0-9]{4}-[0-9]+")


def normalise(ecosystem, name):
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def collect(zip_path, ecosystem):
    """name -> {"every": bool, "versions": set, "ranges": set, "ids": set}"""
    found = {}
    skipped = {"withdrawn": 0, "other_ecosystem": 0, "bad_name": 0, "bad_version": 0, "empty": 0}
    with zipfile.ZipFile(zip_path) as archive:
        for entry in archive.infolist():
            base = os.path.basename(entry.filename)
            if not base.startswith("MAL-") or not base.endswith(".json"):
                continue
            if entry.file_size > 8_000_000:
                continue
            record = json.loads(archive.read(entry))
            if record.get("withdrawn"):
                skipped["withdrawn"] += 1
                continue
            for affected in record.get("affected", []):
                package = affected.get("package", {})
                if package.get("ecosystem") != ecosystem:
                    skipped["other_ecosystem"] += 1
                    continue
                name = normalise(ecosystem, package.get("name", ""))
                if not NAME_OK.fullmatch(name) or "\t" in name:
                    skipped["bad_name"] += 1
                    continue
                every = False
                versions = set()
                ranges = set()
                for version in affected.get("versions", []) or []:
                    if VERSION_OK.fullmatch(version) and "," not in version:
                        versions.add(version)
                    else:
                        skipped["bad_version"] += 1
                for span in affected.get("ranges", []) or []:
                    if span.get("type") not in ("SEMVER", "ECOSYSTEM"):
                        continue
                    floor = None
                    for event in span.get("events", []):
                        if "introduced" in event:
                            floor = event["introduced"]
                        elif "fixed" in event and floor is not None:
                            ceiling = event["fixed"]
                            if VERSION_OK.fullmatch(ceiling) and (floor == "0" or VERSION_OK.fullmatch(floor)):
                                ranges.add(">=%s<%s" % ("0" if floor == "0" else floor, ceiling))
                            floor = None
                        elif "last_affected" in event and floor is not None:
                            # No way to say "up to and including" in a line; the
                            # explicit versions, when given, carry it instead.
                            floor = None
                    if floor == "0":
                        every = True
                    elif floor is not None and VERSION_OK.fullmatch(floor):
                        ranges.add(">=" + floor)
                if not every and not versions and not ranges:
                    skipped["empty"] += 1
                    continue
                slot = found.setdefault(name, {"every": False, "versions": set(), "ranges": set(), "ids": set()})
                slot["every"] = slot["every"] or every
                slot["versions"] |= versions
                slot["ranges"] |= ranges
                identifier = record.get("id", "")
                if isinstance(identifier, str) and ID_OK.fullmatch(identifier):
                    slot["ids"].add(identifier)
    return found, skipped


def advisory_key(identifier):
    parts = identifier.split("-")
    try:
        return (int(parts[1]), int(parts[2]))
    except (IndexError, ValueError):
        return (10**9, 10**9)


def render(found, with_advisories):
    lines = []
    for name in sorted(found, key=lambda n: n.encode("utf-8")):
        slot = found[name]
        versions = "" if slot["every"] else ",".join(sorted(slot["versions"]) + sorted(slot["ranges"]))
        advisory = min((i for i in slot["ids"] if i), key=advisory_key, default="") if with_advisories else ""
        if advisory:
            lines.append("%s\t%s\t%s" % (name, versions, advisory))
        elif versions:
            lines.append("%s\t%s" % (name, versions))
        else:
            lines.append(name)
    return ("\n".join(lines) + "\n").encode("utf-8") if lines else b""


def pack(data):
    buffer = io.BytesIO()
    # mtime=0 and no file name, so the same input always gives the same bytes.
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as stream:
        stream.write(data)
    return buffer.getvalue()


def publish(out_dir, role, stem, extension, data, files):
    digest = hashlib.sha256(data).hexdigest()
    name = "%s.%s.%s" % (stem, digest[:12], extension)
    with open(os.path.join(out_dir, name), "wb") as handle:
        handle.write(data)
    files.append({"role": role, "name": name, "sha256": digest, "bytes": len(data)})
    return name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--npm", required=True)
    parser.add_argument("--pypi", required=True)
    parser.add_argument("--indicators", required=True, help="folder of .ioc files")
    parser.add_argument("--expect", help="file naming, one per line, the indicator files that must be there")
    parser.add_argument("--rules", help="rule text for the rule engine (optional)")
    parser.add_argument("--notice", help="NOTICE.txt to publish alongside")
    parser.add_argument("--out", required=True)
    parser.add_argument("--seq", type=int)
    parser.add_argument("--created")
    parser.add_argument("--no-advisories", action="store_true")
    args = parser.parse_args()

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    created = args.created or now.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Minutes on the clock, so a set made later always has a higher number,
    # wherever it was made.
    seq = args.seq or int(now.strftime("%Y%m%d%H%M"))

    # A downloaded set replaces the app's built-in one whole. If an indicator
    # file the app ships with were missing here (its branch not merged yet),
    # publishing would quietly take those indicators away from every user.
    if args.expect:
        with open(args.expect, encoding="utf-8") as handle:
            expected = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
        present = {base[:-4] for base in os.listdir(args.indicators)
                   if base.endswith(".ioc") and base not in PRIVATE_INDICATORS and not base.endswith(".local.ioc")}
        missing = sorted(set(expected) - present)
        if missing:
            sys.exit("refusing to publish without these indicator files: %s" % ", ".join(missing))

    os.makedirs(args.out, exist_ok=True)
    files = []

    for role, path, ecosystem, stem in (("malicious-npm", args.npm, "npm", "malicious-npm"),
                                        ("malicious-pypi", args.pypi, "PyPI", "malicious-pypi")):
        found, skipped = collect(path, ecosystem)
        text = render(found, not args.no_advisories)
        packed = pack(text)
        name = publish(args.out, role, stem, "txt.gz", packed, files)
        print("%s: %d packages, %d bytes, %d packed -> %s  skipped %s"
              % (ecosystem, len(found), len(text), len(packed), name, skipped), file=sys.stderr)
        if len(found) < 1000:
            sys.exit("refusing to publish a %s list with only %d packages" % (ecosystem, len(found)))

    for base in sorted(os.listdir(args.indicators)):
        if not base.endswith(".ioc") or base in PRIVATE_INDICATORS or base.endswith(".local.ioc"):
            continue
        with open(os.path.join(args.indicators, base), "rb") as handle:
            data = handle.read()
        data.decode("utf-8")
        for line in data.decode("utf-8").splitlines():
            if line.split("|")[0].strip() == "allow":
                sys.exit("%s carries an allow line; allow-lists are private and are not published" % base)
        publish(args.out, "indicators", base[:-4], "ioc", data, files)

    if args.rules:
        with open(args.rules, "rb") as handle:
            publish(args.out, "rules", "rules", "yar.gz", pack(handle.read()), files)

    if args.notice:
        with open(args.notice, "rb") as handle:
            data = handle.read()
        with open(os.path.join(args.out, "NOTICE.txt"), "wb") as handle:
            handle.write(data)
        files.append({"role": "notice", "name": "NOTICE.txt", "sha256": hashlib.sha256(data).hexdigest(),
                      "bytes": len(data)})

    manifest = {"format": FORMAT, "seq": seq, "created": created, "files": files}
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("manifest: seq %d, %d files" % (seq, len(files)), file=sys.stderr)


if __name__ == "__main__":
    main()
