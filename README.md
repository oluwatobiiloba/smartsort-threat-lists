# SmartSort threat lists

The lists SmartSort, a Mac app that sorts files, checks new files against: packages reported as malicious, and marks that known attacks on developers leave behind.

This repository holds no malware and no code from any. It holds a small script that builds the lists and a workflow that publishes them once a night.

## What is published

At `https://oluwatobiiloba.github.io/smartsort-threat-lists/v1/`:

| File | What it is |
|---|---|
| `manifest.json` | `format`, `seq` (a number that only goes up), `created`, and every file's `role`, `name`, `sha256` and `bytes` |
| `manifest.json.sig` | An Ed25519 signature over the exact bytes of `manifest.json`, base64 |
| `malicious-npm.<hash>.txt.gz` | npm packages reported as malicious |
| `malicious-pypi.<hash>.txt.gz` | PyPI packages reported as malicious |
| `<name>.<hash>.ioc` | Indicators for particular attacks: file hashes, package versions, host names, editor extensions |
| `NOTICE.txt` | Where the data comes from and its licences |

The same files are attached to the [`lists` release](../../releases/tag/lists), which SmartSort tries if this address cannot be reached.

### The package lists

One line per package, sorted by the bytes of the name, tab-separated:

```
name                              every version is malicious
name<TAB>1.0.0,1.0.1              those versions
name<TAB>>=2.0.0                  that version and later
name<TAB>>=1.0.0<1.2.0            from the first up to, not including, the second
name<TAB>versions<TAB>MAL-…       the advisory that lists it
```

### The indicator files

`type | value | severity | label`, one per line. `#` starts a comment. Types: `sha256`, `pkgver`, `pkgname`, `pkgscope`, `domain`, `string`, `srcstring`, `script`, `extension`.

## How SmartSort uses them

SmartSort only ever **downloads** these files, and only if the person using it turns that on. It sends nothing about their files. It accepts a new set only if the signature is valid under a key built into the app, `seq` is higher than the set it has, and every file has the size and SHA-256 the manifest gives. Otherwise it keeps the lists it has.

## Building them yourself

```
curl -LO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip   # then the same for PyPI/all.zip
python3 -I tools/build_lists.py --npm npm/all.zip --pypi pypi/all.zip \
    --indicators path/to/ioc/files --notice NOTICE.txt --out site/v1
```

Only the Python standard library is used.

## Keys

`keys/primary.pub.pem` is the public half of the key the workflow signs with. `keys/offline.pub.pem` is a second key, kept offline, that SmartSort also accepts, so the first can be replaced if it is ever exposed. Private keys are never stored here.

## Reporting a wrong entry

A package listed here by mistake should be reported to the [OpenSSF Malicious Packages project](https://github.com/ossf/malicious-packages), where the record lives; the list follows it the next night. For anything else, open an issue.

Sources and licences are in [NOTICE.txt](NOTICE.txt).
