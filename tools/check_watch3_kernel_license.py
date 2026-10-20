#!/usr/bin/env python3
"""Read-only early checksum check for the pinned Samsung GPLv2 kernel COPYING file."""
import hashlib
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
RECIPE = ROOT / "meta-noblesse/recipes-kernel/linux/linux-noblesse_4.9.59.bb"
PIN = "ec258e12887d37362b59e3291c1d3e5363c24bff"
COPYING_MD5 = "d7810fab7487fb0aad327b76f1be7cd7"

def main():
    recipe = RECIPE.read_text(encoding="utf-8")
    revision = re.search(r'(?m)^SRCREV = "([a-f0-9]{40})"$', recipe)
    license_md5 = re.search(r'(?m)^LIC_FILES_CHKSUM = "file://COPYING;md5=([a-f0-9]{32})"$', recipe)
    if revision is None or license_md5 is None:
        print("FAIL: missing exact SRCREV or license checksum in recipe", file=sys.stderr)
        return 1
    if revision.group(1) != PIN or license_md5.group(1) != COPYING_MD5:
        print("FAIL: kernel revision or license checksum differs from audited source", file=sys.stderr)
        return 1
    url = "https://raw.githubusercontent.com/UsrBinLuna/kernel_samsung_galileo/" + PIN + "/COPYING"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Galaxy3-licensing-preflight"})
        with urllib.request.urlopen(req, timeout=30) as response:
            contents = response.read()
    except Exception as e:
        print("FAIL: cannot retrieve pinned COPYING: " + str(e), file=sys.stderr)
        return 1
    actual = hashlib.md5(contents).hexdigest()
    if actual != COPYING_MD5:
        print("FAIL: upstream COPYING md5=" + actual + " expected=" + COPYING_MD5, file=sys.stderr)
        return 1
    if b"GNU GENERAL PUBLIC LICENSE" not in contents or b"Version 2, June 1991" not in contents:
        print("FAIL: expected GPLv2 license text not present", file=sys.stderr)
        return 1
    print("PASS: audited kernel license GPLv2 and md5=" + actual)
    print("License validated before installing OpenEmbedded build dependencies.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
