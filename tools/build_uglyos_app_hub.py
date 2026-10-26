#!/usr/bin/env python3
"""Validate and render a SAFE, read-only UgLy|OS App Hub compatibility catalog.

This is an off-device research UI, NOT an opkg installer, Android runtime,
Google Play integration, or firmware flasher. No hidden remote APIs.
"""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

TOP_KEYS = {"schema_version", "edition", "target", "policy", "entries"}
POLICY_KEYS = {"install_enabled", "watch_boot_verified", "stock_recovery_verified",
               "apk_runtime_available", "third_party_distribution_authorized"}
ENTRY_KEYS = {"id", "name", "category", "kind", "platform", "state", "source",
              "summary", "installable", "requires_on_watch_boot"}
KINDS = {"native-watch", "phone-bridge", "unsupported"}
PLATFORMS = {"asteroidos-opkg", "android-companion", "android-apk", "wear-os"}
STATES = {"source-built", "upstream-source", "existing-upstream-option",
          "research-backed", "planned", "not-compatible"}
HOSTS = {"github.com", "wiki.asteroidos.org", "developer.samsung.com",
         "developers.google.com", "support.google.com"}
MAX_BYTES = 48_000


class CatalogError(ValueError):
    pass


def pairs_unique(pairs):
    d = {}
    for key, value in pairs:
        if key in d:
            raise CatalogError("Duplicate JSON property")
        d[key] = value
    return d


def load(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or not 64 <= path.stat().st_size <= MAX_BYTES:
        raise CatalogError("Unsafe, empty, or oversized local catalog")
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs_unique)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise CatalogError("Invalid UTF-8 JSON catalog") from exc
    validate(data)
    return data


def validate(data: dict) -> None:
    if not isinstance(data, dict) or set(data) != TOP_KEYS:
        raise CatalogError("Unexpected catalog top-level keys")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise CatalogError("Unsupported catalog version")
    if data["edition"] != "UgLy|OS" or data["target"] != "SM-R840X / NOBLESSE-LARGE-BT R08":
        raise CatalogError("Wrong watch edition or machine")
    policy = data["policy"]
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise CatalogError("Incomplete store safety policy")
    if any(value is not False for value in policy.values()):
        raise CatalogError("UNSAFE: no install, boot, distribution or APK capability proven")
    entries = data["entries"]
    if not isinstance(entries, list) or not 2 <= len(entries) <= 32:
        raise CatalogError("Catalog entry count outside reviewed bounds")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise CatalogError("Unexpected app entry fields")
        eid = entry["id"]
        if not isinstance(eid, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+){0,7}", eid):
            raise CatalogError("Unsafe app identifier")
        if eid in seen:
            raise CatalogError("Duplicate app identifier")
        seen.add(eid)
        for key in ("name", "category", "summary"):
            value = entry[key]
            if not isinstance(value, str) or not 2 <= len(value) <= (260 if key == "summary" else 70):
                raise CatalogError(f"Invalid app {key}")
            if any(ord(c) < 32 for c in value):
                raise CatalogError("Control characters in catalog")
        if entry["kind"] not in KINDS or entry["platform"] not in PLATFORMS or entry["state"] not in STATES:
            raise CatalogError("Unsupported app kind / runtime / status")
        if entry["installable"] is not False or entry["requires_on_watch_boot"] is not True:
            raise CatalogError("Install forbidden without verified watch boot and rescue")
        if entry["kind"] == "native-watch" and entry["platform"] != "asteroidos-opkg":
            raise CatalogError("Native apps must use real AsteroidOS packages")
        if entry["kind"] == "phone-bridge" and entry["platform"] != "android-companion":
            raise CatalogError("Phone bridge incorrectly claims native watch compatibility")
        if entry["kind"] == "unsupported" and (entry["state"] != "not-compatible" or entry["platform"] not in ("android-apk", "wear-os")):
            raise CatalogError("Unsupported apps cannot advertise compatible runtime")
        if entry["kind"] != "unsupported" and entry["state"] == "not-compatible":
            raise CatalogError("Contradictory compatibility status")
        uri = urlsplit(entry["source"])
        if uri.scheme != "https" or uri.hostname not in HOSTS or uri.username or uri.password or uri.port or not uri.path.startswith("/"):
            raise CatalogError("Untrusted source URL")
        if uri.fragment or uri.query:
            raise CatalogError("No tracking parameters or fragments permitted")
    if not any(x["kind"] == "phone-bridge" for x in entries) or not any(x["kind"] == "native-watch" for x in entries) or not any(x["kind"] == "unsupported" for x in entries):
        raise CatalogError("Catalog hides relevant compatibility boundaries")


def render(data: dict) -> str:
    validate(data)
    tiles = []
    kind_label = {"native-watch": "Native watch", "phone-bridge": "Android companion",
                  "unsupported": "Not compatible"}
    for e in data["entries"]:
        title = html.escape(e["name"], quote=True)
        summary = html.escape(e["summary"], quote=True)
        badge = html.escape(kind_label[e["kind"]], quote=True)
        state = html.escape(e["state"].replace("-", " ").title(), quote=True)
        category = html.escape(e["category"], quote=True)
        url = html.escape(e["source"], quote=True)
        group = html.escape(e["kind"], quote=True)
        tiles.append(
            f'<article class="app" data-kind="{group}" data-text="{html.escape((e["name"]+" "+e["category"]+" "+e["summary"]).lower(), quote=True)}">'
            f'<div class="app-head"><span class="type">{badge}</span><span class="stage">{state}</span></div>'
            f'<h2>{title}</h2><p class="category">{category}</p><p>{summary}</p>'
            f'<a href="{url}" target="_blank" rel="noopener noreferrer">Inspect source / documentation</a>'
            f'<div class="locked">Installation unavailable: device boot and recovery not verified</div></article>'
        )
    cards = "\n".join(tiles)
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'">
<title>UgLy|OS App Hub · compatibility preview</title>
<style>
:root{font-family:system-ui,Arial,sans-serif;color:#eafff0;background:#07130e}
*{box-sizing:border-box}body{margin:0;min-height:100vh}
main{max-width:1030px;margin:auto;padding:26px 18px 55px}
header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;align-items:center}
h1{font-size:clamp(1.6rem,5vw,2.7rem);margin:.2em 0}
.sub{color:#91bda2;max-width:700px;line-height:1.5}
.note{border:1px solid #4f715e;border-radius:15px;padding:12px 15px;background:#10251a;color:#d5fce4}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:22px 0}
input{flex:1;min-width:180px;font:inherit;background:#101c15;color:inherit;border:1px solid #53745c;border-radius:11px;padding:12px}
button{font:inherit;color:#cfe8d7;background:#13241a;border:1px solid #385b45;border-radius:999px;padding:9px 13px;cursor:pointer}
button[aria-pressed=true]{background:#75c993;color:#04140a;border-color:#75c993}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}
.app{padding:18px;border-radius:18px;border:1px solid #31543e;background:#102117;display:flex;flex-direction:column;min-height:240px}
.app-head{display:flex;justify-content:space-between;align-items:center;gap:5px}
.type{color:#a5f8c4;font-size:.83rem}.stage{font-size:.72rem;color:#b4cbbf}
.app h2{font-size:1.12rem;margin:15px 0 4px}.app p{line-height:1.42;margin:5px 0;color:#c1dac9}
.app .category{font-size:.75rem;color:#7fd4a1;text-transform:uppercase;letter-spacing:.07em}
.app a{color:#a2dffc;margin-top:auto;padding-top:18px}
.locked{font-size:.75rem;margin-top:12px;color:#c9ad89}
footer{font-size:.83rem;color:#88aa93;margin-top:30px}
[hidden]{display:none!important}
@media(max-width:390px){main{padding:16px 12px}.toolbar{gap:8px}.grid{grid-template-columns:1fr}.app{min-height:0}}
</style></head><body><main>
<header><div><p class="category">OFF-DEVICE · RESEARCH PREVIEW</p><h1>UgLy|OS · App Hub</h1></div><span class="note">NO-GO · Installs locked</span></header>
<p class="sub">Discover native AsteroidOS apps, future Android/Samsung/Google companion features, and honest compatibility limits. This is not a Google Play or Galaxy Store client. No firmware or watch operations occur.</p>
<div class="toolbar" role="group" aria-label="Catalog filtering">
<input id="search" type="search" placeholder="Search apps and integrations…" aria-label="Search catalog">
<button type="button" data-filter="all" aria-pressed="true">All</button>
<button type="button" data-filter="native-watch" aria-pressed="false">Watch</button>
<button type="button" data-filter="phone-bridge" aria-pressed="false">Phone</button>
<button type="button" data-filter="unsupported" aria-pressed="false">Limits</button>
</div>
<div id="cards" class="grid">""" + cards + """</div>
<p id="empty" hidden>No catalog entries match.</p>
<footer>Source links open official upstream or project documentation. Not a software distribution service. No accounts, telemetry, APK downloads or install permissions.</footer>
</main>
<script>
"use strict";
const cards = Array.from(document.querySelectorAll(".app"));
const input = document.querySelector("#search");
const buttons = Array.from(document.querySelectorAll("button[data-filter]"));
let selected = "all";
function filter(){
  const term=input.value.toLowerCase().trim();
  let visible=0;
  for(const card of cards){
    const show=(selected==="all"||card.dataset.kind===selected)&&card.dataset.text.includes(term);
    card.hidden=!show;
    if(show)visible++;
  }
  document.querySelector("#empty").hidden=visible!==0;
}
for(const b of buttons)b.addEventListener("click",()=>{
  selected=b.dataset.filter;
  for(const item of buttons)item.setAttribute("aria-pressed",String(item===b));
  filter();
});
input.addEventListener("input",filter);
</script></body></html>
"""


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--catalog", type=Path, default=Path("app-hub/catalog.json"))
    cli.add_argument("--output", type=Path, default=Path("app-hub-preview/index.html"))
    args = cli.parse_args()
    try:
        catalog = load(args.catalog)
        page = render(catalog)
        if args.output.is_symlink():
            raise CatalogError("Refuse to overwrite a symlink")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(page, encoding="utf-8")
    except (CatalogError, OSError) as error:
        print(f"FAIL[app-hub]: {error}", file=sys.stderr)
        return 1
    print(f"PASS[app-hub]: {len(catalog['entries'])} verified compatibility entries, static read-only HTML")
    print("NOT A WATCH INSTALLER. NO APK RUNTIME. NO PHONE BRIDGE IMPLEMENTED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
