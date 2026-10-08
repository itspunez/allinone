#!/usr/bin/env python3
"""All-in-one subscription aggregator.

Reads source URLs from sources.txt (and optionally the EXTRA_SOURCES env var,
one URL per line), downloads them in parallel, decodes base64 if needed,
extracts proxy links, removes duplicates and writes:

  output/all.txt        -> base64 subscription (use this link in your client)
  output/all_plain.txt  -> same, plain text
  output/<proto>.txt    -> base64 subscription per protocol (vless, vmess, ...)
  output/report.txt     -> how many links each source gave

Only the Python standard library is used.
"""
import base64
import os
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "output"
TIMEOUT = 40
WORKERS = 16
UA = "Mozilla/5.0 (compatible; sub-aggregator/1.0)"

PROTOS = ("vmess", "vless", "trojan", "ss", "ssr",
          "hysteria2", "hysteria", "hy2", "tuic", "wireguard")
LINK_RE = re.compile(r"(?:%s)://[^\s\"'<>,]+" % "|".join(PROTOS), re.I)


def load_sources():
    urls = []
    f = ROOT / "sources.txt"
    if f.exists():
        urls += f.read_text(encoding="utf-8").splitlines()
    urls += os.environ.get("EXTRA_SOURCES", "").splitlines()
    clean, seen = [], set()
    for u in urls:
        u = u.strip()
        if not u or u.startswith("#") or not u.startswith("http"):
            continue
        if u not in seen:
            seen.add(u)
            clean.append(u)
    return clean


def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return url, r.read()
    except Exception as e:  # noqa: BLE001
        return url, e


def try_b64(raw: bytes):
    s = re.sub(rb"\s+", b"", raw)
    if not s or re.search(rb"[^A-Za-z0-9+/=_-]", s):
        return None
    s += b"=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, altchars=b"-_" if b"-" in s or b"_" in s else None)
    except Exception:  # noqa: BLE001
        return None


def extract(raw: bytes):
    text = raw.decode("utf-8", errors="ignore")
    links = LINK_RE.findall(text)
    if not links:  # maybe the whole body is base64
        dec = try_b64(raw)
        if dec:
            links = LINK_RE.findall(dec.decode("utf-8", errors="ignore"))
    return links


def key_of(link: str) -> str:
    # same server/config with a different remark (#name) counts as duplicate
    return link.split("#", 1)[0].strip().lower() if link.lower().startswith("vmess://") is False \
        else link.strip()


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def main():
    sources = load_sources()
    if not sources:
        sys.exit("no sources found")
    print(f"{len(sources)} sources")

    seen, final, report = set(), [], []
    with ThreadPoolExecutor(WORKERS) as ex:
        for url, res in ex.map(fetch, sources):
            if isinstance(res, Exception):
                report.append(f"FAIL  {url}  ({type(res).__name__})")
                continue
            links = extract(res)
            new = 0
            for l in links:
                l = l.strip().rstrip(".,;")
                k = key_of(l)
                if k in seen:
                    continue
                seen.add(k)
                final.append(l)
                new += 1
            tag = "OK  " if links else "EMPTY"
            report.append(f"{tag}  {len(links):6d} found, {new:6d} new  {url}")

    OUT.mkdir(exist_ok=True)
    (OUT / "all_plain.txt").write_text("\n".join(final), encoding="utf-8")
    (OUT / "all.txt").write_text(b64("\n".join(final)), encoding="utf-8")

    for p in PROTOS:
        part = [l for l in final if l.lower().startswith(p + "://")]
        f = OUT / f"{p}.txt"
        if part:
            f.write_text(b64("\n".join(part)), encoding="utf-8")
        elif f.exists():
            f.unlink()

    (OUT / "report.txt").write_text("\n".join(report), encoding="utf-8")
    print(f"total unique links: {len(final)}")


if __name__ == "__main__":
    main()
