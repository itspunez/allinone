#!/usr/bin/env python3
"""All-in-one subscription aggregator (v2).

Reads source URLs from sources.txt (+ optional EXTRA_SOURCES env var),
downloads them in parallel, extracts proxy links, removes duplicates,
optionally drops dead servers (TCP check) and writes to ./output :

  all.txt          base64 subscription with everything (can be huge)
  part_1.txt ...   base64 subscriptions, CHUNK_SIZE links each (use these in clients)
  <proto>.txt      base64 subscription per protocol (vless, vmess, trojan, ss ...)
  report.txt       summary + status of every source

Environment variables (all optional):
  CHECK_ALIVE   1 = TCP-check servers and drop dead ones   (default 0)
  ALIVE_TIMEOUT seconds per connection test                (default 4)
  ALIVE_WORKERS parallel connection tests                  (default 300)
  CHUNK_SIZE    links per part_N.txt                       (default 1000)
  MAX_LINKS     keep at most N links, 0 = unlimited        (default 0)
"""
import base64
import json
import os
import re
import shutil
import socket
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "output"
TIMEOUT = 40
WORKERS = 16
UA = "Mozilla/5.0 (compatible; sub-aggregator/2.0)"

CHECK_ALIVE = os.environ.get("CHECK_ALIVE", "0") == "1"
ALIVE_TIMEOUT = float(os.environ.get("ALIVE_TIMEOUT", "4"))
ALIVE_WORKERS = int(os.environ.get("ALIVE_WORKERS", "300"))
CHUNK = int(os.environ.get("CHUNK_SIZE", "1000"))
MAX_LINKS = int(os.environ.get("MAX_LINKS", "0"))

PROTOS = ("vmess", "vless", "trojan", "ssr", "ss",
          "hysteria2", "hysteria", "hy2", "tuic", "wireguard")
UDP_PROTOS = ("hysteria2", "hysteria", "hy2", "tuic", "wireguard", "ssr")  # not TCP-testable
LINK_RE = re.compile(r"(?<![A-Za-z0-9])(?:%s)://[^\s\"'<>,]+" % "|".join(PROTOS), re.I)


# ---------------------------------------------------------------- sources
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
    except urllib.error.HTTPError as e:
        return url, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return url, type(e).__name__


# ---------------------------------------------------------------- parsing
def pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def b64dec(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(pad(s))


def try_b64(raw: bytes):
    s = re.sub(rb"\s+", b"", raw)
    if not s or re.search(rb"[^A-Za-z0-9+/=_-]", s):
        return None
    try:
        return b64dec(s.decode())
    except Exception:  # noqa: BLE001
        return None


def extract(raw: bytes):
    text = raw.decode("utf-8", errors="ignore")
    links = LINK_RE.findall(text)
    if not links:  # whole body may be base64
        dec = try_b64(raw)
        if dec:
            links = LINK_RE.findall(dec.decode("utf-8", errors="ignore"))
    return links


def scheme(link: str) -> str:
    return link.split("://", 1)[0].lower()


def vmess_json(link: str):
    try:
        return json.loads(b64dec(link[8:].split("#", 1)[0]).decode("utf-8", "ignore"))
    except Exception:  # noqa: BLE001
        return None


def dedupe_key(link: str) -> str:
    if scheme(link) == "vmess":
        d = vmess_json(link)
        if d:
            d.pop("ps", None)  # remark does not matter
            return "vmess:" + json.dumps(d, sort_keys=True)
        return link
    return link.split("#", 1)[0].lower()


def host_port(link: str):
    """Return (host, port) for TCP-based protocols, else None."""
    try:
        sc = scheme(link)
        if sc in UDP_PROTOS:
            return None
        if sc == "vmess":
            d = vmess_json(link)
            return (str(d["add"]), int(d["port"])) if d else None
        if sc == "ss":
            rest = link[5:].split("#", 1)[0]
            if "@" not in rest:
                rest = b64dec(rest.split("?")[0]).decode("utf-8", "ignore")
            tail = rest.rsplit("@", 1)[1].split("?")[0].split("/")[0]
            host, port = tail.rsplit(":", 1)
            return host.strip("[]"), int(port)
        from urllib.parse import urlsplit
        u = urlsplit(link)
        if u.hostname and u.port:
            return u.hostname, u.port
    except Exception:  # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------- alive check
def tcp_ok(hp):
    try:
        with socket.create_connection(hp, timeout=ALIVE_TIMEOUT):
            return hp, True
    except Exception:  # noqa: BLE001
        return hp, False


def filter_alive(links):
    hp_of = [host_port(l) for l in links]
    unique = sorted({h for h in hp_of if h})
    print(f"alive check: {len(unique)} unique host:port ...", flush=True)
    alive = set()
    with ThreadPoolExecutor(ALIVE_WORKERS) as ex:
        for hp, ok in ex.map(tcp_ok, unique):
            if ok:
                alive.add(hp)
    kept = [l for l, h in zip(links, hp_of) if h is None or h in alive]
    print(f"alive check: kept {len(kept)} / {len(links)}", flush=True)
    return kept


# ---------------------------------------------------------------- output
def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def main():
    sources = load_sources()
    if not sources:
        sys.exit("no sources found")
    print(f"{len(sources)} sources", flush=True)

    seen, final, report = set(), [], []
    with ThreadPoolExecutor(WORKERS) as ex:
        for url, res in ex.map(fetch, sources):
            if isinstance(res, str):
                report.append(f"FAIL   {res:<14} {url}")
                continue
            links = extract(res)
            new = 0
            for l in links:
                l = l.strip().rstrip(".,;")
                k = dedupe_key(l)
                if k in seen:
                    continue
                seen.add(k)
                final.append(l)
                new += 1
            tag = "OK    " if links else "EMPTY "
            report.append(f"{tag} {len(links):6d} found, {new:6d} new  {url}")

    total_before = len(final)
    if CHECK_ALIVE:
        final = filter_alive(final)
    if MAX_LINKS and len(final) > MAX_LINKS:
        final = final[:MAX_LINKS]

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()

    (OUT / "all.txt").write_text(b64("\n".join(final)), encoding="utf-8")

    parts = 0
    for i in range(0, len(final), CHUNK):
        parts += 1
        (OUT / f"part_{parts}.txt").write_text(
            b64("\n".join(final[i:i + CHUNK])), encoding="utf-8")

    for p in PROTOS:
        sel = [l for l in final if scheme(l) == p]
        if sel:
            (OUT / f"{p}.txt").write_text(b64("\n".join(sel)), encoding="utf-8")

    head = [
        f"unique links before alive check : {total_before}",
        f"final links                     : {len(final)}",
        f"alive check                     : {'on' if CHECK_ALIVE else 'off'}",
        f"parts                           : {parts} (part_1.txt ... part_{parts}.txt)",
        "-" * 60,
    ]
    (OUT / "report.txt").write_text("\n".join(head + report), encoding="utf-8")
    print("\n".join(head))


if __name__ == "__main__":
    main()
