#!/usr/bin/env python3
"""All-in-one subscription aggregator (v3, with filters).

Pipeline:
  sources.txt (+ EXTRA_SOURCES env)  ->  download  ->  extract links  ->  dedupe
  -> static filters (filters.json)   ->  TCP alive check + latency
  -> sort by latency -> max_per_host -> max_total  ->  write ./output

Output (./output):
  all.txt         base64 subscription with all kept configs
  part_N.txt      base64 subscriptions of chunk_size configs each
                  (part_1 = fastest ones when sort_by_latency is on)
  <proto>.txt     base64 subscription per protocol
  report.txt      filter funnel + status of every source

All options live in filters.json.
"""
import base64
import json
import os
import re
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

ROOT = Path(__file__).parent
OUT = ROOT / "output"
FETCH_TIMEOUT = 40
FETCH_WORKERS = 16
ALIVE_TIMEOUT = 4.0
ALIVE_WORKERS = 300
UA = "Mozilla/5.0 (compatible; sub-aggregator/3.0)"

DEFAULTS = {
    "protocols": ["vless", "trojan", "vmess"],
    "require_security": True,
    "networks": [],
    "ports": [],
    "include_keywords": [],
    "exclude_keywords": [],
    "check_alive": True,
    "sort_by_latency": True,
    "max_per_host": 2,
    "max_total": 1500,
    "chunk_size": 500,
    "rename": True,
    "name_template": "Configs Freeiran {n}",
    "real_test": True,
    "real_test_max_candidates": 8000,
    "real_test_timeout": 6,
    "real_test_batch": 300,
    "real_test_workers": 3,
    "keep_untestable": False,
}

PROTOS = ("vmess", "vless", "trojan", "ssr", "ss",
          "hysteria2", "hysteria", "hy2", "tuic", "wireguard")
UDP_PROTOS = ("hysteria2", "hysteria", "hy2", "tuic", "wireguard")  # cannot TCP-test
SECURE = {"tls", "reality", "xtls", "encrypted"}
LINK_RE = re.compile(r"(?<![A-Za-z0-9])(?:%s)://[^\s\"'<>,]+" % "|".join(PROTOS), re.I)


# ---------------------------------------------------------------- config
def load_cfg():
    cfg = dict(DEFAULTS)
    f = ROOT / "filters.json"
    if f.exists():
        cfg.update(json.loads(f.read_text(encoding="utf-8")))
    cfg["protocols"] = [p.lower() for p in cfg["protocols"]]
    cfg["networks"] = [n.lower() for n in cfg["networks"]]
    cfg["ports"] = [int(p) for p in cfg["ports"]]
    return cfg


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


# ---------------------------------------------------------------- download
def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            return url, r.read()
    except urllib.error.HTTPError as e:
        return url, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return url, type(e).__name__


def b64dec(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


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


# ---------------------------------------------------------------- parsing
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
            d.pop("ps", None)  # the remark does not matter
            return "vmess:" + json.dumps(d, sort_keys=True)
        return link
    return link.split("#", 1)[0].lower()


def parse(link: str):
    """Return dict(proto, host, port, security, network, remark) or None."""
    sc = scheme(link)
    info = {"proto": sc, "host": None, "port": None,
            "security": "", "network": "tcp", "remark": ""}
    try:
        if sc == "vmess":
            d = vmess_json(link)
            if not d:
                return None
            info.update(
                host=str(d.get("add", "")).strip().lower(),
                port=int(d.get("port")),
                security="tls" if str(d.get("tls", "")).lower() == "tls" else "none",
                network=str(d.get("net", "tcp")).lower(),
                remark=str(d.get("ps", "")),
            )
            return info

        if sc == "ss":
            body = link[5:]
            info["remark"] = unquote(body.split("#", 1)[1]) if "#" in body else ""
            rest = body.split("#", 1)[0]
            if "@" not in rest:
                rest = b64dec(rest.split("?")[0]).decode("utf-8", "ignore")
            tail = rest.rsplit("@", 1)[1].split("?")[0].split("/")[0]
            host, port = tail.rsplit(":", 1)
            info.update(host=host.strip("[]").lower(), port=int(port), security="encrypted")
            return info

        if sc == "ssr":
            info["security"] = "encrypted"
            return info  # host unknown -> will be dropped unless protocols include it

        u = urlsplit(link)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        sec = q.get("security", "").lower()
        if sc == "trojan" and not sec:
            sec = "tls"                      # trojan is always TLS unless stated
        if sc in ("hysteria", "hysteria2", "hy2", "tuic"):
            sec, info["network"] = "tls", "udp"
        elif sc == "wireguard":
            sec, info["network"] = "encrypted", "udp"
        else:
            info["network"] = q.get("type", "tcp").lower()
        info.update(
            host=(u.hostname or "").lower() or None,
            port=u.port,
            security=sec or "none",
            remark=unquote(u.fragment),
        )
        return info
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- filters
def passes(info, cfg, drops):
    def drop(reason):
        drops[reason] += 1
        return False

    if info["proto"] not in cfg["protocols"]:
        return drop("protocol not allowed")
    if not info["host"] or not info["port"]:
        return drop("unparseable / no host:port")
    if cfg["require_security"] and info["security"] not in SECURE:
        return drop("no tls/reality")
    if cfg["networks"] and info["network"] not in cfg["networks"]:
        return drop("network (transport) not allowed")
    if cfg["ports"] and info["port"] not in cfg["ports"]:
        return drop("port not allowed")
    rem = info["remark"].lower()
    inc = [k.lower() for k in cfg["include_keywords"]]
    exc = [k.lower() for k in cfg["exclude_keywords"]]
    if inc and not any(k in rem for k in inc):
        return drop("include_keywords miss")
    if exc and any(k in rem for k in exc):
        return drop("exclude_keywords hit")
    return True


# ---------------------------------------------------------------- alive check
def probe(hp):
    t = time.perf_counter()
    try:
        with socket.create_connection(hp, timeout=ALIVE_TIMEOUT):
            return hp, (time.perf_counter() - t) * 1000.0
    except Exception:  # noqa: BLE001
        return hp, None


def alive_check(items):
    """items: list of dicts. Adds 'lat' (ms) and drops dead TCP servers."""
    tcp = [it for it in items if it["info"]["proto"] not in UDP_PROTOS]
    unique = sorted({(it["info"]["host"], it["info"]["port"]) for it in tcp})
    print(f"alive check: {len(unique)} unique host:port ...", flush=True)
    lat = {}
    with ThreadPoolExecutor(ALIVE_WORKERS) as ex:
        for hp, ms in ex.map(probe, unique):
            if ms is not None:
                lat[hp] = ms
    kept = []
    for it in items:
        if it["info"]["proto"] in UDP_PROTOS:
            it["lat"] = float("inf")       # untestable: keep, rank last
            kept.append(it)
        else:
            ms = lat.get((it["info"]["host"], it["info"]["port"]))
            if ms is not None:
                it["lat"] = ms
                kept.append(it)
    return kept


# ---------------------------------------------------------------- rename
def rename_link(link: str, name: str) -> str:
    """Replace the config's display name (remark) with `name`."""
    sc = scheme(link)
    if sc == "vmess":
        d = vmess_json(link)
        if not d:
            return link
        d["ps"] = name
        raw = json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode()
        return "vmess://" + base64.b64encode(raw).decode()
    if sc == "ssr":
        return link  # name is inside the base64 body, left untouched
    return link.split("#", 1)[0] + "#" + quote(name, safe="")


def rename_all(links, template):
    width = max(2, len(str(len(links))))          # 01..99, or 001.. when > 99
    out = []
    for i, l in enumerate(links, 1):
        name = template.format(n=str(i).zfill(width), proto=scheme(l).upper())
        out.append(rename_link(l, name))
    return out


# ---------------------------------------------------------------- main
def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def main():
    cfg = load_cfg()
    sources = load_sources()
    if not sources:
        sys.exit("no sources found")
    print(f"{len(sources)} sources", flush=True)

    seen, raw_links, report = set(), [], []
    with ThreadPoolExecutor(FETCH_WORKERS) as ex:
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
                raw_links.append(l)
                new += 1
            tag = "OK    " if links else "EMPTY "
            report.append(f"{tag} {len(links):6d} found, {new:6d} new  {url}")

    funnel = [("unique links downloaded", len(raw_links))]

    # 1) static filters
    drops = Counter()
    items = []
    for l in raw_links:
        info = parse(l)
        if info is None:
            drops["unparseable"] += 1
            continue
        if passes(info, cfg, drops):
            items.append({"link": l, "info": info, "lat": float("inf")})
    funnel.append(("after static filters", len(items)))

    # 2) alive check + latency
    if cfg["check_alive"]:
        items = alive_check(items)
        funnel.append(("after alive check", len(items)))

    # 3) sort by latency
    if cfg["sort_by_latency"]:
        items.sort(key=lambda it: it["lat"])

    # 4) limit per host
    if cfg["max_per_host"] > 0:
        per_host, kept = Counter(), []
        for it in items:
            h = it["info"]["host"]
            if per_host[h] < cfg["max_per_host"]:
                per_host[h] += 1
                kept.append(it)
        items = kept
        funnel.append((f"after max_per_host={cfg['max_per_host']}", len(items)))

    # 4b) real connectivity test through Xray-core (see realtest.py)
    notes = []
    if cfg["real_test"]:
        cand_cap = int(cfg["real_test_max_candidates"])
        cand = items[:cand_cap] if cand_cap > 0 else items
        tested = None
        try:
            import realtest
            tested = realtest.run(cand, cfg)
            st = realtest.LAST_STATS
            notes = [f"real test: {st['tested']} tested, {st['passed']} passed, "
                     f"{st['not_convertible']} not convertible to Xray, "
                     f"{st['bad_config']} rejected by Xray"] if st else []
        except Exception as e:  # noqa: BLE001
            print(f"real test failed ({type(e).__name__}: {e}) -> TCP-only result",
                  flush=True)
        if tested is not None:
            items = tested
            funnel.append(("after real connectivity test", len(items)))
            if cfg["sort_by_latency"]:
                items.sort(key=lambda it: it["lat"])
        else:
            items = cand
            funnel.append(("real test skipped (fallback)", len(items)))

    # 5) total cap
    if cfg["max_total"] > 0 and len(items) > cfg["max_total"]:
        items = items[:cfg["max_total"]]
        funnel.append((f"after max_total={cfg['max_total']}", len(items)))

    final = [it["link"] for it in items]
    if cfg["rename"] and cfg["name_template"]:
        final = rename_all(final, cfg["name_template"])

    # ---- write
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()

    (OUT / "all.txt").write_text(b64("\n".join(final)), encoding="utf-8")

    chunk = max(1, cfg["chunk_size"])
    parts = 0
    for i in range(0, len(final), chunk):
        parts += 1
        (OUT / f"part_{parts}.txt").write_text(
            b64("\n".join(final[i:i + chunk])), encoding="utf-8")

    for p in PROTOS:
        sel = [l for l in final if scheme(l) == p]
        if sel:
            (OUT / f"{p}.txt").write_text(b64("\n".join(sel)), encoding="utf-8")

    head = ["FUNNEL"]
    head += [f"  {name:<34}: {n}" for name, n in funnel]
    head += [f"  ({n})" for n in notes]
    head += ["", "DROPPED BY STATIC FILTERS"]
    head += [f"  {r:<34}: {n}" for r, n in drops.most_common()]
    head += ["", f"FINAL: {len(final)} configs in {parts} part(s) of up to {chunk}",
             "-" * 70]
    (OUT / "report.txt").write_text("\n".join(head + report), encoding="utf-8")
    print("\n".join(head))


if __name__ == "__main__":
    main()
