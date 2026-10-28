#!/usr/bin/env python3
"""Vuln Radar collector - pulls public vulnerability sources, emits only new items.

Runs inside the Managed Agents sandbox (stdlib only) and locally for testing.

    python3 collector.py --state /mnt/memory/vuln-radar-state/collector_state.json \
                         --out /workspace/new_items.json [--lookback-hours 8]

State keeps a per-source watermark plus a short-lived seen-hash set, sized to stay
well under the 100 KB memory-store file limit.
"""
import argparse
import hashlib
import html
import json
import math
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

UA = "vuln-radar/0.1 (defensive security feed reader)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# Chatter sources (news, social) are noisy; keep only items that look vuln-related.
VULN_RE = re.compile(
    r"cve-|vulnerab|exploit|0-?day|zero[- ]day|\brce\b|remote code|auth(entication)? bypass|"
    r"privilege escalation|\blpe\b|injection|deserializ|backdoor|poc\b|proof[- ]of[- ]concept|"
    r"in the wild|actively exploited|patch|advisory|ransomware|compromis|breach|malicious package|"
    r"supply[- ]chain|webshell|ssrf|xss|path traversal|overflow|use-after-free|kev\b",
    re.I,
)
SEEN_TTL_DAYS = 3
OVERLAP = timedelta(hours=2)
TEXT_MAX = 420

# kind: how to parse. filter: apply VULN_RE (chatter sources). tier: rough source weight.
SOURCES = [
    # Authoritative / structured
    {"name": "CISA KEV", "kind": "kev", "tier": "authority",
     "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    {"name": "NVD", "kind": "nvd", "tier": "authority",
     "url": "https://services.nvd.nist.gov/rest/json/cves/2.0"},
    {"name": "GitHub Advisories", "kind": "ghsa", "tier": "authority",
     "url": "https://api.github.com/advisories?per_page=100&sort=published&direction=desc"},
    {"name": "MSRC", "kind": "rss", "tier": "vendor",
     "url": "https://api.msrc.microsoft.com/update-guide/rss"},
    # Pre-disclosure / researcher channels - where things show up before vendors
    {"name": "ZDI Upcoming", "kind": "rss", "tier": "pre-disclosure",
     "url": "https://www.zerodayinitiative.com/rss/upcoming/"},
    {"name": "ZDI Published", "kind": "rss", "tier": "research",
     "url": "https://www.zerodayinitiative.com/rss/published/"},
    {"name": "oss-security", "kind": "rss", "tier": "pre-disclosure",
     "url": "https://seclists.org/rss/oss-sec.rss"},
    {"name": "Full Disclosure", "kind": "rss", "tier": "pre-disclosure",
     "url": "https://seclists.org/rss/fulldisclosure.rss"},
    {"name": "Exploit-DB", "kind": "rss", "tier": "exploit",
     "url": "https://www.exploit-db.com/rss.xml"},
    {"name": "Trickest CVE PoCs", "kind": "rss", "tier": "exploit",
     "url": "https://github.com/trickest/cve/commits/main.atom"},
    {"name": "watchTowr Labs", "kind": "rss", "tier": "research",
     "url": "https://labs.watchtowr.com/rss/"},
    {"name": "Horizon3", "kind": "rss", "tier": "research", "filter": True,
     "url": "https://www.horizon3.ai/feed/"},
    {"name": "Rapid7", "kind": "rss", "tier": "research", "filter": True,
     "url": "https://www.rapid7.com/blog/rss/"},
    {"name": "SANS ISC", "kind": "rss", "tier": "research",
     "url": "https://isc.sans.edu/rssfeed_full.xml"},
    # Vendor PSIRTs
    {"name": "Fortinet PSIRT", "kind": "rss", "tier": "vendor",
     "url": "https://www.fortiguard.com/rss/ir.xml"},
    {"name": "Palo Alto PSIRT", "kind": "rss", "tier": "vendor",
     "url": "https://security.paloaltonetworks.com/rss.xml"},
    {"name": "Cisco PSIRT", "kind": "rss", "tier": "vendor",
     "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"},
    # Community chatter
    {"name": "r/netsec", "kind": "rss", "tier": "chatter", "filter": True,
     "url": "https://www.reddit.com/r/netsec/new/.rss"},
    {"name": "r/blueteamsec", "kind": "rss", "tier": "chatter", "filter": True,
     "url": "https://www.reddit.com/r/blueteamsec/new/.rss"},
    {"name": "r/cybersecurity", "kind": "rss", "tier": "chatter", "filter": True,
     "url": "https://www.reddit.com/r/cybersecurity/new/.rss"},
    {"name": "r/sysadmin", "kind": "rss", "tier": "chatter", "filter": True,
     "url": "https://www.reddit.com/r/sysadmin/new/.rss"},
    {"name": "infosec.exchange #cve", "kind": "rss", "tier": "chatter",
     "url": "https://infosec.exchange/tags/cve.rss"},
    {"name": "Hacker News", "kind": "hn", "tier": "chatter",
     "url": "https://hn.algolia.com/api/v1/search_by_date"},
    # News
    {"name": "BleepingComputer", "kind": "rss", "tier": "news", "filter": True,
     "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "kind": "rss", "tier": "news", "filter": True,
     "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "The Record", "kind": "rss", "tier": "news", "filter": True,
     "url": "https://therecord.media/feed"},
    # Threat infrastructure (abuse.ch): summarized per run. Only CVE-tagged IOCs become
    # items - a CVE seen in live malware infrastructure is evidence of exploitation.
    # IOC values (malware URLs, IPs, hashes) are never copied into the output.
    # URLhaus and ThreatFox retired their open CSV exports; their APIs take a free abuse.ch Auth-Key.
    {"name": "URLhaus", "kind": "urlhaus", "tier": "threat-infra", "key_env": "ABUSECH_AUTH_KEY", "timeout": 90,
     "home": "https://urlhaus.abuse.ch/", "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/"},
    {"name": "ThreatFox", "kind": "threatfox", "tier": "threat-infra", "key_env": "ABUSECH_AUTH_KEY", "timeout": 90,
     "home": "https://threatfox.abuse.ch/", "url": "https://threatfox-api.abuse.ch/api/v1/"},
    {"name": "Feodo Tracker", "kind": "feodo", "tier": "threat-infra",
     "home": "https://feodotracker.abuse.ch/",
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"},
    # Keyed sources: skipped until their key is set. In the cloud sandbox the env var holds
    # a vault placeholder that Anthropic's egress proxy swaps for the real key.
    {"name": "ransomware.live", "kind": "ransomlive", "tier": "threat-infra", "key_env": "RANSOMWARE_LIVE_API_KEY",
     "home": "https://www.ransomware.live/", "url": "https://api-pro.ransomware.live/victims/recent"},
    {"name": "AlienVault OTX", "kind": "otx", "tier": "threat-infra", "key_env": "OTX_API_KEY", "timeout": 60,
     "home": "https://otx.alienvault.com/", "url": "https://otx.alienvault.com/api/v1/pulses/subscribed"},
]
# File-format and architecture tags say nothing about who is behind an IOC.
NOISE_TAGS = {"none", "32-bit", "64-bit", "elf", "exe", "dll", "sh", "bash", "script", "zip", "rar",
              "mips", "mipsel", "arm", "arm7", "aarch64", "x86", "x86-64", "powerpc", "sparc", "m68k",
              "sh4", "ascii", "c2", "payload", "botnet", "honeypot", "cowrie", "ua-wget"}
# Some tags are the IOC itself (an IP written 45-61-161-85); never echo those.
IP_TAG_RE = re.compile(r"\d{1,3}(?:[.-]\d{1,3}){3}")


CTRL_RE = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")  # illegal in XML 1.0; some feeds ship them
# Reddit answers 429 to parallel feed pulls, so its feeds go one at a time.
_reddit_lock = threading.Lock()


def fetch(url, timeout=30, headers=None, data=None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Accept": "*/*", **(headers or {})})
    if "reddit.com" in url:
        with _reddit_lock:
            time.sleep(2)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def clean(text):
    text = html.unescape(re.sub(r"<[^>]+>", " ", text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:TEXT_MAX]


def parse_dt(value):
    if not value:
        return None
    value = value.strip()
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:  # abuse.ch APIs stamp "2026-10-28 12:00:00 UTC"
            dt = datetime.fromisoformat(value.replace("Z", "+00:00").removesuffix(" UTC"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def item(src, title, link, published, text, extra=None):
    blob = f"{title} {text}"
    it = {
        "source": src["name"],
        "tier": src["tier"],
        "title": clean(title)[:200],
        "url": link,
        "published": published.isoformat() if published else None,
        "cves": sorted({c.upper() for c in CVE_RE.findall(blob)}),
        "text": clean(text),
    }
    if extra:
        it.update(extra)
    return it


def local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_rss(src, since):
    root = ET.fromstring(CTRL_RE.sub(b"", fetch(src["url"])))
    out = []
    for node in root.iter():
        if local(node.tag) not in ("item", "entry"):
            continue
        fields = {}
        link = None
        for ch in node:
            name = local(ch.tag)
            if name == "link":
                link = ch.get("href") or (ch.text or "").strip() or link
            elif name not in fields:
                fields[name] = ch.text or ""
        published = parse_dt(fields.get("pubDate") or fields.get("published")
                             or fields.get("updated") or fields.get("date"))
        if published and published < since:
            continue
        title = fields.get("title", "")
        text = fields.get("description") or fields.get("summary") or fields.get("content", "")
        out.append(item(src, title, link, published, text))
    return out


def parse_kev(src, since):
    data = json.loads(fetch(src["url"]))
    out = []
    for v in data.get("vulnerabilities", []):
        added = parse_dt(v.get("dateAdded", "") + "T00:00:00+00:00")
        if added and added < since - timedelta(days=1):  # KEV dates are day-granular
            continue
        title = f"{v['cveID']} {v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}"
        out.append(item(src, title, f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", added,
                        v.get("shortDescription", ""),
                        {"kev": True, "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}))
    return out


def parse_nvd(src, since):
    now = datetime.now(timezone.utc)
    q = urllib.parse.urlencode({
        "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 2000,
    })
    data = json.loads(fetch(f"{src['url']}?{q}", timeout=60))
    out = []
    for wrap in data.get("vulnerabilities", []):
        c = wrap["cve"]
        if c.get("vulnStatus") == "Rejected":
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            metrics = c.get("metrics", {}).get(key)
            if metrics:
                score = metrics[0]["cvssData"].get("baseScore")
                break
        out.append(item(src, c["id"], f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                        parse_dt(c.get("published")), desc, {"cvss": score}))
    return out


def parse_ghsa(src, since):
    # Anonymous calls share an hourly per-IP limit that cloud IPs exhaust; a token lifts it.
    token = os.environ.get("GITHUB_TOKEN")
    data = json.loads(fetch(src["url"], headers={"Authorization": f"Bearer {token}"} if token else None))
    out = []
    for a in data:
        published = parse_dt(a.get("published_at"))
        if published and published < since:
            continue
        pkgs = sorted({f"{v['package']['ecosystem']}:{v['package']['name']}"
                       for v in a.get("vulnerabilities") or [] if v.get("package")})
        title = f"{a.get('ghsa_id')} {a.get('summary', '')}"
        text = f"[{', '.join(pkgs[:5])}] {a.get('description', '')}"
        extra = {"cvss": (a.get("cvss") or {}).get("score"), "severity": a.get("severity"),
                 "malware": a.get("type") == "malware"}
        it = item(src, title, a.get("html_url"), published, text, extra)
        if a.get("cve_id"):
            it["cves"] = sorted(set(it["cves"]) | {a["cve_id"]})
        out.append(it)
    return out


def parse_hn(src, since):
    out, seen = [], set()
    for term in ("vulnerability", "exploit", "zero-day", "CVE"):
        q = urllib.parse.urlencode({"tags": "story", "query": term, "hitsPerPage": 50,
                                    "numericFilters": f"created_at_i>{int(since.timestamp())}"})
        for h in json.loads(fetch(f"{src['url']}?{q}")).get("hits", []):
            if h["objectID"] in seen or (h.get("points") or 0) < 5:
                continue
            seen.add(h["objectID"])
            link = h.get("url") or f"https://news.ycombinator.com/item?id={h['objectID']}"
            out.append(item(src, h.get("title", ""), link, parse_dt(h.get("created_at")), "",
                            {"hn_points": h.get("points"), "hn_comments": h.get("num_comments"),
                             "hn_thread": f"https://news.ycombinator.com/item?id={h['objectID']}"}))
    return out


def abusech_rows(src, since, rows_key, time_col, query=None):
    """abuse.ch APIs: rows flattened to strings (tag lists comma-joined), kept from `since` on."""
    headers, body = {"Auth-Key": os.environ[src["key_env"]]}, None
    if query is not None:  # ThreatFox takes a JSON POST; URLhaus a plain GET
        headers["Content-Type"] = "application/json"
        body = json.dumps(query).encode()
    data = json.loads(fetch(src["url"], timeout=src.get("timeout", 30), headers=headers, data=body))
    status = data.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise ValueError(f"query_status: {status}")
    rows = [{k: ",".join(map(str, v)) if isinstance(v, list) else "" if v is None else str(v)
             for k, v in r.items() if not isinstance(v, dict)} for r in data.get(rows_key) or []]
    return [r for r in rows if (parse_dt(r.get(time_col)) or since) >= since]


def families(tags):
    return [t for t in (x.strip() for x in tags)
            if t and t.lower() not in NOISE_TAGS and not CVE_RE.fullmatch(t) and not IP_TAG_RE.fullmatch(t)]


def threat_summary(src, label, heading, rows, family_of):
    if not rows:
        return []
    fam = Counter(f for r in rows for f in family_of(r))
    top = fam.most_common(8)
    text = f"{heading}: " + ", ".join(f"{k} {v}" for k, v in top) if top else "No family tags."
    return [item(src, f"{src['name']}: {len(rows)} {label}", src["home"], datetime.now(timezone.utc),
                 text, {"summary": True, "count": len(rows), "top": top})]


def threat_cves(src, rows, time_col, family_of, link_of):
    by_cve = {}
    for r in rows:
        for cve in {c.upper() for c in CVE_RE.findall(" ".join(v or "" for v in r.values()))}:
            by_cve.setdefault(cve, []).append(r)
    out = []
    for cve, rs in sorted(by_cve.items()):
        fam = Counter(f for r in rs for f in family_of(r))
        stamps = [d for d in (parse_dt(r.get(time_col)) for r in rs) if d]
        latest = max(stamps) if stamps else None
        text =f"{len(rs)} new IOC(s) tagged {cve}. Families/tags: " + (", ".join(k for k, _ in fam.most_common(6)) or "none")
        it = item(src, f"{src['name']}: {cve} in live malware infrastructure ({len(rs)} IOCs)",
                  link_of(cve, rs), latest, text, {"exploited_signal": True, "ioc_count": len(rs)})
        it["cves"] = [cve]
        out.append(it)
    return out


def parse_urlhaus(src, since):
    rows = abusech_rows(src, since, "urls", "date_added")
    fam = lambda r: families((r.get("tags") or "").split(","))
    out = threat_summary(src, "new malware URLs", "Top tags", rows, fam)
    if len(rows) >= 1000:  # the API returns at most the latest 1000 URLs
        out[0]["text"] = clean(out[0]["text"] + " (capped: the API returns only the latest 1000)")
    return out + threat_cves(
        src, rows, "date_added", fam, lambda cve, rs: rs[0].get("urlhaus_reference") or src["home"])


def parse_threatfox(src, since):
    # get_iocs looks back whole days (1-7); 2 covers the longest gap between scheduled runs.
    days = max(1, min(2, math.ceil((datetime.now(timezone.utc) - since).total_seconds() / 86400)))
    rows = abusech_rows(src, since, "data", "first_seen", {"query": "get_iocs", "days": days})
    fam = lambda r: families([r.get("malware_printable") or ""] + (r.get("tags") or "").split(","))
    return threat_summary(src, "new IOCs", "Top malware", rows,
                          lambda r: families([r.get("malware_printable") or ""])) + threat_cves(
        src, rows, "first_seen", fam, lambda cve, rs: f"https://threatfox.abuse.ch/browse/tag/{cve}/")


def parse_feodo(src, since):
    rows = [r for r in json.loads(fetch(src["url"])) if r.get("status") == "online"]
    return threat_summary(src, "active botnet C2 servers", "Top malware", rows,
                          lambda r: [r.get("malware") or "unknown"])


def parse_ransomlive(src, since):
    """Leak-site victims mirrored off the groups' Tor sites; summarized, victims not itemized."""
    data = json.loads(fetch(src["url"], headers={"X-API-KEY": os.environ[src["key_env"]]}))
    if isinstance(data, dict):  # the spec documents the fields, not the envelope
        data = next((v for v in data.values() if isinstance(v, list)), [])
    rows = [r for r in data if (parse_dt(r.get("discovered")) or since) >= since]
    out = threat_summary(src, "new leak-site victims", "Top groups", rows, lambda r: [r.get("group") or "unknown"])
    if out:
        sectors = Counter(r.get("activity") or "unknown" for r in rows).most_common(5)
        countries = Counter(r.get("country") or "??" for r in rows).most_common(5)
        out[0]["text"] = clean(out[0]["text"] + " | Sectors: " + ", ".join(f"{k} {v}" for k, v in sectors)
                               + " | Countries: " + ", ".join(f"{k} {v}" for k, v in countries))
    return out


def parse_otx(src, since):
    q = urllib.parse.urlencode({"limit": 50, "modified_since": since.isoformat()})
    url, out, pages = f"{src['url']}?{q}", [], 0
    while url and pages < 5:
        data = json.loads(fetch(url, timeout=src.get("timeout", 30),
                                headers={"X-OTX-API-KEY": os.environ[src["key_env"]]}))
        pages += 1
        for p in data.get("results", []):
            fams = [m if isinstance(m, str) else (m.get("display_name") or m.get("name") or "")
                    for m in p.get("malware_families") or []]
            text = f"{p.get('adversary') or ''} [{', '.join(f for f in fams if f)}] {p.get('description') or ''}"
            refs = [r for r in p.get("references") or [] if str(r).startswith("http")]
            it = item(src, p.get("name", ""), refs[0] if refs else src["home"], parse_dt(p.get("modified")),
                      text, {"otx_pulse_id": p.get("id")})
            pulse_cves = {i["indicator"].upper() for i in p.get("indicators") or [] if i.get("type") == "CVE"}
            it["cves"] = sorted(set(it["cves"]) | pulse_cves)
            out.append(it)
        url = data.get("next")
    return out


SHARDS = "0123456789abcdef"


def shard_path(base, c):
    return base.with_name(f"{base.stem}_seen_{c}.json")


def load_state(path):
    """Watermarks in the base file, seen hashes in 16 shards: reads of files over 20 KiB
    through the memory-store mount come back corrupted, so no single file may grow that big."""
    base = Path(path)
    try:
        state = json.loads(base.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        state = {}
    state.setdefault("watermarks", {})
    seen = state.pop("seen", {})  # the pre-shard layout kept everything in one file
    for c in SHARDS:
        try:
            seen.update(json.loads(shard_path(base, c).read_text()))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    state["seen"] = seen
    return state


def save_state(path, state):
    base = Path(path)
    seen = state.pop("seen")
    sizes = []
    for c in SHARDS:
        text = json.dumps({k: d for k, d in seen.items() if k[0] == c}, separators=(",", ":"))
        shard_path(base, c).write_text(text)
        sizes.append(len(text))
    text = json.dumps(state, separators=(",", ":"))
    base.write_text(text)
    state["seen"] = seen
    return len(text), max(sizes)


PARSERS = {"rss": parse_rss, "kev": parse_kev, "nvd": parse_nvd, "ghsa": parse_ghsa, "hn": parse_hn,
           "urlhaus": parse_urlhaus, "threatfox": parse_threatfox, "feodo": parse_feodo,
           "ransomlive": parse_ransomlive, "otx": parse_otx}


def run_source(src, state, default_since):
    if src.get("key_env") and not os.environ.get(src["key_env"]):
        return src, [], "skipped: no API key", 0.0
    mark = parse_dt(state["watermarks"].get(src["name"]))
    overlap = timedelta(0) if src["tier"] == "threat-infra" else OVERLAP  # abuse.ch stamps are real-time
    since = (mark - overlap) if mark else default_since
    started = time.time()
    try:
        items = PARSERS[src["kind"]](src, since)
        if src.get("filter"):
            items = [i for i in items if VULN_RE.search(f"{i['title']} {i['text']}")]
        return src, items, None, time.time() - started
    except Exception as e:  # one broken feed must never sink the run
        return src, [], f"{type(e).__name__}: {e}"[:200], time.time() - started


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--lookback-hours", type=float, default=8,
                    help="window for sources with no watermark yet")
    args = ap.parse_args()

    state = load_state(args.state)

    now = datetime.now(timezone.utc)
    today = int(now.timestamp() // 86400)
    default_since = now - timedelta(hours=args.lookback_hours)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda s: run_source(s, state, default_since), SOURCES))

    new_items, health = [], []
    for src, items, err, secs in results:
        fresh = 0
        for it in items:
            key = hashlib.sha1(f"{src['name']}|{it['url']}|{it['title']}".encode()).hexdigest()[:12]
            if key in state["seen"]:
                continue
            state["seen"][key] = today
            it["id"] = key
            new_items.append(it)
            fresh += 1
        if err is None:
            state["watermarks"][src["name"]] = now.isoformat()
        skipped = (err or "").startswith("skipped:")
        health.append({"name": src["name"], "tier": src["tier"], "ok": err is None, "skipped": skipped,
                       "fetched": len(items), "new": fresh, "error": err, "seconds": round(secs, 1)})

    state["seen"] = {k: d for k, d in state["seen"].items() if today - d <= SEEN_TTL_DAYS}
    state["last_run"] = now.isoformat()

    with open(args.out, "w") as f:
        json.dump({"collected_at": now.isoformat(), "sources": health, "items": new_items}, f)
    base_bytes, shard_bytes = save_state(args.state, state)

    for h in health:
        flag = "ok " if h["ok"] else "-- " if h["skipped"] else "ERR"
        print(f"{flag} {h['name']:<24} new={h['new']:<4} fetched={h['fetched']:<5} {h['error'] or ''}")
    print(f"TOTAL new={len(new_items)} state_base_bytes={base_bytes} largest_shard_bytes={shard_bytes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
