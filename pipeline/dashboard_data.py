#!/usr/bin/env python3
"""Build the dashboard's data files from the latest scan.

Writes findings.json (every scored finding from the last two runs, flagged
ahead/kev/itw/poc/msrc, latest values winning), sources.json and meta.json. With
--items, also maintains items.json: a rolling 2-day list of every raw item the
scanner caught, for the "Everything" tab.

    python dashboard_data.py --out site/data
    python dashboard_data.py --findings <f.json> --items <items.json> --out /workspace/radar/data
"""
import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

ITEM_WINDOW_DAYS = 2
ITEM_CAP = 800
# Runs fire 8h and 16h apart, so 23h back from the current run spans exactly the last two runs.
FINDING_WINDOW_HOURS = 23
# A finding leaves the board this long after Radar first saw it, even if the agent keeps
# re-reporting it. history.json remembers first sightings so expired findings stay gone.
FINDING_MAX_AGE_DAYS = 5
HISTORY_DAYS = 60

HOT_RE = re.compile(r"in the wild|actively exploited|exploited|0-?day|zero[- ]day", re.I)
POC_RE = re.compile(r"\bpoc\b|proof[- ]of[- ]concept|exploit", re.I)
RCE_RE = re.compile(r"\brce\b|remote code|auth(entication)? bypass", re.I)
TIER_BONUS = {"pre-disclosure": 15, "exploit": 15, "research": 10, "vendor": 5}


def is_ahead(f):
    if "ahead_of_microsoft" in f:
        return bool(f["ahead_of_microsoft"])
    return bool(f.get("ahead_of_vendor"))


def rank(item):
    """Cheap no-LLM rank for the long tail; mirrors radar.py's heuristic."""
    if item.get("summary"):
        return 0
    text = f"{item.get('title', '')} {item.get('text', '')}"
    score = min(50, int((item.get("cvss") or 0) * 5))
    score += 40 if item.get("kev") else 0
    score += 25 if item.get("exploited_signal") else 0
    score += TIER_BONUS.get(item.get("tier"), 0)
    score += 20 if HOT_RE.search(text) else 0
    score += 10 if POC_RE.search(text) else 0
    score += 10 if RCE_RE.search(text) else 0
    return min(100, score)


def load_json(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def os_list(f):
    v = f.get("os")
    if isinstance(v, str):
        v = [v]
    return [str(x).strip() for x in (v or []) if str(x).strip()]


def parse_ts(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def merge_findings(out_dir, rows, run_at):
    """Fold this run's findings into the published list; keep what the last two runs reported."""
    now = datetime.now(timezone.utc)
    anchor = parse_ts(run_at) or now
    seen = run_at or now.isoformat(timespec="seconds")
    # Rows written before last_seen existed belong to whichever run wrote them.
    legacy = load_json(os.path.join(out_dir, "meta.json"), {}).get("run_at") or seen
    hist_path = os.path.join(out_dir, "history.json")
    hist = load_json(hist_path, {})  # key -> first_seen, kept after a finding expires
    by = {}
    for r in load_json(os.path.join(out_dir, "findings.json"), []):
        k = r.get("key") or r.get("title")
        if k:
            r.setdefault("last_seen", legacy)
            r.setdefault("first_seen", hist.get(k) or r["last_seen"])
            by[k] = r
            hist.setdefault(k, r["first_seen"])
    for r in rows:
        k = r.get("key") or r.get("title")
        if not k:
            continue
        r["first_seen"] = by.get(k, {}).get("first_seen") or hist.get(k) or seen
        r["last_seen"] = seen
        by[k] = r
        hist.setdefault(k, r["first_seen"])
    seen_cut = anchor - timedelta(hours=FINDING_WINDOW_HOURS)
    age_cut = anchor - timedelta(days=FINDING_MAX_AGE_DAYS)
    kept = [r for r in by.values()
            if (parse_ts(r.get("last_seen")) or anchor) >= seen_cut
            and (parse_ts(r.get("first_seen")) or anchor) >= age_cut]
    kept.sort(key=lambda r: -(r.get("score") or 0))
    hist_cut = anchor - timedelta(days=HISTORY_DAYS)
    hist = {k: v for k, v in hist.items() if (parse_ts(v) or anchor) >= hist_cut}
    json.dump(hist, open(hist_path, "w", encoding="utf-8"), ensure_ascii=False)
    return kept


def merge_items(out_dir, items_path):
    """Fold this run's items into a rolling 2-day, deduped, ranked list."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")
    cutoff = (now - timedelta(days=ITEM_WINDOW_DAYS)).isoformat()

    new = load_json(items_path, [])
    if isinstance(new, dict):
        new = new.get("items", [])
    by = {it["id"]: it for it in load_json(os.path.join(out_dir, "items.json"), []) if it.get("id")}
    for it in new:
        if it.get("summary") or not it.get("id"):
            continue  # skip threat-infra roll-ups and anything unkeyed
        prior = by.get(it["id"], {})
        by[it["id"]] = {
            "id": it["id"], "source": it.get("source", ""), "tier": it.get("tier", ""),
            "title": (it.get("title", "") or "")[:200], "url": it.get("url", ""),
            "cves": it.get("cves", []), "published": it.get("published"),
            "text": (it.get("text", "") or "")[:160], "rank": rank(it),
            "seen_at": prior.get("seen_at", now_iso),
        }
    merged = [it for it in by.values() if (it.get("seen_at") or now_iso) >= cutoff]
    # Everything view is a recency feed across all sources; rank stays as a "notable" flag.
    merged.sort(key=lambda it: (it.get("published") or it.get("seen_at") or ""), reverse=True)
    merged = merged[:ITEM_CAP]
    json.dump(merged, open(os.path.join(out_dir, "items.json"), "w", encoding="utf-8"), ensure_ascii=False)
    return len(merged)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", default="runs")
    ap.add_argument("--findings", help="a specific findings.json (the cloud agent passes its run's output)")
    ap.add_argument("--items", help="this run's items.json, merged into a rolling list for the Everything tab")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    if args.findings:
        src = args.findings
    else:
        cands = glob.glob(os.path.join(args.runs, "*", "findings.json"))
        if not cands:
            sys.exit("no runs found")
        src = max(cands, key=lambda p: load_json(p, {}).get("run_at") or "")
    doc = load_json(src, {})

    rows = []
    for f in doc.get("findings", []):
        sig = f.get("signals") or {}
        rows.append({
            "key": f.get("key", ""), "title": f.get("title", ""),
            "score": f.get("score", 0), "severity": f.get("severity", ""),
            "why": f.get("why_ahead", ""), "action": f.get("action", ""),
            "url": (f.get("sources") or [{}])[0].get("url", ""),
            "ahead": "yes" if is_ahead(f) else "",
            "itw": "yes" if sig.get("exploited_itw") else "",
            "poc": "yes" if sig.get("poc_public") else "",
            "kev": "yes" if sig.get("kev") else "",
            "msrc": sig.get("msrc_published"),
            "vendor": (f.get("vendor") or "").strip(),
            "product": (f.get("product") or "").strip(),
            "os": os_list(f),
        })
    rows.sort(key=lambda r: -r["score"])

    def status(s):
        if s.get("ok"):
            return "ok"
        if s.get("skipped") or str(s.get("error", "")).lower().startswith("skipped"):
            return "skipped"
        return "failed"

    srcs = [{"name": s.get("name", ""), "tier": s.get("tier", ""),
             "status": status(s), "new": s.get("new", 0)} for s in doc.get("sources", [])]
    meta = {"run_at": doc.get("run_at"),
            "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    merged = merge_findings(args.out, rows, doc.get("run_at"))
    for name, obj in (("findings", merged), ("sources", srcs), ("meta", meta)):
        json.dump(obj, open(os.path.join(args.out, f"{name}.json"), "w", encoding="utf-8"), ensure_ascii=False)

    line = (f"run_at {doc.get('run_at')} | this run {len(rows)} | published (last day) {len(merged)}"
            f" | ahead {sum(1 for r in merged if r['ahead'])}")
    if args.items:
        line += f" | items (rolling {ITEM_WINDOW_DAYS}d) {merge_items(args.out, args.items)}"
    print(line)


if __name__ == "__main__":
    main()
