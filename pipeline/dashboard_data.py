#!/usr/bin/env python3
"""Build the dashboard's data files from the latest scan - ahead-of-Microsoft only.

Reads the newest runs/*/findings.json and writes three JSON files (findings, counts,
sources) that the dashboard artifact loads. Only findings still ahead of Microsoft
(not in an MSRC advisory and not in CISA KEV) are published.

    python dashboard_data.py --out <dir>
"""
import argparse
import glob
import json
import os
import sys


def is_ahead(f):
    # New runs set ahead_of_microsoft; older data used ahead_of_vendor.
    if "ahead_of_microsoft" in f:
        return bool(f["ahead_of_microsoft"])
    return bool(f.get("ahead_of_vendor"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", default="runs")
    ap.add_argument("--findings", help="path to a specific findings.json (the cloud agent passes its run's output)")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    if args.findings:
        src = args.findings
    else:
        cands = glob.glob(os.path.join(args.runs, "*", "findings.json"))
        if not cands:
            sys.exit("no runs found")

        def _run_at(p):  # pick the chronologically latest run, not the latest-downloaded file
            try:
                return json.load(open(p, encoding="utf-8")).get("run_at") or ""
            except (OSError, json.JSONDecodeError):
                return ""
        src = max(cands, key=_run_at)
    doc = json.load(open(src, encoding="utf-8"))

    # Every scored finding, with flags. The page filters ahead=="yes" for the Ahead tab
    # and shows them all on the All findings tab.
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
        })
    rows.sort(key=lambda r: -r["score"])
    def status(s):
        if s.get("ok"):
            return "ok"
        # Agent records an optional source with no key as error "skipped: no API key".
        if s.get("skipped") or str(s.get("error", "")).lower().startswith("skipped"):
            return "skipped"
        return "failed"

    srcs = [{"name": s.get("name", ""), "tier": s.get("tier", ""),
             "status": status(s), "new": s.get("new", 0)} for s in doc.get("sources", [])]

    meta = {"run_at": doc.get("run_at"), "built_at": __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).isoformat(timespec="seconds")}
    for name, obj in (("findings", rows), ("sources", srcs), ("meta", meta)):
        json.dump(obj, open(os.path.join(args.out, f"{name}.json"), "w", encoding="utf-8"), ensure_ascii=False)

    ahead = sum(1 for r in rows if r["ahead"])
    print("run_at", doc.get("run_at"))
    print("findings", len(rows), "| ahead of Microsoft", ahead)


if __name__ == "__main__":
    main()
