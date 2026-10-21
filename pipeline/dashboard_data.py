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
        files = sorted(glob.glob(os.path.join(args.runs, "*", "findings.json")), key=os.path.getmtime)
        if not files:
            sys.exit("no runs found")
        src = files[-1]
    doc = json.load(open(src, encoding="utf-8"))

    rows = []
    for f in doc.get("findings", []):
        if not is_ahead(f):
            continue
        sig = f.get("signals") or {}
        rows.append({
            "key": f.get("key", ""), "title": f.get("title", ""),
            "score": f.get("score", 0), "severity": f.get("severity", ""),
            "why": f.get("why_ahead", ""), "action": f.get("action", ""),
            "url": (f.get("sources") or [{}])[0].get("url", ""),
            "itw": "yes" if sig.get("exploited_itw") else "",
            "poc": "yes" if sig.get("poc_public") else "",
        })
    rows.sort(key=lambda r: -r["score"])

    counts = [
        {"metric": "ahead", "n": len(rows)},
        {"metric": "itw", "n": sum(1 for r in rows if r["itw"])},
        {"metric": "poc", "n": sum(1 for r in rows if r["poc"])},
        {"metric": "high", "n": sum(1 for r in rows if r["severity"] in ("critical", "high"))},
    ]
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
    for name, obj in (("findings", rows), ("counts", counts), ("sources", srcs), ("meta", meta)):
        json.dump(obj, open(os.path.join(args.out, f"{name}.json"), "w", encoding="utf-8"), ensure_ascii=False)

    print("run_at", doc.get("run_at"))
    print("ahead-of-Microsoft findings", len(rows), "of", len(doc.get("findings", [])))
    print("counts", {c["metric"]: c["n"] for c in counts})


if __name__ == "__main__":
    main()
