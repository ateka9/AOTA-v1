"""
AOTA v1 — hostile client / marketplace-readiness harness.
"""
from __future__ import annotations
import argparse
import asyncio
import collections
import os
import time
import httpx

BASE_URL = os.environ.get("AOTA_BASE_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.environ.get("AOTA_API_KEY", "")

REQUIRED_TOP_LEVEL = {
    "snapshot_id", "collected_at", "ttl_seconds",
    "schema_version", "probes", "aggregate",
}

class Findings:
    def __init__(self):
        self.status_counts = collections.Counter()
        self.latencies_ms = []
        self.rl_missing_retry_after = 0
        self.rl_with_retry_after = 0
        self.schema_violations = 0
        self.stale_header_missing = 0
        self.exceptions = 0

    def record_200(self, body, headers):
        if not REQUIRED_TOP_LEVEL.issubset(body.keys()):
            self.schema_violations += 1
        if "x-data-stale" not in {k.lower() for k in headers.keys()}:
            self.stale_header_missing += 1

    def record_429(self, headers):
        if headers.get("Retry-After"):
            self.rl_with_retry_after += 1
        else:
            self.rl_missing_retry_after += 1

async def one_request(client, f):
    t0 = time.monotonic()
    try:
        r = await client.get(
            f"{BASE_URL}/v1/telemetry",
            headers={"X-API-Key": API_KEY},
            timeout=10.0,
        )
    except Exception:
        f.exceptions += 1
        return
    f.latencies_ms.append((time.monotonic() - t0) * 1000)
    f.status_counts[r.status_code] += 1
    if r.status_code == 200:
        try:
            f.record_200(r.json(), r.headers)
        except Exception:
            f.schema_violations += 1
    elif r.status_code == 429:
        f.record_429(r.headers)

async def run_burst(total, minutes, concurrency):
    f = Findings()
    interval = (minutes * 60.0) / total if total else 0.0
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient() as client:
        async def worker(i):
            await asyncio.sleep(i * interval)
            async with sem:
                await one_request(client, f)
        await asyncio.gather(*(worker(i) for i in range(total)))
    return f

async def check_health():
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{BASE_URL}/health", timeout=15.0)
        return {"status_code": r.status_code, "body": r.json()}

def pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, int(round(p * (len(s) - 1))))
    return round(s[idx], 1)

def report(f, health, total):
    print("\n" + "=" * 60)
    print("AOTA hostile-client report")
    print("=" * 60)
    print(f"requests attempted : {total}")
    print(f"status distribution: {dict(f.status_counts)}")
    print(f"transport errors   : {f.exceptions}")
    print(f"latency p50 / p95  : {pct(f.latencies_ms, 0.50)}ms / {pct(f.latencies_ms, 0.95)}ms")
    print("-" * 60)
    def line(label, ok, detail=""):
        print(f"[{'PASS' if ok else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")
    triggered = f.status_counts.get(429, 0)
    line("Rate limit triggered (F-08)", triggered > 0,
         f"{triggered} x 429" if triggered else "no 429 seen")
    line("Every 429 carries Retry-After (F-08)", f.rl_missing_retry_after == 0,
         f"{f.rl_missing_retry_after} missing" if f.rl_missing_retry_after else "all present")
    line("Response schema stable (F-07)", f.schema_violations == 0,
         f"{f.schema_violations} bad bodies" if f.schema_violations else "all bodies conform")
    line("X-Data-Stale present on 200s (F-13)", f.stale_header_missing == 0,
         f"{f.stale_header_missing} missing" if f.stale_header_missing else "all present")
    print("-" * 60)
    print(f"/health -> {health['status_code']} status='{health['body'].get('status')}'")
    print("MANUAL CHECK (F-06): stop the collector, re-run, confirm status='degraded'")
    print("=" * 60 + "\n")

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=1000)
    ap.add_argument("--minutes", type=float, default=10.0)
    ap.add_argument("--concurrency", type=int, default=10)
    args = ap.parse_args()
    print(f"Firing {args.requests} requests over {args.minutes} min at {BASE_URL} ...")
    findings = await run_burst(args.requests, args.minutes, args.concurrency)
    health = await check_health()
    report(findings, health, args.requests)

if __name__ == "__main__":
    asyncio.run(main())
