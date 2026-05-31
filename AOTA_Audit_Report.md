# AOTA v1 — Failure-Mode and Effects Analysis (FMEA)

**System:** Autonomous Operational Telemetry API (AOTA v1)
**Audit type:** Red Team / SRE reliability audit
**Posture:** Adversarial — assume every dependency lies, every client is hostile, every free tier evicts you at the worst moment.
**Date:** 2026-05-31

---

## 0. Executive Summary

The AOTA v1 design is functionally correct but operationally naive. It has three fatal blind spots:

1. **It trusts the upstream source.** A `200 OK` from the source portal is treated as proof of good data. It is not. The most dangerous failure in this entire system is *silent staleness* — the pipe stays green while the water turns to poison.
2. **It conflates "process is alive" with "API is healthy."** `/health` reads an in-memory flag, not the actual data path. A marketplace client can be blacklisting you while `/health` cheerfully returns `200`.
3. **It treats free tiers as infrastructure.** Render and Upstash free tiers are *demo environments* with hard eviction, cold starts, and daily command caps. Under load they don't degrade — they disappear.

RPN scoring below uses the standard formula `RPN = Severity × Occurrence × Detection`, each on a 1–10 scale (10 = worst). Anything **RPN ≥ 200** is treated as a release blocker.

---

## 1. FMEA Risk Register (Ranked by RPN)

| ID | Failure Mode | Effect | S | O | D | RPN | Class |
|----|--------------|--------|---|---|---|-----|-------|
| F-01 | Source returns `200` with **frozen/stale data** (same payload every poll) | Clients consume dead data, make wrong decisions, blame your API | 9 | 7 | 9 | **567** | BLOCKER |
| F-02 | Render free tier **cold start** (spun down after idle) | First request after sleep takes 30–60s; client times out and marks endpoint dead | 8 | 9 | 5 | **360** | BLOCKER |
| F-03 | Upstash **daily command quota exhausted** under traffic | Redis ops start failing mid-day; `/v1/telemetry` 500s for remaining hours | 9 | 6 | 6 | **324** | BLOCKER |
| F-04 | `/health` returns `200` but `/v1/telemetry` **500s or times out** | Marketplace polls `/health`, sees green, but real traffic fails → silent blacklist | 9 | 5 | 7 | **315** | BLOCKER |
| F-05 | Source returns `200` with **schema drift** (renamed/removed fields) | Collector writes malformed cache; clients' parsers break | 8 | 5 | 6 | **240** | BLOCKER |
| F-06 | **APScheduler thread dies silently** while uvicorn keeps serving | Cache expires, never refills; every response becomes stale | 9 | 4 | 7 | **252** | BLOCKER |
| F-07 | **Response schema inconsistency** between calls (field order, types, `null` vs absent) | Strict client deserializers (Go/Rust/typed SDKs) reject responses → blacklist | 7 | 6 | 6 | **252** | BLOCKER |
| F-08 | Rate-limit `429` sent **without `Retry-After`** | Client backoff logic treats it as a hard error, not throttling → blacklist | 6 | 6 | 5 | 180 | HIGH |
| F-09 | Source portal **slow but up** (latency creep to 10s+) | Collection coroutine blocks; cron cycles stack; memory climbs to OOM | 7 | 5 | 5 | 175 | HIGH |
| F-10 | **OOM kill** on 512 MB tier during traffic spike | Process dies, Render restarts cold, F-02 cascade | 8 | 4 | 5 | 160 | HIGH |
| F-11 | Source returns `200` with **empty/null body** | `avg_latency_ms` computed over empty set → `NaN`/division-by-zero in payload | 7 | 4 | 5 | 140 | HIGH |
| F-12 | **Clock skew** between collector host and source | `collected_at` and `probe_timestamp` disagree; freshness checks misfire | 5 | 5 | 5 | 125 | MEDIUM |
| F-13 | **TTL race**: cache expires 5s before next write under jitter | Brief windows of `X-Data-Stale: true` flapping; clients see instability | 5 | 5 | 4 | 100 | MEDIUM |
| F-14 | Stripe webhook **replay/duplicate** issues two keys for one payment | Quota accounting drift; minor revenue leak | 4 | 3 | 6 | 72 | LOW |
| F-15 | **Content-Type drift** (returns `text/plain` on error path) | Client JSON parsers reject otherwise-valid responses | 6 | 3 | 4 | 72 | LOW |

---

## 2. Failure Domains in Detail

### 2.1 Data Staleness — the silent killer

The spec's single biggest weakness. `reachable: true, status_code: 200` describes the *transport*, not the *truth*. Five distinct silent-failure modes:

- **Frozen payload (F-01):** Source caches a response and serves it unchanged for hours. Every field is well-formed; the data is just dead. Transport-level checks (status code, reachability) cannot detect this.
- **Schema drift (F-05):** Source renames `latency` → `responseTime`. Collector still gets `200`, still writes "valid" JSON, but the contract is broken downstream.
- **Empty body (F-11):** Source returns `200` with `[]` or `{}`. Aggregate math (`avg`, `p95`) divides by zero.
- **Stuck timestamps:** Body changes but `probe_timestamp` never advances — a tell-tale of a frozen upstream clock.
- **Out-of-range anomaly:** `latency_ms: -1` or `status_code: 0` — physically impossible values that still parse as valid integers.

**Detection strategy:** Never trust transport. Validate *content* on every collection: structural schema (Pydantic), freshness (timestamp monotonicity), liveness (payload hash must change), and sanity (value-range bounds).

### 2.2 Marketplace Blacklisting — green health, dead API

API marketplaces and client SDKs run their own reliability scoring. They blacklist on signals your `/health` endpoint never sees:

- **Health/data path divergence (F-04):** `/health` reads a boolean flag. It does not exercise Redis, the serializer, or the auth path. The real endpoint can fail while health stays green. **Fix: `/health` must perform a real (cached, cheap) read through the actual data path.**
- **Schema instability (F-07):** Typed clients (Go `encoding/json` with strict mode, Rust `serde(deny_unknown_fields)`) reject any response whose shape wanders. Field appearing/disappearing, `int` becoming `float`, `null` vs omitted — all are blacklist triggers. **Fix: serialize through one frozen Pydantic model, always.**
- **Throttle mislabeled as failure (F-08):** A `429` without `Retry-After` looks identical to a flaky `429` from a dying service. Well-behaved clients exponential-back-off and eventually drop you. **Fix: always emit `Retry-After`.**
- **Latency SLO breach (F-09):** Many marketplaces blacklist on p95 latency, not just errors. A slow-but-200 response still burns your reliability score. **Fix: hard response-time budget; serve cache-or-503, never block.**
- **Wrong HTTP semantics (F-15):** Returning `200` with an error body, or an error with `text/plain`, breaks contract-aware clients. **Fix: status code and Content-Type must always match the body.**

### 2.3 Platform Fragility — free tiers are not infrastructure

- **Cold start (F-02):** Render free web services sleep after ~15 min idle. The wake-up request eats 30–60s. To an automated client that is a timeout, and timeouts are the fastest path to blacklisting. **Fix: external keep-warm pinger + accept that free tier has no real availability SLA.**
- **Command quota (F-03):** Upstash free tier caps daily commands. At 60s collection you spend a baseline of ~1,440 writes/day *before any reads*. Add client traffic and you hit the ceiling mid-afternoon, after which all Redis ops fail. **Fix: read-through local cache so client reads almost never touch Redis; batch writes.**
- **Memory ceiling (F-10):** 512 MB. A latency-creeping source (F-09) that stacks overlapping collection cycles will climb to OOM. **Fix: single-flight collection lock + per-collection timeout.**
- **Scheduler death (F-06):** APScheduler runs in-process. If its thread throws an unhandled exception it can die while uvicorn keeps serving — the worst quiet failure, because the API looks alive and serves an ever-staling cache forever. **Fix: heartbeat watchdog that records last successful run and surfaces it in `/health`.**

---

## 3. Mitigation Code

All snippets are drop-in for the FastAPI + APScheduler + Redis stack described in the spec. They are composable: the collector wraps source calls in retry + circuit-breaker + validation; the API layer wraps reads in local-cache + budget + correct HTTP semantics.

### 3.1 Retry with exponential backoff + jitter — mitigates F-09, F-02

```python
import asyncio
import random
import functools
from typing import Callable, Awaitable, TypeVar

T = TypeVar("T")

def async_retry(
    max_attempts: int = 4,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    timeout: float = 5.0,
    retry_on: tuple = (Exception,),
):
    """Retry an async callable with capped exponential backoff and full jitter.
    A per-attempt timeout prevents a slow source (F-09) from blocking the cron cycle."""
    def decorator(func: Callable[..., Awaitable[T]]):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
                except retry_on as exc:
                    last_exc = exc
                    if attempt == max_attempts - 1:
                        break
                    # full jitter: random between 0 and the capped exponential ceiling
                    ceiling = min(max_delay, base_delay * (2 ** attempt))
                    await asyncio.sleep(random.uniform(0, ceiling))
            raise last_exc
        return wrapper
    return decorator
```

### 3.2 Circuit breaker — mitigates F-03, F-09, F-10

Stops hammering a failing dependency (source *or* Redis). Trips OPEN after N consecutive failures, half-opens after a cooldown to probe recovery.

```python
import time
import asyncio
from enum import Enum

class CircuitState(Enum):
    CLOSED = "closed"        # normal
    OPEN = "open"            # failing, reject fast
    HALF_OPEN = "half_open"  # probing recovery

class CircuitBreaker:
    def __init__(self, fail_threshold: int = 5, cooldown: float = 30.0):
        self.fail_threshold = fail_threshold
        self.cooldown = cooldown
        self.failures = 0
        self.state = CircuitState.CLOSED
        self.opened_at = 0.0
        self._lock = asyncio.Lock()

    async def call(self, coro_func, *args, **kwargs):
        async with self._lock:
            if self.state == CircuitState.OPEN:
                if time.monotonic() - self.opened_at >= self.cooldown:
                    self.state = CircuitState.HALF_OPEN
                else:
                    raise RuntimeError("circuit_open")  # fail fast, do not call dependency
        try:
            result = await coro_func(*args, **kwargs)
        except Exception:
            async with self._lock:
                self.failures += 1
                if self.failures >= self.fail_threshold:
                    self.state = CircuitState.OPEN
                    self.opened_at = time.monotonic()
            raise
        else:
            async with self._lock:
                self.failures = 0
                self.state = CircuitState.CLOSED
            return result

source_breaker = CircuitBreaker(fail_threshold=5, cooldown=30.0)
redis_breaker = CircuitBreaker(fail_threshold=3, cooldown=15.0)
```

### 3.3 Data-integrity validation — mitigates F-01, F-05, F-11, F-12

The most important mitigation in the document. Rejects silently-bad data *before* it poisons the cache.

```python
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, field_validator
from typing import Optional

class ProbeModel(BaseModel):
    probe_id: str
    target_label: str
    status_code: int
    reachable: bool
    latency_ms: float
    probe_timestamp: datetime
    tls_valid: Optional[bool] = None
    tls_expires_in_days: Optional[int] = None

    @field_validator("status_code")
    @classmethod
    def status_in_range(cls, v):
        if not (100 <= v <= 599):              # F-11: impossible status code
            raise ValueError(f"status_code out of range: {v}")
        return v

    @field_validator("latency_ms")
    @classmethod
    def latency_sane(cls, v):
        if v < 0 or v > 120_000:               # F-11: negative or absurd latency
            raise ValueError(f"latency_ms implausible: {v}")
        return v


class StalenessGuard:
    """Detects frozen upstream (F-01) and stuck clocks (F-12) across collections."""
    def __init__(self, max_age_seconds: int = 180):
        self.last_hash: Optional[str] = None
        self.last_change_at: float = time.monotonic()
        self.max_age_seconds = max_age_seconds

    def check(self, probes: list[dict]) -> None:
        if not probes:                          # F-11: empty payload
            raise ValueError("empty probe set")

        # F-05: structural validation — raises on schema drift
        validated = [ProbeModel(**p) for p in probes]

        # F-12: timestamps must be recent, not stuck in the past
        now = datetime.now(timezone.utc)
        for p in validated:
            ts = p.probe_timestamp.astimezone(timezone.utc)
            if abs((now - ts).total_seconds()) > self.max_age_seconds:
                raise ValueError(f"probe_timestamp too old/skewed: {ts.isoformat()}")

        # F-01: payload hash must change between collections, or the source is frozen
        payload_hash = hashlib.sha256(
            json.dumps([p.model_dump(mode="json") for p in validated], sort_keys=True).encode()
        ).hexdigest()

        if payload_hash == self.last_hash:
            frozen_for = time.monotonic() - self.last_change_at
            if frozen_for > self.max_age_seconds:
                raise ValueError(f"source frozen for {int(frozen_for)}s — identical payload")
        else:
            self.last_hash = payload_hash
            self.last_change_at = time.monotonic()
```

### 3.4 Safe aggregate computation — mitigates F-11

```python
def compute_aggregate(probes: list[dict]) -> dict:
    """Never divides by zero; degrades gracefully on empty/partial data."""
    n = len(probes)
    reachable = [p for p in probes if p.get("reachable")]
    latencies = sorted(p["latency_ms"] for p in probes if p.get("latency_ms") is not None)

    def p95(values: list[float]) -> Optional[float]:
        if not values:
            return None
        idx = max(0, int(round(0.95 * (len(values) - 1))))
        return round(values[idx], 3)

    return {
        "total_probes": n,
        "reachable_count": len(reachable),
        "unreachable_count": n - len(reachable),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else None,
        "p95_latency_ms": p95(latencies),
    }
```

### 3.5 Scheduler watchdog — mitigates F-06

```python
import time

class CollectorWatchdog:
    """Tracks last successful collection so a dead scheduler thread is visible."""
    def __init__(self):
        self.last_success_ts: float = 0.0
        self.consecutive_failures: int = 0

    def record_success(self):
        self.last_success_ts = time.time()
        self.consecutive_failures = 0

    def record_failure(self):
        self.consecutive_failures += 1

    def seconds_since_success(self) -> float:
        return time.time() - self.last_success_ts if self.last_success_ts else float("inf")

    def is_healthy(self, max_gap: float = 180.0) -> bool:
        return self.seconds_since_success() < max_gap

watchdog = CollectorWatchdog()
```

### 3.6 Collector loop — composes 3.1–3.5

```python
@async_retry(max_attempts=4, timeout=5.0)
async def fetch_source():
    # raw HTTP call to the source portal
    ...

guard = StalenessGuard(max_age_seconds=180)

async def collection_cycle():
    try:
        raw = await source_breaker.call(fetch_source)     # 3.1 + 3.2
        guard.check(raw["probes"])                         # 3.3 — rejects silent staleness
        snapshot = build_snapshot(raw, compute_aggregate(raw["probes"]))  # 3.4
        await redis_breaker.call(write_cache, snapshot)    # 3.2 on Redis too
        watchdog.record_success()                          # 3.5
    except Exception as exc:
        watchdog.record_failure()                          # 3.5 — do NOT overwrite good cache
        log.error("collection failed, keeping last-good cache: %s", exc)
```

> **Key principle:** on any validation or fetch failure, the collector **keeps the last-good cache and does not overwrite it**. A stale-but-flagged response beats a fresh-but-poisoned one.

### 3.7 Local read-through cache — mitigates F-03, F-10

Client reads hit process memory first, so Redis command spend stays near the collection baseline regardless of traffic.

```python
class LocalCache:
    def __init__(self):
        self.value: Optional[dict] = None
        self.written_at: float = 0.0

    def set(self, value: dict):
        self.value = value
        self.written_at = time.monotonic()

    def age(self) -> float:
        return time.monotonic() - self.written_at if self.value else float("inf")

local_cache = LocalCache()

async def get_telemetry_cached() -> tuple[Optional[dict], bool]:
    """Return (data, is_stale). Serves local memory; only refills from Redis when expired."""
    if local_cache.value and local_cache.age() < 50:
        return local_cache.value, False
    try:
        data = await redis_breaker.call(read_cache)   # rare: ~once per ~50s, not per request
        if data:
            local_cache.set(data)
            return data, False
    except Exception:
        pass
    # Redis unreachable or quota hit — serve last local copy, flagged stale
    return local_cache.value, True
```

### 3.8 Response-time budget + correct HTTP semantics — mitigates F-04, F-07, F-08, F-13, F-15

```python
from fastapi import FastAPI, Depends, Response, HTTPException
from fastapi.responses import JSONResponse
import asyncio

app = FastAPI()

@app.get("/v1/telemetry")
async def get_telemetry(response: Response, key: str = Depends(validate_api_key)):
    try:
        # hard budget: never block a client past 2s — serve cache or 503
        data, is_stale = await asyncio.wait_for(get_telemetry_cached(), timeout=2.0)
    except asyncio.TimeoutError:
        # F-04/F-15: correct semantics — 503 + Retry-After, JSON body
        return JSONResponse(
            status_code=503,
            content={"error": "telemetry_unavailable", "retry_after_seconds": 30},
            headers={"Retry-After": "30", "Content-Type": "application/json"},
        )

    if data is None:
        return JSONResponse(
            status_code=503,
            content={"error": "no_data_yet"},
            headers={"Retry-After": "60"},
        )

    # F-07/F-13: serialize through ONE frozen model so the shape never drifts
    payload = TelemetrySnapshot(**data).model_dump(mode="json")
    response.headers["X-Data-Stale"] = "true" if is_stale else "false"
    response.headers["Cache-Control"] = "public, max-age=30"
    return payload
```

```python
# F-08: rate limiting that a client can actually obey
@app.middleware("http")
async def rate_limit(request, call_next):
    allowed, retry_after = check_quota(request)   # your token-bucket logic
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limited", "retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},   # the field clients need
        )
    return await call_next(request)
```

### 3.9 Real health check — mitigates F-04, F-06

`/health` must exercise the actual data path and surface the watchdog, not a static flag.

```python
@app.get("/health")
async def health():
    scheduler_ok = watchdog.is_healthy(max_gap=180.0)
    cache_present = local_cache.value is not None
    cache_age = round(local_cache.age(), 1) if cache_present else None

    # Degraded, not dead: still 200 so transport monitors don't blacklist,
    # but the body tells an intelligent client the truth.
    status = "ok" if (scheduler_ok and cache_present) else "degraded"
    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scheduler_healthy": scheduler_ok,
        "seconds_since_collection": round(watchdog.seconds_since_success(), 1),
        "cache_populated": cache_present,
        "cache_age_seconds": cache_age,
        "version": "1.0.0",
    }
```

---

## 4. Residual Risk & Hard Truths

Some risks **cannot** be engineered away inside the spec's "zero cost" constraint. Naming them is part of the audit.

| Risk | Why code can't fix it | Honest recommendation |
|------|------------------------|------------------------|
| Cold-start blacklisting (F-02) | A sleeping free-tier service has no availability SLA. A keep-warm pinger only narrows the window. | If reliability is a selling point, the free tier is structurally incompatible. Budget the ~$7/mo paid Render tier; it is the difference between a product and a demo. |
| Daily command cap (F-03) | Read-through caching helps, but a viral spike still exhausts writes + cache-miss reads. | Move write path off the per-second cron, or accept a paid Redis tier above a known traffic threshold. |
| Single-process SPOF (F-06/F-10) | Collector and server share one process and one memory ceiling. | Split collection into a separate worker once revenue justifies a second free service; until then, the watchdog is your only safety net. |
| Source contract (F-01/F-05) | You do not control the upstream portal. It can change or freeze without notice. | Treat the source as hostile; the validation in 3.3 is mandatory, not optional. Add a documented SLA disclaimer so a frozen source is the source's liability, not yours. |

---

## 5. Implementation Priority

1. **Ship before any traffic:** 3.3 (data validation), 3.6 (keep-last-good), 3.9 (real health). These prevent the highest-RPN silent failures.
2. **Ship before marketplace listing:** 3.7 (local cache), 3.8 (budget + 429 semantics). These prevent blacklisting.
3. **Ship before scaling:** circuit breakers (3.2), and the paid-tier migration decisions in section 4.

---

*End of report.*
