"""
AOTA v1 — Production-hardened API engine.

This module is the implementation glue between the FMEA audit
(AOTA_Audit_Report.md) and a deployable service. Every resilience
primitive maps directly to a mitigation in Section 3 of the audit:

    async_retry        -> 3.1   (F-09, F-02)
    CircuitBreaker     -> 3.2   (F-03, F-09, F-10)
    StalenessGuard     -> 3.3   (F-01, F-05, F-11, F-12)
    compute_aggregate  -> 3.4   (F-11)
    CollectorWatchdog  -> 3.5   (F-06)
    collection_cycle   -> 3.6   (keep-last-good)
    LocalCache         -> 3.7   (F-03, F-10)
    /v1/telemetry      -> 3.8   (F-04, F-07, F-08, F-13, F-15)
    /health            -> 3.9   (F-04, F-06)
    /v1/provision      -> revenue loop (Stripe -> Redis -> email)

Nothing here trusts a dependency. The source lies, Redis evicts,
the scheduler dies — and the API still answers with correct HTTP
semantics and an honest staleness signal.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Awaitable, Callable, Optional, TypeVar

import httpx
import redis.asyncio as aioredis
import stripe
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# --------------------------------------------------------------------------- #
# Configuration (all secrets from env — never hardcode; see render.yaml)
# --------------------------------------------------------------------------- #

REDIS_URL = os.environ["UPSTASH_REDIS_URL"]
SOURCE_URL = os.environ["SOURCE_PORTAL_URL"]
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "keys@aota.example")

COLLECT_INTERVAL_S = int(os.environ.get("COLLECT_INTERVAL_S", "60"))
CACHE_TTL_S = int(os.environ.get("CACHE_TTL_S", "55"))
LOCAL_FRESH_S = int(os.environ.get("LOCAL_FRESH_S", "50"))
MAX_DATA_AGE_S = int(os.environ.get("MAX_DATA_AGE_S", "180"))
SCHEMA_VERSION = "1.0.0"

stripe.api_key = STRIPE_API_KEY

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("aota")

T = TypeVar("T")

# --------------------------------------------------------------------------- #
# 3.1  Retry with exponential backoff + jitter        (mitigates F-09, F-02)
# --------------------------------------------------------------------------- #


def async_retry(
    max_attempts: int = 4,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    timeout: float = 5.0,
    retry_on: tuple = (Exception,),
):
    """Retry an async callable with capped exponential backoff and full jitter.
    The per-attempt timeout stops a slow source (F-09) blocking the cron cycle."""

    def decorator(func: Callable[..., Awaitable[T]]):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exc: Optional[BaseException] = None
            for attempt in range(max_attempts):
                try:
                    return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
                except retry_on as exc:
                    last_exc = exc
                    if attempt == max_attempts - 1:
                        break
                    ceiling = min(max_delay, base_delay * (2 ** attempt))
                    await asyncio.sleep(random.uniform(0, ceiling))
            assert last_exc is not None
            raise last_exc

        return wrapper

    return decorator


# --------------------------------------------------------------------------- #
# 3.2  Circuit breaker                              (mitigates F-03, F-09, F-10)
# --------------------------------------------------------------------------- #


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


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
                    raise RuntimeError("circuit_open")
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


# --------------------------------------------------------------------------- #
# Pydantic models — one frozen shape, used for BOTH validation and output
# (3.3 structural validation + 3.8 schema stability F-07/F-13)
# --------------------------------------------------------------------------- #


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
    def status_in_range(cls, v: int) -> int:
        if not (100 <= v <= 599):  # F-11
            raise ValueError(f"status_code out of range: {v}")
        return v

    @field_validator("latency_ms")
    @classmethod
    def latency_sane(cls, v: float) -> float:
        if v < 0 or v > 120_000:  # F-11
            raise ValueError(f"latency_ms implausible: {v}")
        return v


class Aggregate(BaseModel):
    total_probes: int
    reachable_count: int
    unreachable_count: int
    avg_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    collection_duration_ms: Optional[float] = None


class TelemetrySnapshot(BaseModel):
    snapshot_id: str
    collected_at: datetime
    ttl_seconds: int
    schema_version: str = SCHEMA_VERSION
    probes: list[ProbeModel]
    aggregate: Aggregate


# --------------------------------------------------------------------------- #
# 3.3  Data-integrity validation            (mitigates F-01, F-05, F-11, F-12)
# --------------------------------------------------------------------------- #


class StalenessGuard:
    """Detects frozen upstream (F-01) and stuck/skewed clocks (F-12)."""

    def __init__(self, max_age_seconds: int = MAX_DATA_AGE_S):
        self.last_hash: Optional[str] = None
        self.last_change_at: float = time.monotonic()
        self.max_age_seconds = max_age_seconds

    def check(self, probes: list[dict]) -> list[ProbeModel]:
        if not probes:  # F-11
            raise ValueError("empty probe set")

        validated = [ProbeModel(**p) for p in probes]  # F-05 schema drift

        now = datetime.now(timezone.utc)
        for p in validated:  # F-12 skew / stuck clock
            ts = p.probe_timestamp.astimezone(timezone.utc)
            if abs((now - ts).total_seconds()) > self.max_age_seconds:
                raise ValueError(f"probe_timestamp too old/skewed: {ts.isoformat()}")

        payload_hash = hashlib.sha256(
            json.dumps(
                [p.model_dump(mode="json") for p in validated], sort_keys=True
            ).encode()
        ).hexdigest()

        if payload_hash == self.last_hash:  # F-01 frozen source
            frozen_for = time.monotonic() - self.last_change_at
            if frozen_for > self.max_age_seconds:
                raise ValueError(f"source frozen for {int(frozen_for)}s — identical payload")
        else:
            self.last_hash = payload_hash
            self.last_change_at = time.monotonic()

        return validated


guard = StalenessGuard()


# --------------------------------------------------------------------------- #
# 3.4  Safe aggregate computation                          (mitigates F-11)
# --------------------------------------------------------------------------- #


def compute_aggregate(probes: list[ProbeModel], duration_ms: float) -> Aggregate:
    n = len(probes)
    reachable = [p for p in probes if p.reachable]
    latencies = sorted(p.latency_ms for p in probes if p.latency_ms is not None)

    def p95(values: list[float]) -> Optional[float]:
        if not values:
            return None
        idx = max(0, int(round(0.95 * (len(values) - 1))))
        return round(values[idx], 3)

    return Aggregate(
        total_probes=n,
        reachable_count=len(reachable),
        unreachable_count=n - len(reachable),
        avg_latency_ms=round(sum(latencies) / len(latencies), 3) if latencies else None,
        p95_latency_ms=p95(latencies),
        collection_duration_ms=round(duration_ms, 3),
    )


# --------------------------------------------------------------------------- #
# 3.5  Scheduler watchdog                                  (mitigates F-06)
# --------------------------------------------------------------------------- #


class CollectorWatchdog:
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

    def is_healthy(self, max_gap: float = float(MAX_DATA_AGE_S)) -> bool:
        return self.seconds_since_success() < max_gap


watchdog = CollectorWatchdog()


# --------------------------------------------------------------------------- #
# 3.7  Local read-through cache                       (mitigates F-03, F-10)
# --------------------------------------------------------------------------- #


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

# Small in-process cache of validated key hashes so auth almost never
# touches Redis (keeps command spend near the collection baseline — F-03).
_key_cache: dict[str, tuple[float, dict]] = {}
_KEY_CACHE_TTL = 300.0


# --------------------------------------------------------------------------- #
# Redis access (always through the breaker)
# --------------------------------------------------------------------------- #

redis: aioredis.Redis = aioredis.from_url(REDIS_URL, decode_responses=True)


async def _redis_get(key: str) -> Optional[str]:
    return await redis.get(key)


async def _redis_set(key: str, value: str, ex: Optional[int] = None, nx: bool = False):
    return await redis.set(key, value, ex=ex, nx=nx)


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #


@async_retry(max_attempts=4, timeout=5.0)
async def fetch_source() -> dict:
    """Raw HTTP pull from the source portal. Returns parsed JSON or raises."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(SOURCE_URL)
        resp.raise_for_status()
        return resp.json()


def build_snapshot(probes: list[ProbeModel], aggregate: Aggregate) -> dict:
    snap = TelemetrySnapshot(
        snapshot_id=secrets.token_hex(16),
        collected_at=datetime.now(timezone.utc),
        ttl_seconds=CACHE_TTL_S,
        schema_version=SCHEMA_VERSION,
        probes=probes,
        aggregate=aggregate,
    )
    return snap.model_dump(mode="json")


async def collection_cycle():
    """3.6 — composes 3.1-3.5. On ANY failure, keep last-good cache untouched."""
    started = time.monotonic()
    try:
        raw = await source_breaker.call(fetch_source)  # 3.1 + 3.2
        probes = guard.check(raw.get("probes", []))  # 3.3 — rejects silent staleness
        duration_ms = (time.monotonic() - started) * 1000
        snapshot = build_snapshot(probes, compute_aggregate(probes, duration_ms))  # 3.4

        await redis_breaker.call(_redis_set, "telemetry:latest", json.dumps(snapshot), CACHE_TTL_S)
        local_cache.set(snapshot)  # warm the local read-through cache immediately
        watchdog.record_success()  # 3.5
        log.info("collection ok: %d probes", len(probes))
    except Exception as exc:  # noqa: BLE001 — deliberate catch-all at the boundary
        watchdog.record_failure()  # 3.5 — do NOT overwrite good cache
        log.error("collection failed, keeping last-good cache: %s", exc)


# --------------------------------------------------------------------------- #
# Authentication — header API key, SHA-256, lookup-by-hash + local cache
# --------------------------------------------------------------------------- #


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def _lookup_key(key_hash: str) -> Optional[dict]:
    cached = _key_cache.get(key_hash)
    if cached and (time.monotonic() - cached[0]) < _KEY_CACHE_TTL:
        return cached[1]
    try:
        raw = await redis_breaker.call(_redis_get, f"apikey:{key_hash}")
    except Exception:
        # Redis down: fall back to a possibly-stale local entry rather than 500 the world.
        return cached[1] if cached else None
    if not raw:
        return None
    meta = json.loads(raw)
    _key_cache[key_hash] = (time.monotonic(), meta)
    return meta


async def validate_api_key(x_api_key: str = Header(...)) -> dict:
    if not x_api_key or not x_api_key.startswith("aota_"):
        raise HTTPException(status_code=401, detail="Missing or malformed API key")
    meta = await _lookup_key(_hash_key(x_api_key))
    if not meta or not meta.get("active", False):
        raise HTTPException(status_code=403, detail="Invalid or revoked API key")
    return meta


# --------------------------------------------------------------------------- #
# 3.8  Rate limiting — token bucket per key, 429 WITH Retry-After (F-08)
# --------------------------------------------------------------------------- #

TIER_HOURLY = {"free": 60, "pro": 600, "enterprise": 10_000_000}
_buckets: dict[str, tuple[float, float]] = {}  # key_hash -> (tokens, last_refill)


def _check_quota(key_hash: str, tier: str) -> tuple[bool, int]:
    limit = TIER_HOURLY.get(tier, 60)
    refill_per_s = limit / 3600.0
    now = time.monotonic()
    tokens, last = _buckets.get(key_hash, (float(limit), now))
    tokens = min(float(limit), tokens + (now - last) * refill_per_s)
    if tokens >= 1.0:
        _buckets[key_hash] = (tokens - 1.0, now)
        return True, 0
    _buckets[key_hash] = (tokens, now)
    retry_after = max(1, int(round((1.0 - tokens) / refill_per_s)))
    return False, retry_after


# --------------------------------------------------------------------------- #
# get_telemetry_cached — 3.7 read-through with stale flag
# --------------------------------------------------------------------------- #


async def get_telemetry_cached() -> tuple[Optional[dict], bool]:
    if local_cache.value and local_cache.age() < LOCAL_FRESH_S:
        return local_cache.value, False
    try:
        raw = await redis_breaker.call(_redis_get, "telemetry:latest")
        if raw:
            data = json.loads(raw)
            local_cache.set(data)
            return data, False
    except Exception:
        pass
    return local_cache.value, True  # Redis down / quota hit -> serve last local, flagged


# --------------------------------------------------------------------------- #
# Email (Resend HTTP API; swap base_url/payload for SendGrid if preferred)
# --------------------------------------------------------------------------- #


async def send_key_email(to_email: str, api_key: str) -> None:
    if not RESEND_API_KEY:
        log.warning("RESEND_API_KEY unset — skipping email (key still provisioned)")
        return
    body = {
        "from": FROM_EMAIL,
        "to": [to_email],
        "subject": "Your AOTA API key",
        "text": (
            "Thanks for subscribing to AOTA telemetry.\n\n"
            f"Your API key (store it securely — it is shown only once):\n\n{api_key}\n\n"
            "Send it on every request as the header:  X-API-Key: <key>\n"
            "Endpoint: GET /v1/telemetry\n"
        ),
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json=body,
        )
        resp.raise_for_status()


# --------------------------------------------------------------------------- #
# App + lifespan (start scheduler, prime cache)
# --------------------------------------------------------------------------- #

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await collection_cycle()  # prime so first client never hits an empty cache
    scheduler.add_job(
        collection_cycle,
        "interval",
        seconds=COLLECT_INTERVAL_S,
        max_instances=1,  # single-flight: no overlapping cycles (F-09/F-10)
        coalesce=True,
    )
    scheduler.start()
    log.info("scheduler started; collecting every %ds", COLLECT_INTERVAL_S)
    yield
    scheduler.shutdown(wait=False)
    await redis.aclose()


app = FastAPI(title="AOTA", version=SCHEMA_VERSION, lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Rate-limit middleware — exempts unauthenticated infra routes
# --------------------------------------------------------------------------- #

_EXEMPT_PATHS = {"/health", "/v1/provision"}


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path in _EXEMPT_PATHS:
        return await call_next(request)

    api_key = request.headers.get("x-api-key", "")
    if not api_key.startswith("aota_"):
        return await call_next(request)  # let the auth dependency reject it with 401

    key_hash = _hash_key(api_key)
    meta = await _lookup_key(key_hash)
    tier = (meta or {}).get("tier", "free")
    allowed, retry_after = _check_quota(key_hash, tier)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limited", "retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},  # F-08: the field clients obey
        )
    return await call_next(request)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@app.get("/v1/telemetry")
async def get_telemetry(response: Response, _key: dict = Depends(validate_api_key)):
    try:
        data, is_stale = await asyncio.wait_for(get_telemetry_cached(), timeout=2.0)  # 3.8 budget
    except asyncio.TimeoutError:
        return JSONResponse(
            status_code=503,
            content={"error": "telemetry_unavailable", "retry_after_seconds": 30},
            headers={"Retry-After": "30"},  # F-04/F-15 correct semantics
        )

    if data is None:
        return JSONResponse(
            status_code=503,
            content={"error": "no_data_yet"},
            headers={"Retry-After": "60"},
        )

    payload = TelemetrySnapshot(**data).model_dump(mode="json")  # F-07/F-13 frozen shape
    response.headers["X-Data-Stale"] = "true" if is_stale else "false"
    response.headers["Cache-Control"] = "public, max-age=30"
    return payload


@app.get("/health")
async def health():
    scheduler_ok = watchdog.is_healthy()
    cache_present = local_cache.value is not None
    cache_age = round(local_cache.age(), 1) if cache_present else None
    status = "ok" if (scheduler_ok and cache_present) else "degraded"  # 3.9, F-04/F-06
    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scheduler_healthy": scheduler_ok,
        "seconds_since_collection": round(watchdog.seconds_since_success(), 1),
        "cache_populated": cache_present,
        "cache_age_seconds": cache_age,
        "version": SCHEMA_VERSION,
    }


@app.post("/v1/provision")
async def provision(request: Request):
    """Stripe checkout.session.completed -> generate key -> hash to Redis -> email.

    SECURITY: the request body is untrusted until the Stripe signature is
    verified. We never act on payload contents before construct_event() passes.
    """
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="provisioning not configured")

    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="invalid signature")

    if event["type"] != "checkout.session.completed":
        return {"ignored": event["type"]}

    # F-14: idempotency — SETNX on event id dedupes Stripe retries / replays.
    first_time = await redis_breaker.call(
        _redis_set, f"stripe:evt:{event['id']}", "1", 60 * 60 * 24 * 7, True
    )
    if not first_time:
        return {"status": "already_processed", "event_id": event["id"]}

    session = event["data"]["object"]
    email = (session.get("customer_details") or {}).get("email") or session.get("customer_email")
    tier = (session.get("metadata") or {}).get("tier", "pro")
    if not email:
        log.error("no email on session %s", session.get("id"))
        raise HTTPException(status_code=422, detail="no customer email")

    raw_key = f"aota_{tier}_{secrets.token_hex(16)}"  # 32 hex chars
    meta = {
        "tier": tier,
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "stripe_session": session.get("id"),
    }
    # Store ONLY the hash. Plaintext key leaves the server exactly once, by email.
    await redis_breaker.call(
        _redis_set, f"apikey:{_hash_key(raw_key)}", json.dumps(meta), None, False
    )

    try:
        await send_key_email(email, raw_key)
    except Exception as exc:  # noqa: BLE001
        # Key is provisioned; email failed. Log loudly — this is the one spot a human
        # may need to intervene. Do not leak the key to logs.
        log.error("key provisioned for %s but email failed: %s", email, exc)
        return {"status": "provisioned_email_failed", "tier": tier}

    return {"status": "provisioned", "tier": tier}
