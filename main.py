"""
LLM Availability Feed — Production API (v2.1)

Direct endpoint probing — measures actual API reachability, not self-reported
status pages. A 401 in 200ms means the provider is UP. A timeout means DOWN.
This is more honest data than any status page.

Providers probed:
  OpenAI, Anthropic, Cohere, Mistral, Groq, Together AI,
  Perplexity, Replicate, Hugging Face
"""
from __future__ import annotations
import asyncio, functools, hashlib, json, logging, os, random, secrets, time
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
from pydantic import BaseModel, field_validator

# --------------------------------------------------------------------------- #
# Direct endpoint probes — no API key needed, 401 = server is alive
# --------------------------------------------------------------------------- #
LLM_PROVIDERS = [
    {
        "id": "openai",
        "label": "OpenAI",
        "url": "https://api.openai.com/v1/models",
        "expected_codes": [200, 401],
    },
    {
        "id": "anthropic",
        "label": "Anthropic",
        "url": "https://api.anthropic.com/v1/models",
        "expected_codes": [200, 401],
    },
    {
        "id": "cohere",
        "label": "Cohere",
        "url": "https://api.cohere.com/v1/models",
        "expected_codes": [200, 401],
    },
    {
        "id": "mistral",
        "label": "Mistral",
        "url": "https://api.mistral.ai/v1/models",
        "expected_codes": [200, 401],
    },
    {
        "id": "groq",
        "label": "Groq",
        "url": "https://api.groq.com/openai/v1/models",
        "expected_codes": [200, 401],
    },
    {
        "id": "together",
        "label": "Together AI",
        "url": "https://api.together.xyz/v1/models",
        "expected_codes": [200, 401],
    },
    {
        "id": "perplexity",
        "label": "Perplexity",
        "url": "https://api.perplexity.ai/models",
        "expected_codes": [200, 401, 404],
    },
    {
        "id": "replicate",
        "label": "Replicate",
        "url": "https://api.replicate.com/v1/models",
        "expected_codes": [200, 401],
    },
    {
        "id": "huggingface",
        "label": "Hugging Face",
        "url": "https://huggingface.co/api/models?limit=1",
        "expected_codes": [200, 401],
    },
]

REDIS_URL             = os.environ["UPSTASH_REDIS_URL"]
STRIPE_API_KEY        = os.environ.get("STRIPE_API_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
RESEND_API_KEY        = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL            = os.environ.get("FROM_EMAIL", "keys@llmfeed.example")
COLLECT_INTERVAL_S    = int(os.environ.get("COLLECT_INTERVAL_S", "60"))
CACHE_TTL_S           = int(os.environ.get("CACHE_TTL_S", "55"))
LOCAL_FRESH_S         = int(os.environ.get("LOCAL_FRESH_S", "50"))
MAX_DATA_AGE_S        = int(os.environ.get("MAX_DATA_AGE_S", "180"))
SCHEMA_VERSION        = "2.1.0"

stripe.api_key = STRIPE_API_KEY
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("llmfeed")
T = TypeVar("T")

def async_retry(max_attempts=3, base_delay=0.5, max_delay=4.0, timeout=8.0):
    def decorator(func: Callable[..., Awaitable[T]]):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
                except Exception as exc:
                    last_exc = exc
                    if attempt == max_attempts - 1:
                        break
                    await asyncio.sleep(random.uniform(0, min(max_delay, base_delay * (2 ** attempt))))
            raise last_exc
        return wrapper
    return decorator

class CircuitState(Enum):
    CLOSED = "closed"; OPEN = "open"; HALF_OPEN = "half_open"

class CircuitBreaker:
    def __init__(self, fail_threshold=5, cooldown=30.0):
        self.fail_threshold = fail_threshold; self.cooldown = cooldown
        self.failures = 0; self.state = CircuitState.CLOSED
        self.opened_at = 0.0; self._lock = asyncio.Lock()
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
                    self.state = CircuitState.OPEN; self.opened_at = time.monotonic()
            raise
        else:
            async with self._lock:
                self.failures = 0; self.state = CircuitState.CLOSED
            return result

redis_breaker = CircuitBreaker(fail_threshold=3, cooldown=15.0)

class ProviderProbe(BaseModel):
    provider_id: str
    provider_label: str
    status: str          # operational | degraded | unreachable
    reachable: bool
    status_code: Optional[int]
    latency_ms: Optional[float]
    probe_timestamp: datetime

    @field_validator("latency_ms")
    @classmethod
    def latency_sane(cls, v):
        if v is not None and (v < 0 or v > 120_000):
            raise ValueError(f"latency_ms implausible: {v}")
        return v

class FeedAggregate(BaseModel):
    total_providers: int
    operational_count: int
    degraded_count: int
    unreachable_count: int
    avg_latency_ms: Optional[float]
    p95_latency_ms: Optional[float]
    collection_duration_ms: float

class LLMFeedSnapshot(BaseModel):
    snapshot_id: str
    collected_at: datetime
    ttl_seconds: int
    schema_version: str = SCHEMA_VERSION
    providers: list[ProviderProbe]
    aggregate: FeedAggregate

class StalenessGuard:
    def __init__(self):
        self.last_hash = None; self.last_change_at = time.monotonic()
    def check(self, probes):
        if not probes: raise ValueError("empty probe set")
        now = datetime.now(timezone.utc)
        for p in probes:
            ts = p.probe_timestamp.astimezone(timezone.utc)
            if abs((now - ts).total_seconds()) > MAX_DATA_AGE_S:
                raise ValueError(f"probe_timestamp skewed: {ts.isoformat()}")
        h = hashlib.sha256(
            json.dumps([p.model_dump(mode="json") for p in probes],
                       sort_keys=True, default=str).encode()
        ).hexdigest()
        if h == self.last_hash:
            if time.monotonic() - self.last_change_at > MAX_DATA_AGE_S:
                raise ValueError("feed frozen")
        else:
            self.last_hash = h; self.last_change_at = time.monotonic()

guard = StalenessGuard()

def compute_aggregate(probes, duration_ms):
    lats = sorted(p.latency_ms for p in probes if p.latency_ms is not None)
    def p95(v): return round(v[max(0, int(0.95*(len(v)-1)))], 2) if v else None
    return FeedAggregate(
        total_providers=len(probes),
        operational_count=sum(1 for p in probes if p.status == "operational"),
        degraded_count=sum(1 for p in probes if p.status == "degraded"),
        unreachable_count=sum(1 for p in probes if not p.reachable),
        avg_latency_ms=round(sum(lats)/len(lats), 2) if lats else None,
        p95_latency_ms=p95(lats),
        collection_duration_ms=round(duration_ms, 2),
    )

class CollectorWatchdog:
    def __init__(self): self.last_success_ts = 0.0; self.consecutive_failures = 0
    def record_success(self): self.last_success_ts = time.time(); self.consecutive_failures = 0
    def record_failure(self): self.consecutive_failures += 1
    def seconds_since_success(self): return time.time() - self.last_success_ts if self.last_success_ts else float("inf")
    def is_healthy(self): return self.seconds_since_success() < MAX_DATA_AGE_S

watchdog = CollectorWatchdog()

class LocalCache:
    def __init__(self): self.value = None; self.written_at = 0.0
    def set(self, v): self.value = v; self.written_at = time.monotonic()
    def age(self): return time.monotonic() - self.written_at if self.value else float("inf")

local_cache = LocalCache()
_key_cache: dict[str, tuple[float, dict]] = {}
redis_client: aioredis.Redis = aioredis.from_url(REDIS_URL, decode_responses=True)

async def _redis_get(key): return await redis_client.get(key)
async def _redis_set(key, value, ex=None, nx=False): return await redis_client.set(key, value, ex=ex, nx=nx)

@async_retry(max_attempts=2, timeout=8.0)
async def probe_provider(client: httpx.AsyncClient, provider: dict) -> ProviderProbe:
    """
    Probes the provider's actual API endpoint directly.
    401 = server alive and responding (we just have no key) = operational.
    Timeout or connection error = unreachable.
    5xx = degraded.
    """
    t0 = time.monotonic()
    try:
        resp = await client.get(
            provider["url"],
            timeout=8.0,
            headers={"User-Agent": "LLMFeed/2.1 uptime-probe"},
        )
        latency_ms = round((time.monotonic() - t0) * 1000, 2)
        code = resp.status_code
        expected = provider.get("expected_codes", [200, 401])

        if code in expected:
            status = "operational"
        elif 500 <= code < 600:
            status = "degraded"
        else:
            status = "operational"  # any response = server is up

        return ProviderProbe(
            provider_id=provider["id"],
            provider_label=provider["label"],
            status=status,
            reachable=True,
            status_code=code,
            latency_ms=latency_ms,
            probe_timestamp=datetime.now(timezone.utc),
        )
    except Exception as exc:
        log.warning("probe failed %s: %s", provider["id"], exc)
        return ProviderProbe(
            provider_id=provider["id"],
            provider_label=provider["label"],
            status="unreachable",
            reachable=False,
            status_code=None,
            latency_ms=None,
            probe_timestamp=datetime.now(timezone.utc),
        )

async def collection_cycle():
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            probes = await asyncio.gather(
                *(probe_provider(client, p) for p in LLM_PROVIDERS)
            )
        duration_ms = (time.monotonic() - started) * 1000
        guard.check(probes)
        snapshot = LLMFeedSnapshot(
            snapshot_id=secrets.token_hex(16),
            collected_at=datetime.now(timezone.utc),
            ttl_seconds=CACHE_TTL_S,
            schema_version=SCHEMA_VERSION,
            providers=probes,
            aggregate=compute_aggregate(probes, duration_ms),
        ).model_dump(mode="json")
        await redis_breaker.call(_redis_set, "llmfeed:latest", json.dumps(snapshot), CACHE_TTL_S)
        local_cache.set(snapshot)
        watchdog.record_success()
        ops = snapshot["aggregate"]["operational_count"]
        log.info("collection ok: %d/%d operational, %.0fms", ops, len(probes), duration_ms)
    except Exception as exc:
        watchdog.record_failure()
        log.error("collection failed, keeping last-good cache: %s", exc)

def _hash_key(raw): return hashlib.sha256(raw.encode()).hexdigest()

async def _lookup_key(key_hash):
    cached = _key_cache.get(key_hash)
    if cached and (time.monotonic() - cached[0]) < 300.0: return cached[1]
    try:
        raw = await redis_breaker.call(_redis_get, f"apikey:{key_hash}")
    except Exception:
        return cached[1] if cached else None
    if not raw: return None
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

TIER_HOURLY = {"free": 60, "pro": 600, "enterprise": 10_000_000}
_buckets: dict[str, tuple[float, float]] = {}

def _check_quota(key_hash, tier):
    limit = TIER_HOURLY.get(tier, 60); refill_per_s = limit / 3600.0
    now = time.monotonic(); tokens, last = _buckets.get(key_hash, (float(limit), now))
    tokens = min(float(limit), tokens + (now - last) * refill_per_s)
    if tokens >= 1.0: _buckets[key_hash] = (tokens - 1.0, now); return True, 0
    _buckets[key_hash] = (tokens, now)
    return False, max(1, int(round((1.0 - tokens) / refill_per_s)))

async def get_feed_cached():
    if local_cache.value and local_cache.age() < LOCAL_FRESH_S: return local_cache.value, False
    try:
        raw = await redis_breaker.call(_redis_get, "llmfeed:latest")
        if raw:
            data = json.loads(raw); local_cache.set(data); return data, False
    except Exception: pass
    return local_cache.value, True

async def send_key_email(to_email, api_key):
    if not RESEND_API_KEY: return
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": FROM_EMAIL,
                "to": [to_email],
                "subject": "Your LLM Feed API key",
                "text": (
                    f"Your API key (shown once):\n\n    {api_key}\n\n"
                    "Usage:\n"
                    "  GET https://aota-api.onrender.com/v1/telemetry\n"
                    "  Header: X-API-Key: <your-key>\n\n"
                    "Updated every 60 seconds. Covers 9 providers."
                ),
            },
        )
        r.raise_for_status()

scheduler = AsyncIOScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await collection_cycle()
    scheduler.add_job(
        collection_cycle, "interval",
        seconds=COLLECT_INTERVAL_S, max_instances=1, coalesce=True,
    )
    scheduler.start()
    log.info("LLM feed running, collecting every %ds", COLLECT_INTERVAL_S)
    yield
    scheduler.shutdown(wait=False)
    await redis_client.aclose()

app = FastAPI(title="LLM Availability Feed", version=SCHEMA_VERSION, lifespan=lifespan)

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path in {"/health", "/v1/provision"}: return await call_next(request)
    api_key = request.headers.get("x-api-key", "")
    if not api_key.startswith("aota_"): return await call_next(request)
    key_hash = _hash_key(api_key); meta = await _lookup_key(key_hash)
    allowed, retry_after = _check_quota(key_hash, (meta or {}).get("tier", "free"))
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limited", "retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},
        )
    return await call_next(request)

@app.get("/v1/telemetry")
async def get_telemetry(response: Response, _key: dict = Depends(validate_api_key)):
    try:
        data, is_stale = await asyncio.wait_for(get_feed_cached(), timeout=2.0)
    except asyncio.TimeoutError:
        return JSONResponse(503, {"error": "feed_unavailable", "retry_after_seconds": 30}, headers={"Retry-After": "30"})
    if data is None:
        return JSONResponse(503, {"error": "no_data_yet"}, headers={"Retry-After": "60"})
    payload = LLMFeedSnapshot(**data).model_dump(mode="json")
    response.headers["X-Data-Stale"] = "true" if is_stale else "false"
    response.headers["Cache-Control"] = "public, max-age=30"
    return payload

@app.get("/health")
async def health():
    ok = watchdog.is_healthy(); present = local_cache.value is not None
    ops = (local_cache.value or {}).get("aggregate", {}).get("operational_count", 0) if present else 0
    return {
        "status": "ok" if (ok and present) else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scheduler_healthy": ok,
        "seconds_since_collection": round(watchdog.seconds_since_success(), 1),
        "cache_populated": present,
        "cache_age_seconds": round(local_cache.age(), 1) if present else None,
        "providers_operational": ops,
        "version": SCHEMA_VERSION,
    }

@app.post("/v1/provision")
async def provision(request: Request):
    if not STRIPE_WEBHOOK_SECRET: raise HTTPException(503, "provisioning not configured")
    payload = await request.body(); sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(400, "invalid signature")
    if event["type"] != "checkout.session.completed": return {"ignored": event["type"]}
    first_time = await redis_breaker.call(
        _redis_set, f"stripe:evt:{event['id']}", "1", 604800, True
    )
    if not first_time: return {"status": "already_processed"}
    session = event["data"]["object"]
    email = (session.get("customer_details") or {}).get("email") or session.get("customer_email")
    tier = (session.get("metadata") or {}).get("tier", "pro")
    if not email: raise HTTPException(422, "no customer email")
    raw_key = f"aota_{tier}_{secrets.token_hex(16)}"
    await redis_breaker.call(
        _redis_set,
        f"apikey:{_hash_key(raw_key)}",
        json.dumps({
            "tier": tier, "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "stripe_session": session.get("id"),
        }),
    )
    try:
        await send_key_email(email, raw_key)
    except Exception as exc:
        log.error("key provisioned for %s but email failed: %s", email, exc)
        return {"status": "provisioned_email_failed", "tier": tier}
    return {"status": "provisioned", "tier": tier}
