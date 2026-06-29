import hashlib
from collections import OrderedDict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.detector import ai_detector, phishing_engine

# Bounded in-process LRU cache keyed by a hash of the email body. Re-opening the
# same email returns instantly and never re-runs the (slow) model. We store only
# the hash, not the text, so no email content lingers in memory beyond the call.
_CACHE_MAX = 512
_verdict_cache: "OrderedDict[str, dict]" = OrderedDict()


def _cache_key(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()

app = FastAPI(title="AI Email Security Shield", version="0.2.0")

# CORS so the Outlook task pane (served from https://localhost:3000) can reach
# this API. Keep this list tight in production - "*" with allow_credentials is
# rejected by browsers anyway and is a security smell.
ALLOWED_ORIGINS = [
    "https://localhost:3000",
    "https://localhost:5173",  # default Vite dev port
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


class EmailPayload(BaseModel):
    text: str


@app.get("/health")
async def health():
    """Liveness probe + which detection path is active for each detector."""
    return {
        "status": "ok",
        "ai_engine": "model" if ai_detector.model_available else "heuristic",
        "phishing_engine": "model+heuristics" if phishing_engine.model_available else "heuristics",
    }


@app.post("/api/analyze")
async def analyze_email(payload: EmailPayload):
    """
    Analyze raw email text fully in-process. No text leaves this server.
    Returns an AI-generation estimate plus explainable phishing signals.
    """
    key = _cache_key(payload.text)
    cached = _verdict_cache.get(key)
    if cached is not None:
        _verdict_cache.move_to_end(key)  # mark as recently used
        return {**cached, "cached": True}

    ai = ai_detector.score(payload.text)
    phish = phishing_engine.analyze(payload.text)

    result = {
        "status": "success",
        "ai_confidence": ai["ai_confidence"],
        "ai_method": ai["method"],
        "phishing": {
            "score": phish.score,
            "level": phish.level,
            "method": phish.method,
            "reasons": phish.reasons,
            "links": phish.links,  # handed to the link crawler in Phase 2
        },
    }

    _verdict_cache[key] = result
    if len(_verdict_cache) > _CACHE_MAX:
        _verdict_cache.popitem(last=False)  # evict least-recently-used

    return {**result, "cached": False}
