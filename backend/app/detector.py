"""
Local, privacy-preserving analysis engine.

HARD REQUIREMENT: everything in this module runs in-process on a backend the
enterprise controls. No email text is ever sent to an external API, because
emails may contain financial records or other confidential data. That is why
we self-host a model instead of calling a hosted LLM.

Two independent layers:
  1. AiTextDetector    - estimates how likely the prose was machine-generated.
  2. PhishingHeuristics - link + intent signals (urgency, credential/payment
                          requests). This is the layer that actually matters
                          for phishing and feeds the future link crawler.

The AI detector lazily loads a HuggingFace sequence-classification model the
first time it is needed. If torch/transformers or the weights are unavailable,
it transparently falls back to a lightweight statistical heuristic so the
service still runs (handy in dev and as a safety net in prod).
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

# Default detector. Override with env var to swap in a stronger local model
# without touching code. Anything HuggingFace-compatible that does binary
# human-vs-machine classification works.
MODEL_NAME = os.getenv("AI_DETECTOR_MODEL", "roberta-base-openai-detector")


# --------------------------------------------------------------------------- #
# AI-generated-text detection
# --------------------------------------------------------------------------- #
class AiTextDetector:
    """Estimate P(text was machine-generated) as a 0-100 confidence score."""

    def __init__(self) -> None:
        self._pipeline = None          # lazily constructed transformers pipeline
        self._tried_load = False       # so we only attempt the heavy import once
        self._fake_label_idx: Optional[int] = None

    # -- public API -------------------------------------------------------- #
    def score(self, text: str) -> dict:
        text = (text or "").strip()
        if len(text) < 40:
            # Too little signal to make a real call; don't fabricate confidence.
            return {"ai_confidence": 0, "method": "insufficient_text"}

        model_score = self._score_with_model(text)
        if model_score is not None:
            return {"ai_confidence": model_score, "method": "model"}

        return {"ai_confidence": self._score_with_heuristic(text), "method": "heuristic"}

    # -- model path -------------------------------------------------------- #
    def _score_with_model(self, text: str) -> Optional[int]:
        pipe = self._ensure_pipeline()
        if pipe is None:
            return None
        try:
            # Truncate to the model's window; long emails still score fine.
            result = pipe(text[:2000], truncation=True, top_k=None)
            # result is a list of {label, score} for each class.
            fake = self._extract_fake_probability(result)
            return int(round(fake * 100))
        except Exception:
            return None

    def _ensure_pipeline(self):
        if self._pipeline is not None or self._tried_load:
            return self._pipeline
        self._tried_load = True
        try:
            from transformers import pipeline  # heavy import, done once
            self._pipeline = pipeline(
                "text-classification",
                model=MODEL_NAME,
                truncation=True,
            )
        except Exception:
            # transformers/torch not installed, no weights, or offline.
            self._pipeline = None
        return self._pipeline

    @staticmethod
    def _extract_fake_probability(result) -> float:
        # `result` may be [[...]] or [...] depending on top_k handling.
        rows = result[0] if result and isinstance(result[0], list) else result
        for row in rows:
            label = str(row.get("label", "")).lower()
            if any(k in label for k in ("fake", "machine", "generated", "ai", "label_1")):
                return float(row["score"])
        # Fallback: assume the second class is the "machine" class.
        return float(rows[-1]["score"]) if rows else 0.0

    # -- heuristic fallback ------------------------------------------------ #
    @staticmethod
    def _score_with_heuristic(text: str) -> int:
        """
        Cheap statistical proxy for "machine-like" prose. NOT a substitute for a
        real model, just a graceful degradation. Combines:
          - low lexical diversity (LLMs repeat vocabulary)
          - low burstiness (uniform sentence lengths)
          - presence of stock LLM phrasing
        """
        words = re.findall(r"[a-zA-Z']+", text.lower())
        if len(words) < 20:
            return 0

        # 1. Lexical diversity: unique / total. Lower => more repetitive.
        diversity = len(set(words)) / len(words)
        diversity_signal = max(0.0, (0.55 - diversity) / 0.55)  # 0..1

        # 2. Burstiness: stdev of sentence lengths. Lower => more uniform/AI-like.
        sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]
        lengths = [len(s.split()) for s in sentences] or [0]
        mean = sum(lengths) / len(lengths)
        var = sum((l - mean) ** 2 for l in lengths) / len(lengths)
        std = math.sqrt(var)
        burstiness_signal = max(0.0, (6.0 - std) / 6.0)  # 0..1

        # 3. Stock LLM phrasing.
        tells = (
            "as an ai", "i hope this email finds you well", "in today's",
            "it is important to note", "i would be happy to", "rest assured",
            "kindly", "furthermore", "in conclusion", "delve",
        )
        lower = text.lower()
        phrase_hits = sum(1 for t in tells if t in lower)
        phrase_signal = min(1.0, phrase_hits / 3.0)

        score = 0.4 * diversity_signal + 0.3 * burstiness_signal + 0.3 * phrase_signal
        return int(round(min(1.0, score) * 100))


# --------------------------------------------------------------------------- #
# Phishing intent + link extraction (feeds the future crawler)
# --------------------------------------------------------------------------- #
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)

URGENCY = (
    "urgent", "immediately", "right away", "act now", "within 24 hours",
    "account suspended", "verify your account", "expire", "final notice",
    "action required", "as soon as possible",
)
CREDENTIAL = (
    "password", "verify your identity", "confirm your login", "ssn",
    "social security", "credentials", "sign in to confirm", "update your details",
)
PAYMENT = (
    "wire transfer", "gift card", "bank account", "invoice attached",
    "payment", "bitcoin", "send money", "billing information",
)


@dataclass
class PhishingResult:
    score: int = 0
    level: str = "low"
    reasons: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


class PhishingHeuristics:
    """Fast, local, explainable phishing signals. No network calls here."""

    def analyze(self, text: str) -> PhishingResult:
        lower = (text or "").lower()
        result = PhishingResult()

        result.links = self._extract_links(text)

        score = 0
        if self._hits(lower, URGENCY):
            score += 30
            result.reasons.append("Creates false urgency / pressure")
        if self._hits(lower, CREDENTIAL):
            score += 35
            result.reasons.append("Requests credentials or identity verification")
        if self._hits(lower, PAYMENT):
            score += 25
            result.reasons.append("Mentions payments / money transfer")

        # Raw IP-address links and obvious URL shorteners are classic markers.
        for url in result.links:
            if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
                score += 20
                result.reasons.append(f"Link points to a raw IP address: {url}")
            if any(s in url for s in ("bit.ly", "tinyurl", "t.co", "is.gd")):
                score += 10
                result.reasons.append(f"Uses a URL shortener (destination hidden): {url}")

        result.score = min(100, score)
        result.level = "high" if score >= 60 else "medium" if score >= 30 else "low"
        return result

    @staticmethod
    def _extract_links(text: str) -> list[str]:
        # De-duplicate while preserving order.
        seen: dict[str, None] = {}
        for m in URL_RE.findall(text or ""):
            seen.setdefault(m.rstrip(".,);"), None)
        return list(seen.keys())

    @staticmethod
    def _hits(lower: str, phrases) -> bool:
        return any(p in lower for p in phrases)


# Module-level singletons so the model loads once per process, not per request.
ai_detector = AiTextDetector()
phishing_heuristics = PhishingHeuristics()
