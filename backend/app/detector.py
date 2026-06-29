"""
Local, privacy-preserving analysis engine.

HARD REQUIREMENT: everything in this module runs in-process on a backend the
enterprise controls. No email text is ever sent to an external API, because
emails may contain financial records or other confidential data. That is why
we self-host models instead of calling a hosted LLM.

Three layers, each independent and each degrading gracefully:
  1. AiTextDetector  - estimates how likely the prose was machine-generated.
  2. PhishingEngine  - blends a fine-tuned phishing CLASSIFIER with explainable
                       rule-based HEURISTICS (urgency, credential/payment intent,
                       link analysis). The heuristics also feed the future crawler.

Both model-backed detectors share `_LazyTextClassifier`, which lazily loads a
HuggingFace text-classification pipeline the first time it is needed. If
torch/transformers or the weights are unavailable, the detector transparently
falls back to a lightweight statistical/rule-based path so the service always
runs (handy in dev and as a safety net in prod).
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Optional

# --- configurable local models (swap via env, no code change) -------------- #
# AI-generated-text detector. Default is GPT-2-era and weak on modern LLMs;
# point this at a MAGE/DeTeCtive-style multi-LLM detector for real accuracy.
AI_MODEL = os.getenv("AI_DETECTOR_MODEL", "roberta-base-openai-detector")
# Phishing classifier. Recommended: a BERT/DeBERTa model fine-tuned on
# email+URL phishing (e.g. ealvaradob/bert-finetuned-phishing). Empty disables
# the model path and falls back to heuristics only.
PHISHING_MODEL = os.getenv("PHISHING_MODEL", "")


# --------------------------------------------------------------------------- #
# Email preprocessing
# --------------------------------------------------------------------------- #
# Markers that begin a quoted reply / forwarded chain; everything after is the
# previous author's text, not what the current sender wrote.
_QUOTE_BOUNDARY = re.compile(
    r"^\s*(>|on .+ wrote:|-{2,}\s*original message|from:\s|sent from my )",
    re.IGNORECASE | re.MULTILINE,
)


def _strip_email_noise(text: str) -> str:
    """
    Reduce an email to the current sender's authored prose so AI-detection scores
    the right thing. Drops quoted reply chains and trailing signature blocks.
    Conservative: if stripping would leave almost nothing, keep the original.
    """
    if not text:
        return ""

    # Cut everything from the first quoted-reply boundary onward.
    m = _QUOTE_BOUNDARY.search(text)
    body = text[: m.start()] if m else text

    # Drop a trailing signature delimited by a standalone "--" line.
    parts = re.split(r"\n--\s*\n", body, maxsplit=1)
    body = parts[0]

    body = body.strip()
    # Don't over-strip: if we gutted the message, fall back to the original.
    return body if len(body) >= 40 else text.strip()


# --------------------------------------------------------------------------- #
# Shared lazy HuggingFace classifier loader
# --------------------------------------------------------------------------- #
class _LazyTextClassifier:
    """
    Wraps a HuggingFace `text-classification` pipeline. The heavy import + model
    load happens once, on first use. Returns the probability of whichever class
    matches `positive_labels`, or None if the model can't be loaded.
    """

    def __init__(self, model_name: str, positive_labels: tuple[str, ...]) -> None:
        self._model_name = model_name
        self._positive_labels = positive_labels
        self._pipeline = None
        self._tried_load = False

    @property
    def available(self) -> bool:
        return self._ensure() is not None

    def positive_probability(self, text: str) -> Optional[float]:
        """0.0-1.0 probability of the positive class, or None if unavailable."""
        pipe = self._ensure()
        if pipe is None:
            return None
        try:
            result = pipe(text[:2000], truncation=True, top_k=None)
            rows = result[0] if result and isinstance(result[0], list) else result
            for row in rows:
                if any(k in str(row.get("label", "")).lower() for k in self._positive_labels):
                    return float(row["score"])
            # Fallback: assume the last class is the positive one.
            return float(rows[-1]["score"]) if rows else None
        except Exception:
            return None

    def _ensure(self):
        if self._pipeline is not None or self._tried_load or not self._model_name:
            return self._pipeline
        self._tried_load = True
        try:
            from transformers import pipeline  # heavy import, done once
            self._pipeline = pipeline(
                "text-classification", model=self._model_name, truncation=True
            )
        except Exception:
            self._pipeline = None  # transformers/torch missing, no weights, offline
        return self._pipeline


# --------------------------------------------------------------------------- #
# AI-generated-text detection
# --------------------------------------------------------------------------- #
class AiTextDetector:
    """Estimate P(text was machine-generated) as a 0-100 confidence score."""

    # The fine-tuned classifier (HC3-era) is weak on modern GPT-4 *emails*, while
    # the stylometric heuristic catches LLM-email phrasing the classifier misses.
    # We ensemble both rather than trusting either alone.
    MODEL_WEIGHT = 0.55
    HEURISTIC_WEIGHT = 0.45

    def __init__(self) -> None:
        self._model = _LazyTextClassifier(
            AI_MODEL, positive_labels=("fake", "machine", "generated", "ai", "label_1")
        )

    @property
    def model_available(self) -> bool:
        return self._model.available

    def score(self, text: str) -> dict:
        # Score the actual authored content, not quoted replies / signatures,
        # which otherwise dilute or confuse both signals.
        clean = _strip_email_noise((text or "").strip())
        if len(clean) < 40:
            # Too little signal to make a real call; don't fabricate confidence.
            return {"ai_confidence": 0, "method": "insufficient_text"}

        heuristic = self._score_with_heuristic(clean)  # 0-100
        prob = self._model.positive_probability(clean)
        if prob is None:
            return {"ai_confidence": heuristic, "method": "heuristic"}

        model_score = prob * 100
        blended = self.MODEL_WEIGHT * model_score + self.HEURISTIC_WEIGHT * heuristic
        return {"ai_confidence": int(round(blended)), "method": "model+heuristic"}

    @staticmethod
    def _score_with_heuristic(text: str) -> int:
        """
        Cheap statistical proxy for "machine-like" prose. NOT a substitute for a
        real model, just a graceful degradation. Combines low lexical diversity,
        low burstiness (uniform sentence lengths), and stock LLM phrasing.
        """
        words = re.findall(r"[a-zA-Z']+", text.lower())
        if len(words) < 20:
            return 0

        diversity = len(set(words)) / len(words)
        diversity_signal = max(0.0, (0.55 - diversity) / 0.55)

        sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]
        lengths = [len(s.split()) for s in sentences] or [0]
        mean = sum(lengths) / len(lengths)
        std = math.sqrt(sum((l - mean) ** 2 for l in lengths) / len(lengths))
        burstiness_signal = max(0.0, (6.0 - std) / 6.0)

        # LLM-email phrasing. These are exactly the constructions ChatGPT reaches
        # for in email/business prose and a human rarely stacks several of.
        tells = (
            "as an ai", "i hope this email finds you well",
            "i hope this message finds you well", "in today's",
            "it is important to note", "i would be happy to", "rest assured",
            "kindly", "furthermore", "moreover", "in conclusion", "delve",
            "i am writing to", "please do not hesitate", "should you have any questions",
            "at your earliest convenience", "thank you for your understanding",
            "i look forward to", "streamline", "navigate the", "in the realm of",
        )
        lower = text.lower()
        phrase_signal = min(1.0, sum(1 for t in tells if t in lower) / 3.0)

        score = 0.4 * diversity_signal + 0.3 * burstiness_signal + 0.3 * phrase_signal
        return int(round(min(1.0, score) * 100))


# --------------------------------------------------------------------------- #
# Phishing: rule-based heuristics (always on) + optional ML classifier
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
    method: str = "heuristics"
    reasons: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


class PhishingHeuristics:
    """Fast, local, explainable phishing signals. No network calls here."""

    def analyze(self, text: str) -> tuple[int, list[str], list[str]]:
        """Returns (heuristic_score 0-100, reasons, links)."""
        lower = (text or "").lower()
        reasons: list[str] = []
        links = self._extract_links(text)

        score = 0
        if self._hits(lower, URGENCY):
            score += 30
            reasons.append("Creates false urgency / pressure")
        if self._hits(lower, CREDENTIAL):
            score += 35
            reasons.append("Requests credentials or identity verification")
        if self._hits(lower, PAYMENT):
            score += 25
            reasons.append("Mentions payments / money transfer")

        for url in links:
            if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
                score += 20
                reasons.append(f"Link points to a raw IP address: {url}")
            if any(s in url for s in ("bit.ly", "tinyurl", "t.co", "is.gd")):
                score += 10
                reasons.append(f"Uses a URL shortener (destination hidden): {url}")

        return min(100, score), reasons, links

    @staticmethod
    def _extract_links(text: str) -> list[str]:
        seen: dict[str, None] = {}
        for m in URL_RE.findall(text or ""):
            seen.setdefault(m.rstrip(".,);"), None)
        return list(seen.keys())

    @staticmethod
    def _hits(lower: str, phrases) -> bool:
        return any(p in lower for p in phrases)


class PhishingEngine:
    """
    Combines the rule-based heuristics (always available, explainable, and the
    source of links for the crawler) with an optional fine-tuned classifier.

    Blend: when the classifier is available, the final score is a weighted mix
    that leans on the model but is floored by strong rule signals, so an obvious
    credential-harvest never gets talked down by a confident-but-wrong model.
    """

    MODEL_WEIGHT = 0.6
    HEURISTIC_WEIGHT = 0.4

    def __init__(self) -> None:
        self._heuristics = PhishingHeuristics()
        self._model = _LazyTextClassifier(
            PHISHING_MODEL, positive_labels=("phishing", "phish", "malicious", "spam", "label_1")
        )

    @property
    def model_available(self) -> bool:
        return self._model.available

    def analyze(self, text: str) -> PhishingResult:
        heur_score, reasons, links = self._heuristics.analyze(text)

        model_prob = self._model.positive_probability(text or "")
        if model_prob is None:
            final = heur_score
            method = "heuristics"
        else:
            model_score = int(round(model_prob * 100))
            blended = self.MODEL_WEIGHT * model_score + self.HEURISTIC_WEIGHT * heur_score
            # Never let the model drag a strong rule signal below itself.
            final = int(round(max(blended, heur_score)))
            method = "model+heuristics"
            reasons.append(f"Classifier phishing probability: {model_score}%")

        final = min(100, final)
        level = "high" if final >= 60 else "medium" if final >= 30 else "low"
        return PhishingResult(
            score=final, level=level, method=method, reasons=reasons, links=links
        )


# Module-level singletons so each model loads once per process, not per request.
ai_detector = AiTextDetector()
phishing_engine = PhishingEngine()
