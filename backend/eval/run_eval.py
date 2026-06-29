"""
Local evaluation harness for the detection engine.

Runs a labeled dataset through the real detectors (in-process, no server, no
network) and reports how well each one separates positives from negatives.

Two design priorities:
  * FALSE POSITIVE RATE is surfaced first. In this product a false positive means
    a legitimate business email got flagged, which destroys user trust faster
    than the occasional miss. Tune your threshold to an acceptable FPR.
  * NO new dependencies. Metrics (including ROC-AUC) are computed with the stdlib
    so this runs in the same slim environment as the backend.

Usage (from the backend/ directory):
    python -m eval.run_eval                         # both tasks, sample data
    python -m eval.run_eval --task phishing
    python -m eval.run_eval --data eval/my_set.csv --thresholds 30,50,60,70

Compare two models objectively:
    $env:PHISHING_MODEL = "model-a"; python -m eval.run_eval --task phishing
    $env:PHISHING_MODEL = "model-b"; python -m eval.run_eval --task phishing

Dataset format (CSV with header):
    text,is_phishing,is_ai
  - text:        the email body (quote it; commas/newlines are fine)
  - is_phishing: 1 phishing, 0 legitimate, blank = not labeled for this task
  - is_ai:       1 AI-written, 0 human-written, blank = not labeled
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from dataclasses import dataclass

# Make `app` importable whether run as a module or a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# NOTE: app.detector reads the model names from the environment at import time,
# so we import it *inside* main() — after any --ai-model/--phishing-model flags
# have been pushed into os.environ. Don't import it at module top level.

DEFAULT_DATA = os.path.join(os.path.dirname(__file__), "sample_emails.csv")
DEFAULT_THRESHOLDS = (30, 50, 60, 70)


@dataclass
class Example:
    text: str
    label: int  # 1 positive, 0 negative


# --------------------------------------------------------------------------- #
# Metrics (stdlib only)
# --------------------------------------------------------------------------- #
def confusion(scores: list[float], labels: list[int], threshold: float):
    tp = fp = tn = fn = 0
    for s, y in zip(scores, labels):
        pred = 1 if s >= threshold else 0
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 0:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def roc_auc(scores: list[float], labels: list[int]) -> float:
    """Rank-based AUC (Mann-Whitney U) with tie handling. 0.5 == random."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return float("nan")
    # Average ranks over all scores (1-indexed), splitting ties.
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    rank_sum_pos = sum(ranks[i] for i in range(len(scores)) if labels[i] == 1)
    n_pos, n_neg = len(pos), len(neg)
    return (rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def evaluate(task: str, scorer, examples: list[Example], thresholds, engine_label: str):
    print(f"\n{'='*72}\n  {task.upper()} DETECTION   (engine: {engine_label})")
    print(f"  {len(examples)} labeled examples "
          f"({sum(e.label for e in examples)} positive / "
          f"{sum(1 - e.label for e in examples)} negative)\n{'='*72}")

    if len(examples) < 2:
        print("  Not enough labeled examples for this task. Add rows to the CSV.")
        return

    scores = [float(scorer(e.text)) for e in examples]
    labels = [e.label for e in examples]

    auc = roc_auc(scores, labels)
    print(f"  ROC-AUC: {auc:.3f}   (0.5 = random, 1.0 = perfect)\n")

    header = f"  {'thresh':>6} | {'acc':>5} | {'prec':>5} | {'recall':>6} | {'F1':>5} | {'FPR':>5} | TP FP TN FN"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for t in thresholds:
        tp, fp, tn, fn = confusion(scores, labels, t)
        prec = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * prec * recall, prec + recall)
        acc = _safe_div(tp + tn, tp + fp + tn + fn)
        fpr = _safe_div(fp, fp + tn)
        flag = "  <-- legit flagged!" if fpr > 0.10 else ""
        print(f"  {t:>6} | {acc:>5.2f} | {prec:>5.2f} | {recall:>6.2f} | "
              f"{f1:>5.2f} | {fpr:>5.2f} | {tp:>2} {fp:>2} {tn:>2} {fn:>2}{flag}")
    print("\n  FPR = fraction of legitimate emails wrongly flagged. Keep this low;"
          "\n  pick the highest threshold that still gives acceptable recall.")


def load(path: str):
    ai, phish = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            text = (row.get("text") or "").strip()
            if not text:
                continue
            if (v := (row.get("is_ai") or "").strip()) in ("0", "1"):
                ai.append(Example(text, int(v)))
            if (v := (row.get("is_phishing") or "").strip()) in ("0", "1"):
                phish.append(Example(text, int(v)))
    return ai, phish


def main() -> None:
    p = argparse.ArgumentParser(description="Evaluate the local detection engine.")
    p.add_argument("--data", default=DEFAULT_DATA, help="Labeled CSV dataset.")
    p.add_argument("--task", choices=("ai", "phishing", "both"), default="both")
    p.add_argument("--thresholds", default=",".join(map(str, DEFAULT_THRESHOLDS)),
                   help="Comma-separated decision thresholds to sweep.")
    p.add_argument("--ai-model", help="Override AI_DETECTOR_MODEL for this run.")
    p.add_argument("--phishing-model", help="Override PHISHING_MODEL for this run.")
    args = p.parse_args()

    # Push model overrides into the environment BEFORE importing the detectors,
    # since they bind their model names at import time.
    if args.ai_model is not None:
        os.environ["AI_DETECTOR_MODEL"] = args.ai_model
    if args.phishing_model is not None:
        os.environ["PHISHING_MODEL"] = args.phishing_model
    from app.detector import ai_detector, phishing_engine  # noqa: E402

    thresholds = [int(t) for t in args.thresholds.split(",") if t.strip()]
    ai_examples, phish_examples = load(args.data)

    if args.task in ("ai", "both"):
        evaluate(
            "ai", lambda t: ai_detector.score(t)["ai_confidence"], ai_examples,
            thresholds, "model+heuristic" if ai_detector.model_available else "heuristic",
        )
    if args.task in ("phishing", "both"):
        evaluate(
            "phishing", lambda t: phishing_engine.analyze(t).score, phish_examples,
            thresholds, "model+heuristics" if phishing_engine.model_available else "heuristics",
        )


if __name__ == "__main__":
    main()
