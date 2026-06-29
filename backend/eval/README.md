# Detection eval harness

Measures how well the local detectors separate positives from negatives on a
labeled dataset. Runs the **real** `ai_detector` / `phishing_engine` in-process —
no server, no network, no extra dependencies.

## Run it

From the `backend/` directory:

```powershell
python -m eval.run_eval                      # both tasks, sample dataset
python -m eval.run_eval --task phishing      # one task
python -m eval.run_eval --data eval/my_set.csv --thresholds 30,50,60,70
```

To evaluate the **model** path (not just heuristics), set the same env vars you
use to run the server before invoking the harness:

```powershell
$env:PHISHING_MODEL = "ealvaradob/bert-finetuned-phishing"
$env:AI_DETECTOR_MODEL = "Hello-SimpleAI/chatgpt-detector-roberta"
python -m eval.run_eval
```

## Compare two models objectively

```powershell
$env:PHISHING_MODEL = "model-a"; python -m eval.run_eval --task phishing
$env:PHISHING_MODEL = "model-b"; python -m eval.run_eval --task phishing
```
Pick the one with higher ROC-AUC and lower FPR at your chosen threshold.

## Dataset format

`sample_emails.csv` is a **seed** — replace/expand it with your own labeled mail.

| column        | meaning                                            |
|---------------|----------------------------------------------------|
| `text`        | the email body (quote it; commas/newlines are fine)|
| `is_phishing` | `1` phishing, `0` legitimate, blank = not labeled  |
| `is_ai`       | `1` AI-written, `0` human-written, blank = not labeled |

A row can be labeled for one task, the other, or both.

## Reading the output

- **ROC-AUC** — overall separability. 0.5 = random, 1.0 = perfect. A high score
  on the seed set is **not** meaningful: the seed text overlaps the heuristic's
  keywords, so it grades itself. Trust it only on *your own* held-out emails.
- **FPR (false positive rate)** — fraction of legitimate emails wrongly flagged.
  This is the metric that matters most: a false positive burns user trust. Pick
  the **highest threshold** that still gives acceptable recall, to keep FPR low.

## Important: collect real data

The seed set is tiny and easy. To get a truthful picture — and to actually fix
AI detection — add **dozens of your own real emails**, especially:
- ChatGPT/GPT-4-drafted emails you wrote (`is_ai=1`) vs. ones you wrote yourself
  (`is_ai=0`). These are the cases the current detector fails on.
- Real phishing samples you've received vs. legitimate business mail.

This labeled set is also the seed corpus for the future on-prem fine-tuning loop.
