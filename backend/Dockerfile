# syntax=docker/dockerfile:1
#
# Deployment-agnostic image for the AI Email Security Shield backend.
# The SAME image runs in a customer VPC or fully on-prem / air-gapped.
#
#   Heuristic-only (small, fast, no model download):
#     docker build -t shield-backend ./backend
#
#   With the local model baked in (no internet needed at runtime):
#     docker build --build-arg WITH_MODEL=true -t shield-backend ./backend
#
FROM python:3.12-slim AS base

# Don't write .pyc files; flush stdout/stderr immediately for clean container logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # HuggingFace caches weights here; we pre-populate it at build time.
    HF_HOME=/models \
    AI_DETECTOR_MODEL=roberta-base-openai-detector

WORKDIR /app

# --- core dependencies (cached layer) ---
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- optional model layer ---
# WITH_MODEL=true installs torch/transformers AND downloads the weights into the
# image, so the running container makes zero outbound network calls.
ARG WITH_MODEL=false
COPY requirements-model.txt .
RUN if [ "$WITH_MODEL" = "true" ]; then \
        pip install --no-cache-dir -r requirements-model.txt && \
        python -c "from transformers import pipeline; pipeline('text-classification', model='$AI_DETECTOR_MODEL')" ; \
    fi

# --- application code ---
COPY . .

# Run as a non-root user (enterprise security baseline).
RUN useradd --create-home --uid 10001 appuser && \
    chown -R appuser:appuser /app /models 2>/dev/null || true
USER appuser

EXPOSE 8000

# Container-native healthcheck hits the same /health route the orchestrator uses.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
