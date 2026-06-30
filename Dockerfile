# syntax=docker/dockerfile:1.7
#
# ExtMcp Guardrail sidecar image.
#
# Multi-stage build:
#   1. base       — shared system deps (ca-certs, curl for healthcheck)
#   2. builder    — pip install into a clean prefix (no build tools leak)
#   3. models     — pre-download Llama-Prompt-Guard-2-86M so runtime never hits HF
#   4. runtime    — nonroot (65532), copy install + models + app, expose :9001
#
# Llama-Prompt-Guard-2-86M is a GATED model on HuggingFace. To pre-download it
# at build time you MUST:
#   1. Accept the license at https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
#   2. Create a HuggingFace access token (read permission) at
#      https://huggingface.co/settings/tokens
#   3. Pass the token as a BuildKit secret named `hf_token`:
#        docker build --secret id=hf_token,env=HF_TOKEN .
#      or in GitHub Actions via `secrets:` in docker/build-push-action.
#
# If the token is absent the build still succeeds — the models stage is
# skipped and the runtime lazy-fetches on first scan (which also needs
# HF_TOKEN set as an env var, see below).
#
# Final image ~1.8-2.2GB (torch CPU + model weights). For a slimmer image swap
# to ONNX PromptGuard + onnxruntime and drop torch entirely (see ARCHITECTURE.md
# "Slim image" variant).

ARG PY_VERSION=3.11-slim

# ---------- base ----------
FROM python:${PY_VERSION} AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/models/hf \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# ---------- builder ----------
FROM base AS builder
WORKDIR /build
COPY requirements.txt .
# Install into /install prefix so we can copy just the artifacts to runtime.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefix=/install -r requirements.txt

# ---------- models ----------
# Pre-download the Llama-Prompt-Guard-2 model into the image. This keeps runtime
# cold-start fast (no 5-10s HF download) and makes the image air-gappable.
#
# The model is GATED — the token is passed as a BuildKit secret (mounted at
# /run/secrets/hf_token) so it never appears in the image layers or build
# history. If the secret is absent or SKIP_MODEL_DOWNLOAD=1, the step is
# skipped and the runtime lazy-fetches on first scan.
FROM base AS models
ARG SKIP_MODEL_DOWNLOAD=0
COPY --from=builder /install /usr/local
RUN --mount=type=secret,id=hf_token,required=false \
    set -e; \
    TOKEN=""; \
    [ -f /run/secrets/hf_token ] && TOKEN="$(cat /run/secrets/hf_token)"; \
    if [ "${SKIP_MODEL_DOWNLOAD}" = "1" ] || [ -z "${TOKEN}" ]; then \
        echo "SKIP: Llama-Prompt-Guard-2 pre-download (SKIP_MODEL_DOWNLOAD=${SKIP_MODEL_DOWNLOAD}, HF_TOKEN set=$([ -n "${TOKEN}" ] && echo yes || echo no))"; \
        echo "      Runtime will lazy-fetch on first scan (requires HF_TOKEN env var)."; \
        exit 0; \
    fi; \
    export HF_TOKEN="${TOKEN}"; \
    python - <<'PY'
from transformers import AutoModelForSequenceClassification, AutoTokenizer
m = "meta-llama/Llama-Prompt-Guard-2-86M"
# token=True picks up HF_TOKEN from the environment.
AutoTokenizer.from_pretrained(m, token=True).save_pretrained("/models/hf/pg2")
AutoModelForSequenceClassification.from_pretrained(m, token=True).save_pretrained("/models/hf/pg2")
print("Llama-Prompt-Guard-2 model cached at /models/hf/pg2")
PY

# ---------- runtime ----------
FROM base AS runtime
# Non-root user matching the K8s securityContext (runAsUser 65532).
RUN useradd -u 65532 -r -s /sbin/nologin nonroot

# Copy installed Python packages.
COPY --from=builder /install /usr/local
# Copy pre-downloaded models (may be empty if the models stage was skipped).
COPY --from=models /models/hf /models/hf

WORKDIR /app
# Application code. proto/ contains the generated stubs (committed) so we do
# not need grpcio-tools in the runtime image.
COPY proto/ext_mcp_pb2.py proto/ext_mcp_pb2_grpc.py /app/proto/
COPY guardrails/ /app/guardrails/
COPY server.py /app/server.py

ENV HF_HOME=/models/hf \
    PYTHONPATH=/app \
    LISTEN_ADDR="[::]:9001"
# HF_TOKEN is NOT baked in — operators set it at runtime (K8s secret env,
# docker run -e HF_TOKEN=...) so the token never lives in the image. It is
# needed for lazy-fetch if the model wasn't pre-downloaded at build time, and
# for any model LlamaFirewall loads at runtime.

USER 65532:65532
EXPOSE 9001

# grpcurl is not installed; use Python's grpc health probe instead so the
# HEALTHCHECK has zero extra system deps.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 --start-period=20s \
    CMD python -c "import grpc; from grpc_health.v1 import health_pb2, health_pb2_grpc; \
    ch=grpc.insecure_channel('localhost:9001'); stub=health_pb2_grpc.HealthStub(ch); \
    r=stub.Check(health_pb2.HealthCheckRequest(service='')); \
    exit(0 if r.status==1 else 1)" || exit 1

ENTRYPOINT ["python", "server.py"]
