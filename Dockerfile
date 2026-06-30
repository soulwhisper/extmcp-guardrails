# syntax=docker/dockerfile:1.7
#
# ExtMcp Guardrail sidecar image.
#
# Multi-stage build:
#   1. base       — shared system deps (ca-certs, curl for healthcheck)
#   2. builder    — pip install into a clean prefix (no build tools leak)
#   3. models     — pre-download PromptGuard-2-86M so runtime never hits HF
#   4. runtime    — nonroot (65532), copy install + models + app, expose :9001
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
# Pre-download the PromptGuard-2 model into the image. This keeps runtime
# cold-start fast (no 5-10s HF download) and makes the image air-gappable.
# If the model is unavailable at build time the build still succeeds — runtime
# will lazy-download on first scan (guarded by a 30s warmup deadline).
FROM base AS models
COPY --from=builder /install /usr/local
RUN python - <<'PY' || echo "WARN: model pre-download failed; runtime will lazy-fetch"
from transformers import AutoModelForSequenceClassification, AutoTokenizer
m = "meta-llama/Prompt-Guard-2-86M"
AutoTokenizer.from_pretrained(m).save_pretrained("/models/hf/pg2")
AutoModelForSequenceClassification.from_pretrained(m).save_pretrained("/models/hf/pg2")
print("PromptGuard-2 model cached at /models/hf/pg2")
PY

# ---------- runtime ----------
FROM base AS runtime
# Non-root user matching the K8s securityContext (runAsUser 65532).
RUN useradd -u 65532 -r -s /sbin/nologin nonroot

# Copy installed Python packages.
COPY --from=builder /install /usr/local
# Copy pre-downloaded models (may be empty if the models stage warned).
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
