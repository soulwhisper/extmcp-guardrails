"""Runtime configuration, environment-driven with sane homelab defaults.

All knobs are environment-variable configurable so the same image serves dev,
homelab and (with resource bumps) production. Defaults encode the design's
"single-user Homelab" tradeoffs: PromptGuard always on, AgentAlignment as an
opt-in second stage, fail-closed, 2Gi memory budget.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .models import FailureMode, HumanReviewMode


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class GuardrailConfig:
    """Full runtime configuration for :class:`GuardrailEngine`."""

    # --- Failure / aggregation policy ---
    failure_mode: FailureMode = FailureMode.FAIL_CLOSED
    human_review_mode: HumanReviewMode = HumanReviewMode.PASS

    # --- Content budget ---
    # Max bytes of text fed to any scanner. Tool output beyond this is
    # truncated and flagged ``truncated=true`` in the audit span.
    max_content_bytes: int = 32 * 1024

    # --- Scanner enable flags ---
    enable_regex_scanner: bool = True
    enable_llamafirewall: bool = True
    # AgentAlignment is LLM-based (~300-800ms). Default off for homelab; only
    # triggered as a second stage when PromptGuard is suspicious.
    enable_agent_alignment: bool = False

    # --- Invariant ---
    invariant_window: int = 64

    # --- Timing ---
    # Per-engine-call deadline. Exceeded -> treated per failure_mode. Keep
    # sidecar < gateway so the sidecar decides first.
    scanner_timeout_ms: int = 500

    # --- Networking ---
    listen_addr: str = "[::]:9001"
    server_max_workers: int = 8

    # --- Observability ---
    otel_endpoint: str | None = None
    otel_service_name: str = "extmcp-guardrail"
    audit_log_path: str | None = None

    # --- Misc ---
    dry_run: bool = False
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> GuardrailConfig:
        fm = os.environ.get("FAILURE_MODE", "failClosed")
        try:
            failure_mode = FailureMode(fm)
        except ValueError:
            failure_mode = FailureMode.FAIL_CLOSED

        hr = os.environ.get("HUMAN_REVIEW_MODE", "pass")
        try:
            human_review_mode = HumanReviewMode(hr)
        except ValueError:
            human_review_mode = HumanReviewMode.PASS

        otel = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or None

        return cls(
            failure_mode=failure_mode,
            human_review_mode=human_review_mode,
            max_content_bytes=_env_int("MAX_CONTENT_BYTES", 32 * 1024),
            enable_regex_scanner=_env_bool("ENABLE_REGEX_SCANNER", True),
            enable_llamafirewall=_env_bool("ENABLE_LLAMAFIREWALL", True),
            enable_agent_alignment=_env_bool("ENABLE_AGENT_ALIGNMENT", False),
            invariant_window=_env_int("INVARIANT_WINDOW", 64),
            scanner_timeout_ms=_env_int("SCANNER_TIMEOUT_MS", 500),
            listen_addr=os.environ.get("LISTEN_ADDR", "[::]:9001"),
            server_max_workers=_env_int("SERVER_MAX_WORKERS", 8),
            otel_endpoint=otel,
            otel_service_name=os.environ.get("OTEL_SERVICE_NAME", "extmcp-guardrail"),
            audit_log_path=os.environ.get("AUDIT_LOG_PATH") or None,
            dry_run=_env_bool("GUARDRAIL_DRY_RUN", False),
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        )
