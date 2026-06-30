"""Content scanners — the semantic layer of the guardrail.

A scanner takes a chunk of text plus an MCP role ("user" | "tool" |
"assistant") and returns a :class:`ScanResult`. The engine composes scanners
per phase:

* Request side (``tools/call`` params): ``RegexScanner`` (hidden ASCII / PII /
  secrets) + LlamaFirewall (PromptGuard injection + CodeShield).
* Response side (tool output / tool descriptions): LlamaFirewall PromptGuard
  for indirect injection, optionally AgentAlignment as a second stage when
  PromptGuard flags suspicion.

The LlamaFirewall wrapper imports ``llamafirewall`` lazily so the package
remains importable without the (heavy) model stack installed.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .models import ScanOutcome, ScanResult

# ---------------------------------------------------------------------------
# Scanner protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Scanner(Protocol):
    """A content scanner.

    Implementations MUST be safe to call concurrently. Synchronous ML
    inference should be wrapped in ``asyncio.to_thread`` by the implementation
    so the asyncio event loop is never blocked.
    """

    name: str

    async def scan(
        self,
        content: str,
        role: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> ScanResult:  # pragma: no cover - protocol
        ...


# ---------------------------------------------------------------------------
# Regex scanner — hidden ASCII, PII, secrets. No ML deps, fully unit-testable.
# ---------------------------------------------------------------------------

# Hidden ASCII: control chars (except tab/newline/CR) and Unicode control
# pictures / RTL override / zero-width chars used to hide instructions.
_HIDDEN_ASCII = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"
    r"\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]"
)

# Common secret shapes (conservative — false-positive-averse).
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_PAT = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")
_GITLAB_PAT = re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
_GENERIC_HIGH_ENTROPY = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

# PII (very conservative; tune per deployment).
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_CREDIT_CARD = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


@dataclass
class Pattern:
    """A named regex with a per-pattern outcome."""

    name: str
    regex: re.Pattern[str]
    outcome: ScanOutcome
    reason: str
    score: float = 0.0

    def evaluate(self, content: str) -> ScanResult | None:
        m = self.regex.search(content)
        if m is None:
            return None
        return ScanResult(
            scanner=f"regex:{self.name}",
            outcome=self.outcome,
            reason=f"{self.reason} (match={m.group(0)[:32]!r})",
            score=self.score,
        )


def default_patterns() -> list[Pattern]:
    """Built-in pattern set, ordered so BLOCK-worthy hits win on first-match."""
    return [
        Pattern(
            "hidden_ascii", _HIDDEN_ASCII, ScanOutcome.BLOCK, "hidden/control unicode detected", 0.9
        ),
        Pattern(
            "private_key", _PRIVATE_KEY, ScanOutcome.BLOCK, "private key material in payload", 0.99
        ),
        Pattern("aws_access_key", _AWS_KEY, ScanOutcome.BLOCK, "AWS access key id", 0.95),
        Pattern("github_pat", _GITHUB_PAT, ScanOutcome.BLOCK, "GitHub personal access token", 0.95),
        Pattern("gitlab_pat", _GITLAB_PAT, ScanOutcome.BLOCK, "GitLab personal access token", 0.95),
        Pattern("slack_token", _SLACK_TOKEN, ScanOutcome.BLOCK, "Slack token", 0.95),
        Pattern(
            "high_entropy_blob",
            _GENERIC_HIGH_ENTROPY,
            ScanOutcome.HUMAN_REVIEW,
            "high-entropy blob (possible secret)",
            0.6,
        ),
        Pattern(
            "credit_card",
            _CREDIT_CARD,
            ScanOutcome.HUMAN_REVIEW,
            "possible credit-card number",
            0.7,
        ),
        Pattern("email", _EMAIL, ScanOutcome.ALLOW, "email address (PII, redact downstream)", 0.2),
    ]


class RegexScanner:
    """Deterministic pattern scanner.

    First-match wins (patterns are evaluated in list order). This makes the
    pattern list a priority chain: put BLOCK patterns before HUMAN_REVIEW
    patterns before ALLOW/redact patterns.
    """

    name = "regex"

    def __init__(self, patterns: Sequence[Pattern] | None = None):
        self._patterns: list[Pattern] = (
            list(patterns) if patterns is not None else default_patterns()
        )

    @property
    def patterns(self) -> tuple[Pattern, ...]:
        return tuple(self._patterns)

    async def scan(
        self,
        content: str,
        role: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> ScanResult:
        for pat in self._patterns:
            hit = pat.evaluate(content)
            if hit is not None:
                return hit
        return ScanResult.allow(self.name)


# ---------------------------------------------------------------------------
# LlamaFirewall wrapper — lazy import; sync scan bridged via to_thread.
# ---------------------------------------------------------------------------

# Map our role strings to llamafirewall's Role enum values lazily.
_ROLE_MAP: dict[str, str] = {
    "user": "USER",
    "tool": "TOOL",
    "assistant": "ASSISTANT",
    "system": "SYSTEM",
}


@dataclass
class LlamaFirewallScanner:
    """Wraps ``llamafirewall.LlamaFirewall``.

    ``lf`` is the live LlamaFirewall instance. ``scanners_by_role`` maps our
    role string to the list of llamafirewall ``ScannerType`` to enable for
    that role; roles not present are not scanned (return ALLOW).

    The real ``llamafirewall`` package is imported in :meth:`from_env` /
    :meth:`from_default`, never at module import time, so the rest of the
    package works without torch/transformers installed.
    """

    lf: Any
    scanners_by_role: Mapping[str, Sequence[str]] = field(default_factory=dict)
    name: str = "llamafirewall"

    @classmethod
    def from_default(cls) -> LlamaFirewallScanner:
        """Build the scanner with the design's default role->scanner mapping."""
        try:  # pragma: no cover - exercised only with llamafirewall installed
            from llamafirewall import LlamaFirewall, Role, ScannerType  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "llamafirewall is not installed; install with "
                "`pip install llamafirewall>=0.9.0` or use RegexScanner/StubScanner"
            ) from exc

        scanners_by_role = {
            "user": ["PROMPT_GUARD", "CODE_SHIELD"],
            "tool": ["PROMPT_GUARD", "AGENT_ALIGNMENT"],
            "assistant": ["PROMPT_GUARD"],
        }
        # Translate string names to ScannerType enum members.
        role_map = {
            "user": Role.USER,
            "tool": Role.TOOL,
            "assistant": Role.ASSISTANT,
            "system": Role.SYSTEM,
        }
        scanners_config: dict[Any, list[Any]] = {}
        for role_str, names in scanners_by_role.items():
            scanners_config[role_map[role_str]] = [getattr(ScannerType, n) for n in names]
        lf = LlamaFirewall(scanners=scanners_config)
        return cls(lf=lf, scanners_by_role=scanners_by_role)

    async def scan(
        self,
        content: str,
        role: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> ScanResult:  # pragma: no cover - requires llamafirewall
        lf_role = _ROLE_MAP.get(role)
        if lf_role is None or role not in self.scanners_by_role:
            return ScanResult.allow(self.name)
        try:
            from llamafirewall import (  # type: ignore
                AssistantMessage,
                ScanDecision,
                ToolMessage,
                UserMessage,
            )
        except ImportError as exc:
            raise ImportError("llamafirewall not installed") from exc

        msg_cls = {
            "USER": UserMessage,
            "TOOL": ToolMessage,
            "ASSISTANT": AssistantMessage,
            "SYSTEM": UserMessage,  # system reuses UserMessage content shape
        }[lf_role]
        message = msg_cls(content=content)

        # LlamaFirewall's scan() is synchronous (CPU-bound model inference).
        # Bridge to a thread so we never block the asyncio event loop.
        result = await asyncio.to_thread(self.lf.scan, message)
        decision = getattr(result, "decision", None)
        reason = getattr(result, "reason", "") or ""
        scanner_name = getattr(result, "scanner", "unknown")
        if decision == ScanDecision.BLOCK:
            return ScanResult.block(f"{self.name}:{scanner_name}", reason or "blocked", 0.9)
        if decision == ScanDecision.HUMAN_IN_THE_LOOP_REQUIRED:
            return ScanResult.review(f"{self.name}:{scanner_name}", reason or "human_review", 0.6)
        return ScanResult.allow(self.name)


# ---------------------------------------------------------------------------
# Stub scanner — for tests and dry-run mode (no ML models loaded).
# ---------------------------------------------------------------------------


@dataclass
class StubScanner:
    """Configurable scanner used by tests and ``GUARDRAIL_DRY_RUN=1``.

    ``decider`` is a callable ``(content, role) -> ScanResult``. If not
    supplied, the scanner always ALLOWs.
    """

    name: str = "stub"
    decider: Callable[[str, str], ScanResult] | None = None

    async def scan(
        self,
        content: str,
        role: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> ScanResult:
        if self.decider is None:
            return ScanResult.allow(self.name)
        return self.decider(content, role)


def truncate(text: str, max_bytes: int) -> tuple[str, bool]:
    """Truncate text to ``max_bytes`` on a UTF-8 boundary.

    Returns ``(truncated_text, was_truncated)``. Tool output can be multi-MB;
    scanning it whole blows the inference latency budget and risks OOM. The
    design default is 32KiB which covers the attacker-relevant head of any
    payload while keeping P95 bounded.
    """
    if max_bytes <= 0:
        return text, False
    encoded = text.encode("utf-8", errors="ignore")
    if len(encoded) <= max_bytes:
        return text, False
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated, True


def extract_text(payload: Any) -> str:
    """Best-effort flattening of an MCP params/result object to a scan string.

    MCP ``tools/call`` params look like ``{"name": ..., "arguments": {...}}``;
    ``tools/call`` results look like ``{"content": [{"type": "text", "text": ...}, ...], "isError": bool}``.
    We pull out the human-meaningful text and fall back to a JSON dump so a
    scanner always sees *something*.
    """
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, Mapping):
        # tools/call result content array
        content = payload.get("content")
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, Mapping):
                    t = item.get("text")
                    if isinstance(t, str):
                        parts.append(t)
                    elif t is not None:
                        parts.append(str(t))
                elif isinstance(item, str):
                    parts.append(item)
            if parts:
                return "\n".join(parts)
        # tools/list result tools array -> scan descriptions for poisoning
        tools = payload.get("tools")
        if isinstance(tools, list):
            parts = []
            for t in tools:
                if isinstance(t, Mapping):
                    parts.append(str(t.get("description", "")))
                    desc_inputs = t.get("inputSchema")
                    if desc_inputs is not None:
                        import json as _json

                        # ensure_ascii=False preserves any hidden unicode in
                        # schema strings so the regex scanner can see them.
                        parts.append(_json.dumps(desc_inputs, ensure_ascii=False))
            joined = "\n".join(p for p in parts if p)
            if joined:
                return joined
    # Fallback: JSON dump. ensure_ascii=False is critical — otherwise hidden
    # control/zero-width chars in argument values get \u-escaped away and the
    # regex scanner never sees them.
    import json as _json

    return _json.dumps(payload, default=str, sort_keys=True, ensure_ascii=False)
