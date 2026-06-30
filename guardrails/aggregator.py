"""Fail-closed decision aggregator.

Combines a list of :class:`ScanResult` into a single :class:`Decision`
according to three rules:

1. Any ``BLOCK`` short-circuits to a hard deny with the offending scanner
   recorded in the reason (fail-closed by default; this is the only path that
   ever produces ``deny=True`` from scanner outcomes).
2. ``HUMAN_REVIEW`` outcomes are resolved by ``human_review_mode`` — either
   pass with an audit flag, or escalate to a deny.
3. Otherwise the exchange is allowed, optionally carrying a mutated payload
   supplied by the engine (e.g. PII redaction, secret masking).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import Decision, HumanReviewMode, ScanOutcome, ScanResult


class DecisionAggregator:
    """Stateless combinator over scanner results."""

    def __init__(self, human_review_mode: HumanReviewMode = HumanReviewMode.PASS):
        self._hr_mode = human_review_mode

    @property
    def human_review_mode(self) -> HumanReviewMode:
        return self._hr_mode

    def aggregate(
        self,
        results: Iterable[ScanResult],
        *,
        mutated: Any = None,
    ) -> Decision:
        collected: list[ScanResult] = list(results)

        # 1) Fail-closed: any BLOCK -> deny.
        for r in collected:
            if r.outcome is ScanOutcome.BLOCK:
                return Decision(
                    deny=True,
                    reason=f"{r.scanner}:block:{r.reason}" if r.reason else f"{r.scanner}:block",
                    scanners=tuple(collected),
                )

        # 2) HUMAN_REVIEW -> resolve per config.
        reviews = [r for r in collected if r.outcome is ScanOutcome.HUMAN_REVIEW]
        if reviews:
            if self._hr_mode is HumanReviewMode.DENY:
                first = reviews[0]
                return Decision(
                    deny=True,
                    reason=f"{first.scanner}:human_review_escalated:{first.reason}",
                    scanners=tuple(collected),
                )
            return Decision(
                deny=False,
                human_review=True,
                reason=",".join(f"{r.scanner}:review" for r in reviews),
                mutated=mutated,
                scanners=tuple(collected),
            )

        # 3) All ALLOW -> pass, optionally mutated.
        return Decision(deny=False, mutated=mutated, scanners=tuple(collected))
