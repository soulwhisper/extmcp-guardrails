"""Tests for the decision aggregator (fail-closed semantics)."""

from __future__ import annotations

from guardrails.aggregator import DecisionAggregator
from guardrails.models import HumanReviewMode, ScanResult


def test_all_allow_passes():
    agg = DecisionAggregator()
    d = agg.aggregate([ScanResult.allow("a"), ScanResult.allow("b")])
    assert not d.deny
    assert not d.is_mutated
    assert not d.human_review
    assert len(d.scanners) == 2


def test_any_block_denies():
    agg = DecisionAggregator()
    d = agg.aggregate([ScanResult.allow("a"), ScanResult.block("b", "bad"), ScanResult.allow("c")])
    assert d.deny
    assert "b:block" in d.reason


def test_first_block_wins():
    agg = DecisionAggregator()
    d = agg.aggregate([ScanResult.block("first", "x"), ScanResult.block("second", "y")])
    assert d.deny
    assert d.reason.startswith("first:")


def test_human_review_pass_mode_forwards_with_flag():
    agg = DecisionAggregator(human_review_mode=HumanReviewMode.PASS)
    d = agg.aggregate([ScanResult.review("lf", "suspicious")])
    assert not d.deny
    assert d.human_review
    assert "review" in d.reason


def test_human_review_deny_mode_escalates():
    agg = DecisionAggregator(human_review_mode=HumanReviewMode.DENY)
    d = agg.aggregate([ScanResult.review("lf", "suspicious")])
    assert d.deny
    assert "human_review_escalated" in d.reason


def test_block_overrides_human_review():
    agg = DecisionAggregator(human_review_mode=HumanReviewMode.PASS)
    d = agg.aggregate([ScanResult.review("lf", "x"), ScanResult.block("inv", "toxic")])
    assert d.deny
    assert "inv:block" in d.reason


def test_mutation_passthrough_on_allow():
    agg = DecisionAggregator()
    d = agg.aggregate([ScanResult.allow("regex")], mutated={"redacted": True})
    assert not d.deny
    assert d.is_mutated
    assert d.mutated == {"redacted": True}


def test_empty_results_pass():
    agg = DecisionAggregator()
    d = agg.aggregate([])
    assert not d.deny
    assert not d.is_mutated
