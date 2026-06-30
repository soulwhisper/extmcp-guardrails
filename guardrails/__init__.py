"""ExtMcp Guardrail — agentgateway ExtMcp policy sidecar.

This package wraps LlamaFirewall (semantic content scanners) and Invariant
Guardrails (cross-call toxic-flow rules) behind the agentgateway ExtMcp gRPC
contract. The public entrypoint is :class:`guardrails.engine.GuardrailEngine`,
which the gRPC servicer in :mod:`guardrails.servicer` drives.

Heavy ML dependencies (``llamafirewall``, ``transformers``, ``torch``) are
imported lazily so that the pure-Python policy core (models, aggregator,
invariant engine, regex scanners) remains importable and unit-testable in an
environment without the model weights.
"""

from .models import Decision, ScanOutcome, ScanResult

__version__ = "0.1.0"
__all__ = ["Decision", "ScanOutcome", "ScanResult", "__version__"]
