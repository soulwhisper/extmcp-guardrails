"""Bridge the generated protobuf stubs into the package namespace.

The stubs live in ``<repo>/proto/`` (or ``/app/proto/`` in the container) and
import each other as top-level modules (``import ext_mcp_pb2``). Rather than
re-running protoc with package-relative imports, we add the proto directory to
``sys.path`` once and re-export the modules here.
"""

from __future__ import annotations

import os
import sys

_PROTO_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "proto",
)
if _PROTO_DIR not in sys.path:  # pragma: no cover - path mutation, not testable
    sys.path.insert(0, _PROTO_DIR)

import ext_mcp_pb2 as pb  # noqa: E402
import ext_mcp_pb2_grpc as pbg  # noqa: E402

__all__ = ["pb", "pbg"]
