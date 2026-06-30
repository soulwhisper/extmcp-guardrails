"""Smoke test for the ``server`` module.

The unit-test suite never starts the gRPC server (that's the job of
``tests/e2e_smoke.py``, which boots ``server.py`` as a subprocess). Importing
``server`` here serves two purposes:

1. It exercises the module-level imports / logger setup so ``--cov=server``
   produces meaningful coverage instead of the
   ``CoverageWarning: Module server was never imported`` noise.
2. It guards against trivial import-time regressions (a typo in a top-level
   import would otherwise only surface at container boot).

The ``serve()`` coroutine is NOT invoked — importing the module only runs the
top-level def statements; ``asyncio.run(serve())`` lives under the
``if __name__ == "__main__"`` guard.
"""

from __future__ import annotations

import server


def test_server_module_exposes_entrypoints():
    assert callable(server.serve)
    assert callable(server.grpc_aio_server)
