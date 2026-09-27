#!/usr/bin/env python3
"""Deterministic default registry for the offline universal solver."""

from __future__ import annotations

from ico_solver_engine import SolverRegistry
from ico_external_ctf import ExternalCtfSolver
from ico_universal_crypto import CryptoSolver
from ico_universal_data import DataSolver
from ico_universal_forensics import ForensicsSolver
from ico_universal_media import MediaSolver
from ico_universal_reverse import ReverseSolver
from ico_universal_web import WebSolver


def build_default_registry() -> SolverRegistry:
    """Return the stable low-risk solver order used by ``ico-scan``."""

    # Registry ordering is only a tie breaker after detection score.  Keep the
    # broad data pass first so derived containers become visible to specialized
    # profiles while each solver remains independently recorded.
    return SolverRegistry(
        [
            DataSolver(),
            MediaSolver(),
            ForensicsSolver(),
            CryptoSolver(),
            ReverseSolver(),
            WebSolver(),
            ExternalCtfSolver(),
        ]
    )
