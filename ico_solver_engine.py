#!/usr/bin/env python3
"""Bounded registry primitives for universal offline CTF solvers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
import time
from typing import Any, Protocol, Sequence


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


@dataclass(frozen=True)
class SolverLimits:
    max_bytes: int = 100 * 1024 * 1024
    max_files: int = 200
    max_depth: int = 3
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.max_bytes < 1 or self.max_files < 1 or self.max_depth < 0 or self.timeout_seconds <= 0:
            raise ValueError("solver limits must be positive; max_depth may be zero")

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass
class SolverContext:
    input_path: Path
    report_dir: Path
    limits: SolverLimits
    related_paths: tuple[Path, ...] = ()
    task_text: str | None = None
    classification: dict[str, object] = field(default_factory=dict)
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class Detection:
    name: str
    category: str
    score: int
    reason: str
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass
class SolverResult:
    solver: str
    category: str
    status: str
    steps: list[dict[str, object]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    candidates: list[dict[str, object]] = field(default_factory=list)
    error: str | None = None
    detection: Detection | None = None
    duration_seconds: float = 0.0
    derived_inputs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


class UniversalSolver(Protocol):
    name: str
    category: str

    def detect(self, context: SolverContext) -> Detection | None:
        ...

    def solve(self, context: SolverContext) -> SolverResult:
        ...


def _solver_name(solver: UniversalSolver) -> str:
    return str(getattr(solver, "name", type(solver).__name__))


def _solver_category(solver: UniversalSolver) -> str:
    return str(getattr(solver, "category", "misc"))


def _failure_result(solver: UniversalSolver, stage: str, exc: BaseException) -> SolverResult:
    message = f"{type(exc).__name__}: {exc}"
    return SolverResult(
        solver=_solver_name(solver),
        category=_solver_category(solver),
        status="failed",
        steps=[{"name": stage, "status": "error", "details": {"error": message}}],
        error=message,
    )


class SolverRegistry:
    """Register and run compatible solvers in deterministic score order."""

    def __init__(self, solvers: Sequence[UniversalSolver] = ()) -> None:
        self._solvers: list[UniversalSolver] = []
        for solver in solvers:
            self.register(solver)

    @property
    def solvers(self) -> tuple[UniversalSolver, ...]:
        return tuple(self._solvers)

    def register(self, solver: UniversalSolver) -> None:
        name = _solver_name(solver)
        if not callable(getattr(solver, "detect", None)) or not callable(getattr(solver, "solve", None)):
            raise TypeError(f"solver {name!r} must provide detect() and solve()")
        if any(_solver_name(item) == name for item in self._solvers):
            raise ValueError(f"solver already registered: {name}")
        self._solvers.append(solver)

    def detect(self, context: SolverContext) -> list[Detection]:
        """Return compatible detections, isolating a broken detector."""

        detections: list[Detection] = []
        for solver in self._solvers:
            try:
                detection = solver.detect(context)
            except Exception:
                continue
            if detection is not None:
                if not isinstance(detection, Detection):
                    continue
                detections.append(detection)
        detections.sort(key=lambda item: (-item.score, item.name))
        return detections

    def solve(self, context: SolverContext) -> list[SolverResult]:
        """Run every compatible solver and keep failures as evidence."""

        failures: list[SolverResult] = []
        detected: list[tuple[UniversalSolver, Detection]] = []
        for solver in self._solvers:
            try:
                detection = solver.detect(context)
            except Exception as exc:
                failures.append(_failure_result(solver, "detect", exc))
                continue
            if detection is None:
                continue
            if not isinstance(detection, Detection):
                failures.append(
                    _failure_result(
                        solver,
                        "detect",
                        TypeError(f"invalid detection type: {type(detection).__name__}"),
                    )
                )
                continue
            detected.append((solver, detection))

        ordered = sorted(detected, key=lambda item: (-item[1].score, item[0].name))
        solved: list[SolverResult] = []
        for solver, detection in ordered:
            started = time.monotonic()
            try:
                result = solver.solve(context)
            except Exception as exc:
                result = _failure_result(solver, "solve", exc)
            if not isinstance(result, SolverResult):
                result = _failure_result(
                    solver,
                    "solve",
                    TypeError(f"invalid result type: {type(result).__name__}"),
                )
            result.detection = detection
            result.duration_seconds = round(time.monotonic() - started, 6)
            solved.append(result)
        return failures + solved
