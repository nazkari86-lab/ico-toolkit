# Autonomous Evidence Hardening Design

## Goal

Make the offline ICO toolkit more trustworthy and resumable on unknown CTF
artifacts while preserving the existing `ico-solve` command and specialized
solvers.

## Scope

The change has five independently testable parts:

1. A score/evolution gate that rejects duplicate or incomplete results.
2. A SQLite evidence store for content-addressed artifacts, executions,
   findings, candidates, and parent/child transformations.
3. An optional resource policy for the existing shell-free command runner.
4. A revisioned adapter cache so code/protocol changes cannot reuse stale
   results silently.
5. A blind holdout manifest and scorer that stores only answer hashes and
   reports verified rate, false positives, duplicates, and missing tasks.

The current solver facade, task-aware profiles, and offline-by-default network
boundary remain compatible. The generated hardest benchmark remains a
regression suite; blind holdouts are the evidence used for generalization.

## Design

`ico_solve.py` remains the public orchestration facade. `ico_evidence_store.py`
owns the durable provenance schema and accepts duck-typed solve reports so it
does not create an import cycle. `CommandRunner` receives an optional
`RunnerPolicy`; its existing timeout and process-group cleanup remain the
default. `scripts/holdout_benchmark.py` uses hash-only records and refuses
plaintext answer fields.

All persisted records are bounded metadata. Large artifact bytes are never
copied into SQLite; only a SHA-256, path, size, and relationship are stored.
SQLite uses foreign keys and WAL mode. A work item is resumable by the tuple
`(artifact_sha256, solver_id, solver_revision, context_hash)`.

## Safety and non-goals

- No automatic requests to ICO infrastructure or arbitrary remote hosts.
- No execution of challenge binaries is enabled by default.
- No plaintext flags are added to holdout manifests.
- No broad rewrite of existing solver modules is required for this change.

## Acceptance criteria

- A scorecard with one duplicate cannot be `ten_out_of_ten` and cannot create a
  successor.
- Evidence can be written, reopened, queried, and resumed from SQLite.
- Resource policy validation is deterministic and command output remains
  bounded; existing runner behavior stays compatible when no policy is set.
- Changing the cache protocol/revision invalidates the adapter cache.
- A holdout manifest containing `answer`, `flag`, or `value` plaintext is
  rejected; hash-only reports produce a deterministic scorecard.
- Existing tests, the full verification script, and the hardest benchmark
  cycle remain green.
