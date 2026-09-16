# SWI NODE-ACCESS BOUNDARY

## Stage 1 Demonstrator — Build Guide

### A Tested Implementation of Sections 6–17, 25, 27, 29–30 of the “SWI Distributed Node Isolation & Rebuild Manual”

*Everything in this guide was actually built and run — 14/14 tests passing against real V1 modules (M02, M05, M06), not a design sketch. It implements only Stage 1 (Section 34: a small demonstrator, single machine, simulated node identities) — not the full cross-machine, multi-platform architecture the source manual describes across all 42 sections.*

# 1. What This Guide Actually Proves

Per the source manual’s own completion standard (Section 42), a claim only earns “tested behavior” status once implementation, tests, and documented limitations all exist together. This guide delivers exactly that, scoped to Stage 1:

- A real, standalone `swi_node_access` package — never modifies V1 or V2 internals (per Section 13)
- Three real V1 modules (SecurityProbe, RedactionEngine, DriftAnalyzer) bound to three simulated node identities
- A fail-closed ALLOW/DENY/HALT decision engine
- An on-disk, hash-chained evidence log — built to actually persist, learning directly from the V1 hardening review’s finding that Module 07 claims persistence it doesn’t have
- 14 adversarial and structural tests, covering Section 16’s Tests A, B, C, D (bonus), E, F, G, Section 29 (discovery ≠ access), Section 30 (no implicit module trust), and Section 15 (concurrency-order independence)
- All 14 passing

**What this is not**: three separate physical computers. This is a single-process simulation of node separation — real, tested access-control logic, with the “nodes” as Python objects rather than machines on a network. Section 34 itself recommends proving the boundary logic before generalizing it across real infrastructure — this guide is that first step, not a claim of physical distribution.

# 2. Explicitly Out of Scope for Stage 1

- Real network transport between genuinely separate machines or processes
- Cross-platform rebuild scripts (already present in V2 tools/)
- Wire-format JSON access contract for cross-machine requests
- Replay-attempt and partial-node-failure tests (Stage 2/3)
- Any interaction with M11 or evidence continuity across nodes (Stage 3)

# 3. Package Layout

```
swi_node_access/
  __init__.py
  contracts.py      # NodeIdentity, ModuleIdentity, ResourceContract, AccessRequest, …
  boundary.py       # AccessBoundary (ALLOW / DENY / HALT)
  evidence.py       # On-disk, hash-chained EvidenceLog
  demonstrator.py   # Real V1 M02/M05/M06 gated behind the boundary
test/
  test_access_boundary.py
docs/
  STAGE1_BUILD_GUIDE.md
```

# 4. Running the Tests

Requires a local checkout of SWI-V1-Module-1-10 (or the package installed) so the demonstrator can import the real modules. Adjust `_V1_ROOT` in `demonstrator.py` if needed.

```bash
pip install pytest
python -m pytest test/test_access_boundary.py -v
```

Expected: 14 passed.

# 5. Next Steps

1. Confirm pytest on your machine.
2. Stage 2: run M02/M05/M06 in separate OS processes (not just separate Python objects).
3. Only after Stage 2: Stage 3 M11-interaction questions.
