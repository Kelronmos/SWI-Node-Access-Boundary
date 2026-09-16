# SWI Node-Access Boundary

**Stage 1 Demonstrator** of the distributed node-authorization boundary described in the SWI Distributed Node Isolation & Rebuild Manual.

## Status

- Standalone package — does **not** modify V1 (`SWI-V1-Module-1-10`) or V2 (`SWI-V2-Modules-11-22`) internals.
- Single-process simulation of three logical nodes (NODE-A / NODE-B / NODE-C) bound to real V1 modules M02, M05, M06.
- Fail-closed ALLOW / DENY / HALT decision engine.
- On-disk, hash-chained evidence log (follows Module 09’s real persistence pattern, not Module 07’s in-memory-only claim).
- 14 adversarial tests covering wrong node / resource / operation, missing & expired & tampered authorization, discovery ≠ access, no implicit module-to-module trust, and execution-order independence.

## What this is not

Not real network transport, not separate physical machines, not Stage 2/3 (replay, partial-node failure, M11 interaction). See `docs/STAGE1_BUILD_GUIDE.md`.

## Quick start

```bash
# Requires SWI-V1-Module-1-10 available for the demonstrator imports
python -m pytest test/test_access_boundary.py -v
```

## Related repositories

- [SWI-V1-Module-1-10](https://github.com/Kelronmos/SWI-V1-Module-1-10)
- [SWI-V2-Modules-11-22](https://github.com/Kelronmos/SWI-V2-Modules-11-22)
