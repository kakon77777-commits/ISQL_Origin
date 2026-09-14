# ISQL Origin Runtime v0.3.0 — OMIR P2

P2 activates the reserved OMIR semantic sections without changing the P0/P1 envelope or native wrapping contract.

## Added

- canonical section 2 `SemanticCharts` codec;
- canonical section 3 `Transitions` codec;
- explicit F0..F4 fidelity classes;
- deterministic/reversible flags;
- preserved/lost invariant declarations;
- local chart/invariant reference validation;
- bounded closed-path holonomy harness;
- whitelist-only non-canonical reference harness JSON;
- exact / within-tolerance / drift reports;
- `semantic-info` and `holonomy-check` CLI commands;
- P2 golden, invalid and holonomy conformance vectors.

## Security boundary

OMIR still carries references, not executable transformer code. `decode`, `validate`, and `semantic-info` execute no transformation. `holonomy-check` only uses a hard-coded whitelist of reference harness operations (`identity`, `int-add`, `bytes`, `int`, `exact`, `numeric-abs`) loaded from non-canonical JSON.

## Compatibility

P0/P1 canonical OMIR/ORB and native MEM/DSR wrappers remain valid. P1 wrapper validation still rejects extra sections and therefore P2 does not silently widen the native wrapper contract.
