# AI Handoff — ISQL Origin P4 v0.5.0

Current stacked line:

`P0 machine substrate → P1 native profile binding → P2 semantic transport → P3 operator/authority → P4 bridge receipts`

P4 rule: **External Conversion, Internal Verification**. Origin accepts already-produced source/target native artifacts; it does not convert MEM to DSR or execute transformer code.

Core source: `src/isql_origin/p4_bridge.py`.
CLI compatibility layer: `src/isql_origin/p4_cli.py`.

Important invariants:
- source/target native SHA-256 and profile/artifact/version are explicit;
- preserved and lost invariant sets are disjoint;
- observations are non-canonical and SHA-bound;
- comparator whitelist only;
- VERIFIED is contract-relative, not universal semantic equivalence;
- REJECTED is a valid auditable receipt;
- `execute=false`, `conversion_performed=false` always.

Next natural phase after P4: third-profile stress test / MLF and broader bridge-contract pressure testing before adding stronger conversion machinery.
