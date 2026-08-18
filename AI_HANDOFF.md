# ISQL Origin P3 v0.4.0 — AI Handoff

P0 = deterministic OMIR/ORB substrate.
P1 = byte-exact MEM/DSR native wrappers.
P2 = local SemanticChart/Transition contracts + bounded holonomy.
P3 = OperatorDescriptor/AuthorityRecord + deny-first ActionCertificate + non-executing DSR program handoff.

Authority records are declarations, not automatic trust. Only refs explicitly accepted by the non-canonical ActionContext participate. Matching denies override grants.

`ready` means eligible under the supplied context; it never means executed.

DSR handoff accepts only native causal/VM `.isqlp`, binds Origin and DSR bytes with SHA-256, and always sets `execute=false`.

Next natural phase: P4 bridge receipts with explicit preserved/lost cross-profile invariants. Keep conversion separate from authority and execution.
