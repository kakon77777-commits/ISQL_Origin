# OMIR P2 Semantic Charts and Holonomy — Design Anchor

P2 activates existing OMIR tags 2 (`SemanticCharts`) and 3 (`Transitions`) without changing the P0/P1 envelope.

A `SemanticChart` is local metadata: chart ref, chart type, version, domain, coordinate schema, payload, authority, provenance and flags.

A `TransitionContract` declares source/target charts, transformer reference, F0..F4 fidelity, deterministic/reversible flags, bound reference, preserved/lost invariants, validator, authority and provenance.

Validation is local and fail-closed: unknown chart refs, unknown invariant refs, malformed section payloads, non-canonical ordering, invalid fidelity, and preserved/lost overlap are rejected.

The canonical object stores references only. The reference holonomy harness is non-canonical and whitelist-only. It can evaluate bounded closed paths and compare declared observables under invariant contracts. It never turns a transformer ref into execution authority.

Holonomy status: `exact` means invariants pass and bytes return exactly; `within_tolerance` means invariants pass while bytes differ; `drift` means at least one tested invariant fails.
