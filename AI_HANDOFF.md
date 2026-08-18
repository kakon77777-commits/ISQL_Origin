# ISQL Origin OMIR P2 v0.3.0 — AI Handoff

- P0: deterministic OMIR-1 / ORB-1 substrate.
- P1: byte-exact native MEM/DSR profile wrappers.
- P2: local SemanticChart and Transition contracts plus the first bounded holonomy harness.

Canonical P2 sections: `2 SemanticCharts`, `3 Transitions`.

A transition contains references and declarations, not executable code. The external reference harness is non-canonical and whitelist-only.

Holonomy statuses: `exact`, `within_tolerance`, `drift`. Drift is a measured result, not a decode error.

Hard boundaries: no arbitrary execution from OMIR; no AI in canonical decode; no network resolution; no global ontology requirement; no MEM↔DSR semantic conversion; P1 wrapper contract still rejects extra sections.

Next natural phase: P3 Operator descriptors + Authority records + ActionCertificate + DSR execution handoff. Origin itself must not become a VM.
