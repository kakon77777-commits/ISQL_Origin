# OMIR P4 Bridge Receipt Design

P4 verifies cross-profile claims; it does not perform conversion.

1. Detect exact source/target native profile, artifact kind, version, SHA-256 and byte length.
2. Parse a BridgePlan that declares transition, fidelity, preserved invariants, explicit lost invariants and validation/authority/provenance refs.
3. Accept a non-canonical ObservationBundle bound to the exact native SHA-256 pair.
4. Evaluate only whitelisted comparators.
5. Emit a non-canonical BridgeReceipt with `VERIFIED` or `REJECTED` status.
6. Keep `execute=false` and `conversion_performed=false` throughout.

`VERIFIED` is contract-relative evidence only and must never be upgraded to global semantic equivalence.
