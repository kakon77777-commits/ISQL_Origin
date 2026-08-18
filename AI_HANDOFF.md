# ISQL Origin OMIR P5 v0.6.0 — AI Handoff

P0–P4 remain unchanged in contract. P5 adds MLF 1.0 as a materially different third profile.

## P5 architectural results

- Slot 0 is the frozen historical P1 MEM/DSR/common registry. Never append a new profile to it: doing so changes its digest and invalidates historical wrappers.
- MLF is an extension profile in registry slot 1.
- MLF wrappers preserve native `.mlf` bytes and store five identity entries: native-byte SHA-256 plus MLF structural/content/semantic/presentation fingerprints.
- The P4 BridgeReceipt schema is unchanged. MEM→MLF and MLF→DSR use the same plan/observation/receipt machinery.
- Runtime must not depend on `mlf_compiler`; external MLF Compiler 1.0.0 is the semantic validation/fingerprint oracle.

## Hard boundaries

No MLF compilation, no MLF execution, no mutation of historical registry slot 0, no new OMIR section, no MLF-specific BridgeReceipt, and no promotion of MLF semantic fingerprint to universal semantic truth.

## Next step

Prefer independent implementation/conformance work over immediately adding a fourth special-case profile.
