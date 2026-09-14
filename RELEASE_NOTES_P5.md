# ISQL Origin OMIR P5 v0.6.0

P5 is the third-profile stress test for the Origin mother architecture.

## Findings

1. Adding MLF did **not** require an OMIR wire change.
2. Adding a third profile exposed that the historical P1 registry digest is immutable; MLF therefore uses a new registry slot instead of mutating slot 0.
3. Existing IdentityFamily directly carries MLF structural/content/semantic/presentation fingerprints alongside the native-byte identity.
4. Existing P4 BridgeReceipt works unchanged for MEM→MLF and MLF→DSR.

## Boundary

Origin only detects/inspects the MLF container, validates package-local checksums, preserves bytes, and records stored fingerprints. MLF semantic conformance remains the authority of the external MLF Compiler 1.0.0 reference implementation used by CI.
