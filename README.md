# ISQL Origin — OMIR P4 v0.5.0

P4 adds **cross-profile BridgePlan / BridgeCandidate / BridgeReceipt contracts** on top of P3 without performing profile conversion inside Origin.

## P4 boundary

```text
external producer supplies source + target native bytes
        ↓
Origin detects exact profile/artifact/version + SHA-256
        ↓
BridgePlan declares transition, F0..F4, preserved/lost invariants
        ↓
SHA-bound ObservationBundle
        ↓
whitelisted comparator verification
        ↓
BridgeReceipt: VERIFIED or REJECTED
```

Every P4 candidate/receipt is non-canonical sidecar metadata and fixes:

```text
execute = false
conversion_performed = false
```

`VERIFIED` means only that the declared P4 observations satisfy the declared preserved-invariant contract. It does **not** claim global MEM↔DSR semantic equivalence.

Built-in comparison is deliberately bounded to `bytes-eq` and `utf8-int-distance`; no arbitrary plugin, AI, network, subprocess, native runtime import or converter VM is introduced.

## CLI

```bash
isql-origin bridge-candidate SOURCE TARGET --plan plan.json
isql-origin bridge-verify SOURCE TARGET --plan plan.json --observations observations.json --out receipt.json
isql-origin bridge-receipt-verify receipt.json --source SOURCE --target TARGET
```

P0–P3 commands remain delegated to the previous compatibility CLI layers.

## Verification

The downloadable archival release carries the fully integrated runtime, wheel, complete **103-test** suite, MEM/DSR v1.0 reference-decoder logs and **231-file checksum manifest**.

This GitHub stacked branch is intentionally source-focused and carries a P4 PR-triggered smoke workflow using the same schemas, identities and VERIFIED/REJECTED behavior.
