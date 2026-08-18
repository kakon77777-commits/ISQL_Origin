# ISQL Origin — OMIR P5 v0.6.0

P5 is the **third-profile stress test** for the Origin mother architecture.

## P5 adds MLF 1.0 without changing P0–P4 contracts

- MLF `.mlf` deterministic ZIP exchange form is preserved byte-exactly.
- Historical P1 registry slot `0` remains immutable; MLF uses a new slot `1` extension registry.
- Existing `IdentityFamily` carries five identities for MLF: native-byte SHA-256 plus structural, content, semantic, and presentation fingerprints.
- Existing P4 BridgeReceipt schema is reused unchanged for `MEM -> MLF` and `MLF -> DSR`.
- Origin does not compile MLF, execute MLF, or depend on `mlf_compiler` at runtime.

## Source-focused commands

```bash
isql-origin mlf-info fixtures/p5/sample.mlf
isql-origin wrap-native fixtures/p5/sample.mlf --out /tmp/sample.omir
isql-origin validate-wrapper /tmp/sample.omir
isql-origin unwrap-native /tmp/sample.omir --out /tmp/restored.mlf

isql-origin bridge-verify fixtures/p4/mem-source.isql7 fixtures/p5/sample.mlf \
  --plan examples/p5/mem-to-mlf-plan.json \
  --observations examples/p5/mem-to-mlf-observations-verified.json
```

## Reference-oracle boundary

The GitHub P5 workflow checks out MLF Compiler 1.0.0 at commit `ad2b3f4ef0960e8d96119825e26ee3807ea62b90` and runs its own validator and fingerprint recomputation over `fixtures/p5/sample.mlf`.

The downloadable archival release contains the fully integrated runtime, 119-test source/installed verification, wheel, native reference logs, and checksum archive.
