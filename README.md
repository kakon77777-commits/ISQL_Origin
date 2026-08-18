# ISQL Origin — OMIR P2 v0.3.0

Standalone reference runtime for the internal ISQL Origin architecture.

## P0 — canonical machine substrate

- shortest-form UVarInt/SVarInt, Ref, ByteString and Digest;
- ORB-1 append-only local registries;
- OMIR-1 deterministic envelope and RegistryPin;
- IdentityFamily, InvariantContracts, PayloadTable and ProfileBinding;
- fail-closed canonical decoding and Registry validation.

## P1 — native MEM/DSR profile binding

P1 carries existing MEM/DSR native bytes unchanged inside Origin wrappers and proves:

```text
unwrap(wrap(native_bytes)) == native_bytes
```

No MEM↔DSR format assimilation or native execution occurs.

## P2 — local semantic charts and transition contracts

Reserved OMIR sections are now active:

```text
2  SemanticCharts
3  Transitions
```

A chart records local semantic coordinate metadata. A transition records source/target chart refs, transformer ref, F0..F4 fidelity, deterministic/reversible flags, resource-bound ref, and explicit preserved/lost invariants.

P2 validates transitions against object-local chart refs and section-8 invariant contracts.

## Holonomy reference harness

P2 can run a bounded closed-loop experiment:

```text
A -> B -> C -> A
```

and report:

```text
exact
within_tolerance
drift
```

The runtime does **not** execute code carried by OMIR. The reference harness is external non-canonical JSON and only supports a small whitelist of pure deterministic operations.

## CLI

```bash
isql-origin semantic-info examples/p2/valid-holonomy.omir

isql-origin holonomy-check examples/p2/valid-holonomy.omir \
  --harness examples/p2/harness-exact.json \
  --payload-file examples/p2/source.txt \
  --path 0:301,0:302,0:303 \
  --invariant 0:601
```

Existing P0/P1 commands remain available:

```bash
isql-origin inspect examples/minimal.omir
isql-origin validate examples/minimal.omir
isql-origin profile-list
isql-origin profile-detect fixtures/mem/base.isql7
isql-origin wrap-native fixtures/mem/base.isql7 --out memory.omir
isql-origin validate-wrapper memory.omir
isql-origin unwrap-native memory.omir --out restored.isql7
```

## Verification

The GitHub repository is source-focused. The full release ZIP contains the complete 57-test suite, wheel, native MEM/DSR reference-decoder validation logs, and 137-file checksum manifest.

Core source smoke/conformance tests can be run with:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Canonical boundary

Canonical authority remains binary OMIR/ORB bytes plus profile-native bytes. CLI JSON, harness JSON and holonomy reports are inspection/test artifacts, not canonical source of truth.
