# ISQL Origin — OMIR P1 v0.2.0

Standalone reference runtime for the internal ISQL Origin architecture.

## P0 substrate retained

- deterministic shortest-form UVarInt/SVarInt, Ref, ByteString and Digest primitives;
- ORB-1 local append-only registries with SHA-256 parent lineage and no ID rebinding;
- OMIR-1 canonical header, RegistryPin and section envelope;
- P0 section codecs for IdentityFamily, InvariantContracts, PayloadTable and ProfileBinding;
- exact canonical OMIR/ORB round-trip;
- fail-closed canonicality and Registry pin validation.

## P1 adds read-only native profile wrapping

Supported MEM 1.0 artifacts:

```text
ISN7  standalone machine-native memory
ISD8  one-hop locality delta
ILI1  compact machine-native locality index
```

Supported DSR 1.0 artifacts:

```text
.isqlr  native symbol registry
.isqln  registered semantic state
.isqle  native event stream
.isqlb  branch artifact
.isqlp  causal native program
.isqlp  register VM program (v7/v8/v9/v10)
```

The P1 wrapper is deliberately simple:

```text
native canonical bytes
  -> SHA-256 native identity
  -> byte-exact invariant
  -> inline PayloadTable entry
  -> ProfileBinding
  -> OMIR canonical bytes
```

Unwrap returns the original native bytes exactly.

## Read-only CLI

```bash
isql-origin profile-list
isql-origin profile-detect fixtures/mem/base.isql7
isql-origin profile-registry-write --out profiles.orb
isql-origin wrap-native fixtures/mem/base.isql7 --out memory.omir
isql-origin validate-wrapper memory.omir
isql-origin wrapper-info memory.omir
isql-origin unwrap-native memory.omir --out restored.isql7
```

Existing P0 commands remain:

```bash
isql-origin inspect examples/minimal.omir
isql-origin hash examples/minimal.omir
isql-origin registry-info examples/minimal.orb
isql-origin validate examples/minimal.omir --registry 0=examples/minimal.orb
```

## Verification

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python tools/reference_profile_gate.py \
  --mem-source /path/to/ISQL_Core_Runtime_v1.0.0 \
  --dsr-source /path/to/ISQL_DSR_Runtime_v1.0.0
```

## Canonical boundary

Canonical authority remains binary OMIR/ORB bytes plus the wrapped profile-native bytes. JSON emitted by CLI commands is inspection only.

The Origin profile registry provides local numeric references and version binding; it is not a universal semantic authority.

P1 performs **no format assimilation, no semantic conversion, no network access, and no native execution**.
