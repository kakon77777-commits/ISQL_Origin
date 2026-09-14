# P6 Independent Implementation — Specification Gaps

P6 intentionally implemented from specs + published vectors without reading Python implementation source.

The following byte-level details are required by published vectors but are not explicit in `OMIR1_WIRE_SPEC.md`:

1. **Section criticality bit:** published vectors demonstrate section `flags & 1` means critical for unknown-section rejection.
2. **IdentityFamily optional refs:** vectors show an extra options field after `scope_flags`; P6 interprets bit 0 as `authority_ref` and bit 1 as `provenance_ref`.
3. **Invariant tolerance:** vectors show a `0/1` presence field before optional `tolerance_ref`.
4. **Operator executor:** vectors show a `0/1` presence field before optional `executor_ref`.
5. **Authority optional refs:** vectors show an options bitmask after `scope_ref`; P6 interprets bits 0/1/2 as validity/evidence/signature.
6. **Canonical list encoding:** design specs describe sorted canonical lists but the wire spec does not explicitly state that every ref/uint list is encoded as `count + values` with strict ascending order; P6 follows published vectors.

These are protocol-specification gaps, not Python-runtime dependencies. P6 recommends promoting these details into a future normative wire-spec revision before public freeze.

## P5 encoder gap

The P5 design specifies an MLF slot-1 extension Registry but does not freeze the Registry's numeric assignment as normative protocol data. Therefore an independent implementation can validate/read MLF artifacts and P5 bridges, but cannot uniquely reproduce the reference `mlf-wrap` encoder without consulting implementation-specific assignments. P6 intentionally reports this as `SPEC_GAP` rather than copying Python constants.
