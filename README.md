# ISQL Origin — OMIR P3 v0.4.0

P3 extends the P2 source branch with operator, authority, deterministic action-eligibility, and a non-executing DSR program handoff.

## Canonical contracts

```text
4 Operators
5 Authority
```

`OperatorDescriptor` declares type/signature/guard, capabilities, effects, authority requirements, invariant obligations, optional executor ref, resource bound, and provenance.

`AuthorityRecord` declares subject, issuer, grant/deny sets, scope, and optional validity/evidence/signature refs. Presence in OMIR is a declaration, not automatic trust.

## ActionCertificate

A non-canonical `ActionContext` explicitly selects subject/target/type, satisfied guards, direct capability grants/denials, and accepted authority records. Evaluation is deterministic and deny-first.

```text
ready != executed
```

## DSR handoff boundary

A ready certificate may be paired with native `dsr.causal-program` or `dsr.vm-program` bytes to create a handoff receipt. The receipt binds Origin and DSR bytes by SHA-256 and always reports `execute=false`.

Origin does not import or invoke DSR.

## Source-focused GitHub layout

The stacked P3 branch keeps P2 source intact and adds compatibility extension modules:

- `p3_sections.py` — section 4/5 wire codec;
- `p3_validation.py` — P3 contract validation;
- `action.py` — deny-first ActionCertificate;
- `handoff.py` — non-executing DSR handoff;
- `p3_cli.py` — P3 commands, delegating all older commands to the P2 CLI.

The downloadable archival release contains the fully integrated source tree, 85-test suite, wheel, MEM/DSR reference-decoder logs, and 180-file checksum manifest.

## P3 commands

```bash
isql-origin operator-info examples/p3/valid-action.omir
isql-origin action-certificate examples/p3/valid-action.omir --operator 0:701 --context examples/p3/context-valid.json
isql-origin dsr-handoff examples/p3/valid-action.omir --operator 0:701 --context examples/p3/context-valid.json --executor-file fixtures/dsr/vm.isqlp
```

## Hard boundaries

- no arbitrary executor invocation from OMIR;
- no DSR import or VM execution in Origin;
- no AI authorization;
- no network resolution;
- no implicit signature/issuer trust;
- no world mutation;
- no MEM↔DSR semantic assimilation.
