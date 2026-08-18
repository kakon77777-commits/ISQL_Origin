# OMIR P4 v0.5.0 Release Notes

P4 introduces cross-profile bridge accounting without format assimilation.

- BridgePlan: source/target profile contract, transition ref, fidelity, preserved/lost invariants, validator/authority/provenance/temporal refs.
- BridgeCandidate: exact native profile/artifact/version/SHA/length binding; non-executing and non-converting.
- ObservationBundle: non-canonical SHA-bound evidence for preserved invariants.
- Built-in comparators: `bytes-eq`, `utf8-int-distance`.
- BridgeReceipt: auditable `VERIFIED` or `REJECTED` result with explicit loss accounting and target output digest.
- Receipt binding can be revalidated against exact native source/target bytes.

Archival verification: 103/103 source tests, 103/103 fresh-wheel tests, MEM/DSR v1.0 reference decoder PASS, 231/231 extracted release checksums PASS.
