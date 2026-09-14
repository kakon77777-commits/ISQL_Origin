# P6 Independent Go Conformance

P6 is a second implementation in Go 1.23+ using only the standard library. It was implemented from Origin specifications and published vectors without consulting Python implementation source for behavior.

Archival release result: **46 published cases = 45 PASS + 1 SPEC_GAP + 0 FAIL**.

The deliberate gap is `p5/mlf-wrap`: P5 describes the slot-1 MLF extension Registry but does not freeze its numeric assignment as normative protocol data. An independent encoder therefore cannot uniquely reproduce the reference wrapper without copying implementation constants.

The GitHub source-focused branch recompiles the Go source and runs a smoke against inherited P3/P4/P5 fixtures. The complete vectors, cross-implementation subprocess oracle, binaries, wheel, checksums, and validation logs are carried by the downloadable P6 archival release.
