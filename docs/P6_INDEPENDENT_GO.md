# OMIR P6 — Independent Go Implementation

P6 asks whether Origin can be reconstructed by a second implementation rather than extending the Python reference runtime.

## Boundary

The Go implementation is stdlib-only and does not import Python, MEM, DSR, or MLF runtimes. During implementation, Python source is not used to fill protocol behavior. Published vectors may disambiguate under-specified byte details; every such case is recorded in `independent/go/SPEC_GAPS.md`.

## Result

The archival conformance run reports `45 PASS / 1 SPEC_GAP / 0 FAIL` across 46 P0-P5 published cases. A subprocess-only Go↔Python oracle compares stable OMIR/ORB/MLF fields after the independent implementation exists.

The remaining P5 encoder gap blocks a claim of complete public interoperability freeze. The next step should be a normative wire/conformance amendment, followed by rerunning this independent implementation without consulting Python.
