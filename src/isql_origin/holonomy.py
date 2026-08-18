from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from .binary import Ref
from .omir import OMIRObject
from .sections import decode_invariants, decode_semantic_charts, decode_transitions
from .validation import validate_p2_sections


@dataclass(frozen=True, slots=True)
class HolonomyStep:
    transition_ref: Ref
    source_chart_ref: Ref
    target_chart_ref: Ref
    input_sha256: str
    output_sha256: str


@dataclass(frozen=True, slots=True)
class HolonomyInvariantResult:
    invariant_ref: Ref
    passed: bool
    distance: float | None
    tolerance: float | None
    observable_count: int


@dataclass(frozen=True, slots=True)
class HolonomyReport:
    status: str
    source_chart_ref: Ref
    final_chart_ref: Ref
    source_sha256: str
    final_sha256: str
    step_count: int
    steps: tuple[HolonomyStep, ...]
    invariants: tuple[HolonomyInvariantResult, ...]
    final_payload: bytes


class ReferenceHarness:
    """Non-canonical whitelist-only transformer/observable/comparator bindings."""

    def __init__(self) -> None:
        self._transformers: dict[Ref, tuple[str, Any]] = {}
        self._observables: dict[Ref, str] = {}
        self._comparators: dict[Ref, str] = {}
        self._tolerances: dict[Ref, float] = {}

    @staticmethod
    def parse_ref(text: str) -> Ref:
        try:
            slot_text, local_text = text.split(":", 1)
            ref = Ref(int(slot_text), int(local_text))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"P2_HARNESS_REF_INVALID:{text}") from exc
        if ref.bundle_slot < 0 or ref.local_id < 0:
            raise ValueError(f"P2_HARNESS_REF_INVALID:{text}")
        return ref

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReferenceHarness":
        if data.get("schema") != "isql-origin-p2-reference-harness/v0.3":
            raise ValueError("P2_HARNESS_SCHEMA_UNSUPPORTED")
        harness = cls()
        for text, spec in data.get("transformers", {}).items():
            harness.bind_transformer(cls.parse_ref(text), spec.get("op"), spec.get("arg"))
        for text, spec in data.get("observables", {}).items():
            harness.bind_observable(cls.parse_ref(text), spec.get("op"))
        for text, spec in data.get("comparators", {}).items():
            harness.bind_comparator(cls.parse_ref(text), spec.get("op"))
        for text, value in data.get("tolerances", {}).items():
            harness.bind_tolerance(cls.parse_ref(text), value)
        return harness

    def bind_transformer(self, ref: Ref, operation: str, argument: Any = None) -> None:
        if operation not in {"identity", "int-add"}:
            raise ValueError(f"P2_HARNESS_TRANSFORMER_OPERATION_UNSUPPORTED:{operation}")
        if operation == "int-add" and (isinstance(argument, bool) or not isinstance(argument, int)):
            raise ValueError("P2_HARNESS_INT_ADD_ARGUMENT_INVALID")
        self._transformers[ref] = (operation, argument)

    def bind_observable(self, ref: Ref, operation: str) -> None:
        if operation not in {"bytes", "int"}:
            raise ValueError(f"P2_HARNESS_OBSERVABLE_OPERATION_UNSUPPORTED:{operation}")
        self._observables[ref] = operation

    def bind_comparator(self, ref: Ref, operation: str) -> None:
        if operation not in {"exact", "numeric-abs"}:
            raise ValueError(f"P2_HARNESS_COMPARATOR_OPERATION_UNSUPPORTED:{operation}")
        self._comparators[ref] = operation

    def bind_tolerance(self, ref: Ref, value: float) -> None:
        value = float(value)
        if value < 0:
            raise ValueError("P2_HARNESS_TOLERANCE_NEGATIVE")
        self._tolerances[ref] = value

    def transform(self, ref: Ref, payload: bytes) -> bytes:
        binding = self._transformers.get(ref)
        if binding is None:
            raise ValueError(f"P2_TRANSFORMER_UNBOUND:{ref.bundle_slot}:{ref.local_id}")
        operation, argument = binding
        if operation == "identity":
            return bytes(payload)
        if operation == "int-add":
            try:
                value = int(payload.decode("ascii"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("P2_HARNESS_INT_PAYLOAD_INVALID") from exc
            return str(value + int(argument)).encode("ascii")
        raise AssertionError("validated transformer operation became unreachable")

    def observe(self, ref: Ref, payload: bytes) -> object:
        operation = self._observables.get(ref)
        if operation is None:
            raise ValueError(f"P2_OBSERVABLE_UNBOUND:{ref.bundle_slot}:{ref.local_id}")
        if operation == "bytes":
            return bytes(payload)
        if operation == "int":
            try:
                return int(payload.decode("ascii"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("P2_HARNESS_INT_PAYLOAD_INVALID") from exc
        raise AssertionError("validated observable operation became unreachable")

    def tolerance(self, ref: Ref | None) -> float | None:
        if ref is None:
            return None
        if ref not in self._tolerances:
            raise ValueError(f"P2_TOLERANCE_UNBOUND:{ref.bundle_slot}:{ref.local_id}")
        return self._tolerances[ref]

    def compare(self, ref: Ref, left: object, right: object, tolerance: float | None) -> tuple[bool, float | None]:
        operation = self._comparators.get(ref)
        if operation is None:
            raise ValueError(f"P2_COMPARATOR_UNBOUND:{ref.bundle_slot}:{ref.local_id}")
        if operation == "exact":
            return left == right, 0.0 if left == right else 1.0
        if operation == "numeric-abs":
            if tolerance is None:
                raise ValueError("P2_NUMERIC_COMPARATOR_TOLERANCE_REQUIRED")
            try:
                distance = abs(float(left) - float(right))
            except (TypeError, ValueError) as exc:
                raise ValueError("P2_NUMERIC_COMPARATOR_VALUE_INVALID") from exc
            return distance <= tolerance, distance
        raise AssertionError("validated comparator operation became unreachable")


def _ref_key(ref: Ref) -> tuple[int, int]:
    return ref.bundle_slot, ref.local_id


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def run_holonomy(
    obj: OMIRObject,
    path: tuple[Ref, ...],
    source_payload: bytes,
    harness: ReferenceHarness,
    *,
    invariant_refs: tuple[Ref, ...] | None = None,
    max_path: int = 64,
    max_payload_bytes: int = 1024 * 1024,
) -> HolonomyReport:
    errors = validate_p2_sections(obj)
    if errors:
        raise ValueError("P2_OBJECT_INVALID:" + "|".join(errors))
    if not path:
        raise ValueError("P2_HOLONOMY_PATH_EMPTY")
    if len(path) > max_path:
        raise ValueError("P2_HOLONOMY_PATH_BOUND_EXCEEDED")
    if len(source_payload) > max_payload_bytes:
        raise ValueError("P2_HOLONOMY_PAYLOAD_BOUND_EXCEEDED")

    by_tag = {section.tag: section for section in obj.sections}
    if 2 not in by_tag or 3 not in by_tag or 8 not in by_tag:
        raise ValueError("P2_HOLONOMY_REQUIRED_SECTION_MISSING")
    charts = decode_semantic_charts(by_tag[2].payload)
    transitions = decode_transitions(by_tag[3].payload)
    invariants = decode_invariants(by_tag[8].payload)
    chart_refs = {chart.chart_ref for chart in charts}
    transition_map = {transition.transition_ref: transition for transition in transitions}
    invariant_map = {contract.invariant_ref: contract for contract in invariants}

    selected = []
    for ref in path:
        transition = transition_map.get(ref)
        if transition is None:
            raise ValueError(f"P2_HOLONOMY_TRANSITION_UNKNOWN:{ref.bundle_slot}:{ref.local_id}")
        selected.append(transition)
    for previous, current in zip(selected, selected[1:]):
        if previous.target_chart_ref != current.source_chart_ref:
            raise ValueError("P2_HOLONOMY_PATH_DISCONTINUITY")
    if selected[-1].target_chart_ref != selected[0].source_chart_ref:
        raise ValueError("P2_HOLONOMY_NOT_CLOSED")
    if selected[0].source_chart_ref not in chart_refs:
        raise ValueError("P2_HOLONOMY_SOURCE_CHART_UNKNOWN")
    if any(not transition.deterministic for transition in selected):
        raise ValueError("P2_HOLONOMY_NONDETERMINISTIC")

    common = set(selected[0].preserved_invariants)
    for transition in selected[1:]:
        common.intersection_update(transition.preserved_invariants)
    if invariant_refs is None:
        chosen_refs = tuple(sorted(common, key=_ref_key))
    else:
        chosen_refs = invariant_refs
        for ref in chosen_refs:
            if ref not in common:
                raise ValueError(f"P2_HOLONOMY_INVARIANT_NOT_PRESERVED:{ref.bundle_slot}:{ref.local_id}")
    if not chosen_refs:
        raise ValueError("P2_HOLONOMY_NO_COMMON_INVARIANTS")
    for ref in chosen_refs:
        if ref not in invariant_map:
            raise ValueError(f"P2_HOLONOMY_INVARIANT_UNKNOWN:{ref.bundle_slot}:{ref.local_id}")

    source = bytes(source_payload)
    current = source
    steps: list[HolonomyStep] = []
    for transition in selected:
        before = current
        current = harness.transform(transition.transformer_ref, before)
        if len(current) > max_payload_bytes:
            raise ValueError("P2_HOLONOMY_PAYLOAD_BOUND_EXCEEDED")
        steps.append(
            HolonomyStep(
                transition.transition_ref,
                transition.source_chart_ref,
                transition.target_chart_ref,
                _sha256(before),
                _sha256(current),
            )
        )

    invariant_results: list[HolonomyInvariantResult] = []
    for ref in chosen_refs:
        contract = invariant_map[ref]
        tolerance = harness.tolerance(contract.tolerance_ref)
        outcomes: list[tuple[bool, float | None]] = []
        for observable_ref in contract.observable_refs:
            left = harness.observe(observable_ref, source)
            right = harness.observe(observable_ref, current)
            outcomes.append(harness.compare(contract.comparator_ref, left, right, tolerance))
        passed = bool(outcomes) and all(outcome[0] for outcome in outcomes)
        distances = [outcome[1] for outcome in outcomes if outcome[1] is not None]
        distance = max(distances) if distances else None
        invariant_results.append(HolonomyInvariantResult(ref, passed, distance, tolerance, len(outcomes)))

    all_pass = all(result.passed for result in invariant_results)
    if all_pass and current == source:
        status = "exact"
    elif all_pass:
        status = "within_tolerance"
    else:
        status = "drift"
    return HolonomyReport(
        status,
        selected[0].source_chart_ref,
        selected[-1].target_chart_ref,
        _sha256(source),
        _sha256(current),
        len(steps),
        tuple(steps),
        tuple(invariant_results),
        current,
    )
