from dataclasses import replace
from pathlib import Path
import unittest

from isql_origin.profiles import (
    artifact_registry_slots,
    detect_native_artifact,
    experimental_profile_registry,
    profile_registry,
)
from isql_origin.wrapping import (
    native_binding,
    unwrap_native_artifact,
    validate_native_wrapper,
    wrap_native_artifact,
)


ISX1_WIDTH65 = bytes.fromhex(
    "495358310101020022f662d4aff992fd72ec865f04f0abd98ae0791ee6b630c0"
    "a87b54042132e475011212121212121212121212121212121212121212121212"
    "1212121212121212120341ffffffffffffffff800000000000000040000000000"
    "0000000f30636fb"
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class ISX1ExperimentalProfileTests(unittest.TestCase):
    def test_detects_isx1_as_experimental_mem_artifact(self):
        detected = detect_native_artifact(ISX1_WIDTH65)
        self.assertEqual(detected.profile.name, "isql-mem")
        self.assertEqual(detected.artifact.key, "mem.isx1.experimental")
        self.assertEqual(detected.native_version, 1)
        self.assertEqual(detected.artifact.object_kind_ref.bundle_slot, 1)
        self.assertEqual(detected.artifact.codec_ref.bundle_slot, 1)
        self.assertEqual(artifact_registry_slots(detected.artifact), (0, 1))

    def test_isx1_wrap_is_byte_exact_and_pins_stable_plus_experimental_registries(self):
        wrapped = wrap_native_artifact(ISX1_WIDTH65)
        self.assertEqual(tuple(pin.slot for pin in wrapped.registry_pins), (0, 1))
        self.assertEqual(wrapped.object_kind_ref.bundle_slot, 1)
        self.assertEqual(validate_native_wrapper(wrapped), [])
        self.assertEqual(unwrap_native_artifact(wrapped), ISX1_WIDTH65)
        binding = native_binding(wrapped)
        self.assertEqual(binding.profile, "isql-mem")
        self.assertEqual(binding.artifact_kind, "mem.isx1.experimental")
        self.assertEqual(binding.native_version, 1)
        self.assertEqual(binding.native_bytes, len(ISX1_WIDTH65))

    def test_stable_registry_remains_free_of_isx1_entries(self):
        stable_labels = {entry.payload.decode("utf-8") for entry in profile_registry().entries}
        experimental_labels = {
            entry.payload.decode("utf-8") for entry in experimental_profile_registry().entries
        }
        self.assertFalse(any("isx1" in label for label in stable_labels))
        self.assertIn("object:mem.isx1.experimental", experimental_labels)
        self.assertIn("codec:mem.isx1.experimental", experimental_labels)

    def test_existing_isn7_wrapper_still_uses_only_stable_slot_zero(self):
        native = (FIXTURES / "p4" / "mem-source.isql7").read_bytes()
        detected = detect_native_artifact(native)
        self.assertEqual(detected.artifact.key, "mem.isn7")
        wrapped = wrap_native_artifact(native)
        self.assertEqual(tuple(pin.slot for pin in wrapped.registry_pins), (0,))
        self.assertEqual(validate_native_wrapper(wrapped), [])
        self.assertEqual(unwrap_native_artifact(wrapped), native)

    def test_isx1_wrapper_missing_experimental_pin_fails_closed(self):
        wrapped = wrap_native_artifact(ISX1_WIDTH65)
        tampered = replace(wrapped, registry_pins=(wrapped.registry_pins[0],))
        errors = validate_native_wrapper(tampered)
        self.assertTrue(any(error.startswith("P1_REGISTRY_PIN_SET_INVALID") for error in errors))

    def test_stable_wrapper_with_unneeded_experimental_pin_fails_closed(self):
        stable_native = (FIXTURES / "p4" / "mem-source.isql7").read_bytes()
        stable = wrap_native_artifact(stable_native)
        experimental = wrap_native_artifact(ISX1_WIDTH65)
        tampered = replace(
            stable,
            registry_pins=(stable.registry_pins[0], experimental.registry_pins[1]),
        )
        errors = validate_native_wrapper(tampered)
        self.assertTrue(any(error.startswith("P1_REGISTRY_PIN_SET_INVALID") for error in errors))


if __name__ == "__main__":
    unittest.main()
