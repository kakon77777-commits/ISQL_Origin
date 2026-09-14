from pathlib import Path
import json
import unittest

from isql_origin.omir import decode_omir, encode_omir
from isql_origin.sections import decode_identity_family
from isql_origin.p5_mlf import inspect_mlf_native, wrap_mlf_native, validate_mlf_wrapper, unwrap_mlf_native
from isql_origin.p5_bridge import build_bridge_candidate, evaluate_bridge_observations, finalize_bridge_receipt, parse_bridge_plan, parse_observation_bundle, verify_bridge_receipt_binding

ROOT = Path(__file__).resolve().parents[1]
MLF = (ROOT / "fixtures/p5/sample.mlf").read_bytes()
MEM = (ROOT / "fixtures/p4/mem-source.isql7").read_bytes()
DSR = (ROOT / "fixtures/p4/dsr-target.isqln").read_bytes()


def load_json(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class P5GitHubSmoke(unittest.TestCase):
    def test_mlf_wrapper_has_five_identities_and_exact_roundtrip(self):
        info = inspect_mlf_native(MLF)
        self.assertEqual(set(info.fingerprints), {"structural", "content", "semantic", "presentation"})
        obj = wrap_mlf_native(MLF)
        self.assertEqual(validate_mlf_wrapper(obj), [])
        self.assertEqual(unwrap_mlf_native(obj), MLF)
        restored = decode_omir(encode_omir(obj))
        section1 = next(section for section in restored.sections if section.tag == 1)
        identities = decode_identity_family(section1.payload)
        self.assertEqual(len(identities), 5)
        self.assertEqual(identities[0].identity_kind_ref.bundle_slot, 0)
        self.assertTrue(all(item.identity_kind_ref.bundle_slot == 1 for item in identities[1:]))
        self.assertEqual(len(restored.registry_pins), 2)

    def _receipt(self, source, target, plan_path, obs_path):
        plan = parse_bridge_plan(load_json(plan_path))
        candidate = build_bridge_candidate(source, target, plan)
        bundle = parse_observation_bundle(load_json(obs_path))
        results = evaluate_bridge_observations(candidate, bundle)
        return finalize_bridge_receipt(candidate, results)

    def test_mem_to_mlf_verified_without_new_receipt_schema(self):
        receipt = self._receipt(MEM, MLF, "examples/p5/mem-to-mlf-plan.json", "examples/p5/mem-to-mlf-observations-verified.json")
        self.assertEqual(receipt.status, "VERIFIED")
        self.assertEqual(receipt.target_profile, "mlf-1.0")
        self.assertEqual(verify_bridge_receipt_binding(receipt, MEM, MLF), ())

    def test_mem_to_mlf_rejected_is_auditable(self):
        receipt = self._receipt(MEM, MLF, "examples/p5/mem-to-mlf-plan.json", "examples/p5/mem-to-mlf-observations-rejected.json")
        self.assertEqual(receipt.status, "REJECTED")
        self.assertTrue(receipt.errors)

    def test_mlf_to_dsr_verified_without_bridge_schema_change(self):
        receipt = self._receipt(MLF, DSR, "examples/p5/mlf-to-dsr-plan.json", "examples/p5/mlf-to-dsr-observations-verified.json")
        self.assertEqual(receipt.status, "VERIFIED")
        self.assertEqual(receipt.source_profile, "mlf-1.0")
        self.assertEqual(verify_bridge_receipt_binding(receipt, MLF, DSR), ())


if __name__ == "__main__":
    unittest.main()
