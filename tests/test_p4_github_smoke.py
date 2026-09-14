import json
from pathlib import Path
import unittest

from isql_origin.p4_bridge import (
    build_bridge_candidate, bridge_receipt_to_dict, evaluate_bridge_observations,
    finalize_bridge_receipt, parse_bridge_plan, parse_bridge_receipt,
    parse_observation_bundle, verify_bridge_receipt_binding,
)

ROOT=Path(__file__).resolve().parents[1]
SRC=(ROOT/'fixtures/p4/mem-source.isql7').read_bytes()
TGT=(ROOT/'fixtures/p4/dsr-target.isqln').read_bytes()
PLAN=parse_bridge_plan(json.loads((ROOT/'examples/p4/plan.json').read_text()))

class P4GithubSmoke(unittest.TestCase):
    def candidate(self): return build_bridge_candidate(SRC,TGT,PLAN)
    def obs(self,name): return parse_observation_bundle(json.loads((ROOT/f'examples/p4/{name}').read_text()))

    def test_candidate_is_nonexecuting_cross_profile(self):
        c=self.candidate(); self.assertEqual((c.source_profile,c.target_profile),('isql-mem','isql-dsr'))
        self.assertEqual((c.source_artifact_kind,c.target_artifact_kind),('mem.isn7','dsr.state'))
        self.assertFalse(c.execute); self.assertFalse(c.conversion_performed)

    def test_verified_and_rejected_receipts_are_auditable(self):
        c=self.candidate()
        ok=finalize_bridge_receipt(c,evaluate_bridge_observations(c,self.obs('observations-verified.json')))
        bad=finalize_bridge_receipt(c,evaluate_bridge_observations(c,self.obs('observations-rejected.json')))
        self.assertEqual(ok.status,'VERIFIED'); self.assertEqual(bad.status,'REJECTED')
        self.assertEqual(bad.errors,('P4_PRESERVED_INVARIANT_FAILED:0:601',))
        self.assertEqual(verify_bridge_receipt_binding(ok,SRC,TGT),())

    def test_digest_mismatch_is_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'P4_OBSERVATION_SOURCE_DIGEST_MISMATCH'):
            evaluate_bridge_observations(self.candidate(),self.obs('observations-bad-digest.json'))

    def test_receipt_roundtrip_preserves_nonexecution_boundary(self):
        c=self.candidate(); r=finalize_bridge_receipt(c,evaluate_bridge_observations(c,self.obs('observations-verified.json')))
        parsed=parse_bridge_receipt(bridge_receipt_to_dict(r))
        self.assertFalse(parsed.execute); self.assertFalse(parsed.conversion_performed)
        self.assertEqual(parsed.output_digest,parsed.target_native_sha256)

if __name__=='__main__': unittest.main()
