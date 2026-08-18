import json
from pathlib import Path
import unittest
from isql_origin.binary import Ref
from isql_origin.holonomy import ReferenceHarness, run_holonomy
from isql_origin.omir import decode_omir
from isql_origin.sections import decode_semantic_charts, decode_transitions
from isql_origin.validation import validate_p2_sections
ROOT=Path(__file__).resolve().parents[1]; P2=ROOT/'vectors'/'p2'; PATH=(Ref(0,301),Ref(0,302),Ref(0,303))
class P2GitHubSmokeTests(unittest.TestCase):
 def load(self,n): return decode_omir((P2/n).read_bytes())
 def harness(self,n): return ReferenceHarness.from_dict(json.loads((P2/n).read_text()))
 def test_contract(self):
  obj=self.load('valid-holonomy.omir'); self.assertEqual(validate_p2_sections(obj),[]); by={s.tag:s for s in obj.sections}; self.assertEqual((len(decode_semantic_charts(by[2].payload)),len(decode_transitions(by[3].payload))),(3,3))
 def test_statuses(self):
  obj=self.load('valid-holonomy.omir'); src=(P2/'source.txt').read_bytes(); exact=run_holonomy(obj,PATH,src,self.harness('harness-exact.json'),invariant_refs=(Ref(0,601),)); drift=run_holonomy(obj,PATH,src,self.harness('harness-drift.json'),invariant_refs=(Ref(0,601),)); tol=run_holonomy(obj,PATH,src,self.harness('harness-drift.json'),invariant_refs=(Ref(0,602),)); self.assertEqual((exact.status,drift.status,tol.status),('exact','drift','within_tolerance'))
 def test_invalid_contracts(self):
  self.assertTrue(any('P2_TRANSITION_CHART_REF_UNKNOWN' in e for e in validate_p2_sections(self.load('unknown-chart.omir')))); self.assertTrue(any('P2_TRANSITION_INVARIANT_REF_UNKNOWN' in e for e in validate_p2_sections(self.load('unknown-invariant.omir')))); self.assertTrue(any('P2_SECTION_DECODE_FAILED:2' in e for e in validate_p2_sections(self.load('malformed-chart.omir'))))
 def test_nondeterministic(self):
  with self.assertRaisesRegex(ValueError,'P2_HOLONOMY_NONDETERMINISTIC'): run_holonomy(self.load('nondeterministic.omir'),PATH,(P2/'source.txt').read_bytes(),self.harness('harness-exact.json'),invariant_refs=(Ref(0,601),))
if __name__=='__main__': unittest.main()
