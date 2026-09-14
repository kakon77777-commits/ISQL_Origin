from pathlib import Path
import unittest

from isql_origin.action import ActionContext, build_action_certificate
from isql_origin.binary import Ref
from isql_origin.handoff import prepare_dsr_handoff
from isql_origin.omir import decode_omir
from isql_origin.p3_sections import decode_authorities, decode_operators
from isql_origin.p3_validation import validate_p3_sections

ROOT = Path(__file__).resolve().parents[1]
OBJ_BYTES = (ROOT / "examples/p3/valid-action.omir").read_bytes()
OBJ = decode_omir(OBJ_BYTES)


def context(*, authorities=(Ref(0, 411),), denied=()):
    return ActionContext(
        subject_ref=Ref(0, 501),
        target_ref=Ref(0, 511),
        target_type_ref=Ref(0, 101),
        satisfied_guard_refs=(),
        granted_capabilities=(Ref(0, 201),),
        denied_capabilities=tuple(denied),
        accepted_authority_refs=tuple(authorities),
    )


class P3GithubSmoke(unittest.TestCase):
    def test_operator_authority_sections_validate(self):
        self.assertEqual(validate_p3_sections(OBJ), [])
        by_tag = {section.tag: section for section in OBJ.sections}
        self.assertEqual(len(decode_operators(by_tag[4].payload)), 1)
        self.assertEqual(len(decode_authorities(by_tag[5].payload)), 2)

    def test_ready_certificate_is_not_execution(self):
        cert = build_action_certificate(OBJ, Ref(0, 701), context())
        self.assertTrue(cert.ready)
        self.assertEqual(cert.executor_ref, Ref(0, 801))
        self.assertEqual(cert.errors, ())

    def test_authority_deny_overrides_grant(self):
        cert = build_action_certificate(OBJ, Ref(0, 701), context(authorities=(Ref(0, 411), Ref(0, 412))))
        self.assertFalse(cert.ready)
        self.assertIn("AUTHORITY_DENIED:0:401", cert.errors)

    def test_dsr_program_handoff_is_non_executing(self):
        cert = build_action_certificate(OBJ, Ref(0, 701), context())
        handoff = prepare_dsr_handoff(OBJ_BYTES, cert, (ROOT / "fixtures/dsr/vm.isqlp").read_bytes())
        self.assertEqual(handoff.status, "READY")
        self.assertFalse(handoff.execute)
        self.assertEqual(handoff.dsr_artifact_kind, "dsr.vm-program")

    def test_dsr_state_is_rejected_as_executor(self):
        cert = build_action_certificate(OBJ, Ref(0, 701), context())
        with self.assertRaisesRegex(ValueError, "P3_DSR_EXECUTOR_NOT_PROGRAM"):
            prepare_dsr_handoff(OBJ_BYTES, cert, (ROOT / "fixtures/dsr/state.isqln").read_bytes())


if __name__ == "__main__":
    unittest.main()
