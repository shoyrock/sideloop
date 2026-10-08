import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('diagnostic', Path(__file__).resolve().parents[1] / 'tools' / 'diagnose-auth.py')
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class DiagnosticTests(unittest.TestCase):
    def test_rejection_at_init(self):
        report = diagnostic.summarize('Received auth response status code: 200\nAuthentication failed: rejected (-22411) (-22411).\n')
        self.assertEqual(report['last_gsa_operation'], 'init')
        self.assertEqual(report['apple_error_codes'], [-22411])

    def test_rejection_at_complete(self):
        report = diagnostic.summarize('Received auth response status code: 200\n' * 2)
        self.assertEqual(report['last_gsa_operation'], 'complete')

    def test_mfa_does_not_claim_a_single_exchange(self):
        report = diagnostic.summarize('Received auth response status code: 200\nRequires two factor...\nEnter two factor code\n')
        self.assertTrue(report['mfa_requested'])
        self.assertNotIn('last_gsa_operation', report)

    def test_no_raw_secrets_returned(self):
        report = diagnostic.summarize('Value : secret-token\nX-Apple-I-MD: secret-header\nAuthentication failed: secret-password (-22411)\nAccount authentication succeeded.\n')
        self.assertNotIn('secret-', str(report))
        self.assertTrue(report['sign_in_verified'])


if __name__ == '__main__':
    unittest.main()
