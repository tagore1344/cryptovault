import os
import unittest
from app import app, hash_otp, issue_email_otp
from backup_db import create_verified_backup


class CryptoVaultVerificationTests(unittest.TestCase):
    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    def test_01_public_landing_and_security_headers(self):
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get('X-Frame-Options'), 'SAMEORIGIN')
        self.assertEqual(res.headers.get('X-Content-Type-Options'), 'nosniff')

    def test_02_unauthenticated_api_blocked(self):
        for route in ('/api/dashboard', '/api/db/schema', '/api/admin/overview'):
            res = self.client.get(route)
            self.assertIn(res.status_code, (401, 403))

    def test_03_csrf_protection_enforced(self):
        res = self.client.post('/api/transactions', json={"symbol": "BTC", "tx_type": "BUY", "quantity": 1, "price_usd": 100})
        self.assertEqual(res.status_code, 403)

    def test_04_otp_hashing_never_plaintext(self):
        digest = hash_otp('student@example.com', 'REGISTER', '482910')
        self.assertNotIn('482910', digest)
        self.assertEqual(len(digest), 64)

    def test_05_demo_mode_isolation_and_sql_injection_block(self):
        demo = self.client.post('/api/demo/start')
        self.assertEqual(demo.status_code, 200)
        csrf = demo.get_json()['csrf_token']

        # Attempt unauthorized access to users table via SQL console
        sqli = self.client.post(
            '/api/db/query',
            headers={'X-CSRF-Token': csrf},
            json={"sql": "SELECT password_hash FROM users"}
        )
        self.assertEqual(sqli.status_code, 403)

    def test_06_database_backup_verification(self):
        meta = create_verified_backup('MANUAL')
        self.assertTrue(meta['verified'])
        self.assertTrue(os.path.isfile(meta['file_path']))


if __name__ == '__main__':
    unittest.main(verbosity=2)