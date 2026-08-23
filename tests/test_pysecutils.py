import unittest
import time
from pysecutils.crypto import AESGCMCipher, hash_password, verify_password, derive_key
from pysecutils.jwt_validator import SecureJWTHandler
from pysecutils.sanitizer import InputSanitizer
from pysecutils.rate_limiter import SlidingWindowRateLimiter, TokenBucketRateLimiter
from pysecutils.headers import SecurityHeadersBuilder
from pysecutils.secrets_manager import generate_api_key, generate_secure_token, constant_time_compare
from pysecutils.audit_logger import SecurityAuditLogger

class TestPySecUtils(unittest.TestCase):

    def test_aes_gcm_encryption_decryption(self):
        cipher = AESGCMCipher()
        secret_text = "Sensitive Application Secret"
        ad = "Context_Auth_Data"
        
        b64_enc = cipher.encrypt_to_base64(secret_text, ad)
        dec = cipher.decrypt_from_base64(b64_enc, ad)
        self.assertEqual(dec, secret_text)

        with self.assertRaises(Exception):
            cipher.decrypt_from_base64(b64_enc, "Wrong_AD")

    def test_aes_custom_key(self):
        key = b"\x01" * 32
        cipher = AESGCMCipher(key=key)
        encrypted = cipher.encrypt(b"Hello World")
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(decrypted, b"Hello World")

    def test_aes_invalid_key_length(self):
        with self.assertRaises(ValueError):
            AESGCMCipher(key=b"too_short")

    def test_derive_key(self):
        salt = b"random_salt_1234"
        key1 = derive_key("my_passphrase", salt)
        key2 = derive_key("my_passphrase", salt)
        self.assertEqual(len(key1), 32)
        self.assertEqual(key1, key2)

    def test_password_hashing(self):
        pwd = "CorrectHorseBatteryStaple123!"
        hashed = hash_password(pwd)
        self.assertTrue(verify_password(pwd, hashed))
        self.assertFalse(verify_password("WrongPassword", hashed))
        self.assertFalse(verify_password(pwd, "invalid_hash_string"))

    def test_jwt_validation_success(self):
        handler = SecureJWTHandler(secret_key="super-secret-key-12345678901234567890")
        token = handler.create_token(subject="user_123", custom_claims={"role": "admin"}, expires_in_seconds=60)
        
        decoded = handler.verify_token(token)
        self.assertEqual(decoded["sub"], "user_123")
        self.assertEqual(decoded["role"], "admin")

    def test_jwt_expired_token(self):
        handler = SecureJWTHandler(secret_key="super-secret-key-12345678901234567890")
        exp_token = handler.create_token(subject="user_123", expires_in_seconds=-10)
        with self.assertRaises(ValueError):
            handler.verify_token(exp_token)

    def test_jwt_invalid_signature(self):
        handler1 = SecureJWTHandler(secret_key="secret-key-1-1234567890123456")
        handler2 = SecureJWTHandler(secret_key="secret-key-2-1234567890123456")
        token = handler1.create_token(subject="user_123")
        with self.assertRaises(ValueError):
            handler2.verify_token(token)

    def test_input_sanitizer_xss(self):
        xss_payload = "<script>alert('XSS')</script>"
        escaped = InputSanitizer.escape_html(xss_payload)
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)

    def test_input_sanitizer_path_traversal(self):
        safe_path = InputSanitizer.sanitize_path("/var/www/uploads", "../../../etc/passwd")
        self.assertIsNone(safe_path)

        valid_path = InputSanitizer.sanitize_path("/var/www/uploads", "avatar.png")
        self.assertEqual(valid_path, "/var/www/uploads/avatar.png")

    def test_input_sanitizer_validators(self):
        self.assertTrue(InputSanitizer.is_valid_email("chetan@example.com"))
        self.assertFalse(InputSanitizer.is_valid_email("not-an-email"))
        self.assertTrue(InputSanitizer.is_valid_username("chetan_biranje"))
        self.assertFalse(InputSanitizer.is_valid_username("a")) # too short

    def test_input_sanitizer_sqli_patterns(self):
        self.assertTrue(InputSanitizer.check_sql_injection_patterns("admin' OR '1'='1"))
        self.assertTrue(InputSanitizer.check_sql_injection_patterns("1; DROP TABLE users;"))
        self.assertTrue(InputSanitizer.check_sql_injection_patterns("1 UNION SELECT username, password FROM users"))
        self.assertFalse(InputSanitizer.check_sql_injection_patterns("john_doe_99"))

    def test_sliding_window_rate_limiter(self):
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=1)
        self.assertTrue(limiter.is_allowed("user1"))
        self.assertTrue(limiter.is_allowed("user1"))
        self.assertFalse(limiter.is_allowed("user1"))

    def test_token_bucket_rate_limiter(self):
        limiter = TokenBucketRateLimiter(capacity=3, refill_rate_per_second=1.0)
        self.assertTrue(limiter.consume(2))
        self.assertTrue(limiter.consume(1))
        self.assertFalse(limiter.consume(1))

    def test_security_headers_builder(self):
        builder = SecurityHeadersBuilder()
        headers = builder.build()
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("Content-Security-Policy", headers)

    def test_security_headers_customization(self):
        builder = SecurityHeadersBuilder()
        builder.with_custom_csp("default-src 'self' https://trusted.cdn.com")
        headers = builder.build()
        self.assertEqual(headers["Content-Security-Policy"], "default-src 'self' https://trusted.cdn.com")

    def test_secrets_manager(self):
        key = generate_api_key(prefix="live_key")
        self.assertTrue(key.startswith("live_key_"))
        self.assertEqual(len(generate_secure_token(16)), 22) # base64 length
        self.assertTrue(constant_time_compare("password123", "password123"))
        self.assertFalse(constant_time_compare("password123", "password321"))

    def test_audit_logger_pii_masking(self):
        logger = SecurityAuditLogger()
        log_output = logger.log_event("LOGIN_ATTEMPT", "user_1", "SUCCESS", {"email": "chetan@proton.me", "password": "SecretPassword123"})
        self.assertNotIn("chetan@proton.me", log_output)
        self.assertIn("***@proton.me", log_output)
        self.assertNotIn("SecretPassword123", log_output)

if __name__ == "__main__":
    unittest.main()
