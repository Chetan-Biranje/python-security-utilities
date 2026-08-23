# Python Security Utilities (PySecUtils)

A robust, modular, and production-grade Python security utility library designed for secure application engineering, cryptographic operations, input validation, and DevSecOps pipelines.

## Author
**Chetan Biranje**  
[GitHub Profile](https://github.com/Chetan-Biranje) | [LinkedIn](https://www.linkedin.com/in/chetanbiranje)

---

## Key Modules

- **Cryptography (`crypto.py`):** Authenticated AES-256-GCM encryption/decryption, PBKDF2-SHA256 password hashing, secure key derivation.
- **JWT Validator (`jwt_validator.py`):** Cryptographic token generation & validation with strict algorithm enforcement (prevents 'none' algorithm and key confusion vulnerabilities).
- **Input Sanitization (`sanitizer.py`):** HTML escaping, path traversal defense, regex validation for emails/usernames, heuristic SQL injection pattern detection.
- **Rate Limiting (`rate_limiter.py`):** Thread-safe Sliding Window and Token Bucket algorithms for API endpoint protection.
- **Security Headers (`headers.py`):** Builder for standard OWASP HTTP security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy).
- **Secrets Management (`secrets_manager.py`):** Cryptographically secure token/API key generators and timing-attack-safe string comparisons.
- **Security Audit Logger (`audit_logger.py`):** Structured JSON security event logger with automatic PII masking (passwords, tokens, emails).

---

## Installation

```bash
git clone https://github.com/Chetan-Biranje/python-security-utilities.git
cd python-security-utilities
pip install -e .
```

## Running Unit Tests

```bash
python3 -m unittest discover tests/ -v
```
