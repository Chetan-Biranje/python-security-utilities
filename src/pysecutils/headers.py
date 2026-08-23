from typing import Dict

class SecurityHeadersBuilder:
    """Factory for generating OWASP-recommended HTTP security headers."""

    def __init__(self):
        self.headers: Dict[str, str] = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "0",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none';",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
            "Cache-Control": "no-store, max-age=0",
        }

    def with_custom_csp(self, csp_string: str):
        self.headers["Content-Security-Policy"] = csp_string
        return self

    def build(self) -> Dict[str, str]:
        return self.headers.copy()
