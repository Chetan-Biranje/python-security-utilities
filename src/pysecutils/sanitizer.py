import html
import re
import os
from typing import Optional

class InputSanitizer:
    @staticmethod
    def escape_html(text: str) -> str:
        if not isinstance(text, str):
            return str(text)
        return html.escape(text, quote=True)

    @staticmethod
    def sanitize_path(base_dir: str, requested_filename: str) -> Optional[str]:
        base_abs = os.path.abspath(base_dir)
        safe_rel = os.path.normpath(requested_filename).lstrip(os.sep)
        target_path = os.path.abspath(os.path.join(base_abs, safe_rel))
        if os.path.commonpath([base_abs, target_path]) == base_abs:
            return target_path
        return None

    @staticmethod
    def is_valid_email(email: str) -> bool:
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return bool(re.match(pattern, email))

    @staticmethod
    def is_valid_username(username: str) -> bool:
        pattern = r"^[a-zA-Z0-9_-]{3,32}$"
        return bool(re.match(pattern, username))

    @staticmethod
    def check_sql_injection_patterns(text: str) -> bool:
        patterns = [
            r"(--|#|/\*|;)",
            r"\bUNION\b.*\bSELECT\b",
            r"\bOR\b\s+['\"]?\w+['\"]?\s*=",
            r"\bDROP\b\s+\bTABLE\b",
            r"\bEXEC\b\s*\(|\bEXECUTE\b\s*\(",
        ]
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                return True
        return False
