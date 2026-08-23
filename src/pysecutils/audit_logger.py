import json
import logging
import time
import re
from typing import Dict, Any

class SecurityAuditLogger:
    """Structured JSON audit logger with automatic PII masking."""

    def __init__(self, logger_name: str = "SecurityAudit"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def mask_pii(self, text: str) -> str:
        # Mask emails
        text = re.sub(r'([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', r'***@\g<2>', text)
        # Mask passwords
        text = re.sub(r'("password"\s*:\s*")[^"]+(")', r'\g<1>***\g<2>', text, flags=re.IGNORECASE)
        # Mask tokens
        text = re.sub(r'("token"\s*:\s*")[^"]+(")', r'\g<1>***\g<2>', text, flags=re.IGNORECASE)
        return text

    def log_event(self, event_type: str, user_id: str, status: str, details: Dict[str, Any] = None):
        event = {
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            "event_type": event_type,
            "user_id": user_id,
            "status": status,
            "details": details or {}
        }
        raw_json = json.dumps(event)
        masked_json = self.mask_pii(raw_json)
        self.logger.info(masked_json)
        return masked_json
