"""Payload redaction for secrets, keys, credentials, and high-volume strings."""

import re
from typing import Any

SENSITIVE_KEY_RE = re.compile(
    r"password|secret|token|apikey|api_key|private_key|credential|authorization",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_RE = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN.*PRIVATE KEY-----", re.DOTALL)
JWT_TOKEN_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
MAX_STRING_LEN = 4000


def redact(value: Any) -> Any:
    """Recursively redact sensitive data, tokens, keys, and oversize strings.

    Rules applied:
    1. Dict values where the key matches sensitive terms are replaced with '***REDACTED***'.
    2. Strings containing PEM private key blocks are replaced with '***REDACTED***'.
    3. Strings matching AWS access key IDs are replaced with '***REDACTED***'.
    4. Strings matching JWT tokens are replaced with '***REDACTED***'.
    5. Environment variable lists of dicts shaped `{'name': ..., 'value': ...}` keep 'name'
       and redact 'value'.
    6. Strings longer than 4000 characters are truncated with '…[truncated N chars]'.
    """
    if isinstance(value, dict):
        redacted_dict: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and SENSITIVE_KEY_RE.search(k):
                redacted_dict[k] = "***REDACTED***"
            else:
                redacted_dict[k] = redact(v)
        return redacted_dict

    if isinstance(value, list):
        redacted_list: list[Any] = []
        for item in value:
            if isinstance(item, dict) and "name" in item and "value" in item:
                env_item: dict[str, Any] = {}
                for k, v in item.items():
                    if k == "name":
                        env_item[k] = v
                    elif k == "value":
                        env_item[k] = "***REDACTED***"
                    else:
                        env_item[k] = redact(v)
                redacted_list.append(env_item)
            else:
                redacted_list.append(redact(item))
        return redacted_list

    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)

    if isinstance(value, set):
        return {redact(item) for item in value}

    if isinstance(value, str):
        # 1. PEM block check (entire string replaced if private key found)
        if PEM_PRIVATE_KEY_RE.search(value):
            return "***REDACTED***"

        # 2. AWS Access Key replacement
        s = AWS_ACCESS_KEY_RE.sub("***REDACTED***", value)

        # 3. JWT token replacement
        s = JWT_TOKEN_RE.sub("***REDACTED***", s)

        # 4. Truncation for strings > 4000 chars
        if len(s) > MAX_STRING_LEN:
            truncated_chars = len(s) - MAX_STRING_LEN
            s = f"{s[:MAX_STRING_LEN]}…[truncated {truncated_chars} chars]"

        return s

    return value
