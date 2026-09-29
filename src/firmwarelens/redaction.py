"""Conservative redaction at artifact, retrieval and export boundaries."""

import re
from typing import Any

PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|\Z)"
)
ASSIGNMENT = re.compile(
    r"(?im)(\b(?:[\w.-]*[_.-])?(?:password|passwd|pwd|secret|token|api[_-]?key|psk)\b[\"']?\s*[:=]\s*)([^\r\n]+)"
)
HASH = re.compile(r"\$(?:[1256]|2[aby]|y)\$[^\s:]+")
URL_AUTH = re.compile(r"(https?://)[^\s/@]+:[^\s/@]+@")
SECRET_KEY = re.compile(
    r"(?i)(?:[\w.-]*[_.-])?(?:password|passwd|pwd|secret|token|api[_-]?key|psk)"
)


def redact(text: str, path: str = "") -> str:
    if path.endswith(("/shadow", "/gshadow")) or path in ("etc/shadow", "etc/gshadow"):
        return "\n".join(
            ":".join([p[0], "[REDACTED]", *p[2:]]) if len(p := line.split(":")) > 1 else line
            for line in text.splitlines()
        )
    text = PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    text = ASSIGNMENT.sub(r"\1[REDACTED]", text)
    text = HASH.sub("[REDACTED HASH]", text)
    return URL_AUTH.sub(r"\1[REDACTED]@", text)


def clean(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [clean(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SECRET_KEY.fullmatch(str(key)) else clean(item)
            for key, item in value.items()
        }
    return value
