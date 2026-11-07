"""Mechanical check that dummy secrets never reach outputs (values, slices, hashes)."""

import base64
import hashlib
import json

# Every dummy secret planted in tests/fixtures. They are fake by construction (contain FAKE).
FIXTURE_SECRETS = [
    "sk-FAKEleak0000000000000000000000",
    "ghp_FAKEleak000000000000000000000000000",
    "FAKEpasswordLeak99",
    "sk-ant-FAKEleak000000000000000",
    "FAKEqueryLeak123456",
    "FAKEclientSecretLeak42",
    "AKIAFAKEFAKE00000000",
    "FAKEawsSecretKeyLeak0000000000000000000000",
    "xoxb-FAKE-000000000000-leak",
    "sk-FAKEworkflowLeak00000000000000",
    "FAKEhunter2Leak",
]


def _variants(secret: str):
    yield secret
    b = secret.encode()
    for algo in ("md5", "sha1", "sha256", "sha512"):
        yield hashlib.new(algo, b).hexdigest()
    yield base64.b64encode(b).decode()
    # strip a known prefix: the body must not leak either
    for p in ("sk-ant-", "sk-", "ghp_", "xoxb-", "AKIA"):
        if secret.startswith(p) and len(secret) - len(p) >= 8:
            yield secret[len(p):]


def assert_no_secret_leak(obj, secrets=FIXTURE_SECRETS):
    text = obj if isinstance(obj, str) else json.dumps(obj, sort_keys=True, ensure_ascii=False)
    for s in secrets:
        for v in _variants(s):
            assert v not in text, f"secret material leaked (variant of a planted dummy, len={len(v)})"
