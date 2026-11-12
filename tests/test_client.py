"""GitHub client security helper tests."""
import hashlib
import hmac

from codeguardian.github.client import verify_webhook_signature


def test_valid_webhook_signature():
    secret = "webhook-secret"
    body = b'{"action":"opened"}'
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(body, f"sha256={digest}", secret)


def test_invalid_or_missing_webhook_signatures_fail_closed():
    assert not verify_webhook_signature(b"{}", "", "secret")
    assert not verify_webhook_signature(b"{}", "sha256=abc", "")
    assert not verify_webhook_signature(b"{}", "sha1=abc", "secret")
    assert not verify_webhook_signature(b'{"a":1}', "sha256=abc", "secret")
