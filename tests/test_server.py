"""Webhook endpoint security and dispatch tests."""
import hashlib
import hmac
import json

from fastapi.testclient import TestClient
import pytest

import codeguardian.server as server


@pytest.fixture
def client():
    return TestClient(server.app)


def signed_headers(body: bytes, secret: str, event: str = "ping") -> dict[str, str]:
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {"X-GitHub-Event": event, "X-Hub-Signature-256": f"sha256={signature}"}


def test_health_is_public_and_does_not_expose_configuration(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_webhook_fails_closed_when_secret_is_missing(client, monkeypatch):
    monkeypatch.setattr(server.settings, "github_webhook_secret", "")
    response = client.post("/webhook", headers={"X-GitHub-Event": "ping"}, content=b"{}")
    assert response.status_code == 503


def test_webhook_rejects_invalid_signature(client, monkeypatch):
    monkeypatch.setattr(server.settings, "github_webhook_secret", "expected-secret")
    response = client.post(
        "/webhook",
        headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": "sha256=invalid"},
        content=b"{}",
    )
    assert response.status_code == 401


def test_webhook_rejects_oversized_payload(client, monkeypatch):
    monkeypatch.setattr(server.settings, "github_webhook_secret", "test-secret")
    monkeypatch.setattr(server.settings, "max_webhook_bytes", 3)
    response = client.post(
        "/webhook",
        headers=signed_headers(b'{"ok":true}', "test-secret"),
        content=b'{"ok":true}',
    )
    assert response.status_code == 413


def test_valid_ping_is_acknowledged(client, monkeypatch):
    secret = "test-secret"
    monkeypatch.setattr(server.settings, "github_webhook_secret", secret)
    response = client.post(
        "/webhook",
        headers=signed_headers(b"{}", secret),
        content=b"{}",
    )
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "event": "pong"}


def test_pull_request_event_dispatches_after_signature_validation(client, monkeypatch):
    secret = "test-secret"
    monkeypatch.setattr(server.settings, "github_webhook_secret", secret)
    monkeypatch.setattr(server.settings, "github_token", "test-token")
    payload = {
        "action": "opened",
        "repository": {"full_name": "owner/repo"},
        "pull_request": {"number": 7},
    }
    body = json.dumps(payload).encode()
    calls = []

    def fake_handler(received, **kwargs):
        calls.append((received, kwargs))

    monkeypatch.setattr("codeguardian.github.webhook.handle_pull_request", fake_handler)
    response = client.post(
        "/webhook",
        headers=signed_headers(body, secret, event="pull_request"),
        content=body,
    )
    assert response.status_code == 200
    assert calls == [(payload, {"github_token": "test-token", "anthropic_api_key": None, "use_ai": False})]


def test_webhook_rejects_malformed_json(client, monkeypatch):
    secret = "test-secret"
    monkeypatch.setattr(server.settings, "github_webhook_secret", secret)
    body = b"{bad json"
    response = client.post("/webhook", headers=signed_headers(body, secret), content=body)
    assert response.status_code == 400
