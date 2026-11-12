"""FastAPI webhook server for receiving GitHub events."""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.concurrency import run_in_threadpool


class Settings(BaseSettings):
    github_token: str = ""
    github_webhook_secret: str = ""
    anthropic_api_key: str = ""
    use_ai: bool = False
    log_level: str = "INFO"
    max_webhook_bytes: int = Field(default=1_000_000, ge=1, le=10_000_000)
    model_config = SettingsConfigDict(env_prefix="CODEGUARDIAN_", extra="ignore")

settings = Settings()
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
logger = logging.getLogger(__name__)
app = FastAPI(title="CodeGuardian", description="GitHub pull-request review webhook")

@app.post("/webhook")
async def webhook(request: Request) -> dict[str, Any]:
    """Validate and process a GitHub webhook event."""
    from codeguardian.github.client import verify_webhook_signature
    from codeguardian.github.webhook import handle_pull_request
    if not settings.github_webhook_secret:
        raise HTTPException(status_code=503, detail="Webhook signing secret is not configured")
    event = request.headers.get("X-GitHub-Event")
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not event:
        raise HTTPException(status_code=400, detail="Missing X-GitHub-Event header")
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_webhook_bytes:
                raise HTTPException(status_code=413, detail="Webhook payload too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > settings.max_webhook_bytes:
            raise HTTPException(status_code=413, detail="Webhook payload too large")
    body = bytes(chunks)
    if not verify_webhook_signature(body, signature, settings.github_webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object")
    if event == "ping":
        return {"status": "ok", "event": "pong"}
    if event == "pull_request":
        if not settings.github_token:
            raise HTTPException(status_code=503, detail="GitHub token is not configured")
        await run_in_threadpool(handle_pull_request, payload, github_token=settings.github_token, anthropic_api_key=settings.anthropic_api_key or None, use_ai=settings.use_ai)
        return {"status": "ok", "event": event}
    return {"status": "ignored", "event": event}

@app.get("/health")
async def health() -> dict[str, str]:
    """Return process liveness without disclosing configuration."""
    return {"status": "healthy"}

def run() -> None:
    """Run the server locally."""
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
