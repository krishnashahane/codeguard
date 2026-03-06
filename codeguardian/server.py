"""FastAPI webhook server for receiving GitHub events."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, HTTPException
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    github_token: str = ""
    github_webhook_secret: str = ""
    anthropic_api_key: str = ""
    use_ai: bool = False
    log_level: str = "INFO"

    model_config = {"env_prefix": "CODEGUARDIAN_"}


settings = Settings()
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)

app = FastAPI(title="CodeGuardian", description="AI-powered PR reviewer webhook")


@app.post("/webhook")
async def webhook(request: Request):
    """Handle incoming GitHub webhook events."""
    from codeguardian.github.client import verify_webhook_signature
    from codeguardian.github.webhook import handle_pull_request

    event = request.headers.get("X-GitHub-Event")
    if not event:
        raise HTTPException(400, "Missing X-GitHub-Event header")

    body = await request.body()

    # Verify signature if secret is configured
    if settings.github_webhook_secret:
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not verify_webhook_signature(body, signature, settings.github_webhook_secret):
            raise HTTPException(401, "Invalid signature")

    payload = await request.json()

    if event == "pull_request":
        handle_pull_request(
            payload,
            github_token=settings.github_token,
            anthropic_api_key=settings.anthropic_api_key,
            use_ai=settings.use_ai,
        )
        return {"status": "ok", "event": event}

    if event == "ping":
        return {"status": "ok", "event": "pong"}

    return {"status": "ignored", "event": event}


@app.get("/health")
async def health():
    return {"status": "healthy"}


def run():
    """Run the server (for convenience)."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
