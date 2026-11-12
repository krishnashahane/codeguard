# CodeGuardian

**CodeGuardian** reviews pull-request diffs for security, performance, correctness and maintainability risks. It includes a local CLI, a reusable GitHub Action and an optional GitHub webhook service.

## Capabilities

- 13 deterministic rules for common security and code-quality patterns.
- Optional AI-assisted review for contextual analysis.
- Severity-ranked findings and a bounded 0–100 risk score.
- CLI support for diff files, stdin, staged changes and branch comparisons.
- GitHub Action and webhook-driven PR reviews.

CodeGuardian is a review aid, not a replacement for human review, SAST/DAST, dependency scanning or security testing. Pattern-based rules can produce false positives and miss context-dependent defects.

## Requirements

- Python 3.10 or later.
- Git for CLI git modes.
- A GitHub token with pull-request read/write permissions for automated reviews.
- An Anthropic API key only when AI review is enabled.

## Install

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

## CLI

```bash
codeguardian review changes.diff
codeguardian review --git
codeguardian review --branch main
git diff origin/main...HEAD | codeguardian review
codeguardian review changes.diff --json
codeguardian review changes.diff --fail-on high
ANTHROPIC_API_KEY=... codeguardian review changes.diff --ai
codeguardian rules
```

Choose exactly one diff source: file, `--git`, `--branch`, or stdin. JSON mode writes only JSON to stdout; diagnostics go to stderr.

## GitHub Action

```yaml
name: CodeGuardian
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: krishnashahane/codeguard@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          use_ai: "false"
          fail_on: "high"
```

Grant only required workflow permissions. AI is disabled by default. Store credentials in repository secrets, not workflow source.

## Webhook service

```bash
export CODEGUARDIAN_GITHUB_TOKEN="..."
export CODEGUARDIAN_GITHUB_WEBHOOK_SECRET="..."
export CODEGUARDIAN_USE_AI="false"
uvicorn codeguardian.server:app --host 127.0.0.1 --port 8000
```

Configure GitHub webhook events `pull_request` and `ping`, with the same signing secret. Requests without a valid `X-Hub-Signature-256` are rejected. A request-body size limit is enforced. Use TLS termination, a reverse proxy and network restrictions before exposing the service publicly.

## Configuration

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Optional AI key for CLI |
| `CODEGUARDIAN_GITHUB_TOKEN` | Token used by webhook service |
| `CODEGUARDIAN_GITHUB_WEBHOOK_SECRET` | Required webhook signing secret |
| `CODEGUARDIAN_ANTHROPIC_API_KEY` | Optional AI key for webhook service |
| `CODEGUARDIAN_USE_AI` | Enable AI review in webhook service |
| `CODEGUARDIAN_LOG_LEVEL` | Python log level |

## Security and privacy

- Diffs sent to the optional AI provider leave your environment; enable AI only when policy permits.
- Webhook signatures are mandatory. Store secrets in environment variables or a secret manager.
- Use least-privilege GitHub tokens and restrict network access to the webhook service.
- Review findings before treating them as confirmed vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).
