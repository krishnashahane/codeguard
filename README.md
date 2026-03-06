# CodeGuardian

AI-powered Pull Request reviewer that detects bad patterns, security issues, and performance problems.

## Features

- **13 built-in rules** covering security, performance, and code quality
- **AI-powered review** using Claude for deeper analysis
- **3 deployment modes**: CLI, GitHub Action, webhook server
- **Risk scoring** (0-100) for every review
- **CI/CD integration** with configurable fail thresholds

### Detection Categories

| Category | Examples |
|----------|----------|
| Security | Hardcoded secrets, SQL injection, XSS, command injection, insecure practices |
| Performance | N+1 queries, large allocations, blocking calls |
| Bad Patterns | Debug statements, bare except, deep nesting, large diffs, TODOs |

## Installation

```bash
pip install .
```

## Usage

### CLI

```bash
# Review a diff file
codeguardian review changes.diff

# Review staged git changes
codeguardian review --git

# Compare against a branch
codeguardian review --branch main

# Pipe from stdin
git diff | codeguardian review

# With AI review
codeguardian review --git --ai

# JSON output for CI
codeguardian review changes.diff --json --fail-on high

# List all rules
codeguardian rules
```

### GitHub Action

```yaml
name: PR Review
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
      - uses: your-org/CodeGuardian@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}  # optional
          use_ai: "false"
          fail_on: "critical"
```

### Webhook Server

```bash
# Configure via environment variables
export CODEGUARDIAN_GITHUB_TOKEN=ghp_...
export CODEGUARDIAN_GITHUB_WEBHOOK_SECRET=your_secret
export CODEGUARDIAN_ANTHROPIC_API_KEY=sk-...  # optional
export CODEGUARDIAN_USE_AI=false

# Run the server
uvicorn codeguardian.server:app --host 0.0.0.0 --port 8000

# Or with Docker
docker build -t codeguardian .
docker run -p 8000:8000 \
  -e CODEGUARDIAN_GITHUB_TOKEN=ghp_... \
  -e CODEGUARDIAN_GITHUB_WEBHOOK_SECRET=secret \
  codeguardian
```

Point your GitHub webhook to `https://your-server/webhook` with the `pull_request` event.

## Configuration

| Environment Variable | Description |
|---------------------|-------------|
| `ANTHROPIC_API_KEY` | API key for Claude AI review (CLI) |
| `CODEGUARDIAN_GITHUB_TOKEN` | GitHub token (webhook server) |
| `CODEGUARDIAN_GITHUB_WEBHOOK_SECRET` | Webhook secret (server) |
| `CODEGUARDIAN_ANTHROPIC_API_KEY` | API key (server) |
| `CODEGUARDIAN_USE_AI` | Enable AI review (server) |

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT