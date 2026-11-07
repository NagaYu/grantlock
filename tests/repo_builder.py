"""Tiny helpers to build throwaway repos for diff/check tests."""

from pathlib import Path

import grantlock
from grantlock import lockfile

CODEOWNERS = "*  @acme/eng\n"

MCP = """{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}",
        "GITHUB_TOOLSETS": "repos"
      }
    }
  }
}
"""

DEPLOY = """name: Deploy
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: make test
  deploy:
    runs-on: ubuntu-latest
    needs: test
    environment: production
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/gha-deploy
          aws-region: us-east-1
      - run: ./deploy.sh
"""

ENV = "GITHUB_PERSONAL_ACCESS_TOKEN=\n"

BASE = {
    ".github/CODEOWNERS": CODEOWNERS,
    ".mcp.json": MCP,
    ".github/workflows/deploy.yml": DEPLOY,
    ".env.example": ENV,
}


def write(repo: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = repo / rel
        if text is None:
            if p.exists():
                p.unlink()
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return repo


def base_repo(tmp_path: Path, files: dict | None = None) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    write(repo, dict(BASE, **(files or {})))
    relock(repo)
    return repo


def relock(repo: Path) -> None:
    lockfile.write(repo / "grantlock.json", grantlock.lock(grantlock.scan(repo)))


def run_check(repo: Path, policy=None):
    from grantlock.diff import diff
    return diff(grantlock.scan(repo), lockfile.read(repo / "grantlock.json"), policy)


def of_class(findings, cls):
    return [f for f in findings["findings"] if f["class"] == cls]
