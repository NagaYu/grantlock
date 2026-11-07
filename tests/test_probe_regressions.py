"""Regressions found by the Phase 2 real-repository probe (D-036). Inputs are minimal re-creations."""

from grantlock import model
from grantlock.parsers.gha import parse_workflow


def test_shell_variable_named_like_npm_token_is_not_a_secret():
    assert not model.literal_is_secret(None, "npm_packages")
    assert model.classify_known_shape("npm_" + "A1" * 18)["class"] == "npm_token"  # real 36-char body still matches
    wf = """
on: push
jobs:
  detect:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: |
          for p in $npm_packages; do echo "$p"; done
"""
    entries, _ = parse_workflow(".github/workflows/r.yml", wf)
    assert all(e["credential"]["storage"] != "inline" for e in entries)


def test_step_outcome_named_like_secrets_is_not_a_secret_reference():
    wf = """
on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - id: redact_secrets
        run: echo hi
      - if: always() && steps.redact_secrets.outcome == 'success'
        run: echo ok
      - run: echo ${{ secrets.REAL_TOKEN }}
"""
    entries, _ = parse_workflow(".github/workflows/w.yml", wf)
    names = sorted(e["credential"]["name"] for e in entries)
    assert names == ["GITHUB_TOKEN", "REAL_TOKEN"]
