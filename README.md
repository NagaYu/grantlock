# GrantLock

**A lockfile for *who your AI agent stack runs as* — and a CI gate on changes to it.**

GrantLock records the identities an agent stack operates under — API keys, OAuth grants, service
accounts, MCP server secrets, CI tokens, cloud roles and their scopes — in a committed, reviewable
lockfile, `grantlock.json`. In CI, `grantlock check` recomputes the inventory from the repository and
classifies what changed *semantically*: a new identity in production, a scope added to an existing
one, a wildcard or admin grant, a long-lived key where federation is available, a grant nobody uses
any more. It never records secret values.

Surfaces read: **MCP configs** (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, …),
**GitHub Actions workflows**, **`.env` / `.env.example`**, **docker-compose**, **Kubernetes manifests**
(Secrets, ServiceAccounts, RBAC, workloads) and **Terraform** (IAM policies and roles, keys, provider
credentials, the compute that uses them).

> **Status: research prototype, published for evaluation.** The pre-registered acceptance gate on a
> sealed, independently written benchmark (GATE 2) **has not been passed**; the full gate history is
> below. Not published on PyPI. See [License](#license).

## What is recorded — and what never is

The lockfile, findings, SARIF and evidence pack contain only variable / secret names, providers, the
storage class (`vault_ref`, `env`, `inline`, `federated`), lifespans, normalized scopes, owners and,
for inline literals, a *format class* from a fixed table (e.g. `openai_key` with prefix `sk-`). No
secret values, no slices of values, no hashes of values. `.env` files are read for names only;
Kubernetes Secret `data` is never base64-decoded; Terraform literals are classified and discarded.
The scanning core makes no network calls.

## Quick start

Requires Python ≥ 3.10 (dependencies: PyYAML, jsonschema). Install from a checkout:

```bash
pip install -e .
grantlock lock                      # writes grantlock.json — review it and commit it
# ... change an MCP config, a workflow, a manifest ...
grantlock check                     # exit 1 on a critical finding, 0 otherwise, 2 on bad input
grantlock check --format sarif --output grantlock.sarif
grantlock evidence --output-dir evidence/ [--previous-lock prev-grantlock.json]
grantlock scan                      # print the identity inventory as JSON
```

`check` never modifies `grantlock.json`. To accept a change in grants, a human runs `grantlock lock`
and commits the lockfile diff — that diff is the review surface. `grantlock evidence` writes an audit
pack (JSON + Markdown) with a *suggestive* mapping of finding classes to NIST SP 800-53 IA-5 / AC-6
and SOC 2 CC6.1 / CC6.6; it is not a compliance attestation.

## Finding classes

| Class | Meaning | Default severity |
|---|---|---|
| G1 | Inline secret value in configuration | warning |
| G2 | Scope / permission added to an existing identity | critical in production, else warning |
| G3 | Wildcard or admin-level grant (`write-all`, `*`, admin/owner roles) | critical in production when newly introduced, else warning |
| G4 | Identity without an owner (no CODEOWNERS entry / declared owner) | warning |
| G5 | One identity shared by multiple components | warning |
| G6 | Long-lived static key where federation / short-lived credentials exist | warning |
| G7 | New identity not declared in `grantlock.json` | critical in production, else warning |
| G8 | Dormant grant: a locked identity no component uses any more | warning |

"Production" is a deterministic naming heuristic (environment names, hosts, roles, components matching
`prod|production|prd|live`); the evidence is included in every finding. Severities and patterns can be
overridden in `grantlock.policy.json`.

## GrantBench results

GrantBench is a set of small repository snapshots with planted risks (`planted`), least-privilege
repositories (`clean`) and before/after pairs (`diff_pair`). Recall is per planted case with strict
matching on class, file and component.

### Development corpora (written by the same author as the detector)

| Corpus | G1–G8 recall | Clean false positives | Diff accuracy |
|---|---|---|---|
| `dev` (frozen, 120 cases) | 10/10 for every class | 0/24 | 16/16 |
| `dev-ext` (compose / Kubernetes / Terraform, 68 cases) | 6/6 for every class | 0/12 | 8/8 |

These are consistency checks: the generator and the detector share an author and a specification.
They are not evidence of performance on configurations written by someone else.

### Gate history (sealed holdouts written by independent authors)

Pre-registered bar (GATE 2): recall on G2, G3 and G7 each ≥ 80% and their mean ≥ 90%, and clean
false positives ≤ 5%.

| Step | Corpus | Result | Outcome |
|---|---|---|---|
| Gate attempt 1 | Sealed holdout v1 (independent author) | G2 6/7, G3 5/7, G7 8/8 (mean 85.7%); clean false positives 0/16 | **Fail** (recall) |
| Fix round 1 | — | Four blind spots fixed (unbound Kubernetes roles, Terraform provider credentials, declaration-side static keys in Kubernetes, Terraform `var.*` references) | — |
| Gate attempt 2 | Sealed holdout v2 (second independent author) | G2 7/8, G3 7/8, G7 8/8 (mean 91.7%, recall within the bar); G1 6/8 (one case was a detector exception); clean false positives 5/16 | **Fail** (false positives) |
| Fix round 2 | — | The single compose rule behind all five false positives was narrowed, and a format-table / schema mismatch behind the exception was fixed | — |
| Re-verification (not a gate) | Holdout v2, now disclosed | Clean false positives 0/16, G1 7/8, diff 8/8; G2, G3, G7 unchanged | not a pass |

**The pre-registered GATE 2 has not been passed.** Holdouts v1 and v2 have both been seen after
scoring, so results on them are re-verification only. Passing would require a new sealed holdout.
Details: [`reports/phase2.md`](reports/phase2.md), [`reports/phase2-fix.md`](reports/phase2-fix.md),
[`reports/phase2-fix2.md`](reports/phase2-fix2.md), and the decision log in [`DECISIONS.md`](DECISIONS.md).

### Real repositories

A false-positive probe on three public repositories (`NagaYu/caplock`, `modelcontextprotocol/servers`,
`github/github-mcp-server`) produced 87 findings, all reviewed by hand: 56 valid, 19 false positives,
12 undecided. None of the three contains compose, Kubernetes or Terraform files.

## Baselines: value scanners vs. value-free classes

gitleaks 8.30.1 and trufflehog 3.99.8 were run offline on the same snapshots
(`--redact` / `--no-verification --no-update`).

| Corpus | gitleaks G1 | trufflehog G1 | G2–G8 (both) |
|---|---|---|---|
| `dev` | 6/10 | 7/10 | 0/10 per class |
| `dev-ext` | 5/6 | 6/6 | 0 |
| Holdout v2 | 5/8 | 5/8 | 0 |

Secret scanners answer "is there a secret value in this file?". Classes G2–G8 — a scope added, an admin
role, an owner removed, a key shared, a federated role swapped for a static key, an identity that
appears or goes dormant — contain no secret value, so value scanners structurally cannot see them. On
G1 the comparison depends on how faithfully dummy secrets mimic real formats; the `dev` dummies were
prefix-only imitations, which disadvantages the baselines.

## Known limitations

- Terraform: literals inside nested maps / objects (e.g. a function's environment variables) are not read.
- MCP: toolsets selected through an HTTP header of a remote MCP server are not read as scopes.
- Kubernetes: a service-account key file mounted from a Secret volume (with its path in an env var) is
  not recognized as a static key.
- MCP: a credential-named key holding a non-secret literal is treated as a credential reference
  (compose was narrowed in fix round 2; the MCP parser was not).

## Repository layout

`grantlock/` scanner, lockfile, diff engine, CLI · `grantbench/` corpus generators and scoring harness ·
`bench/dev`, `bench/dev-frozen` (frozen copy used for regression), `bench/dev-ext` · `tests/` ·
`SPEC.md`, `DECISIONS.md`, `STATUS.md`, `reports/`. Sealed holdout corpora are not included.

## License

Copyright © 2026 NagaYu. **All Rights Reserved.** This repository is published for evaluation only; no
license to use, copy, modify or distribute it is granted. See [LICENSE](LICENSE). For licensing or
transfer inquiries, please use the contact form at https://nagayu-portfolio.nagayu.workers.dev/en.
