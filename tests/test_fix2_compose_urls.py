"""Fix2 A (D-049): in compose, a credential-named key holding a passwordless URL or a host name is configuration,
not a credential reference. Key-file paths stay references; URLs with a password stay inline secrets."""

from grantlock.parsers.compose import parse_compose
from repo_builder import of_class, relock, run_check, write
from secret_guard import assert_no_secret_leak

SHARED_URL = """services:
  api:
    image: ghcr.io/acme/api:1
    environment:
      REDIS_URL: redis://cache:6379/0
      DATABASE_URL: postgres://db:5432/app
  worker:
    image: ghcr.io/acme/worker:1
    environment:
      REDIS_URL: redis://cache:6379/0
      DATABASE_URL: postgres://db:5432/app
  cache:
    image: redis:7
"""


def _repo(tmp_path, compose):
    repo = tmp_path / "r"
    repo.mkdir()
    write(repo, {".github/CODEOWNERS": "* @acme/platform\n", "compose.yaml": compose})
    relock(repo)
    return repo


def test_shared_passwordless_urls_are_clean(tmp_path):
    entries, _ = parse_compose("compose.yaml", SHARED_URL)
    assert entries == []
    assert run_check(_repo(tmp_path, SHARED_URL))["findings"] == []


def test_host_name_values_are_not_references():
    text = "services:\n  a:\n    environment:\n      REDIS_URL: cache:6379\n      MONGODB_URI: mongo.internal\n"
    assert parse_compose("compose.yaml", text)[0] == []


def test_key_file_path_is_still_a_reference():
    text = "services:\n  a:\n    environment:\n      GOOGLE_APPLICATION_CREDENTIALS: /run/secrets/gcp-sa.json\n"
    e, _ = parse_compose("compose.yaml", text)
    assert [(x["identity_id"], x["credential"]["storage"]) for x in e] == [("gcp:GOOGLE_APPLICATION_CREDENTIALS", "env")]


def test_url_with_password_is_still_an_inline_secret(tmp_path):
    pw = "FAKEcomposeUrlPw1234"
    leak = SHARED_URL.replace("postgres://db:5432/app", f"postgres://app:{pw}@db:5432/app", 1)
    repo = _repo(tmp_path, SHARED_URL)
    write(repo, {"compose.yaml": leak})
    f = run_check(repo)
    g1 = of_class(f, "G1")
    assert [(g["component"]["name"], g["details"]["format"]["class"]) for g in g1] == [("api", "connection_string_with_password")]
    assert_no_secret_leak(f, [pw])
