import pytest

from grantlock.owners import compile_pattern, match, owner_record, parse_codeowners


@pytest.mark.parametrize("pattern,path,hit", [
    ("*", "a/b/c.json", True),
    ("/.github/", ".github/workflows/ci.yml", True),
    ("/.github/", "x/.github/workflows/ci.yml", False),
    (".github/", "x/.github/workflows/ci.yml", True),  # trailing-slash-only pattern: any depth
    ("/.mcp.json", ".mcp.json", True),
    ("/.mcp.json", "sub/.mcp.json", False),
    (".mcp.json", "sub/.mcp.json", True),
    ("*.json", "tools/agents/mcp.json", True),
    ("docs/*", "docs/a.md", True),
    ("docs/*", "docs/a/b.md", False),
    ("/apps/**/mcp.json", "apps/x/y/mcp.json", True),
    ("/apps/**/mcp.json", "apps/mcp.json", True),
    ("tools", "tools/agents/mcp.json", True),
    ("/.github/workflows/deploy.yml", ".github/workflows/ci.yml", False),
])
def test_patterns(pattern, path, hit):
    assert bool(compile_pattern(pattern).match(path)) is hit


def test_last_match_wins_and_empty_owner_rule():
    rules = parse_codeowners("*  @org/all\n/tools/  @org/tools\n/tools/exp/\n# c\n")
    assert owner_record(rules, "src/a.py")["owners"] == ["@org/all"]
    rec = owner_record(rules, "tools/x.json")
    assert rec == {"source": "codeowners", "owners": ["@org/tools"], "rule": ".github/CODEOWNERS: /tools/ @org/tools", "line": 2}
    # explicit rule without owners -> unowned
    assert owner_record(rules, "tools/exp/mcp.json") is None
    assert match(rules, "tools/exp/mcp.json").line == 3


def test_inline_comment_stripped():
    rules = parse_codeowners("/a/   @x/y   # owners of a\n")
    assert rules[0].owners == ("@x/y",)


def test_no_rules_no_owner():
    assert owner_record([], ".mcp.json") is None
