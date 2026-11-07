"""Phase 2 Step 0: frozen dev archive and the optional strict_recorded_g3 flag (D-010 stays default)."""

from pathlib import Path

import pytest

from grantbench.generator import corpus_digest
from grantlock.policy import PolicyError, default_policy, merge_policy, severity_for
from repo_builder import DEPLOY, base_repo, of_class, run_check

FROZEN = Path(__file__).parents[1] / "bench" / "dev-frozen"
FROZEN_SHA = "806d821b43fe1813f21d0c7dded45e2b5871b50426a012fd791dbf5627aeae76"
WRITE_ALL_PROD = DEPLOY.replace("    permissions:\n      contents: read\n      id-token: write\n", "    permissions: write-all\n")


def test_frozen_dev_archive_unchanged():
    assert FROZEN.is_dir()
    assert corpus_digest(FROZEN) == FROZEN_SHA


def test_default_keeps_d010():
    pol = default_policy()
    assert pol["strict_recorded_g3"] is False
    assert severity_for("G3", True, "unchanged", pol) == "warning"
    assert severity_for("G3", True, "introduced", pol) == "critical"


def test_strict_flag_keeps_recorded_production_g3_critical(tmp_path):
    repo = base_repo(tmp_path, {".github/workflows/deploy.yml": WRITE_ALL_PROD})
    default = run_check(repo)
    assert of_class(default, "G3")[0]["severity"] == "warning" and default["summary"]["exit_code"] == 0
    strict = merge_policy({"schema_version": "1.0", "document": "grantlock.policy", "strict_recorded_g3": True})
    f = run_check(repo, strict)
    g3 = of_class(f, "G3")
    assert len(g3) == 1 and g3[0]["change"] == "unchanged" and g3[0]["severity"] == "critical"
    assert f["summary"]["exit_code"] == 1


def test_strict_flag_only_affects_g3():
    strict = merge_policy({"schema_version": "1.0", "document": "grantlock.policy", "strict_recorded_g3": True})
    assert severity_for("G2", True, "unchanged", strict) == "warning"
    assert severity_for("G7", True, "unchanged", strict) == "warning"
    assert severity_for("G3", False, "unchanged", strict) == "warning"  # non-production unaffected


def test_strict_flag_type_checked():
    with pytest.raises(PolicyError):
        merge_policy({"schema_version": "1.0", "document": "grantlock.policy", "strict_recorded_g3": "yes"})


def test_frozen_dev_rescore_reproduces_phase1_numbers():
    """GATE 2 criterion 2: the untouched archive, scored with today's code, gives Phase 1's results."""
    from grantbench.score import score_grantlock
    r = score_grantlock(FROZEN)
    assert all(v == {"detected": 10, "total": 10, "recall": 1.0} for v in r["recall_by_class"].values())
    assert r["clean"]["fp_cases"] == 0 and r["clean"]["cases"] == 24
    assert r["diff_pair"]["correct"] == 16 and r["diff_pair"]["cases"] == 16
    assert corpus_digest(FROZEN) == FROZEN_SHA  # scoring wrote nothing
