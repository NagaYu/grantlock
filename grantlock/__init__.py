"""GrantLock: a declarative lockfile for the identities an AI-agent stack runs as.

The core is a set of pure, stateless functions:

    scan(repo_path) -> inventory (dict, schema_version'd JSON)
    diff(inventory, lockfile, policy) -> findings (dict, schema_version'd JSON)

The core never performs network I/O and never records secret values.
"""

__version__ = "0.1.0"


def scan(repo_path):
    """scan(repo_path) -> inventory dict (schema grantlock.inventory 1.0)."""
    from .inventory import scan as _scan

    return _scan(repo_path)


def lock(inventory):
    """lock(inventory) -> lockfile dict (schema grantlock.lock 1.0)."""
    from .lockfile import lock as _lock

    return _lock(inventory)


# Load the submodule *before* binding the public function: importing a submodule
# sets the package attribute of the same name, which would otherwise replace
# `grantlock.diff` (the function) with the module (D-032).
from . import diff as _diff_module  # noqa: E402


def diff(inventory, lockfile, policy=None):
    """diff(inventory, lockfile, policy) -> findings dict (schema grantlock.findings 1.0)."""
    return _diff_module.diff(inventory, lockfile, policy)
