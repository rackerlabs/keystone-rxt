"""pytest bootstrap for keystone-rxt verification tests.

Imports the real Keystone 2026.1 (installed editable into the shared
/Users/chris.breu/code/openstack/.venv) and registers its config groups
before the RXT driver is imported, mirroring keystone/tests/unit/core.py.
"""

import warnings

import keystone.conf

# Register all keystone config groups (incl. [federation]) BEFORE importing the
# RXT driver, whose module body calls CONF.set_override on import.
keystone.conf.configure()

from keystone.auth.plugins import mapped
import keystone_rxt.rackspace as rxt

warnings.filterwarnings("ignore", category=DeprecationWarning)


def assert_patch_active():
    """Sanity: the RXT monkey-patch must be installed on the real module."""
    assert mapped.handle_projects_from_mapping is rxt._handle_projects_from_mapping


# Expose for the test modules.
__all__ = ["mapped", "rxt", "assert_patch_active"]
