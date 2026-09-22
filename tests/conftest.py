"""Shared bootstrap for tests that use an installed Keystone package."""

import warnings

import keystone.conf

# Register Keystone's configuration groups before importing RXT. The plugin
# applies federation configuration overrides during module initialization.
keystone.conf.configure()

from keystone.auth.plugins import mapped
import keystone_rxt.rackspace as rxt

warnings.filterwarnings("ignore", category=DeprecationWarning)


def assert_patch_active():
    """Assert that Keystone is using the adapter selected by RXT."""
    assert mapped.handle_projects_from_mapping is rxt._handle_projects_from_mapping


__all__ = ["assert_patch_active", "mapped", "rxt"]
