"""Tests for the project projection of the RXT SAML login path.

An empty project list must deny the login rather than project an empty
project name, which every affected user resolves to one shared project.
"""

import flask
import keystone.conf
from keystone import exception

from conftest import rxt


DDI = "916098"


def build_auth(access_projects):
    """Return a SAML auth object whose IdP lookup is stubbed out."""
    auth = rxt.RXTSAMLAuth({})
    auth._return_rxt_roles = lambda uid, ddi, token: (
        list(access_projects),
        {"identity": "reader"},
        True,
    )
    handled = []
    auth._return_auth_handler = lambda **kwargs: handled.append(kwargs)
    return auth, handled


def run(access_projects, enforcement):
    keystone.conf.CONF.set_override(
        "role_attribute_enforcement", enforcement, group="rackspace"
    )
    auth, handled = build_auth(access_projects)
    try:
        with flask.Flask("test").test_request_context("/"):
            flask.request.environ.update(
                {
                    "uid": "test-uid",
                    "REMOTE_DDI": DDI,
                    "REMOTE_AUTH_TOKEN": "token-abc",
                }
            )
            try:
                auth.rxt_auth()
                raised = None
            except exception.Unauthorized as e:
                raised = e
            environ = dict(flask.request.environ)
    finally:
        keystone.conf.CONF.clear_override(
            "role_attribute_enforcement", group="rackspace"
        )

    return raised, handled, environ


def test_empty_projection_denies_login():
    raised, handled, environ = run([], enforcement=True)

    assert raised is not None
    assert not handled
    # Nothing may reach the mapping, otherwise the empty project name is
    # projected and the shared project is created.
    assert "REMOTE_PROJECTS" not in environ


def test_projected_projects_are_passed_to_the_mapping():
    raised, handled, environ = run(["11111111", "22222222"], enforcement=True)

    assert raised is None
    assert handled == [{"status": True, "reenable_user": True}]
    assert environ["REMOTE_PROJECTS"] == "11111111;22222222"
    assert environ["RXT_orgPersonType"] == "reader"
    assert environ[rxt.RXT_RECONCILE_ROLES_ENV] == "true"


def test_ddi_fallback_does_not_apply_to_federated_login():
    raised, handled, environ = run([], enforcement=False)

    assert raised is not None
    assert not handled
    assert "REMOTE_PROJECTS" not in environ
