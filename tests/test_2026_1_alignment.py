"""Real (no-stub) verification of the keystone-rxt project-projection handler
against actual Keystone 2026.1.

Exercises the REAL patched function
``keystone_rxt.rackspace._handle_projects_from_mapping`` through the
upstream 2026.1 positional call signature, using a realistic shadow
federated user ref (flat ``domain_id`` -- NOT a nested ``domain`` dict) and
fake provider APIs.
"""

import hashlib

import flask
from keystone import exception

from conftest import mapped, rxt


# ---------------------------------------------------------------------------
# Fake provider APIs (test-local state per test run)
# ---------------------------------------------------------------------------
class FakeAssignmentAPI:
    def __init__(self):
        self.granted = []
        self.deleted = []

    def create_grant(self, role_id, user_id=None, project_id=None):
        self.granted.append((role_id, user_id, project_id))

    def delete_grant(self, role_id, user_id=None, project_id=None):
        self.deleted.append((role_id, user_id, project_id))


class FakeResourceAPI:
    def __init__(self, existing_projects):
        self.projects = dict(existing_projects)
        self.configure_domain_calls = []

    def get_domain_by_name(self, name):
        return {"id": "rackspace_cloud_domain"}

    def get_project_by_name(self, name, domain_id):
        key = (name, domain_id)
        if key not in self.projects:
            raise exception.ProjectNotFound(name)
        return self.projects[key]

    def create_project(self, project_id, project_ref):
        ref = {
            "id": project_id,
            "name": project_ref["name"],
            "domain_id": project_ref["domain_id"],
            "tags": [],
            "description": None,
        }
        self.projects[(project_ref["name"], project_ref["domain_id"])] = ref
        return ref

    def update_project(self, project_id, project):
        for (name, dom), ref in self.projects.items():
            if ref["id"] == project_id:
                ref.update(project)
                return
        self.projects[("?", "?")] = project


def _build_fixtures():
    existing_roles = {
        "member": {"id": "role-member", "domain_id": None},
        "creator": {"id": "role-creator", "domain_id": None},
        "reader": {"id": "role-reader", "domain_id": None},
        "user-admin": {"id": "role-user-admin", "domain_id": None},
    }

    # REALISTIC shadow federated user ref: flat "domain_id" (the SQL model
    # emits a column, not a nested "domain" dict) -- the exact shape Keystone
    # passes to the handler.
    user = {
        "id": "fed-user-1",
        "name": "feduser",
        "domain_id": "rackspace_cloud_domain",
        "enabled": True,
    }

    shadow_projects = [
        {
            "name": "11111111",
            "domain": {"id": "rackspace_cloud_domain"},
            "roles": [{"name": "member"}, {"name": "creator"}],
            "tags": [{"project_tag": "ddi-11111111"}],
            "description": "Project for DDI 11111111",
            "metadata": [{"key": "ddi", "value": "11111111"}],
        },
        {
            "name": "22222222",
            "domain": {"id": "rackspace_cloud_domain"},
            "roles": [{"name": "reader"}],
            "tags": [],
            # "description" intentionally absent
            "metadata": [],
        },
        {
            "name": "33333333",
            "domain": {"id": "rackspace_cloud_domain"},
            "roles": [{"name": "user-admin"}],
            "tags": [],
            "description": None,  # present-but-null edge case
            "metadata": [],
        },
        {
            "name": "44444444",
            "domain": {"name": "rackspace_cloud_domain"},  # name-only, no id
            "roles": [{"name": "member"}],
            "tags": [],
            "metadata": [],
        },
    ]

    resource_api = FakeResourceAPI(
        {
            ("11111111", "rackspace_cloud_domain"): {
                "id": "proj-11111111",
                "name": "11111111",
                "domain_id": "rackspace_cloud_domain",
                "tags": ["ddi-11111111"],
                "description": "Project for DDI 11111111",
                "ddi": "11111111",
            }
        }
    )
    assignment_api = FakeAssignmentAPI()
    return existing_roles, user, shadow_projects, resource_api, assignment_api


def _run_handler():
    """Run the patched handler on the fixtures, recording domain derivation
    via a wrapper around the real upstream configure_project_domain."""
    existing_roles, user, shadow_projects, resource_api, assignment_api = _build_fixtures()

    real_impl = mapped.configure_project_domain
    calls = []

    def recording(sp, did, ra):
        calls.append((sp.get("name"), did))
        real_impl(sp, did, ra)

    ctx = flask.Flask("test").test_request_context("/")
    ctx.push()
    try:
        flask.request.environ["RXT_orgPersonType"] = "reader;member"
        mapped.configure_project_domain = recording
        try:
            rxt._handle_projects_from_mapping(
                shadow_projects,
                existing_roles,
                user,
                "2.0",  # schema_version
                assignment_api,
                resource_api,
            )
        finally:
            mapped.configure_project_domain = real_impl
    finally:
        ctx.pop()

    return {
        "granted": assignment_api.granted,
        "deleted": assignment_api.deleted,
        "domain_calls": calls,
        "shadow_projects": shadow_projects,
        "resource_api": resource_api,
    }


def test_handler_runs_with_upstream_2026_1_signature():
    res = _run_handler()
    id_222 = hashlib.shake_256("22222222".encode()).hexdigest(length=16)
    id_333 = hashlib.shake_256("33333333".encode()).hexdigest(length=16)
    id_444 = hashlib.shake_256("44444444".encode()).hexdigest(length=16)

    # RXT_orgPersonType = "reader;member" applies to every shadow project.
    expected = {
        ("role-member", "fed-user-1", "proj-11111111"),
        ("role-creator", "fed-user-1", "proj-11111111"),
        ("role-reader", "fed-user-1", "proj-11111111"),
        ("role-member", "fed-user-1", id_222),
        ("role-reader", "fed-user-1", id_222),
        ("role-user-admin", "fed-user-1", id_333),
        ("role-reader", "fed-user-1", id_333),
        ("role-member", "fed-user-1", id_333),
        ("role-member", "fed-user-1", id_444),
        ("role-reader", "fed-user-1", id_444),
    }
    assert set(res["granted"]) == expected
    assert not res["deleted"], "RXT must not delete grants (additive semantics)"

    # Flat user['domain_id'] must be derived and passed for every project.
    assert res["domain_calls"], "configure_project_domain was never called"
    for name, dom in res["domain_calls"]:
        assert dom == "rackspace_cloud_domain", (name, dom)

    # The name-only project 44444444 must resolve to the user's domain.
    resolved_444 = next(p for p in res["shadow_projects"] if p["name"] == "44444444")
    assert resolved_444["domain"]["id"] == "rackspace_cloud_domain"

    # Newly-created projects exist with their deterministic shake_256 ids.
    project_ids = [p["id"] for p in res["resource_api"].projects.values()]
    for pid in (id_222, id_333, id_444):
        assert pid in project_ids


def test_legacy_call_style_raises_typeerror():
    """A pre-2026.1 positional call style must fail loudly, not misbind."""
    existing_roles, user, shadow_projects, resource_api, assignment_api = _build_fixtures()
    ctx = flask.Flask("test").test_request_context("/")
    ctx.push()
    try:
        flask.request.environ["RXT_orgPersonType"] = "reader"
        try:
            rxt._handle_projects_from_mapping(
                shadow_projects,
                "rackspace_cloud_domain",  # legacy idp_domain_id slot
                existing_roles,
                user,
                assignment_api,
                resource_api,
            )
        except TypeError as e:
            assert "2026.1" in str(e)
        else:
            raise AssertionError("legacy call style did not raise TypeError")
    finally:
        ctx.pop()
