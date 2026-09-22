"""Compatibility tests for the RXT project-projection adapters.

The tests use real objects from the installed Keystone package with lightweight
provider fakes. Both supported handler contracts are exercised directly so the
shared RXT behavior remains equivalent across Keystone releases.
"""

import hashlib
import inspect

import flask
from keystone import exception

from conftest import mapped, rxt


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
        for ref in self.projects.values():
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
            "tags": [
                {"project_tag": "ddi-11111111"},
                {"project_tag": "managed-by-rxt"},
            ],
            "description": "Updated project for DDI 11111111",
            "metadata": [
                {"key": "ddi", "value": "must-not-overwrite"},
                {"key": "region", "value": "DFW"},
            ],
        },
        {
            "name": "22222222",
            "domain": {"id": "rackspace_cloud_domain"},
            "roles": [{"name": "reader"}],
            "tags": [{"project_tag": "ddi-22222222"}],
            "description": "Project for DDI 22222222",
            "metadata": [{"key": "ddi", "value": "22222222"}],
        },
        {
            "name": "33333333",
            "domain": {"id": "rackspace_cloud_domain"},
            "roles": [{"name": "user-admin"}],
            "tags": [],
            "description": None,
            "metadata": [],
        },
        {
            "name": "44444444",
            "domain": {"name": "rackspace_cloud_domain"},
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


def _run_handler(handler, contract):
    """Run one adapter and record the domain supplied to shared projection."""
    fixtures = _build_fixtures()
    existing_roles, user, shadow_projects, resource_api, assignment_api = fixtures
    real_impl = mapped.configure_project_domain
    domain_calls = []

    def recording(shadow_project, domain_id, provider_api):
        domain_calls.append((shadow_project.get("name"), domain_id))
        real_impl(shadow_project, domain_id, provider_api)

    with flask.Flask("test").test_request_context("/"):
        flask.request.environ["RXT_orgPersonType"] = "reader;member"
        mapped.configure_project_domain = recording
        try:
            if contract == "pre-2026.1":
                handler(
                    shadow_projects,
                    "rackspace_cloud_domain",
                    existing_roles,
                    user,
                    assignment_api,
                    resource_api,
                )
            else:
                handler(
                    shadow_projects,
                    existing_roles,
                    user,
                    "2.0",
                    assignment_api,
                    resource_api,
                )
        finally:
            mapped.configure_project_domain = real_impl

    return {
        "granted": assignment_api.granted,
        "deleted": assignment_api.deleted,
        "domain_calls": domain_calls,
        "shadow_projects": shadow_projects,
        "resource_api": resource_api,
    }


def _assert_expected_projection(result):
    id_222 = hashlib.shake_256(b"22222222").hexdigest(length=16)
    id_333 = hashlib.shake_256(b"33333333").hexdigest(length=16)
    id_444 = hashlib.shake_256(b"44444444").hexdigest(length=16)

    expected_grants = {
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
    assert set(result["granted"]) == expected_grants
    assert not result["deleted"]
    assert result["domain_calls"]
    assert all(
        domain_id == "rackspace_cloud_domain"
        for _, domain_id in result["domain_calls"]
    )

    resolved_444 = next(
        project
        for project in result["shadow_projects"]
        if project["name"] == "44444444"
    )
    assert resolved_444["domain"]["id"] == "rackspace_cloud_domain"

    projects = result["resource_api"].projects
    updated_111 = projects[("11111111", "rackspace_cloud_domain")]
    assert set(updated_111["tags"]) == {
        "ddi-11111111",
        "managed-by-rxt",
    }
    assert updated_111["description"] == "Updated project for DDI 11111111"
    assert updated_111["ddi"] == "11111111"
    assert updated_111["region"] == "DFW"

    created_222 = projects[("22222222", "rackspace_cloud_domain")]
    assert created_222["tags"] == ["ddi-22222222"]
    assert created_222["description"] == "Project for DDI 22222222"
    assert created_222["ddi"] == "22222222"

    project_ids = [project["id"] for project in projects.values()]
    for project_id in (id_222, id_333, id_444):
        assert project_id in project_ids


def test_2026_1_adapter_projects_expected_state():
    result = _run_handler(
        rxt._handle_projects_from_mapping_2026_1, "2026.1"
    )
    _assert_expected_projection(result)


def test_pre_2026_1_adapter_projects_expected_state():
    result = _run_handler(
        rxt._handle_projects_from_mapping_pre_2026_1, "pre-2026.1"
    )
    _assert_expected_projection(result)


def test_installed_handler_matches_original_upstream_contract():
    expected_handler = rxt._select_project_mapping_handler(
        rxt._UPSTREAM_HANDLE_PROJECTS_FROM_MAPPING
    )
    assert rxt._handle_projects_from_mapping is expected_handler
    assert inspect.signature(expected_handler) == inspect.signature(
        rxt._UPSTREAM_HANDLE_PROJECTS_FROM_MAPPING
    )


def test_missing_upstream_handler_fails_during_selection():
    try:
        rxt._select_project_mapping_handler(None)
    except RuntimeError as exc:
        assert "handle_projects_from_mapping is not defined" in str(exc)
    else:
        raise AssertionError("missing Keystone handler was accepted")


def test_unknown_upstream_signature_fails_during_selection():
    def unsupported_handler(shadow_projects, assignment_api):
        return None

    try:
        rxt._select_project_mapping_handler(unsupported_handler)
    except RuntimeError as exc:
        message = str(exc)
        assert "Unsupported Keystone handle_projects_from_mapping" in message
        assert str(inspect.signature(unsupported_handler)) in message
    else:
        raise AssertionError("unsupported Keystone signature was accepted")


def test_schema_3_registration_is_preserved_when_available():
    schema_3 = getattr(mapped.utils, "IDP_ATTRIBUTE_MAPPING_SCHEMA_3_0", None)
    if schema_3 is not None:
        assert mapped.utils.IDP_ATTRIBUTE_MAPPING_SCHEMAS["3.0"]["schema"] is schema_3
