"""Integration check for the installed Keystone project-mapping call path.

The test invokes the RXT override through the call contract used by the
installed Keystone release. Keystone 2026.1 uses
``configure_federated_projects``; earlier releases call the project handler
directly.
"""

import hashlib

import flask
from keystone import exception

from conftest import assert_patch_active, mapped, rxt


class FakeAssignmentAPI:
    def __init__(self):
        self.granted = []
        self.deleted = []

    def create_grant(self, role_id, user_id=None, project_id=None):
        self.granted.append((role_id, user_id, project_id))

    def delete_grant(self, role_id, user_id=None, project_id=None):
        self.deleted.append((role_id, user_id, project_id))


class FakeResourceAPI:
    def __init__(self, existing):
        self.projects = dict(existing)

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


def test_installed_keystone_call_contract_drives_rxt_patch():
    assert_patch_active()

    user = {
        "id": "fed-user-1",
        "name": "feduser",
        "domain_id": "rackspace_cloud_domain",
        "enabled": True,
    }
    existing_roles = {
        "member": {"id": "role-member", "domain_id": None},
        "reader": {"id": "role-reader", "domain_id": None},
        "creator": {"id": "role-creator", "domain_id": None},
    }
    shadow_projects = [
        {
            "name": "55555555",
            "domain": {"id": "rackspace_cloud_domain"},
            "roles": [{"name": "member"}],
            "tags": [{"project_tag": "ddi-55555555"}],
            "description": "Project for DDI 55555555",
            "metadata": [{"key": "ddi", "value": "55555555"}],
        },
        {
            "name": "66666666",
            "domain": {"name": "rackspace_cloud_domain"},
            "roles": [{"name": "reader"}, {"name": "creator"}],
            "tags": [],
            "metadata": [],
        },
    ]
    resource_api = FakeResourceAPI(
        {
            ("66666666", "rackspace_cloud_domain"): {
                "id": "proj-66666666",
                "name": "66666666",
                "domain_id": "rackspace_cloud_domain",
                "tags": [],
                "description": None,
            }
        }
    )
    assignment_api = FakeAssignmentAPI()

    with flask.Flask("test").test_request_context("/"):
        flask.request.environ["RXT_orgPersonType"] = "member"
        if (
            rxt._handle_projects_from_mapping
            is rxt._handle_projects_from_mapping_2026_1
        ):
            mapped.configure_federated_projects(
                shadow_projects,
                "rackspace_cloud_domain",
                existing_roles,
                user,
                assignment_api,
                resource_api,
                "2.0",
            )
        else:
            mapped.handle_projects_from_mapping(
                shadow_projects,
                "rackspace_cloud_domain",
                existing_roles,
                user,
                assignment_api,
                resource_api,
            )

    id_555 = hashlib.shake_256(b"55555555").hexdigest(length=16)
    expected_grants = {
        ("role-member", "fed-user-1", id_555),
        ("role-reader", "fed-user-1", "proj-66666666"),
        ("role-creator", "fed-user-1", "proj-66666666"),
        ("role-member", "fed-user-1", "proj-66666666"),
    }
    assert set(assignment_api.granted) == expected_grants
    assert not assignment_api.deleted

    created_555 = resource_api.projects[
        ("55555555", "rackspace_cloud_domain")
    ]
    assert created_555["id"] == id_555
    assert created_555["tags"] == ["ddi-55555555"]
    assert created_555["description"] == "Project for DDI 55555555"
    assert created_555["ddi"] == "55555555"
