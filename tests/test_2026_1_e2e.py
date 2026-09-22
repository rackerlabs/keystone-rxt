"""End-to-end integration check against real Keystone 2026.1.

Drives the GENUINE upstream call path -- ``mapped.configure_federated_projects``
(which calls ``mapped.handle_projects_from_mapping``) -- and asserts that the
keystone-rxt monkey-patch is what executes, with the correct 2026.1 arguments
flowing through. This proves the fix works on the exact code path a real
federated login uses.
"""

import hashlib

import flask
from keystone import exception

from conftest import mapped, rxt, assert_patch_active


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
        for (name, dom), ref in self.projects.items():
            if ref["id"] == project_id:
                ref.update(project)
                return


def test_configure_federated_projects_drives_rxt_patch():
    assert_patch_active()

    # Realistic flat-domain shadow user.
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
            "domain": {"name": "rackspace_cloud_domain"},  # name-only
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

    ctx = flask.Flask("test").test_request_context("/")
    ctx.push()
    try:
        flask.request.environ["RXT_orgPersonType"] = "member"
        # EXACT upstream 2026.1 signature for configure_federated_projects.
        mapped.configure_federated_projects(
            shadow_projects,
            "rackspace_cloud_domain",  # idp_domain_id
            existing_roles,
            user,
            assignment_api,
            resource_api,
            "2.0",  # schema_version
        )
    finally:
        ctx.pop()

    id_555 = hashlib.shake_256("55555555".encode()).hexdigest(length=16)
    # RXT_orgPersonType = "member" applies to every project.
    expected = {
        ("role-member", "fed-user-1", id_555),
        ("role-reader", "fed-user-1", "proj-66666666"),
        ("role-creator", "fed-user-1", "proj-66666666"),
        ("role-member", "fed-user-1", "proj-66666666"),
    }
    assert set(assignment_api.granted) == expected
    assert not assignment_api.deleted
    project_ids = [p["id"] for p in resource_api.projects.values()]
    assert id_555 in project_ids
