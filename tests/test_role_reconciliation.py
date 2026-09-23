"""Tests for revoking project-role grants the identity provider dropped.

Rackspace Identity is authoritative for the direct project-role grants of an
authenticating RXT user, but only when it returned a complete role and tenant
view. These tests exercise both supported Keystone handler contracts.
"""

import flask
from keystone import exception

from conftest import rxt


USER = {
    "id": "fed-user-1",
    "name": "feduser",
    "domain_id": "rackspace_cloud_domain",
    "enabled": True,
}
EXISTING_ROLES = {
    "member": {"id": "role-member", "domain_id": None},
    "reader": {"id": "role-reader", "domain_id": None},
}


class FakeAssignmentAPI:
    def __init__(self, assignments=()):
        self.assignments = list(assignments)
        self.granted = []
        self.deleted = []
        self.listed_user_ids = []

    def create_grant(self, role_id, user_id=None, project_id=None):
        self.granted.append((role_id, user_id, project_id))

    def delete_grant(self, role_id, user_id=None, project_id=None):
        self.deleted.append((role_id, user_id, project_id))

    def list_role_assignments(self, user_id=None):
        self.listed_user_ids.append(user_id)
        return self.assignments


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


def _shadow_project(name):
    return {
        "name": name,
        "domain": {"id": "rackspace_cloud_domain"},
        "roles": [{"name": "member"}],
        "tags": [],
        "metadata": [],
    }


def _existing_project(name, project_id):
    return {
        ("rackspace_cloud_domain", name): None,
        (name, "rackspace_cloud_domain"): {
            "id": project_id,
            "name": name,
            "domain_id": "rackspace_cloud_domain",
            "tags": [],
            "description": None,
        },
    }


def _run(handler, shadow_projects, assignment_api, resource_api, reconcile):
    """Drive one adapter with the reconciliation marker set as requested."""
    with flask.Flask("test").test_request_context("/"):
        flask.request.environ["RXT_orgPersonType"] = "member"
        flask.request.environ[rxt.RXT_RECONCILE_ROLES_ENV] = reconcile
        if handler is rxt._handle_projects_from_mapping_2026_1:
            handler(
                shadow_projects,
                EXISTING_ROLES,
                USER,
                "2.0",
                assignment_api,
                resource_api,
            )
        else:
            handler(
                shadow_projects,
                "rackspace_cloud_domain",
                EXISTING_ROLES,
                USER,
                assignment_api,
                resource_api,
            )


ADAPTERS = [
    rxt._handle_projects_from_mapping_pre_2026_1,
    rxt._handle_projects_from_mapping_2026_1,
]


def test_stale_role_on_retained_project_is_revoked():
    for handler in ADAPTERS:
        projects = _existing_project("11111111", "proj-1")
        assignment_api = FakeAssignmentAPI(
            [
                # Still supplied by the IdP, so it must survive.
                {
                    "user_id": USER["id"],
                    "project_id": "proj-1",
                    "role_id": "role-member",
                },
                # No longer supplied by the IdP.
                {
                    "user_id": USER["id"],
                    "project_id": "proj-1",
                    "role_id": "role-reader",
                },
            ]
        )

        _run(
            handler,
            [_shadow_project("11111111")],
            assignment_api,
            FakeResourceAPI(projects),
            "true",
        )

        assert ("role-member", USER["id"], "proj-1") in assignment_api.granted
        assert assignment_api.deleted == [
            ("role-reader", USER["id"], "proj-1")
        ]
        assert assignment_api.listed_user_ids == [USER["id"]]


def test_grants_for_omitted_project_are_revoked():
    for handler in ADAPTERS:
        projects = _existing_project("11111111", "proj-1")
        assignment_api = FakeAssignmentAPI(
            [
                {
                    "user_id": USER["id"],
                    "project_id": "proj-1",
                    "role_id": "role-member",
                },
                # Project absent from the authoritative IdP response.
                {
                    "user_id": USER["id"],
                    "project_id": "proj-gone",
                    "role_id": "role-member",
                },
            ]
        )

        _run(
            handler,
            [_shadow_project("11111111")],
            assignment_api,
            FakeResourceAPI(projects),
            "true",
        )

        assert assignment_api.deleted == [
            ("role-member", USER["id"], "proj-gone")
        ]


def test_incomplete_idp_response_never_revokes():
    for handler in ADAPTERS:
        projects = _existing_project("11111111", "proj-1")
        assignment_api = FakeAssignmentAPI(
            [
                {
                    "user_id": USER["id"],
                    "project_id": "proj-gone",
                    "role_id": "role-member",
                }
            ]
        )

        _run(
            handler,
            [_shadow_project("11111111")],
            assignment_api,
            FakeResourceAPI(projects),
            "false",
        )

        assert not assignment_api.deleted
        assert not assignment_api.listed_user_ids


def test_group_domain_and_other_user_assignments_are_preserved():
    for handler in ADAPTERS:
        projects = _existing_project("11111111", "proj-1")
        assignment_api = FakeAssignmentAPI(
            [
                # Group-derived project assignment.
                {
                    "user_id": USER["id"],
                    "project_id": "proj-gone",
                    "role_id": "role-member",
                    "indirect": {"group_id": "group-1"},
                },
                # Domain assignment carries no project_id.
                {
                    "user_id": USER["id"],
                    "domain_id": "rackspace_cloud_domain",
                    "role_id": "role-member",
                },
                # Belongs to a different user.
                {
                    "user_id": "other-user",
                    "project_id": "proj-gone",
                    "role_id": "role-member",
                },
            ]
        )

        _run(
            handler,
            [_shadow_project("11111111")],
            assignment_api,
            FakeResourceAPI(projects),
            "true",
        )

        assert not assignment_api.deleted


def test_inherited_assignments_are_preserved():
    for handler in ADAPTERS:
        projects = _existing_project("11111111", "proj-1")
        assignment_api = FakeAssignmentAPI(
            [
                {
                    "user_id": USER["id"],
                    "project_id": "proj-gone",
                    "role_id": "role-member",
                    "inherited_to_projects": "projects",
                }
            ]
        )

        _run(
            handler,
            [_shadow_project("11111111")],
            assignment_api,
            FakeResourceAPI(projects),
            "true",
        )

        assert not assignment_api.deleted


def test_empty_projection_never_revokes():
    for handler in ADAPTERS:
        assignment_api = FakeAssignmentAPI(
            [
                {
                    "user_id": USER["id"],
                    "project_id": "proj-1",
                    "role_id": "role-member",
                }
            ]
        )

        _run(handler, [], assignment_api, FakeResourceAPI({}), "true")

        assert not assignment_api.deleted


def test_already_revoked_grant_is_tolerated():
    class RacingAssignmentAPI(FakeAssignmentAPI):
        def delete_grant(self, role_id, user_id=None, project_id=None):
            raise exception.RoleAssignmentNotFound(
                role_id=role_id, actor_id=user_id, target_id=project_id
            )

    projects = _existing_project("11111111", "proj-1")
    assignment_api = RacingAssignmentAPI(
        [
            {
                "user_id": USER["id"],
                "project_id": "proj-gone",
                "role_id": "role-member",
            }
        ]
    )

    _run(
        rxt._handle_projects_from_mapping_2026_1,
        [_shadow_project("11111111")],
        assignment_api,
        FakeResourceAPI(projects),
        "true",
    )

    assert not assignment_api.deleted
