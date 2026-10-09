"""Tests for configured Rackspace role-attribute tenant prefixes."""

import flask
import keystone.conf

from conftest import rxt


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)

    def get(self, url, timeout=None, headers=None):
        return self.responses.pop(0)


def role_response(*tenant_ids):
    return {
        "RAX-AUTH:roleAssignments": {
            "tenantAssignments": [
                {
                    "onRoleName": "identity:default",
                    "sources": [{"forTenants": list(tenant_ids)}],
                }
            ]
        }
    }


def tenant_response(*tenant_refs):
    tenants = []
    for tenant_ref in tenant_refs:
        if isinstance(tenant_ref, dict):
            tenant = dict(tenant_ref)
            tenant.setdefault("enabled", True)
        else:
            tenant = {"id": tenant_ref, "enabled": True}
        tenants.append(tenant)
    return {"tenants": tenants}


def return_roles(
    attributes,
    tenant_ids,
    enabled_tenants=None,
    ddi="123456",
    allow_bare_ddi_flex=False,
):
    keystone.conf.CONF.set_override(
        "role_attribute", attributes, group="rackspace"
    )
    auth = rxt.RXTv2BaseAuth()
    auth._return_auth_url = lambda ddi: "https://identity.example/"
    auth.session = FakeSession(
        [
            FakeResponse(role_response(*tenant_ids)),
            FakeResponse(tenant_response(*(enabled_tenants or tenant_ids))),
        ]
    )
    cache_suffix = "-".join(attributes + list(tenant_ids))
    try:
        with flask.Flask("test").test_request_context("/"):
            return auth._return_rxt_roles(
                uid=f"role-attribute-test-user-{cache_suffix}",
                ddi=ddi,
                token="token",
                allow_bare_ddi_flex=allow_bare_ddi_flex,
            )
    finally:
        keystone.conf.CONF.clear_override(
            "role_attribute", group="rackspace"
        )


def test_role_attribute_defaults_to_single_os_flex_value():
    assert keystone.conf.CONF.rackspace.role_attribute == ["os_flex"]


def test_role_attribute_accepts_comma_separated_values():
    assert rxt.ROLE_ATTRIBUTE.type("os_flex,os_flex_mrr") == [
        "os_flex",
        "os_flex_mrr",
    ]


def test_single_role_attribute_remains_supported():
    projects, _roles, authoritative = return_roles(
        ["os_flex"], ["os_flex:project-one", "other:ignored"]
    )

    assert projects == ["project-one"]
    assert authoritative is True


def test_multiple_role_attributes_are_supported():
    projects, _roles, authoritative = return_roles(
        ["os_flex", "os_flex_mrr"],
        [
            "os_flex:project-one",
            "os_flex_mrr:project-two",
            "unconfigured:ignored",
        ],
    )

    assert projects == ["project-one", "project-two"]
    assert authoritative is True


def test_ddi_flex_project_names_are_supported():
    projects, _roles, authoritative = return_roles(
        ["os_flex", "os_flex_mrr"],
        ["123456_Flex", "654321_Flex", "not-a-ddi_Flex"],
        allow_bare_ddi_flex=True,
        enabled_tenants=[
            {
                "id": "tenant-id-for-ddi-flex",
                "name": "123456_Flex",
            },
            {
                "id": "tenant-id-for-other-ddi-flex",
                "name": "654321_Flex",
            },
            {
                "id": "tenant-id-for-invalid-flex",
                "name": "not-a-ddi_Flex",
            },
        ],
    )

    assert projects == ["123456_Flex", "654321_Flex"]
    assert authoritative is True


def test_direct_auth_can_return_prefixed_and_bare_ddi_flex_projects():
    projects, _roles, authoritative = return_roles(
        ["os_flex", "os_flex_mrr"],
        ["os_flex:federated-one", "os_flex_mrr:federated-two", "123456_Flex"],
        allow_bare_ddi_flex=True,
        enabled_tenants=[
            "os_flex:federated-one",
            "os_flex_mrr:federated-two",
            {
                "id": "tenant-id-for-ddi-flex",
                "name": "123456_Flex",
            },
        ],
    )

    assert projects == ["123456_Flex", "federated-one", "federated-two"]
    assert authoritative is True


def test_ddi_flex_project_names_are_ignored_by_default():
    projects, _roles, authoritative = return_roles(
        ["os_flex", "os_flex_mrr"],
        ["123456_Flex", "654321_Flex"],
        enabled_tenants=[
            {
                "id": "tenant-id-for-ddi-flex",
                "name": "123456_Flex",
            },
            {
                "id": "tenant-id-for-other-ddi-flex",
                "name": "654321_Flex",
            },
        ],
    )

    assert projects == []
    assert authoritative is True


def test_direct_auth_fallback_does_not_double_suffix_ddi_flex_tenant():
    service_catalog = {
        "access": {
            "user": {
                "id": "test-user-id",
                "name": "test-user",
                "email": "test@example.com",
                "RAX-AUTH:domainId": "domain-id",
            },
            "token": {
                "id": "token",
                "tenant": {"id": "123456_Flex"},
            },
        }
    }
    keystone.conf.CONF.set_override(
        "role_attribute_enforcement", True, group="rackspace"
    )
    try:
        with flask.Flask("test").test_request_context("/"):
            auth = rxt.RXTv2Credentials({"user": {"name": "test-user"}})
            auth._return_rxt_roles = (
                lambda uid, ddi, token, allow_bare_ddi_flex=False: (
                    ["federated-one", "federated-two"],
                    {"identity": "reader"},
                    True,
                )
            )
            auth._parse_service_catalog(service_catalog)
            environ = dict(flask.request.environ)
    finally:
        keystone.conf.CONF.clear_override(
            "role_attribute_enforcement", group="rackspace"
        )

    assert environ["RXT_TenantID"] == "federated-one;federated-two;123456_Flex"


def test_direct_auth_projects_ddi_flex_with_enforcement_enabled():
    service_catalog = {
        "access": {
            "user": {
                "id": "test-user-id",
                "name": "test-user",
                "email": "test@example.com",
                "RAX-AUTH:domainId": "domain-id",
            },
            "token": {"id": "token", "tenant": {"id": "123456"}},
        }
    }
    keystone.conf.CONF.set_override(
        "role_attribute_enforcement", True, group="rackspace"
    )
    try:
        with flask.Flask("test").test_request_context("/"):
            auth = rxt.RXTv2Credentials({"user": {"name": "test-user"}})
            auth._return_rxt_roles = lambda uid, ddi, token: (
                [],
                {"identity": "reader"},
                True,
            )
            auth._parse_service_catalog(service_catalog)
            environ = dict(flask.request.environ)
    finally:
        keystone.conf.CONF.clear_override(
            "role_attribute_enforcement", group="rackspace"
        )

    assert environ["RXT_TenantID"] == "123456_Flex"
