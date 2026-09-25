"""Tests for the Rackspace Identity enabled-tenant lookup.

The effective-roles endpoint always reports RCN-sourced tenant assignments,
so the tenant collection must be requested with ``apply_rcn_roles=true`` to
describe the same tenants. The collection is also paginated, and a partial
read must never be reported as the user's complete tenant state.
"""

import flask
import requests

from conftest import rxt


TOKEN = "token-abc"
DDI = "5551212"
BASE = "https://identity.api.rackspacecloud.com/v2.0/tenants"


def flex(uuid, enabled=True):
    return {"id": f"os_flex:{uuid}", "enabled": enabled}


class FakeResponse:
    def __init__(self, payload=None, status=200):
        self.payload = payload if payload is not None else {}
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.HTTPError(f"HTTP {self.status_code}")
            error.response = self
            raise error

    def json(self):
        return self.payload


class FakeSession:
    """Serve queued responses and record the URLs that were requested."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []

    def get(self, url, timeout=None, headers=None):
        self.urls.append(url)
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def fetch(responses):
    """Run the real lookup against queued responses."""
    auth = rxt.RXTv2BaseAuth()
    auth.session = FakeSession(responses)
    with flask.Flask("test").test_request_context("/"):
        tenants = auth._fetch_enabled_tenants(ddi=DDI, token=TOKEN)
    return tenants, auth.session.urls


def test_rcn_tenants_are_requested_and_kept():
    tenants, urls = fetch(
        [FakeResponse({"tenants": [flex("rcn-only"), flex("direct")]})]
    )

    assert "apply_rcn_roles=true" in urls[0]
    assert tenants == {"rcn-only", "direct"}

    # The RCN-reachable tenant must survive the project filter.
    assert rxt.RXTv2BaseAuth._filter_projects_by_enabled_tenants(
        ["rcn-only", "direct"], tenants
    ) == ["rcn-only", "direct"]


def test_disabled_tenants_are_still_excluded():
    tenants, _urls = fetch(
        [FakeResponse({"tenants": [flex("on"), flex("off", enabled=False)]})]
    )

    assert tenants == {"on"}


def test_paginated_collection_is_fully_traversed():
    page_two = f"{BASE}?apply_rcn_roles=true&marker=1"
    tenants, urls = fetch(
        [
            FakeResponse(
                {
                    "tenants": {
                        "values": [flex("first")],
                        "links": [{"rel": "next", "href": page_two}],
                    }
                }
            ),
            FakeResponse({"tenants": {"values": [flex("second")], "links": []}}),
        ]
    )

    assert tenants == {"first", "second"}
    assert urls[1] == page_two


def test_flat_collection_links_are_followed():
    page_two = f"{BASE}?apply_rcn_roles=true&marker=2"
    tenants, urls = fetch(
        [
            FakeResponse(
                {
                    "tenants": [flex("first")],
                    "tenants_links": [{"rel": "next", "href": page_two}],
                }
            ),
            FakeResponse({"tenants": [flex("second")]}),
        ]
    )

    assert tenants == {"first", "second"}
    assert urls[1] == page_two


def test_failure_midway_through_pagination_reports_nothing():
    tenants, _urls = fetch(
        [
            FakeResponse(
                {
                    "tenants": {
                        "values": [flex("first")],
                        "links": [{"rel": "next", "href": f"{BASE}?marker=1"}],
                    }
                }
            ),
            requests.ConnectionError("boom"),
        ]
    )

    assert tenants is None


def test_repeated_page_link_reports_nothing():
    repeated = f"{BASE}?apply_rcn_roles=true"
    tenants, _urls = fetch(
        [
            FakeResponse(
                {
                    "tenants": [flex("first")],
                    "tenants_links": [{"rel": "next", "href": repeated}],
                }
            )
        ]
    )

    assert tenants is None


def test_unsupported_collection_shape_reports_nothing():
    tenants, _urls = fetch([FakeResponse({"tenants": "nonsense"})])

    assert tenants is None


def test_http_errors_report_nothing():
    tenants, _urls = fetch([FakeResponse(status=503)])

    assert tenants is None
