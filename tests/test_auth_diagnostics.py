"""Tests for sanitized Rackspace Identity authentication diagnostics."""

import requests

from conftest import rxt


class FakeResponse:
    def __init__(self, status_code=200, headers=None, payload=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.payload = payload or {"access": {"token": {}}}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


def _auth(session):
    auth = object.__new__(rxt.RXPWAuth)
    auth.hashed_auth_payload = "cache-key"
    auth.auth_payload = {}
    auth.session_id = None
    auth.session = session
    auth.rxt_headers = {}
    auth._parse_service_catalog = lambda service_catalog: None
    auth._return_auth_handler = lambda **kwargs: kwargs
    return auth


def _capture_logs(monkeypatch):
    records = {"debug": [], "info": [], "warning": []}

    for level in records:
        monkeypatch.setattr(
            rxt.LOG,
            level,
            lambda message, *args, _level=level: records[_level].append(
                (message, args)
            ),
        )
    return records


def test_upstream_request_id_is_sanitized_and_bounded():
    response = FakeResponse(
        headers={"X-Trans-Id": "tx-good\nforged secret=value"}
    )

    request_id = rxt._upstream_request_id(response)

    assert request_id == "tx-good_forged_secret_value"
    assert "\n" not in request_id


def test_success_logs_status_request_id_and_elapsed_without_payload(
    monkeypatch,
):
    secret = "never-log-this-password"
    response = FakeResponse(
        headers={"X-Trans-Id": "tx-123"},
        payload={"access": {"token": {"id": "never-log-this-token"}}},
    )
    session = FakeSession(response=response)
    auth = _auth(session)
    records = _capture_logs(monkeypatch)
    monkeypatch.setattr(rxt.RXT_SERVICE_CACHE, "get", lambda key: None)
    monkeypatch.setattr(rxt.RXT_SERVICE_CACHE, "set", lambda key, value: None)
    times = iter((10.0, 10.125))
    monkeypatch.setattr(rxt.time, "monotonic", lambda: next(times))

    result = auth.get_rxt_auth(
        auth_data={"auth": {"passwordCredentials": {"password": secret}}},
        auth_type="passwordCredentials",
    )

    assert result == {"reenable_user": True}
    response_log = records["info"][-1]
    assert response_log[1] == ("passwordCredentials", 200, "tx-123", 125)
    rendered_logs = repr(records)
    assert secret not in rendered_logs
    assert "never-log-this-token" not in rendered_logs


def test_http_error_logs_sanitized_response_metadata(monkeypatch):
    response = FakeResponse(
        status_code=401,
        headers={"X-Request-Id": "upstream-401"},
        payload={"unauthorized": {"message": "sensitive upstream body"}},
    )
    auth = _auth(FakeSession(response=response))
    records = _capture_logs(monkeypatch)
    monkeypatch.setattr(rxt.RXT_SERVICE_CACHE, "get", lambda key: None)
    times = iter((20.0, 20.050))
    monkeypatch.setattr(rxt.time, "monotonic", lambda: next(times))

    try:
        auth.get_rxt_auth({}, "passwordCredentials")
    except requests.HTTPError:
        pass
    else:
        raise AssertionError("401 response did not raise HTTPError")

    response_log = records["warning"][-1]
    assert response_log[1] == (
        "passwordCredentials",
        401,
        "upstream-401",
        50,
    )
    assert "sensitive upstream body" not in repr(records)


def test_network_error_logs_only_exception_type_and_elapsed(monkeypatch):
    secret_in_error = "secret-from-exception"
    auth = _auth(
        FakeSession(error=requests.ConnectionError(secret_in_error))
    )
    records = _capture_logs(monkeypatch)
    monkeypatch.setattr(rxt.RXT_SERVICE_CACHE, "get", lambda key: None)
    times = iter((30.0, 30.010))
    monkeypatch.setattr(rxt.time, "monotonic", lambda: next(times))

    try:
        auth.get_rxt_auth({}, "passwordCredentials")
    except requests.ConnectionError:
        pass
    else:
        raise AssertionError("connection failure was not propagated")

    failure_log = records["warning"][-1]
    assert failure_log[1] == (
        "passwordCredentials",
        "ConnectionError",
        10,
    )
    assert secret_in_error not in repr(records)


def test_cache_hit_avoids_upstream_request(monkeypatch):
    session = FakeSession(response=FakeResponse())
    auth = _auth(session)
    records = _capture_logs(monkeypatch)
    catalog = {
        "access": {"token": {"expires": "2999-01-01T00:00:00Z"}}
    }
    monkeypatch.setattr(rxt.RXT_SERVICE_CACHE, "get", lambda key: catalog)

    result = auth.get_rxt_auth({}, "passwordCredentials")

    assert result == {}
    assert not session.calls
    assert records["debug"][-1][1] == ("passwordCredentials",)
