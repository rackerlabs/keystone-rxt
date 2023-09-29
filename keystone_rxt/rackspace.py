# Copyright 2023 Cloudnull
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re

import requests
from oslo_log import log
import flask

from keystone.auth.plugins import password
from keystone.auth.plugins import base
from keystone.auth.plugins import mapped
from keystone.common import provider_api
from keystone import exception
from keystone.i18n import _


LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs
RACKPSACE_IDENTITY_V2 = "https://identity.api.rackspacecloud.com/v2.0/tokens"


class RXTv2Credentials(object):
    """Return an autneitcation object based on the provided auth payload.

    Check the value type of the provided auth payload and determine the
    correct authentication method.
    """

    hash_types = [r"^[a-fA-F0-9]{%s}$" % i for i in [32, 40, 64]]

    def __init__(self, auth_payload) -> None:
        self.auth_payload = auth_payload

    @property
    def _username(self):
        """This property is used to return the username from the auth payload."""

        try:
            return self.auth_payload["user"]["name"]
        except KeyError:
            try:
                return self.auth_payload["user"]["username"]
            except KeyError:
                raise exception.Unauthorized(
                    _("The authentication payload is missing the name")
                )

    @property
    def _password(self):
        """This property is used to return the password from the auth payload."""

        try:
            return self.auth_payload["user"]["password"]
        except KeyError:
            raise exception.Unauthorized(
                _("The authentication payload is missing the password")
            )

    @property
    def apiKeyCredentials(self):
        """Return the API type."""

        return "apiKeyCredentials", {
            "auth": {
                "RAX-KSKEY:apiKeyCredentials": {
                    "username": self._username,
                    "apiKey": self._password,
                }
            }
        }

    @property
    def passwordCredentials(self):
        """Return the Password type."""

        return "passwordCredentials", {
            "auth": {
                "passwordCredentials": {
                    "username": self._username,
                    "password": self._password,
                }
            }
        }

    def __enter__(self):
        """Return the correct authentication method.

        This method is used to return the authentication method which is evaluating
        the password parameter in the auth payload. If the password is a valid
        `hash_types` then the auth method is first apiKeyCredentials, otherwise the
        passwordCredentials will be used.
        """

        rxt_auth_payloads = list()

        for hash_type in self.hash_types:
            if re.match(hash_type, self._password) is not None:
                rxt_auth_payloads.insert(0, self.apiKeyCredentials)
                break

        rxt_auth_payloads.append(self.passwordCredentials)

        for auth_type, auth_data in rxt_auth_payloads:
            LOG.debug(
                "Attempting to authenticate using {auth_type}".format(
                    auth_type=auth_type
                )
            )
            try:
                r = requests.post(RACKPSACE_IDENTITY_V2, json=auth_data)
                r.raise_for_status()
                return r.json()
            except (
                requests.HTTPError,
                requests.ConnectionError,
                requests.exceptions.JSONDecodeError,
            ):
                LOG.warning(
                    "Failed to authenticate using the Rackspace Identity API with {auth_type}".format(
                        auth_type=auth_type
                    )
                )
        else:
            raise exception.Unauthorized(
                _(
                    "Could not validate access through the Rackspace Identity API"
                )
            )

    def __exit__(self, *args, **kwargs):
        LOG.debug("Rackspace IDP Login complete, returning to OS")


class RXT(password.Password):
    def authenticate(self, auth_payload):
        """Turn a signed request with an access key into a keystone token."""

        try:
            assert (
                auth_payload["user"]["domain"]["name"]
                == "rackspace_cloud_domain"
            )
        except (KeyError, AssertionError):
            LOG.debug("Using OS Password Authentication")
            return super(RXT, self).authenticate(auth_payload)
        else:
            LOG.debug("Using Rackspace Global Authentication")
            auth_payload["identity_provider"] = "rackspace"
            auth_payload["protocol"] = "rackspace"
            return self._v2(auth_payload=auth_payload)

    @staticmethod
    def _v2(auth_payload):
        """Authenticate using the Rackspace Identity API.

        This method is used to authenticate against the Rackspace Identity API.
        """

        with RXTv2Credentials(auth_payload) as return_data:
            try:
                access = return_data["access"]
                access_user = access["user"]
                access_token = access["token"]
                access_user_roles = set(
                    [
                        i["name"].split(":")[-1]
                        for i in return_data["access"]["user"]["roles"]
                    ]
                )
            except KeyError as e:
                raise exception.Unauthorized(
                    "Could not parse the Rackspace Service Catalog for access: {error}".format(
                        error=e
                    )
                )

        flask.request.environ["RXT_UserName"] = access_user["name"]
        flask.request.environ["RXT_Email"] = access_user["email"]
        flask.request.environ["RXT_DomainID"] = access_user[
            "RAX-AUTH:domainId"
        ]
        flask.request.environ["RXT_TenantName"] = access_token["tenant"][
            "name"
        ]
        flask.request.environ["RXT_TenantID"] = access_token["tenant"]["id"]

        orgPersonType = set()
        for role in access_user_roles:
            orgPersonType.add(role)
        else:
            flask.request.environ["RXT_orgPersonType"] = ";".join(
                orgPersonType
            )

        if "id" in auth_payload:
            token_ref = PROVIDERS.token_provider_api.validate_token(
                auth_payload["id"]
            )
            response_data = mapped.handle_scoped_token(
                token_ref, PROVIDERS.federation_api, PROVIDERS.identity_api
            )
        else:
            response_data = mapped.handle_unscoped_token(
                auth_payload,
                PROVIDERS.resource_api,
                PROVIDERS.federation_api,
                PROVIDERS.identity_api,
                PROVIDERS.assignment_api,
                PROVIDERS.role_api,
            )

        return base.AuthHandlerResponse(
            status=True, response_body=None, response_data=response_data
        )
