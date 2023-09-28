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

import requests

from oslo_log import log
import flask

from keystone.auth.plugins import password
from keystone.auth.plugins import base
from keystone.auth.plugins import mapped
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _


LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs
RACKPSACE_IDENTITY_V2 = "https://identity.api.rackspacecloud.com/v2.0/tokens"


# The keystone config options used by this module and forced to be RXT
keystone.conf.CONF.set_override("assertion_prefix", "RXT", group="federation")


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

    def _v1(self, auth_payload):
        raise exception.AuthMethodNotSupported(method="RackspaceV1")

    def _v2(self, auth_payload):
        try:
            auth_data = {
                "auth": {
                    "RAX-KSKEY:apiKeyCredentials": {
                        "username": auth_payload["user"]["name"],
                        "apiKey": auth_payload["user"]["password"],
                    }
                }
            }
            r = requests.post(RACKPSACE_IDENTITY_V2, json=auth_data)
            r.raise_for_status()
            return_data = r.json()
        except (
            requests.HTTPError,
            requests.ConnectionError,
            requests.exceptions.JSONDecodeError,
            KeyError,
        ):
            raise exception.Unauthorized(
                _("Could not validate the access token")
            )

        access = return_data["access"]
        access_user = access["user"]
        access_token = access["token"]
        flask.request.environ["RXT_UserName"] = access_user["name"]
        flask.request.environ["RXT_Email"] = access_user["email"]
        flask.request.environ["RXT_DomainID"] = access_user[
            "RAX-AUTH:domainId"
        ]
        flask.request.environ["RXT_TenantName"] = access_token["tenant"][
            "name"
        ]
        flask.request.environ["RXT_TenantID"] = access_token["tenant"]["id"]

        orgPersonType = set(
            "Rackspace:Cloud:User",
        )
        for role in return_data["access"]["user"]["roles"]:
            orgPersonType.add(role["name"])
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
