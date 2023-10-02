# Copyright 2023 Cloudnull <kevin@cloudnull.com>
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

from dateutil import parser
import re
import hashlib
import json

import requests
from oslo_log import log
import flask

from keystone.auth.plugins import base
from keystone.auth.plugins import mapped
from keystone.auth.plugins import password
from keystone.auth.plugins import totp
from keystone.common import cache as ks_cache
import keystone.conf
from keystone import exception
from keystone.i18n import _


keystone.conf.CONF.set_override("caching", True, group="federation")

RXT_SESSION_CACHE = ks_cache.create_region(name="rxt_sess")
ks_cache.cache.configure_cache_region(keystone.conf.CONF, RXT_SESSION_CACHE)
RXT_SESSION_CACHE.expiration_time = 120

RXT_SERVICE_CACHE = ks_cache.create_region(name="rxt_srv")
ks_cache.cache.configure_cache_region(keystone.conf.CONF, RXT_SERVICE_CACHE)
RXT_SERVICE_CACHE.expiration_time = 60

LOG = log.getLogger(__name__)
PROVIDERS = mapped.PROVIDERS
RACKPSACE_IDENTITY_V2 = "https://identity.api.rackspacecloud.com/v2.0/tokens"


class RXTv2Credentials(object):
    """Return an authenticate object based on the provided auth payload.

    Check the value type of the provided auth payload and determine the
    correct authentication method.
    """

    hash_types = [r"^[a-fA-F0-9]{%s}$" % i for i in [32, 40, 64]]
    rxt_auth_payload = None
    rxt_headers = dict()
    session = requests.Session()
    session_id = None

    def __init__(self, auth_payload):
        """Initialize the RXTv2Credentials object.

        This method is used to initialize the RXTv2Credentials object. The
        method will hash the auth payload and username for use in caching
        and session headers.

        :param dict auth_payload: The auth payload to be used for authentication.
        """

        self.auth_payload = auth_payload
        self.hashed_auth_payload = hashlib.sha224(
            json.dumps(self.auth_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self.hashed_auth_user = hashlib.sha224(
            self._username.encode("utf-8")
        ).hexdigest()
        self.session_id = self._sessionID

    def __exit__(self, *args, **kwargs):
        """Close the session.

        This method is used to close the session after the authentication
        method has completed.
        """

        self.session.close()
        LOG.debug(_("Rackspace IDP Login complete, returning to OS"))

    @property
    def _sessionID(self):
        """Return a parsed sessionID property.

        This property is used to return the sessionID from the session header.
        The property will first check the local cache for the sessionID and
        then the environmental variable. If the sessionID is not found in
        either location the property will return None.

        :returns: The sessionID from the session header.
        :rtype: str or None
        """

        session_id = RXT_SESSION_CACHE.get(self.hashed_auth_user)
        if session_id:
            LOG.debug(_("Using cached Rackspace Session header"))
            return session_id

        session_id = flask.request.environ.get("RXT_SessionID")
        if session_id:
            LOG.debug(_("Using environmental Rackspace Session header"))
            return session_id

    @property
    def _username(self):
        """Return a parsed username property.

        This property is used to return the username from the auth payload.

        :returns: The username from the auth payload.
        :rtype: str
        """

        try:
            return self.auth_payload["user"]["name"]
        except KeyError:
            try:
                return self.auth_payload["user"]["username"]
            except KeyError:
                raise exception.Unauthorized(
                    _("The authentication payload is missing the name")
                )

    @staticmethod
    def _return_session_id(session_header):
        """Return the sessionID from the session header.

        Using the provided session header, return the sessionID from the
        session header if it exists.

        :param str session_header: The session header to be parsed.
        :returns: The sessionID from the session header.
        :rtype: str or None
        """

        r = re.compile(r"""sessionId='(.*?[^\\])'""")
        try:
            return r.findall(session_header).pop()
        except IndexError:
            raise exception.AuthPluginException(
                _("Could not parse the Rackspace Session header for sessionId")
            )

    def _set_session_id(self, session_header):
        """Set the sessionID from the session header into the local cache.

        Using the provided session header, return the sessionID from the
        session header if it exists.

        :param str session_header: The session header to be parsed.
        :returns: The sessionID from the session header.
        :rtype: str or None
        """

        session_id = self._return_session_id(session_header=session_header)
        if session_id:
            RXT_SESSION_CACHE.set(
                self.hashed_auth_user,
                session_id,
            )
            flask.request.environ["RXT_SessionID"] = session_id

    def _set_federation_env(
        self,
        username=None,
        email=None,
        domain_id=None,
        tenant_name=None,
        tenant_id=None,
        org_person_type=None,
    ):
        """Set the federation environment variables.

        Set the federation environment variables based on the provided
        parameters. If the parameters are not provided the environment
        variables will not be set.

        :param str username: The username to be set in the environment.
        :param str email: The email to be set in the environment.
        :param str domain_id: The domain_id to be set in the environment.
        :param str tenant_name: The tenant_name to be set in the environment.
        :param str tenant_id: The tenant_id to be set in the environment.
        :param str org_person_type: The org_person_type to be set in the
                                    environment.
        """

        if username:
            flask.request.environ["RXT_UserName"] = username
        if email:
            flask.request.environ["RXT_Email"] = email
        if domain_id:
            flask.request.environ["RXT_DomainID"] = domain_id
        if tenant_name:
            flask.request.environ["RXT_TenantName"] = tenant_name
        if tenant_id:
            flask.request.environ["RXT_TenantID"] = tenant_id
        if org_person_type:
            flask.request.environ["RXT_orgPersonType"] = org_person_type

    def _parse_service_catalog(self, service_catalog):
        """Parse the Rackspace Service Catalog and set the environment variables.

        We're parsing the Rackspace Service Catalog and setting the federation
        environment variables. If there's an error parsing the service catalog
        the method will deny access.
        """

        try:
            access = service_catalog["access"]
            access_user = access["user"]
            access_token = access["token"]
            access_user_roles = set(
                [
                    i["name"].split(":")[-1]
                    for i in service_catalog["access"]["user"]["roles"]
                ]
            )
            self._set_federation_env(
                username=access_user["name"],
                email=access_user["email"],
                domain_id=access_user["RAX-AUTH:domainId"],
                tenant_name=access_token["tenant"]["name"],
                tenant_id=access_token["tenant"]["id"],
                org_person_type=";".join(access_user_roles),
            )
        except KeyError as e:
            raise exception.Unauthorized(
                _(
                    "Could not parse the Rackspace Service Catalog for access:"
                    " {error}".format(error=e)
                )
            )

    def _return_auth_handler(
        self, status=True, response_body=None, response_data=None
    ):
        """Return the auth handler response.

        Using the provided auth payload, return the auth handler response.
        This will work for both scoped and unscoped tokens.
        """

        if status is True:
            self.auth_payload["identity_provider"] = "rackspace"
            self.auth_payload["protocol"] = "rackspace"
            if "id" in self.auth_payload:
                token_ref = PROVIDERS.token_provider_api.validate_token(
                    self.auth_payload["id"]
                )
                response_data = mapped.handle_scoped_token(
                    token_ref, PROVIDERS.federation_api, PROVIDERS.identity_api
                )
            else:
                response_data = mapped.handle_unscoped_token(
                    self.auth_payload,
                    PROVIDERS.resource_api,
                    PROVIDERS.federation_api,
                    PROVIDERS.identity_api,
                    PROVIDERS.assignment_api,
                    PROVIDERS.role_api,
                )

        return base.AuthHandlerResponse(
            status=status,
            response_body=response_body,
            response_data=response_data,
        )

    def get_rxt_auth(self, auth_data, auth_type):
        """Authenticate using the Rackspace Identity API.

        Internal method used to authenticate using the Rackspace Identity API.
        The method will return True if the Rackspace Identity API returns a
        boolean. The boolean informs the main auth method if the user is
        attempting to use rackspace MFA.

        :param dict auth_data: The auth data to be used for authentication.
        :param str auth_type: The auth type to be used for authentication.
        :returns: True if the Rackspace Identity API returns a boolean.
        :rtype: bool
        """
        service_catalog = RXT_SERVICE_CACHE.get(self.hashed_auth_payload)
        if service_catalog:
            try:
                expires = service_catalog["access"]["token"]["expires"]
            except KeyError:
                LOG.debug(
                    _("Rackspace service catalog is invalid, running cleanup.")
                )
                RXT_SERVICE_CACHE.delete(self.hashed_auth_payload)
            else:
                token_expire = parser.parse(expires)
                if token_expire.timestamp() > token_expire.now().timestamp():
                    LOG.debug(_("Using cached Rackspace service catalog"))
                    self._parse_service_catalog(
                        service_catalog=service_catalog
                    )
                    return self._return_auth_handler()
                else:
                    LOG.debug(
                        _(
                            "Rackspace service catalog is expired, running cleanup."
                        )
                    )
                    RXT_SERVICE_CACHE.delete(self.hashed_auth_payload)

        if auth_type == "passwordCredentials" and self.session_id:
            LOG.debug(_("Found cached Rackspace session header for MFA."))
            return self._return_auth_handler(status=False)

        LOG.debug(
            _(
                "Attempting to authenticate using {auth_type}".format(
                    auth_type=auth_type
                )
            )
        )
        r = self.session.post(
            RACKPSACE_IDENTITY_V2,
            json=auth_data,
            headers=self.rxt_headers,
        )
        if r.status_code == 401 and "WWW-Authenticate" in r.headers:
            LOG.debug(_("Caching Rackspace session header"))
            self._set_session_id(session_header=r.headers["WWW-Authenticate"])
            return self._return_auth_handler(status=False)
        else:
            r.raise_for_status()
            service_catalog = r.json()
            self._parse_service_catalog(service_catalog=service_catalog)
            LOG.debug(_("Caching Rackspace service catalog"))
            RXT_SERVICE_CACHE.set(self.hashed_auth_payload, service_catalog)
            return self._return_auth_handler()


class RXPWAuth(RXTv2Credentials):
    """Rackspace Password Authentication."""

    def __enter__(self):
        """Return the correct authentication method.

        This method is used to return the authentication method which is
        evaluating the password parameter in the auth payload. If the
        password is a valid `hash_types` then the auth method is first
        apiKeyCredentials, otherwise the passwordCredentials will be used.
        """

        LOG.debug(_("Rackspace IDP Login started"))
        for hash_type in self.hash_types:
            if re.match(hash_type, self._password) is not None:
                self.rxt_auth_payload = self.apiKeyCredentials
                break

        if not self.rxt_auth_payload:
            self.rxt_auth_payload = self.passwordCredentials

        return self

    @property
    def _password(self):
        """Return a parsed password property.

        This property is used to return the password from the auth payload.

        :returns: The password from the auth payload.
        :rtype: str
        """

        try:
            return self.auth_payload["user"]["password"]
        except KeyError:
            raise exception.Unauthorized(
                _("The authentication payload is missing the password")
            )

    @property
    def apiKeyCredentials(self):
        """Return the API type.

        This method is used to return the apiKeyCredentials auth payload.

        :returns: The apiKeyCredentials auth payload.
        :rtype: tuple
        """

        LOG.debug(_("Using api key auth payload"))
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
        """Return the Password type.

        This method is used to return the passwordCredentials auth payload.

        :returns: The passwordCredentials auth payload.
        :rtype: tuple
        """

        LOG.debug(_("Using password auth payload"))
        return "passwordCredentials", {
            "auth": {
                "passwordCredentials": {
                    "username": self._username,
                    "password": self._password,
                }
            }
        }

    def rxt_auth(self):
        """Authenticate using the Rackspace Identity API.

        This method is used to authenticate using the Rackspace Identity API.
        The method will return an auth handler response.

        > In the event of a failure when using the apiKeyCredentials auth
          method, the method will attempt to re-authenticate using the
          passwordCredentials auth method.

        :returns: An auth handler response if the Rackspace Identity API
                  returns a boolean
        :rtype: keystone.auth.plugins.base.AuthHandlerResponse
        """

        try:
            auth_type, auth_data = self.rxt_auth_payload
            return self.get_rxt_auth(auth_data=auth_data, auth_type=auth_type)
        except requests.HTTPError:
            if auth_type == "apiKeyCredentials":
                self.rxt_auth_payload = self.passwordCredentials
                LOG.debug(
                    _(
                        "Attempting to re-authenticate using passwordCredentials"
                    )
                )
                return self.rxt_auth()

            raise exception.Unauthorized(
                _(
                    "Failed to authenticate using the Rackspace Identity API"
                    " with {auth_type}".format(auth_type=auth_type)
                )
            )


class RXTTOTPAuth(RXTv2Credentials):
    """Rackspace TOTP Authentication."""

    def __enter__(self):
        """Return the correct authentication method.

        This method is used to return the authentication method which is
        evaluating the password parameter in the auth payload. If the
        password is a valid `hash_types` then the auth method is first
        apiKeyCredentials, otherwise the passwordCredentials will be used.
        """

        LOG.debug(_("Rackspace IDP Login started for TOTP"))
        if not self._passcode and not self.session_id:
            raise exception.Unauthorized(
                _("Missing passcode or sessionID for TOTP, aborting.")
            )

        self.rxt_auth_payload = self.passcodeCredentials
        self.rxt_headers["X-SessionId"] = self.session_id

        return self

    @property
    def _passcode(self):
        """Return a parsed passcode property.

        This property is used to return the passcode from the auth payload.

        :returns: The passcode from the auth payload.
        :rtype: str or None
        """

        try:
            return self.auth_payload["user"]["passcode"]
        except KeyError:
            return None

    @property
    def passcodeCredentials(self):
        """Return the Passcode type.

        This method is used to return the passcodeCredentials auth payload.

        :returns: The passcodeCredentials auth payload.
        :rtype: tuple
        """

        LOG.debug(_("Using passcode auth payload"))
        return "passcodeCredentials", {
            "auth": {
                "RAX-AUTH:passcodeCredentials": {
                    "passcode": self._passcode,
                }
            }
        }

    def rxt_auth(self):
        """Authenticate using the Rackspace Identity API.

        This method is used to authenticate using the Rackspace Identity API.
        The method will return an auth handler response.

        :returns: An auth handler response if the Rackspace Identity API
                  returns a boolean
        :rtype: keystone.auth.plugins.base.AuthHandlerResponse
        """

        try:
            auth_type, auth_data = self.rxt_auth_payload
            return self.get_rxt_auth(auth_data=auth_data, auth_type=auth_type)
        except requests.HTTPError:
            raise exception.Unauthorized(
                _(
                    "Failed to authenticate using the Rackspace Identity API"
                    " with {auth_type}".format(auth_type=auth_type)
                )
            )


class RXTPassword(password.Password):
    """Rackspace Authentication.

    This class is used to authenticate using the Rackspace Identity API
    with a username and password. The class will attempt to authenticate
    using the Rackspace Identity API with the provided auth payload.
    """

    def authenticate(self, auth_payload):
        """Return a signed request with an access key into a keystone token."""

        try:
            assert (
                auth_payload["user"]["domain"]["name"]
                == "rackspace_cloud_domain"
            )
        except (KeyError, AssertionError):
            LOG.debug(_("Using OS Password Authentication"))
            return super(RXTPassword, self).authenticate(auth_payload)
        else:
            LOG.debug(_("Using Rackspace Global Authentication"))
            with RXPWAuth(auth_payload=auth_payload) as rxt:
                return rxt.rxt_auth()


class RXTTOTP(totp.TOTP):
    """Rackspace TOTP Authentication.

    This class is used to authenticate using the Rackspace Identity API
    with TOTP. The class will attempt to authenticate using the Rackspace
    Identity API with the provided MFA auth payload.
    """

    def authenticate(self, auth_payload):
        """Return a signed request with an access key into a keystone token."""

        try:
            assert (
                auth_payload["user"]["domain"]["name"]
                == "rackspace_cloud_domain"
            )
        except (KeyError, AssertionError):
            LOG.debug(_("Using OS TOTP Authentication"))
            return super(RXTTOTP, self).authenticate(auth_payload)
        else:
            LOG.debug(_("Using Rackspace Global Authentication TOTP"))
            with RXTTOTPAuth(auth_payload=auth_payload) as rxt:
                return rxt.rxt_auth()
