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

import keystone.conf.utils
import keystone.exception
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
ROLE_ATTRIBUTE = keystone.conf.cfg.StrOpt(
    "role_attribute",
    help=keystone.conf.utils.fmt(
        """The attribute to use for the role granting account access.

This attribute can be any role within the Rackspace Identity API.
The system will process the attribute as a prefix sourcing the `tenantId`
from the `user` `roles` found within Rackspace Identity API catalog.

If an empty string is used, the system will disable this mechanism and
fall back to using the DDI.
"""
    ),
    default="os_flex",
)
ROLE_ATTRIBUTE_ENFORCEMENT = keystone.conf.cfg.BoolOpt(
    "role_attribute_enforcement",
    help=keystone.conf.utils.fmt(
        """Enables or disables the enforcement of role attributes.

If disabled and no role is found, the plugin will fall back to using the DDI.
""",
    ),
    default=False,
)

keystone.conf.CONF.register_opts(
    [ROLE_ATTRIBUTE, ROLE_ATTRIBUTE_ENFORCEMENT], group="rackspace"
)


class RuleProcessor(mapped.utils.RuleProcessor):
    """Rule processor subclass to dynamically map multiple projects.

    This class will dynamically map multiple projects based on the
    provided mapping rules. The class will iterate through the mapping
    rules to find assertions that are valid and return the mapped
    properties.

    The system ensures that an account with multiple roles defined by
    `role_attribute` automatically map to `projects` with expected RBAC.
    """

    def process(self, assertion_data):
        """Transform assertion to a dictionary.

        The dictionary contains mapping of user name and group ids
        based on mapping rules.

        This function will iterate through the mapping rules to find
        assertions that are valid.

        :param assertion_data: an assertion containing values from an IdP
        :type assertion_data: dict

        Example assertion_data::

            {
                'RXT_UserName': 'testacct',
                'RXT_Email': 'testacct@example.com',
                'RXT_DomainID': 'rackspace_cloud_domain',
                'RXT_TenantName': '00000000-0000-0000-0000-000000000000;0000000_Flex',
                'RXT_TenantID': '00000000-0000-0000-0000-000000000000;0000000_Flex',
                'RXT_orgPersonType': 'default;tenant-access'
            }

        :returns: dictionary with user and projects mapping

        The expected return structure is::
            {
                "user": {
                    "name": "testacct",
                    "email": "testacct@example.com",
                    "domain": {
                        "name": "rackspace_cloud_domain"
                    },
                    "type": "ephemeral",
                },
                "group_ids": [],
                "group_names": [],
                "projects": [
                    {
                        "name": "00000000-0000-0000-0000-000000000000",
                        "domain": {"name": "rackspace_cloud_domain"},
                        "roles": [
                            {"name": "member"},
                            {"name": "load-balancer_member"},
                            {"name": "heat_stack_user"},
                        ],
                    },
                    {
                        "name": "0000000_Flex",
                        "domain": {
                            "name": "rackspace_cloud_domain"
                        },
                        "roles": [
                            {"name": "member"},
                            {"name": "load-balancer_member"},
                            {"name": "heat_stack_user"},
                        ],
                    },
                ],
            }
        """
        # Assertions will come in as string key-value pairs, and will use a
        # semi-colon to indicate multiple values, i.e. groups.
        # This will create a new dictionary where the values are arrays, and
        # any multiple values are stored in the arrays.
        LOG.debug("assertion data: %s", assertion_data)
        assertion = {
            n: v.split(";")
            for n, v in assertion_data.items()
            if isinstance(v, str)
        }
        LOG.debug("assertion: %s", assertion)
        identity_values = []

        LOG.debug("rules: %s", self.rules)
        for rule in self.rules:
            direct_maps = self._verify_all_requirements(
                rule["remote"], assertion
            )

            # If the compare comes back as None, then the rule did not apply
            # to the assertion data, go on to the next rule
            if direct_maps is None:
                continue

            # If there are no direct mappings, then add the local mapping
            # directly to the array of saved values. However, if there is
            # a direct mapping, then perform variable replacement.
            if not direct_maps:
                identity_values += rule["local"]
            else:
                LOG.debug("original_direct_maps: %s", direct_maps)
                new_direct_maps = list()
                for map_index, map_value in enumerate(direct_maps):
                    if isinstance(map_value, list):
                        for iso_value in map_value:
                            _copy_direct_maps = list(direct_maps)
                            _copy_direct_maps[map_index] = iso_value
                            _direct_map = mapped.utils.DirectMaps()
                            for item in _copy_direct_maps:
                                _direct_map.add([item])
                            else:
                                LOG.debug("new_direct_map: %s", _direct_map)
                                new_direct_maps.append(_direct_map)

                for local in rule["local"]:
                    if new_direct_maps:
                        new_local = dict()
                        for direct_map in new_direct_maps:
                            new_local = self._merge_dict(
                                new_local,
                                self._update_local_mapping(local, direct_map),
                            )
                        identity_values.append(new_local)
                    else:
                        new_local = self._update_local_mapping(
                            local, direct_maps
                        )
                        identity_values.append(new_local)

        LOG.debug("identity_values: %s", identity_values)
        mapped_properties = self._transform(identity_values)

        LOG.debug("mapped_properties: %s", mapped_properties)
        return mapped_properties

    def _merge_dict(self, base, new, extend=True):
        """Recursively merge new into base.

        :param base: Base dictionary to load items into
        :type base: Dictionary
        :param new: New dictionary to merge items from
        :type new: Dictionary
        :param extend: Boolean option to enable or disable extending
                       iterable arrays.
        :type extend: Boolean
        :returns: Dictionary
        """

        if isinstance(new, dict):
            for key, value in new.items():
                if key not in base:
                    base[key] = value
                elif extend and isinstance(value, dict):
                    base[key] = self._merge_dict(
                        base=base.get(key, {}), new=value, extend=extend
                    )
                elif extend and isinstance(value, list):
                    base[key].extend(value)
                elif extend and isinstance(value, (tuple, set)):
                    if isinstance(base.get(key), tuple):
                        base[key] += tuple(value)
                    elif isinstance(base.get(key), set):
                        base[key].update(value)
                else:
                    base[key] = new[key]
        elif isinstance(new, list):
            if extend:
                base.extend(new)
            else:
                base = new

        return base


class RuleProcessorToHonorDomainOption(
    mapped.utils.RuleProcessorToHonorDomainOption, RuleProcessor
):
    """RuleProcessorToHonorDomainOption for dynamic scheme v2.0.

    The RuleProcessorToHonorDomainOption class is used to dynamically map
    multiple projects based on the provided mapping rules. The class will
    iterate through the mapping rules to find assertions that are valid and
    return the mapped properties. The system ensures that an account with
    multiple roles defined by `role_attribute` automatically map to `projects`
    with expected RBAC.

    The subclass will ensure that the Rackspace plugin is scheme v2.0
    compatible.
    """


def _handle_projects_from_mapping(
    shadow_projects,
    idp_domain_id,
    existing_roles,
    user,
    assignment_api,
    resource_api,
):
    for shadow_project in shadow_projects:
        mapped.configure_project_domain(
            shadow_project, idp_domain_id, resource_api
        )
        try:
            # Check and see if the project already exists and if it
            # does not, try to create it.
            project = resource_api.get_project_by_name(
                shadow_project["name"], shadow_project["domain"]["id"]
            )
        except exception.ProjectNotFound:
            LOG.info(
                "Project %(project_name)s does not exist. It will be "
                "automatically provisioning for user %(user_id)s.",
                {
                    "project_name": shadow_project["name"],
                    "user_id": user["id"],
                },
            )
            project_ref = {
                "id": hashlib.sha224(
                    shadow_project["name"].encode("utf-8")
                ).hexdigest(),
                "name": shadow_project["name"],
                "domain_id": shadow_project["domain"]["id"],
            }
            project = resource_api.create_project(
                project_ref["id"], project_ref
            )
        shadow_roles = shadow_project["roles"]
        for shadow_role in shadow_roles:
            assignment_api.create_grant(
                existing_roles[shadow_role["name"]]["id"],
                user_id=user["id"],
                project_id=project["id"],
            )
        # Run project update to ensure that the project has the correct tags
        # and description.
        update_needed = False
        for shadow_tag in shadow_project.get("tags", list()):
            shadow_tag = shadow_tag.get("project_tag")
            if shadow_tag and shadow_tag not in project["tags"]:
                project["tags"].append(shadow_tag)
                update_needed = True

        description = shadow_project.get("description", "").strip()
        if description and project.get("description") != description:
            project["description"] = description
            update_needed = True

        metadata = shadow_project.get("metadata", list())
        for item in metadata:
            if item["key"] not in project:
                project[item["key"]] = item["value"]
                update_needed = True

        if update_needed:
            resource_api.update_project(
                project_id=project["id"], project=project
            )


# NOTE(cloudnull): Adds tag and description support to the project mapping.
mapped.handle_projects_from_mapping = _handle_projects_from_mapping

# NOTE(cloudnull): Ensures that the Rackspace plugin is permits the use of tags
#                  and a description within PROJECTS_SCHEMA_2_0.
mapped.utils.PROJECTS_SCHEMA_2_0["items"]["properties"]["tags"] = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["project_tag"],
        "properties": {
            "project_tag": {"type": "string"},
        },
        "additionalProperties": False,
    },
}
mapped.utils.PROJECTS_SCHEMA_2_0["items"]["properties"]["metadata"] = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["key", "value"],
        "properties": {
            "key": {"type": "string"},
            "value": {"type": "string"},
        },
        "additionalProperties": False,
    },
}
mapped.utils.PROJECTS_SCHEMA_2_0["items"]["properties"]["description"] = {
    "type": "string"
}
mapped.utils.IDP_ATTRIBUTE_MAPPING_SCHEMA_2_0["properties"]["rules"]["items"][
    "properties"
]["local"]["items"]["properties"][
    "projects"
] = mapped.utils.PROJECTS_SCHEMA_2_0
# NOTE(cloudnull): This is to ensure that the RuleProcessor is used for the
#                  1.0 schema and the RuleProcessorToHonorDomainOption is
#                  used for the 2.0 schema when running with the rxt auth
#                  plugin.
mapped.utils.IDP_ATTRIBUTE_MAPPING_SCHEMAS = {
    "1.0": {
        "schema": mapped.utils.IDP_ATTRIBUTE_MAPPING_SCHEMA_1_0,
        "processor": RuleProcessor,
    },
    "2.0": {
        "schema": mapped.utils.IDP_ATTRIBUTE_MAPPING_SCHEMA_2_0,
        "processor": RuleProcessorToHonorDomainOption,
    },
}


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

        role_attribute = keystone.conf.CONF.rackspace.role_attribute
        access_projects = list()

        try:
            access = service_catalog["access"]
            access_user = access["user"]
            access_token = access["token"]
            access_user_roles = set()

            for role in service_catalog["access"]["user"]["roles"]:
                rxt_tenantId = role.get("tenantId")
                try:
                    if access_token["tenant"]["id"] in rxt_tenantId:
                        access_user_roles.add(role["name"].split(":")[-1])
                    role, value = rxt_tenantId.split(":")
                except (ValueError, TypeError):
                    continue
                else:
                    if role.startswith(role_attribute):
                        access_projects.append(value)

            access_projects = sorted(access_projects)
            if not keystone.conf.CONF.rackspace.role_attribute_enforcement:
                access_projects.append(
                    "{tenant}_Flex".format(tenant=access_token["tenant"]["id"])
                )

            if len(access_projects) < 1:
                raise exception.Unauthorized(
                    _(
                        "User does not have the required role"
                        " attribute to continue."
                    )
                )

            tenant_ids = ";".join(access_projects)
            self._set_federation_env(
                username=access_user["name"],
                email=access_user["email"],
                domain_id=access_user["RAX-AUTH:domainId"],
                tenant_name=tenant_ids,
                tenant_id=tenant_ids,
                org_person_type=";".join(sorted(access_user_roles)),
            )
        except KeyError as e:
            raise exception.Unauthorized(
                _(
                    "Could not parse the Rackspace Service Catalog for"
                    " access: {error}".format(error=e)
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
                    token_ref,
                    PROVIDERS.federation_api,
                    PROVIDERS.identity_api,
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
