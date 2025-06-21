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

from datetime import datetime
from dateutil import parser
import re
import hashlib
import json

import urllib.parse as urlparse

import keystone.conf.utils
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
RACKSPACE_US_IDENTITY_URL = "https://identity.api.rackspacecloud.com"
RACKSPACE_UK_IDENTITY_URL = "https://lon.identity.api.rackspacecloud.com"
UK_DDI_PREFIX = "100"
REQUEST_TIMEOUT = 30
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

# NOTE(cloudnull): The roles defined here are the roles that are
#                  expected to be returned from the Rackspace Identity
#                  API. The roles are used to map the user to the
#                  appropriate project and role.
RXT_ROLES = {
    "autoscale": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "bigdata": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "cbs": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "cdb": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "cdn": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "cloudBackup": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "cloudfeeds": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "cloudImages": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "cloudNetworks": {
        "admin": "network_member",
        "creator": "network_creator",
        "default": None,
        "observer": "network_observer",
    },
    "compute": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "dnsaas": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "heat": {
        "admin": "heat_stack_user",
        "creator": "heat_stack_user",
        "default": None,
        "observer": "heat_stack_user",
    },
    "identity": {
        "admin": "member",
        "creator": "reader",
        "default": "reader",
        "tenant-access": "reader",
        "user-admin": "member",
        "observer": "reader",
    },
    "LBaaS": {
        "admin": "load-balancer_member",
        "creator": "load-balancer_member",
        "default": None,
        "observer": "load-balancer_observer",
    },
    "monitoring": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "nova": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "object-store": {
        "admin": "creator",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
    "rms": {
        "admin": "member",
        "creator": "creator",
        "default": None,
        "observer": "reader",
    },
}
SESSION_ID_REGEX = re.compile(r"""sessionId='(.*?[^\\])'""")


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
        assertion = {
            n: v.split(";")
            for n, v in assertion_data.items()
            if isinstance(v, str)
        }
        identity_values = []

        LOG.debug(_("rules: %s"), self.rules)
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
                LOG.debug(_("original_direct_maps: %s"), direct_maps)
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
                                LOG.debug(_("new_direct_map: %s"), _direct_map)
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

        LOG.debug(_("identity_values: %s"), identity_values)
        mapped_properties = self._transform(identity_values)

        LOG.debug(_("mapped_properties: %s"), mapped_properties)
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
                _(
                    "Project %s does not exist. It will be "
                    "automatically provisioning for user %s.",
                ),
                shadow_project["name"],
                user["id"],
            )
            project_ref = {
                "id": hashlib.shake_256(
                    shadow_project["name"].encode("utf-8")
                ).hexdigest(length=16),
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

        # NOTE(cloudnull): Dynmically add roles to the user for a project.
        #                  This is used to ensure that the user has the
        #                  correct roles for the project based on what is
        #                  defined in the mapping, which is retruned from
        #                  the IdP.
        req_roles = flask.request.environ.get("RXT_orgPersonType", "reader")
        for role in req_roles.split(";"):
            if role in existing_roles:
                assignment_api.create_grant(
                    existing_roles[role]["id"],
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


class RXTv2BaseAuth(object):
    """Base class for Rackspace v2 authentication."""

    def __init__(self):
        """Initialize the base authentication object."""
        self.session = requests.Session()
        self.session_id = None

    def __enter__(self):
        pass

    def __exit__(self, *args, **kwargs):
        """Close the session.

        This method is used to close the session after the authentication
        method has completed.
        """

        if hasattr(self, "session") and self.session:
            self.session.close()
        LOG.debug(_("Rackspace IDP Login complete, returning to OS"))

    @staticmethod
    def _role_parser(role_list):
        LOG.debug(_("Parsing roles: %s"), role_list)

        access_roles = {
            k: v["default"]
            for k, v in RXT_ROLES.items()
            if v.get("default") is not None
        }

        for role in role_list:
            role_name = role.get("name", "")
            if role_name == "admin" or (
                role_name.startswith("identity:")
                and role_name.endswith("user-admin")
            ):
                LOG.debug(_("RXT Auth admin discovered: %s"), role)
                access_roles = {
                    k: v["admin"]
                    for k, v in RXT_ROLES.items()
                    if v.get("admin") is not None
                }
                break

            try:
                rxt_role, rxt_value = role_name.split(":", 1)
            except ValueError as e:
                LOG.debug(
                    _(
                        "Could not parse the role name and value, skipping: %s - %s"
                    ),
                    role,
                    e,
                )
                continue
            except AttributeError as e:
                LOG.debug(_("Access role is undefined: %s - %s"), role, e)
                continue
            else:
                rxt_role_mapping = RXT_ROLES.get(rxt_role, dict())
                rxt_role_mapped_value = rxt_role_mapping.get(rxt_value)
                if rxt_role_mapped_value:
                    # NOTE(cloudnull): The compute role is mapped to the
                    #                  nova role for backwards compatibility.
                    if rxt_role == "nova":
                        access_roles["compute"] = rxt_role_mapped_value
                    access_roles[rxt_role] = rxt_role_mapped_value

        LOG.debug(_("Access Roles: %s"), access_roles)

        access_projects = set()
        for role in role_list:
            try:
                project_tenant = role["tenantId"]
                project_type, project_value = project_tenant.split(":")
            except KeyError as e:
                LOG.debug(
                    _("Role lacks assigned tenant IDs, skipping: %s - %s"),
                    role,
                    e,
                )
                continue
            except ValueError as e:
                LOG.debug(
                    _("Could not parse the project value, skipping: %s - %s"),
                    role,
                    e,
                )
                continue
            else:
                if project_type.startswith(
                    keystone.conf.CONF.rackspace.role_attribute
                ):
                    access_projects.add(project_value)

        LOG.debug(_("Access Projects: %s"), access_projects)

        return list(access_projects), access_roles

    @staticmethod
    def _return_auth_url(ddi):
        """Return the Rackspace authentication URL.

        Inspect the ddi and return the correct Rackspace authentication URL.
        If the ddi is not provided, the method will return the REMOTE_AUTH_URL
        from the Flask request environment.

        :param str ddi: The user ID to be used for determining the auth URL.
        :type ddi: int, str
        :returns: The Rackspace authentication URL.
        :rtype: str
        """

        remote_auth_url = flask.request.environ.get("REMOTE_AUTH_URL", "")
        if (
            remote_auth_url.startswith("http")
            and "rackspacecloud" in remote_auth_url
        ):
            LOG.debug(
                _("Using REMOTE_AUTH_URL from Flask request environment: %s"),
                remote_auth_url,
            )
            return remote_auth_url

        if ddi is None:
            return remote_auth_url

        ddi_str = str(ddi)
        if not ddi_str:
            raise ValueError("DDI cannot be empty")

        if ddi_str.startswith(UK_DDI_PREFIX):
            return RACKSPACE_UK_IDENTITY_URL
        else:
            return RACKSPACE_US_IDENTITY_URL

    def _return_auth_handler(
        self, status=True, response_body=None, response_data=None
    ):
        """Return the auth handler response.

        Using the provided auth payload, return the auth handler response.
        This will work for both scoped and unscoped tokens.
        """

        if status is True:
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

    def _return_rxt_roles(self, uid, ddi, token):
        """Authenticate using the Rackspace Identity API.

        This method is used to query the Rackspace role assigment API.
        The method will return an auth handler responce.

        The response will contain the role assignments for the user
        and the roles that are available to the user. The response will
        look like the following:
        >>> {
        ...   "RAX-AUTH:roleAssignments": {
        ...     "tenantAssignments": [
        ...       {
        ...         "onRoleName": "identity:user-admin",
        ...         "sources": [
        ...           {
        ...             "sourceId": "12345678901234567890",
        ...             "sourceType": "USER",
        ...             "forTenants": [
        ...               "MossoCloudFS_1234567890",
        ...               "os_flex:00000000-0000-0000-0000-000000000000",
        ...               "1234567890"
        ...             ],
        ...             "assignmentType": "DOMAIN"
        ...           }
        ...         ],
        ...         "forTenants": [
        ...           "MossoCloudFS_1234567890",
        ...           "os_flex:00000000-0000-0000-0000-000000000000",
        ...           "1234567890"
        ...         ],
        ...         "onRole": "3"
        ...       }
        ...     ]
        ...   }

        The roles names will be assigned to projects based on the `forTenants`
        property.

        :param str uid: The user ID to be used for the authentication.
        :param dict ddi: The DDI to be used for the authentication.
        :param str token: The token to be used for the authentication.
        :returns: A tuple containing the role assignments and the roles that are
                  available to the user.
        :rtype: tuple
        :raises keystone.exception.Unauthorized: If the Rackspace Identity API
            returns an error or the user is not authorized.
        """

        try:
            auth_url = urlparse.urljoin(
                self._return_auth_url(ddi=ddi),
                f"v2.0/users/{uid}/RAX-AUTH/roles",
            )
            LOG.debug(_("Using Rackspace Authentication URL: %s"), auth_url)
            r = self.session.get(
                auth_url,
                timeout=REQUEST_TIMEOUT,
                headers={
                    "X-Auth-Token": token,
                    "Accept": "application/json",
                },
            )
            r.raise_for_status()
            role_assignment = r.json()

            LOG.debug(
                _("Rackspace Role Assignments: %s"),
                role_assignment,
            )

            role_list = list()
            for assignment in role_assignment["RAX-AUTH:roleAssignments"][
                "tenantAssignments"
            ]:
                for source in assignment["sources"]:
                    for tenant in source.get("forTenants", list()):
                        if tenant.startswith("os_flex"):
                            role_list.append(
                                dict(
                                    name=assignment["onRoleName"],
                                    tenantId=tenant,
                                )
                            )
        except requests.Timeout:
            LOG.error(_("Timeout retrieving roles for user %s"), uid)
            raise exception.Unauthorized("Request timeout")
        except requests.ConnectionError:
            LOG.error(_("Connection error for user %s"), uid)
            raise exception.Unauthorized("Network error")
        except requests.HTTPError as e:
            LOG.error(_("HTTP error retrieving roles for user %s: %s"), uid, e)
            raise exception.Unauthorized(
                _("Failed to authenticate using the Rackspace Identity API")
            )
        except requests.RequestException as e:
            LOG.error(
                _("Request error retrieving roles for user %s: %s"), uid, e
            )
            raise exception.Unauthorized(
                _("Network error communicating with Rackspace Identity API")
            )
        except ValueError as e:
            LOG.error(_("Value error during role parsing: %s"), e)
            raise exception.Unauthorized(
                _("Failed to parse role data from Rackspace Identity API")
            )
        else:
            return self._role_parser(role_list=role_list)


class RXTv2Credentials(RXTv2BaseAuth):
    """Return an authenticate object based on the provided auth payload.

    Check the value type of the provided auth payload and determine the
    correct authentication method.
    """

    hash_types = [r"^[a-fA-F0-9]{%s}$" % i for i in [32, 40, 64]]
    rxt_auth_payload = None
    rxt_headers = dict()

    def __init__(self, auth_payload):
        """Initialize the RXTv2Credentials object.

        This method is used to initialize the RXTv2Credentials object. The
        method will hash the auth payload and username for use in caching
        and session headers.

        :param dict auth_payload: The auth payload to be used for authentication.
        """

        super(RXTv2Credentials, self).__init__()

        self.auth_payload = auth_payload
        self.hashed_auth_payload = hashlib.shake_256(
            json.dumps(self.auth_payload, sort_keys=True).encode("utf-8")
        ).hexdigest(length=16)
        self.hashed_auth_user = hashlib.shake_256(
            self._username.encode("utf-8")
        ).hexdigest(length=16)
        self.session_id = self._sessionID

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

        try:
            return SESSION_ID_REGEX.findall(session_header).pop()
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
            access_user = service_catalog["access"]["user"]
            access_token = service_catalog["access"]["token"]
            access_tenant_id = access_token["tenant"]["id"]
            access_projects, access_roles = self._return_rxt_roles(
                uid=access_user["id"],
                ddi=access_tenant_id,
                token=access_token["id"],
            )
            access_projects = sorted(access_projects)
            if not keystone.conf.CONF.rackspace.role_attribute_enforcement:
                access_projects.append(f"{access_tenant_id}_Flex")

            if len(access_projects) < 1:
                raise exception.Unauthorized(
                    _(
                        "User does not have the required role"
                        " attribute to continue."
                    )
                )
            LOG.debug(
                _("Access Roles Set for user %s: %s"),
                access_user["name"],
                access_roles,
            )
            tenant_ids = ";".join(access_projects)
            self._set_federation_env(
                username=access_user["name"],
                email=access_user["email"],
                domain_id=access_user["RAX-AUTH:domainId"],
                tenant_name=tenant_ids,
                tenant_id=tenant_ids,
                org_person_type=";".join(set(access_roles.values())),
            )
        except (KeyError, TypeError, ValueError) as e:
            LOG.error(
                _("Failed to parse the Rackspace Service Catalog: %s"), e
            )
            raise exception.Unauthorized(
                _("Could not parse the Rackspace Service Catalog for access")
            )
        except requests.RequestException as e:
            LOG.error(_("Network error during role retrieval: %s"), e)
            raise exception.Unauthorized(
                _("Failed to communicate with Rackspace Identity API")
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
        self.auth_payload["identity_provider"] = "rackspace"
        self.auth_payload["protocol"] = "rackspace"

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
                if token_expire > datetime.now(token_expire.tzinfo):
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

        LOG.debug(_("Attempting to authenticate using %s"), auth_type)
        r = self.session.post(
            urlparse.urljoin(RACKSPACE_US_IDENTITY_URL, "v2.0/tokens"),
            timeout=REQUEST_TIMEOUT,
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
        except requests.Timeout:
            LOG.error(_("Timeout while authenticating"))
            raise exception.Unauthorized("Request timeout")
        except requests.ConnectionError:
            LOG.error(_("Connection error while authenticating"))
            raise exception.Unauthorized("Network error")
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
                _("Failed to authenticate using the Rackspace Identity API")
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
                _("Failed to authenticate using the Rackspace Identity API")
            )


class RXTSAMLAuth(RXTv2BaseAuth):
    """Rackspace TOTP Authentication."""

    def __init__(self, auth_payload):
        """Initialize the RXTv2Credentials object.

        This method is used to initialize the RXTv2Credentials object. The
        method will hash the auth payload and username for use in caching
        and session headers.

        :param dict auth_payload: The auth payload to be used for authentication.
        """

        super(RXTSAMLAuth, self).__init__()

        self.auth_payload = auth_payload

    def __enter__(self):
        """Return the correct authentication method.

        This method is used to return the authentication method which is
        evaluating the SAML assertion in the auth payload.
        """

        LOG.debug(_("Rackspace IDP Login started for SAML"))
        return self

    def rxt_auth(self, auth_payload=None):
        """Authenticate using the Rackspace Identity API.

        The roles names will be assigned to projects based on the `forTenants`
        property.

        :param dict auth_payload: The auth payload to be used for authentication.
        :returns: An auth handler response if the Rackspace Identity API
                  returns a boolean
        :rtype: keystone.auth.plugins.base.AuthHandlerResponse
        """

        LOG.debug(_("Rackspace IDP SAML2 Login started"))

        try:
            access_projects, access_roles = self._return_rxt_roles(
                uid=flask.request.environ["uid"],
                ddi=flask.request.environ["REMOTE_DDI"],
                token=flask.request.environ["REMOTE_AUTH_TOKEN"],
            )
            flask.request.environ["REMOTE_PROJECTS"] = ";".join(
                access_projects
            )
            flask.request.environ["RXT_orgPersonType"] = ";".join(
                set(access_roles.values())
            )
        except (ValueError, requests.HTTPError):
            raise exception.Unauthorized(
                _("Failed to authenticate using the Rackspace Identity API")
            )
        else:
            return self._return_auth_handler(status=True)


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


class RXTSAML2(mapped.Mapped):
    """Rackspace SAML Authentication.

    This class is used to authenticate using the Rackspace Identity API
    with SAML. The class will attempt to authenticate using the Rackspace
    Identity API with the provided MFA auth payload.
    """

    def authenticate(self, auth_payload):
        """Return a signed request with an access key into a keystone token."""

        try:
            assert auth_payload["identity_provider"] == "Rackspace-Federation"
        except (KeyError, AssertionError):
            LOG.debug(_("Using OS SAML Authentication"))
            return super(RXTSAML2, self).authenticate(auth_payload)
        else:
            if "id" in auth_payload:
                LOG.debug(_("Using Scoped Token Normally"))
                return base.AuthHandlerResponse(
                    status=True,
                    response_body=None,
                    response_data=mapped.handle_scoped_token(
                        self._get_token_ref(auth_payload),
                        PROVIDERS.federation_api,
                        PROVIDERS.identity_api,
                    ),
                )
            else:
                LOG.debug(
                    _("Using Rackspace Global Authentication via OS SAML")
                )
                with RXTSAMLAuth(auth_payload=auth_payload) as rxt:
                    return rxt.rxt_auth()
