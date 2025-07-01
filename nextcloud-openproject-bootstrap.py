#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 B1 Systems GmbH <info@b1-systems.de>

# NOTE: This is a--yet to be completed--rewrite of the original bash script found here:
# https://github.com/nextcloud/integration_openproject/blob/c4295155d162966cfd42bdcee0e9b59762c6bf2b/integration_setup.sh
# Just a couple days after we wrote this script, a newer version of the integration with
# external OIDC support was released. This new feature was not part of the rewrite.

# TODO: Also use ENV vars in addition to config
# TODO: Better retry mechanism
# TODO: Retry whenever sensible
# MAYBE: Split into multiple files?

# Required for the forward reference of classes
from __future__ import annotations
import logging
import os
from configparser import ConfigParser
from dataclasses import dataclass
from typing import Self

import requests
from requests import Response

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO").upper())
logger = logging.getLogger(__name__)


@dataclass
class API:
    server_url: str
    access_key: str
    access_secret: str
    ready_endpoint: str
    max_retries: str

    client_id = ""
    client_secret = ""

    @classmethod
    def from_config(cls, config_file: str) -> Self:
        logging.info(f"Creating new {cls.__name__} from {config_file}")
        # Get required config options from class attributes
        # NOTE: We could add exceptions if necessary
        required = cls.__dataclass_fields__.keys()
        # logging.debug(f"{required}")

        config = ConfigParser()
        config.read(config_file)
        logging.debug(f"Config: {config.sections()}")

        # Exit on Error
        if cls.config_name not in config:
            logging.error(
                f"Could not find config section '[{cls.config_name}]' "
                "in config file '{config_file}'"
            )
            exit(1)

        elif any(missing := [c for c in required if c not in config[cls.config_name]]):
            for c in missing:
                logging.error(
                    f"Could not read required config option '{cls.config_name}.{c}' "
                    "in config file '{config_file}'"
                )
            exit(1)

        # Return instance with config from config file
        return cls(**config[cls.config_name])

    def debug(self) -> None:
        logging.debug(self)

    def is_ready(self) -> bool:
        ready = True if self.GET(self.ready_endpoint).status_code == 200 else False
        if not ready:
            logging.warning(
                f"No connection to {self.__class__.__name__} @ {self.server_url}/{self.ready_endpoint}"
            )
        return ready

    def GET(self, endpoint: str, headers={}) -> Response:
        return self._request("GET", endpoint, {}, {}, headers)

    def POST(self, endpoint: str, data={}, json={}, headers={}) -> Response:
        return self._request("POST", endpoint, data, json, headers)

    def PATCH(self, endpoint: str, data={}, json={}, headers={}) -> Response:
        return self._request("PATCH", endpoint, data, json, headers)

    def DELETE(self, endpoint: str, data={}, json={}, headers={}) -> Response:
        return self._request("DELETE", endpoint, data, json, headers)

    def _request(
        self, method: str, endpoint: str, data={}, json={}, headers={}
    ) -> Response:
        resp = requests.request(
            method=method,
            url=f"{self.server_url}/{endpoint}",
            auth=(self.access_key, self.access_secret),
            **({"json": json} if json else {"data": data}),
            headers=headers,
        )
        return resp

    def get_embedded(self, res: Response) -> dict:
        return res["_embedded"]


@dataclass
class NextcloudAPI(API):
    enable_navigation: str
    enable_unified_search: str
    enable_project_folder: str
    enable_app_password: str
    config_name = "nextcloud"
    op_integration_endpoint = "index.php/apps/integration_openproject"
    op_integration_app_name = "integration_openproject"
    op_groupfolders_endpoint = "index.php/apps/groupfolders"
    op_integration_group_name = "OpenProject"
    op_integration_user_name = "OpenProject"
    op_integration_groupfolder_name = "OpenProject"
    ocs_endpoint = "ocs/v2.php/cloud"
    ocs_headers = {"OCS-APIRequest": "true", "accept": "application/json"}

    def __post_init__(self):
        if not self.is_ready():
            # TODO: retry
            pass

        self.navigation = bool(self.enable_navigation)
        self.unified_search = bool(self.enable_unified_search)
        self.project_folder = bool(self.enable_project_folder)
        self.app_password = bool(self.enable_app_password)

        logging.info("Nextcloud API successfully initialized")

    def setup_openproject_integration(self, op: OpenProjectAPI):
        req = {
            "values": {
                "openproject_instance_url": f"{op.server_url}",
                "openproject_client_id": f"{op.client_id}",
                "openproject_client_secret": f"{op.client_secret}",
                "default_enable_navigation": self.navigation,
                "default_enable_unified_search": self.unified_search,
                "setup_project_folder": self.project_folder,
                "setup_app_password": self.app_password,
            }
        }

        # FIXME: This is just a workaround if the User/Group/GroupFolder already exists
        res = self.POST(f"{self.op_integration_endpoint}/setup", json=req).json()
        if "error" in res and '"OpenProject" already exists' in res["error"]:
            self.DELETE(
                f"{self.ocs_endpoint}/apps/{self.op_integration_app_name}",
                headers=self.ocs_headers,
            )
            self.DELETE(
                f"{self.ocs_endpoint}/groups/{self.op_integration_group_name}",
                headers=self.ocs_headers,
            )
            self.DELETE(
                f"{self.ocs_endpoint}/users/{self.op_integration_group_name}",
                headers=self.ocs_headers,
            )
            res = self.GET(
                f"{self.op_groupfolders_endpoint}/folders",
                headers=self.ocs_headers,
            ).json()

            # TODO: Maybe risky
            groupfolder_id = [
                x["id"]
                for x in res["ocs"]["data"].values()
                if x["mount_point"] == self.op_integration_groupfolder_name
            ].pop()

            self.DELETE(
                f"{self.op_groupfolders_endpoint}/folders/{groupfolder_id}",
                headers=self.ocs_headers,
            )
            self.POST(
                f"{self.ocs_endpoint}/apps/{self.op_integration_app_name}",
                headers=self.ocs_headers,
            )
            # TODO: Use loop & max retries instead of recursion
            self.setup_openproject_integration(op)
            return

        logging.debug(res)
        self.client_id = res.get("nextcloud_client_id")
        self.client_secret = res.get("nextcloud_client_secret")
        self.app_password = res.get("openproject_user_app_password")
        op.setup_nextcloud_integration_stage_2(self)


@dataclass
class OpenProjectAPI(API):
    # Additional config options
    storage_name: str
    # Static configuration
    storage_id = -1
    config_name = "openproject"
    # Feature: Extend storage API to include boolean “configured” attribute [#55158]
    supported_version = "14.0.2"
    base_endpoint = "api/v3"
    storage_endpoint = f"{base_endpoint}/storages"
    headers = {"accept": "application/hal+json", "X-Requested-With": "XMLHttpRequest"}

    def __post_init__(self):
        if not self.is_ready():
            # TODO: retry
            pass

        if not self.is_supported():
            logging.error(f"OpenProject version must be above {self.supported_version}")
            exit(1)

        logging.info("OpenProject API successfully initialized")

    def is_supported(self) -> bool:
        supported = False
        res = self.GET(f"{self.base_endpoint}").json()
        version = res.get("coreVersion")
        if version >= self.supported_version:
            supported = True
        return supported

    def get_storages(self) -> dict:
        storages = {}
        res = self.GET(self.storage_endpoint).json()
        logging.debug(res)
        if res.get("_type") == "Collection":
            storages = res["_embedded"]["elements"]
            storages = {
                s["name"]: {
                    "id": s["id"],
                    "configured": s["configured"],
                    "hasApplicationPassword": s["hasApplicationPassword"],
                }
                for s in storages
            }
        else:
            logging.error("Unexpected error while fetching storages")
        # _type: Storage, id: <ID>, name: <NAME>, configured: BOOL
        return storages

    def get_storage_id(self) -> int:
        if self.storage_id == -1:
            self.storage_id = (
                self.get_storages().get(self.storage_name, {}).get("id", -1)
            )

        logging.debug(f"Storage ID: {self.storage_id}")
        return self.storage_id

    def delete_storage_configuration(self) -> bool:
        return (
            self.DELETE(f"{self.storage_endpoint}/{self.get_storage_id()}").status_code
            == 204
        )

    def is_already_configured(self) -> bool:
        # TODO: hasApplicationPassword or configured?
        pass

    def setup_nextcloud_integration_stage_1(self, nc: NextcloudAPI):
        req = {
            "name": f"{self.storage_name}",
            "applicationPassword": "",
            "_links": {
                "origin": {"href": f"{nc.server_url}"},
                "type": {"href": "urn:openproject-org:api:v3:storages:Nextcloud"},
            },
        }
        res = self.POST(self.storage_endpoint, json=req).json()
        logging.debug(res)
        # TODO: Retry
        match res.get("_type"):
            case "Error":
                logging.error(
                    f"Error during storage creation of `{self.storage_name}`: "
                    f"{res.get('message')}"
                )
                # TODO: Name OR URL could be already in use, handle both?
                # Delete storage and try again
                self.delete_storage_configuration()
                self.setup_nextcloud_integration_stage_1(nc)
            case "Storage":
                logging.info(
                    f"Storage creation of `{self.storage_name}` successfully initiated"
                )
                oauth = self.get_embedded(res).get("oauthApplication")
                self.storage_id = res.get("id")
                self.client_id = oauth.get("clientId")
                self.client_secret = oauth.get("clientSecrcet")
                nc.setup_openproject_integration(self)
                return
            case _:
                logging.error(f"Unexpected Error: {res}")

    def setup_nextcloud_integration_stage_2(self, nc: NextcloudAPI):
        req = {
            "clientId": f"{nc.client_id}",
            "clientSecret": f"{nc.client_secret}",
        }

        logging.debug(f"OAUTH Request: {req}")
        res = self.POST(
            f"{self.storage_endpoint}/{self.storage_id}/oauth_client_credentials",
            json=req,
            headers=self.headers
        ).json()
        logging.debug(res)

        # Setup "Automatically managed folders"
        req = {
            "applicationPassword": f"{nc.app_password}",
        }

        logging.debug(f"Automatically Managed Folders Request: {req}")
        res = self.PATCH(
            f"{self.storage_endpoint}/{self.storage_id}",
            json=req,
        ).json()
        logging.debug(res)
        # TODO: Check if this still yields incorrect password (maybe \\ escaping of some kind)


def main():
    nc = NextcloudAPI.from_config("config.cnf")
    op = OpenProjectAPI.from_config("config.cnf")
    op.setup_nextcloud_integration_stage_1(nc)


if __name__ == "__main__":
    main()
