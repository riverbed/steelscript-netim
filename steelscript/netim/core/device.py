# Copyright (c) 2021 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.
from steelscript.common.service import Service
import logging

logger = logging.getLogger(__name__)

class Device(object):
    """NetIM Core Device API

    Responsible for DELETE, GET, POST, PUT methods against NetIM Device.

    """
    def __init__(self, host, auth, port=8543, version=None):
        """Initialize Device object.
        :param str host: name or IP address of the NetIM Core.

        :param auth: defines the authentication method and credentials
            to use to access the NetIM Core. It should be an instance of
            :py:class:`UserAuth<steelscript.common.service.UserAuth>` or
            :py:class:`OAuth<steelscript.common.service.OAuth>`

        :param port: integer, port number to connect to core

        :param str version: API version to use when communicating.
            if unspecified, this will use the latest version
        """
        
        self.host = host
        self.auth = auth

        self.service = Service('NetIM', host=host, auth=auth, port=port,
        verify_ssl=False, versions=None,
        enable_auth_detection = False,
        supports_auth_basic=True,
        supports_auth_cookie=False,
        supports_auth_oauth=False,
        enable_services_version_detection=False
        )

        if version is None:
            self.version = 'v1'
        else:
            self.version = version
        
        self.base_url = f'/api/netim/{self.version}/'
        logger.info("Initialized NetIM Core Device API object with %s" % self.host)

    def get_all_devices(self):
        """Return all of the devices in the data model
        Args:

        Returns:
            result (dict): All data associated with a response.
        """

        url = f"{self.base_url}devices"
        response = self.service.conn.json_request('GET', url)
        # result = ParseMethods.parse_data(response)
        print(response)
        return response