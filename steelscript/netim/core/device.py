# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.
from steelscript.netim.utils import RequestMethods
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
        if port != 8543:
            self.host = '{0}:{1}'.format(self.host, port)
        self.auth = auth
        if version is None:
            self.version = 'v1'
        else:
            self.version = version
        self.base_url = f'https://{self.host}:{self.port}/api/netim/{self.version}/'
        logger.info("Initialized NetIM Core Device API object with %s" % self.host)

    def get_all_devices(self):
        """Return all of the devices in the data model
        Args:

        Returns:
            result (dict): All data associated with a response.
        """

        url = f"{self.base_url}device"
        response = RequestMethods(self.session, url).request('GET')
        result = ParseMethods.parse_data(response)
        return result