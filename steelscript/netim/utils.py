# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

class RequestMethods(object):
    """Provides interaction with the NetIM REST API.
    """
    def __init__(self, session, url):
        """Initialize RequestMethods object with auth parameters.
        Args:
            auth (obj): Requests auth object
            url (str): URL of the API service being called
        """

        self.auth = auth
        self.url = url

    def request(self, urlpath, method, headers=None, payload=None):
        """Performs HTTP REST API Call.
        Args:
            method (str): DELETE, GET, POST, PUT
            headers (dict): Use standard or custom header for specific API interaction
            payload (str): A formatted string to be sent via POST or PUT REST call
        Returns:
            result (dict): All data associated with a response.
        """

