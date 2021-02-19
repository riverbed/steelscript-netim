#!/usr/bin/env python

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from steelscript.common import UserAuth
from steelscript.netim.core.device import Device
import pprint

# Fill these in with appropriate values
host = '$host'
username = '$username'
password = '$password'

auth=UserAuth(username, password)
netim_device = Device(host, auth)

device_list = netim_device.get_all_devices()
pprint.pprint(device_list)