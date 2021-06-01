#!/usr/bin/env python
'''
' Riverbed Community SteelScript
'
' print-netim-devices-raw.py
'
' Encoding: UTF8
' End of Line Sequence: LF
'
' Description
' 
'     Print the list of the devices of the Device Manager in NetIM
'
' Usage:
'     
'    python print-netim-devices-raw.py {NetIM Core fqdn or ip} --username {username} -password {password}
''
' Usage:
'     
'    python print-netim-devices-raw.py 10.10.10.148 --username api --password password
'
' Copyright (c) 2021 Riverbed Technology, Inc.
' This software is licensed under the terms and conditions of the MIT License accompanying the software ("License").  This software is distributed "AS IS" as set forth in the License.
'''

#!/usr/bin/env python
from steelscript.common.app import Application
from steelscript.common.service import Service, UserAuth
from steelscript.netim.core.netim import NetIM
import pprint

class SteelScriptApp(Application):
    def add_positional_args(self):
        self.add_positional_arg('host','NetIM Core fqdn or IP address')

    def add_options(self, parser):
        super(SteelScriptApp, self).add_options(parser)
        self.add_standard_options()

    def main(self):
        host=(self.options.host)
        username=(self.options.username)
        password=(self.options.password)
        auth = UserAuth(username=username, password=password)

        netim_device = NetIM(host, auth)

        device_list = netim_device.get_all_devices()
        
        pprint.pprint(device_list)

if __name__ == '__main__':
    SteelScriptApp().run()

