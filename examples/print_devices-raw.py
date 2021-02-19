#!/usr/bin/env python
'''
' Riverbed Community SteelScript
`
' print_devices-raw.py`
'
' Usage
'     python print_devices-raw.py netim-ip-address -u admin -p password
'
' Example
'     python print_hostgroups-raw.py 10.10.10.10 -u admin -p password
'
' Copyright (c) 2021 Riverbed Technology, Inc.
'
' This software is licensed under the terms and conditions of the MIT License
' accompanying the software ("License").  This software is distributed "AS IS"
' as set forth in the License.
'''

from steelscript.netim.core.app import NetIM
from steelscript.common.datautils import Formatter
class DevicesApp(NetIMApp):
    def main(self):
        for device in self.netim.classification.get_devices():
            print(device)

app = DevicesApp()
app.run()