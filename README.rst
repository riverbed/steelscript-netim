Riverbed SteelScript for NetIM
==============================

**Riverbed SteelScript** is a collection of libraries and scripts written in Python for interacting
with Riverbed appliances and solutions, and other network infrastructure devices.

As part of the Riverbed SteelScript this module provides specific bindings for `Riverbed NetIM <https://www.riverbed.com/netim>`__ 

Quick start
-----------

.. code:: shell

  # Build a docker image from latest code
  docker build --tag steelscript:latest https://github.com/riverbed/steelscript.git

  # Run the image in an interactive container
  docker run -it steelscript:latest /bin/bash

  # Replace the tokens {...} with actual values
  python print-netim-devices-raw.py {NetIM Core fqdn or ip} --username {username} -password {password}

Contribute
-----------

Feel free to use, enhance and contribute by creating issues, sendind pull requests (PR), ...

Links
-----

- `SteelScript main code repository on GitHub <https://github.com/riverbed/steelscript>`__ 

- `SteelScript complete guide <https://support.riverbed.com/apis/steelscript>`__

License
=======

Copyright (c) 2021 Riverbed Technology, Inc.

SteelScript is licensed under the terms and conditions of the MIT License
accompanying the software ("License").  SteelScript is distributed "AS
IS" as set forth in the License. SteelScript also includes certain third
party code.  All such third party code is also distributed "AS IS" and is
licensed by the respective copyright holders under the applicable terms and
conditions (including, without limitation, warranty and liability disclaimers)
identified in the license notices accompanying the software.
