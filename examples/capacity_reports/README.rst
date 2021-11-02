Example Capacity Reports
==============================

**Capacity Reports** is a set of example Python scripts using the SteelScript libraries along with Python pandas, matplotlib, and Facebook prophet open source libraries to pull utilization metrics for interfaces from NetIM, analyze them, graph them, and trend them.

Quick start
-----------

.. code:: shell

  # To execute the report and forecast commands
  cd <SteelScript-NetIM installation path>/examples/capacity_reports
  pip3 install -r requirements.txt
  python3 report.py --sites_yml sites.yml --config_yml config.yml
  python3 forecast.py --sites_yml sites.yml --config_yml config.yml

- sites_example.yml is an example of what needs to be included for each site and interface
- config_example.yml is where the NetIM authentication information is provided, along with reporting period and other parameters
- The report/ directory and forecast/ directory shows example output from a lab environment

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
