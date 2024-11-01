# Riverbed SteelScript for NetIM

This package as part of [SteelScript](https://github.com/riverbed/steelscript) provides specific bindings for interacting with [Riverbed NetIM](https://www.riverbed.com/products/netim) 

## Quick start

```shell
  # Build a docker image from latest code
  docker build --tag steelscript:latest https://github.com/riverbed/steelscript.git

  # Run the image in an interactive container
  docker run -it steelscript:latest /bin/bash

  # Replace the tokens {...} with actual values
  python print-netim-devices-raw.py {NetIM Core fqdn or ip} --username {username} -password {password}
```

Please see [SteelScript](https://github.com/riverbed/steelscript) for more details

## License

Copyright (c) 2019-2024 Riverbed Technology, Inc.

SteelScript-NetProfiler is licensed under the terms and conditions of the MIT
License accompanying the software ("License").  SteelScript-NetProfiler is
distributed "AS IS" as set forth in the License.
