# Third-Party Notices

RXEngine is licensed under the Apache License, Version 2.0. It depends on
third-party packages that are installed separately and remain under their own
licenses. This file records code adapted into the RXEngine source tree and
summarizes dependency licenses. Always treat each package's own LICENSE file as
authoritative.

## ida-pro-mcp

Portions of `headless_ida_mcp_server/helper.py` are adapted from
[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).

```text
MIT License

Copyright (c) 2025 Duncan Ogilvie

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Runtime dependencies

| Package | License (as declared by the installed distribution) |
| --- | --- |
| `headless-ida` | MIT |
| `angr` / `claripy` / `cle` / `archinfo` | BSD-2-Clause |
| `qiling` | GPL-2.0 |
| `unicorn` | BSD |
| `z3-solver` | MIT |
| `capstone` | BSD |
| `keystone-engine` | BSD-3-Clause |
| `STPyV8` | Apache-2.0 |
| `pyelftools` | Public domain |
| `mcp` (Python SDK) | MIT |

### Note on GPL components

`qiling` is licensed under GPL-2.0. RXEngine imports it at runtime but does not
redistribute it; the Apache-2.0 license covers the RXEngine source in this
repository. If you redistribute a bundle that includes qiling (for example a
container image or an all-in-one installer), that combined distribution must
also comply with GPL-2.0. Consult legal counsel for your distribution model.

IDA Pro is a commercial product of Hex-Rays SA and is not distributed with this
project.
