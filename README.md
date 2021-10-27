# Introduction

BLint is a Binary Linter to check the security properties, capabilities, and hardcoded credentials in your executables. It is powered by [lief](https://github.com/lief-project/LIEF)

[![BLint Demo](https://asciinema.org/a/438138.png)](https://asciinema.org/a/438138)

Capabilities review is supported for go and rust binaries.

Supported binary formats:

- ELF
- PE
- Mach-O (Soon)

## Installation

- Install python 3.8 or 3.9

```bash
pip3 install blint
```

## Usage

```bash
usage: blint [-h] [-i SRC_DIR_IMAGE] [-o REPORTS_DIR] [--no-error] [--no-banner] [--no-reviews]

Linting tool for binary files powered by lief.

optional arguments:
  -h, --help            show this help message and exit
  -i SRC_DIR_IMAGE, --src SRC_DIR_IMAGE
                        Source directory or container image or binary file
  -o REPORTS_DIR, --reports REPORTS_DIR
                        Reports directory
  --no-error            Continue on error to prevent build from breaking
  --no-banner           Do not display banner
  --no-reviews          Do not perform method reviews
```

To test any binary including default commands

```bash
blint -i /bin/netstat -o /tmp/blint
```

Use -i to check any other binary. For eg: to check ngrok

```bash
blint -i ~/ngrok -o /tmp/blint
```

PowerShell example

![PowerShell](./docs/blint-powershell.jpg)

## References

- [lief examples](https://github.com/lief-project/LIEF/tree/master/examples/python)
- [checksec](https://github.com/Wenzel/checksec.py)
