# check_dnsbl.py

A Nagios check to monitor if a host/IP address appears in DNS based blacklists

## Requirements

Nagios or Icinga, Python3 with the following modules:

* pydnsbl
* argparse
* ipaddress

## Usage

```lang-none
$ ./check_dnsbl.py --help
usage: check_dnsbl.py [-h] --host HOST [--warn WARN] [--crit CRIT] [--providers PROVIDERS]

Check if a hostname/IP address appears in DNS based blacklists

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           the IP/host to check
  --warn WARN, -w WARN  WARN when host appears in this many blacklists. Defaults to 1
  --crit CRIT, -c CRIT  CRIT when host appears in this many blacklists. Defaults to 2
```
