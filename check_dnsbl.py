#!/usr/bin/env python3
import pydnsbl
import sys
import argparse
import socket
import ipaddress

def nagios_exit(message, code):
    print(message)
    sys.exit(code)

def is_ipaddr(string):
    try:
        ip = ipaddress.ip_address(string)
        return True
    except ValueError:
        return False

try:
    parser = argparse.ArgumentParser(description='Check if a hostname/IP address appears in DNS based blacklists')
    parser.add_argument('--host', help='the IP/host to check', required=True)
    parser.add_argument('--warn', '-w',
                        help='WARN when host appears in this many blacklists. Defaults to 1',
                        required=False, type=int, default=1)
    parser.add_argument('--crit', '-c',
                        help='CRIT when host appears in this many blacklists. Defaults to 2',
                        required=False, type=int, default=2)
    # TODO
    #  parser.add_argument('--providers',
    #                      help='Comma separated list of DNS blacklist provider hostname. Defaults to the _BASE_PROVIDERS set that is listed at https://github.com/dmippolitov/pydnsbl/blob/master/pydnsbl/providers.py'
    #                      )

    args = parser.parse_args()

    host = args.host
    warn = args.warn
    crit = args.crit
    providers = args.providers

    # Start with a clean slate
    ok_msg = []
    warn_msg = []
    crit_msg = []

    host_is_ip = is_ipaddr(host)

    # Find all IPv4 and IPv6 addresses
    ip_addresses = [a[4][0] for a in socket.getaddrinfo(host=host, port=0, proto=socket.IPPROTO_TCP)]

    checker = pydnsbl.DNSBLIpChecker()

    # List of blacklist results per IP
    results = [p for p in [checker.check(ip) for ip in ip_addresses] if p.blacklisted]

    msg = []
    total_hits = 0
    for result in results:
        detected_by = result.detected_by
        total_hits += len(detected_by)
        if host_is_ip:
            reported_host = host
        else:
            reported_host = f"{host}'s IP address {result.addr}"

        msg.append(f"{reported_host} appears in {len(detected_by)} blacklist{'s' if len(detected_by) > 1 else ''}: {', '.join(list(detected_by.keys()))}")

    if total_hits == 1 and crit > warn:
        warn_msg.append('. '.join(msg))
    elif total_hits > 1 and crit > warn:
        crit_msg.append('. '.join(msg))
    else:
        if host_is_ip:
            ok_msg.append(f"IP address {host} does not appear on a blacklist")
        else:
            ok_msg.append(f"None of {host}'s IP addresses ({', '.join(ip_addresses)}) appear on a blacklist")

except Exception as e:
    nagios_exit("UNKNOWN: Unknown error: {0}.".format(e), 3)

# Exit with accumulated message(s)
if crit_msg:
    nagios_exit("CRITICAL: " + ' '.join(crit_msg + warn_msg), 2)
elif warn_msg:
    nagios_exit("WARNING: " + ' '.join(warn_msg), 1)
else:
    nagios_exit("OK: " + ' '.join(ok_msg), 0)
