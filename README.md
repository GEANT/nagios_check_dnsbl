# check_dnsbl.py

A Nagios check to monitor if a host/IP address appears in DNS based blacklists

## Requirements

Nagios or Icinga, Python3 with the following modules:

* pydnsbl
* argparse
* ipaddress

## Usage

```lang-none
usage: check_dnsbl.py [-h] --host HOST [--warn WARN] [--crit CRIT] [--providers PROVIDERS] [--verbose]

Check if a hostname/IP address appears in DNS based blacklists

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           the IP/host to check
  --warn WARN, -w WARN  WARN when host appears in this many blacklists. Defaults to 1
  --crit CRIT, -c CRIT  CRIT when host appears in this many blacklists. Defaults to 2
  --providers PROVIDERS, --blacklists PROVIDERS
                        Comma or space separated list of DNS blacklist provider hostnames. Defaults to: all.s5h.net, aspews.ext.sorbs.net,
                        b.barracudacentral.org, bl.nordspam.com, bl.spamcop.net, blackholes.five-ten-sg.com, blacklist.woody.ch, bogons.cymru.com,
                        cbl.abuseat.org, combined.abuse.ch, combined.rbl.msrbl.net, db.wpbl.info, dnsbl-2.uceprotect.net, dnsbl-3.uceprotect.net,
                        dnsbl.cyberlogic.net, dnsbl.dronebl.org, dnsbl.sorbs.net, drone.abuse.ch, dul.ru, dyna.spamrats.com, images.rbl.msrbl.net,
                        ips.backscatterer.org, ix.dnsbl.manitu.net, korea.services.net, matrix.spfbl.net, noptr.spamrats.com,
                        phishing.rbl.msrbl.net, proxy.bl.gweep.ca, proxy.block.transip.nl, psbl.surriel.com, rbl.interserver.net,
                        relays.bl.gweep.ca, relays.bl.kundenserver.de, relays.nether.net, residential.block.transip.nl, singular.ttk.pte.hu,
                        spam.dnsbl.sorbs.net, spam.rbl.msrbl.net, spam.spamrats.com, spambot.bls.digibase.ca, spamlist.or.kr, spamrbl.imp.ch,
                        spamsources.fabel.dk, ubl.lashback.com, virbl.bit.nl, virus.rbl.msrbl.net, virus.rbl.jp, wormrbl.imp.ch, z.mailspike.net,
                        zen.spamhaus.org.
  --verbose, -v         Show verbose output
```

## Examples


```sh
# Default with just a host
./check_dnsbl.py --host de-smtp-1.mimecast.com
OK: None of de-smtp-1.mimecast.com's IP addresses (62.140.10.21, 51.163.159.21) appear on a blacklist
```

```sh
# Verbose, will list the used blacklists
./check_dnsbl.py --host de-smtp-1.mimecast.com --verbose
OK: None of de-smtp-1.mimecast.com's IP addresses (62.140.10.21, 51.163.159.21) appear on a blacklist 
Blacklists used:

all.s5h.net
aspews.ext.sorbs.net
b.barracudacentral.org
bl.nordspam.com
bl.spamcop.net
blackholes.five-ten-sg.com
blacklist.woody.ch
bogons.cymru.com
cbl.abuseat.org
combined.abuse.ch
combined.rbl.msrbl.net
db.wpbl.info
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dnsbl.cyberlogic.net
dnsbl.dronebl.org
dnsbl.sorbs.net
drone.abuse.ch
dul.ru
dyna.spamrats.com
images.rbl.msrbl.net
ips.backscatterer.org
ix.dnsbl.manitu.net
korea.services.net
matrix.spfbl.net
noptr.spamrats.com
phishing.rbl.msrbl.net
proxy.bl.gweep.ca
proxy.block.transip.nl
psbl.surriel.com
rbl.interserver.net
relays.bl.gweep.ca
relays.bl.kundenserver.de
relays.nether.net
residential.block.transip.nl
singular.ttk.pte.hu
spam.dnsbl.sorbs.net
spam.rbl.msrbl.net
spam.spamrats.com
spambot.bls.digibase.ca
spamlist.or.kr
spamrbl.imp.ch
spamsources.fabel.dk
ubl.lashback.com
virbl.bit.nl
virus.rbl.msrbl.net
virus.rbl.jp
wormrbl.imp.ch
z.mailspike.net
zen.spamhaus.org
```

```sh
# Use custom blacklists
/check_dnsbl.py --host de-smtp-1.mimecast.com --blacklists zen.spamhaus.org,proxy.block.transip.nl -v
OK: None of de-smtp-1.mimecast.com's IP addresses (62.140.10.21, 51.163.159.21) appear on a blacklist
Blacklists used:

zen.spamhaus.org
proxy.block.transip.nl
```


```sh
# Approximation of the blacklists that are used by mxtoolbox.com
# See 'mxtoolbox.blacklists.txt'
./check_dnsbl.py --host outbound2.mail.transip.nl --blacklists 'bl.0spam.org rbl.abuse.ro spam.dnsbl.anonmails.de ips.backscatterer.org b.barracudacentral.org bl.blocklist.de dnsbl.calivent.com.pe v4.fullbogons.cymru.com v6.fullbogons.cymru.com tor.dan.me.uk torexit.dan.me.uk bl.drmx.org dnsbl.dronebl.org spamsources.fabel.dk hostkarma.junkemailfilter.com dnsrbl.imp.ch spamrbl.imp.ch wormrbl.imp.ch uribl.swinog.ch rblspamassassin.interserver.net rbl.interserver.net mail-abuse.blacklist.jippg.org dnsbl.kempt.net ubl.unsubscore.com bl.mailspike.net phishing.rbl.msrbl.net spam.rbl.msrbl.net ix.dnsbl.manitu.net bl.nordspam.com bl.nosolicitado.org psbl.surriel.com all.spamrats.com all.s5h.net rbl.schulte.org backscatter.spameatingmonkey.net bl.spameatingmonkey.net korea.services.net spam.dnsbl.sorbs.net dnsbl.sorbs.net bl.ipv6.spameatingmonkey.net bl.spamcop.net zen.spamhaus.org dnsbl.spfbl.net bl.suomispam.net truncate.gbudb.net dnsbl-1.uceprotect.net dnsbl-2.uceprotect.net dnsbl-3.uceprotect.net blacklist.woody.ch ipv6.blacklist.woody.ch db.wpbl.info dnsbl.zapbl.net'
WARNING: outbound2.mail.transip.nl's IP address 149.210.149.73 appears in 1 blacklist: hostkarma.junkemailfilter.com
```
