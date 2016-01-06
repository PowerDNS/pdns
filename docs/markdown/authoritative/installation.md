# Installing PowerDNS
Installation of the PowerDNS Authoritative server on UNIX systems can be done in several ways:

  * Binary packages provided by your distribution
  * Binary packages provided by PowerDNS on [repo.powerdns.com](https://repo.powerdns.com)
  * Using the statically linked binary packages provided on the [website](https://www.powerdns.com/downloads.html)
  * Compiling from source

Running PowerDNS on Microsoft Windows is unsupported from version 3.0 onward.

## Binary Packages
### Debian-based Systems
PowerDNS Authoritative Server is available through the [apt](https://packages.debian.org/pdns-server) system.

**Note**: In the current 'stable' (codenamed 'wheezy') version 3.1 is included, it is recommended you install version 3.3 from backports.

`# apt-get install pdns-server`

Debian splits the backends into [several different packages](https://packages.debian.org/pdns-backend), install the required backend as follows:

`# apt-get install pdns-backend-$backend`

Alternatively, a statically linked binary package is provided on the [powerdns.com](https://www.powerdns.com/downloads.html) website that can be downloaded and installed by issueing:

`# dpkg -i pdns-static_$version_$arch.deb`

### Redhat-based Systems
On RedHat based system there are 2 options to install PowerDNS, from [EPEL](https://fedoraproject.org/wiki/EPEL) or the [repository from Kees Monshouwer](https://www.monshouwer.eu/download/3rd_party/pdns-recursor/). Add either to your list of reposities and install PowerDNS by issueing:

`# yum install pdns`

The different backends can be installed using

`# yum install pdns-backend-$backend`


### FreeBSD
PowerDNS Authoritative Server is available through the [ports](http://www.freshports.org/dns/powerdns/) system:

For the package:

`# pkg install dns/powerdns`

To have your system build the port:
`cd /usr/ports/dns/powerdns/ && make install clean`

### Mac OS X
PowerDNS Authoritative Server is available through Homebrew:

`$ brew install pdns`

## From source
See the [Compiling PowerDNS](../appendix/compiling-powerdns.md) chapter
