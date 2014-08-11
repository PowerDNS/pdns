# Installing PowerDNS
Installation of the PowerDNS Authoritative server on UNIX systems can be done in several ways:

  * Binary packages provided by your distribution
  * Using the statically linked binary packages provided on the [website](https://www.powerdns.com/downloads.html)
  * Compiling from source

Running PowerDNS on Microsoft Windows is unsupported from version 3.0 onward.

## Binary Packages
### Debian-based Systems
PowerDNS Authoritative Server is available through the [apt](https://packages.debian.org/stable/pdns-server) system.

*Note: In the current 'stable' (codenamed 'wheezy') version 3.1 is included, it is recommended you install version 3.3 from backports.*

`# apt-get install pdns-server`

Debian splits the backends into [several different packages](https://packages.debian.org/stable/pdns-backend), install the required backend as follows:

`# apt-get install pdns-backend-$backend`

Alternatively, a statically linked binary package is provided on the [powerdns.com](https://www.powerdns.com/downloads.html) website that can be downloaded and installed by issueing:

`# dpkg -i pdns-static_$version_$arch.deb`

### Redhat-based Systems
XXX

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

# Running PowerDNS
PDNS is normally controlled via a SysV-style init.d script, often located in `/etc/init.d` or `/etc/rc.d/init.d`. This script accepts the following commands:

`monitor`:
Monitor is a special way to view the daemon. It executes PDNS in the foreground with a lot of logging turned on, which helps in determining startup problems. Besides running in the foreground, the raw PDNS control socket is made available. All external communication with the daemon is normally sent over this socket. While useful, the control console is not an officially supported feature. Commands which work are: **QUIT**, **SHOW \***, **SHOW varname**, **RPING**.

`start`:
Start PDNS in the background. Launches the daemon but makes no special effort to determine success, as making database connections may take a while. Use **status** to query success. You can safely run **start** many times, it will not start additional PDNS instances.

`restart`:
Restarts PDNS if it was running, starts it otherwise.

`status`:
Query PDNS for status. This can be used to figure out if a launch was successful. The status found is prefixed by the PID of the main PDNS process.

`stop`:
Requests that PDNS stop. Again, does not confirm success. Success can be ascertained with the **status** command.

`dump`:
Dumps a lot of statistics of a running PDNS daemon. It is also possible to single out specific variable by using the **show** command.

`show variable`:
Show a single statistic, as present in the output of the **dump**.

`mrtg`:
See the performance [monitoring](logging.md#performance-monitoring) documentation.
