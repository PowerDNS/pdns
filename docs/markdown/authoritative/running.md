# Running and Operating PowerDNS
PowerDNS is normally controlled via a SysV-style init.d script, often located in
`/etc/init.d` or `/etc/rc.d/init.d`. For Linux distributions with systemd, a
service file is provided (either in the package or in the contrib directory of
the tarball).

Furthermore, PowerDNS can be run on the foreground for testing or in other init-
systems that supervise processes.

## Guardian
When the init-system of the Operating System does not properly supervises processes,
like SysV init, it is recommended to run PowerDNS with the [`guardian`](settings.md#guardian)
option set to 'yes'.

When launched with `guardian=yes`, `pdns_server` wraps itself inside a 'guardian'.
This guardian monitors the performance of the inner `pdns_server` instance which
shows up in the process list of your OS as `pdns_server-instance`. It is also
this guardian that [`pdns_control`](#pdns_control) talks to. A **STOP** is
interpreted by the guardian, which causes the guardian to sever the connection
to the inner process and terminate it, after which it terminates itself. Requests
that require data from the actual nameserver are passed to the inner process as well.

# Controlling A Running PowerDNS Server
As a DNS server is critical infrastructure, downtimes should be avoided as much
as possible. Even though PowerDNS (re)starts very fast, it offers a way to
control it while running.

## Control Socket
The controlsocket is the means to contact a running PowerDNS process. Over this
socket, instructions can be sent using the `pdns_control` program. The control
socket is called `pdns.controlsocket` and is created inside the [`socket-dir`](settings.md#socket-dir).

## `pdns_control`
To communicate with PowerDNS Authoritative Server over the controlsocket, the
`pdns_control` command is used. The syntax is simple: `pdns_control command arguments`.
Currently this is most useful for telling backends to rediscover domains or to
force the transmission of notifications. See [Master Operation](../authoritative/modes-of-operation.md#master-operation).

For all supported `pdns_control` commands and options, see [the manpage](../manpages/pdns_control.1)
and the output of `pdns_control --help` on your system.

# The SysV init
This script supplied with the PowerDNS source accepts the following commands:

* `monitor`: Monitor is a special way to view the daemon. It executes PowerDNS in the foreground with a lot of logging turned on, which helps in determining startup problems. Besides running in the foreground, the raw PowerDNS control socket is made available. All external communication with the daemon is normally sent over this socket. While useful, the control console is not an officially supported feature. Commands which work are: `QUIT`, `SHOW *`, `SHOW varname`, `RPING`.
* `start`: Start PowerDNS in the background. Launches the daemon but makes no special effort to determine success, as making database connections may take a while. Use `status` to query success. You can safely run `start` many times, it will not start additional PowerDNS instances.
* `restart`: Restarts PowerDNS if it was running, starts it otherwise.
* `status`: Query PowerDNS for status. This can be used to figure out if a launch was successful. The status found is prefixed by the PID of the main PowerDNS process.
* `stop`: Requests that PowerDNS stop. Again, does not confirm success. Success can be ascertained with the `status` command.
* `dump`: Dumps a lot of statistics of a running PowerDNS daemon. It is also possible to single out specific variable by using the `show` command.
* `show variable`: Show a single statistic, as present in the output of the `dump`.
* `mrtg`: Dump statistics in mrtg format. See the performance [monitoring](../common/logging.md#performance-monitoring) documentation.

**Note**: Packages provided by Operating System vendors might support different
or less commands.

# Running in the foreground
One can run PowerDNS in the foreground by invoking the `pdns_server` executable.
Without any options, it will load the `pdns.conf` and run. To make sure PowerDNS
starts in the foreground, add the `--daemon=no` option.

All [settings](settings.md) can be added on the commandline. e.g. to test a new
database config, you could start PowerDNS like this:

```
pdns_server --no-config --daemon=no --local-port=5300 --launch=gmysql --gmysql-user=my_user --gmysql-password=mypassword
```

This starts PowerDNS without loading on-disk config, in the foreground, on all
network interfaces on port 5300 and starting the [gmysql](backend-generic-mysql.md)
backend.

## Commandline Parameters
There are several important command-line switches for `pdns_server`. All [settings](settings.md)
can also be added as a commandline option (e.g. `pdns_server --daemon=no`) and
will overwrite any options set in pdns.conf.

### `--help`
Outputs all known parameters, including those of launched backends, see below.

To run on the command line, use the `pdns_server` binary. For example, to see
options for the gpgsql backend, use the following:

```
      $ /usr/sbin/pdns_server --launch=gpgsql --help=gpgsql
```

### `--list-modules`
Will list all available modules, both compiled in and in dynamically loadable modules.

### `--config`
This will dump the config to standard out. Should you combine this with e.g. a
[`launch`](settings.md#launch) statement (`pdns_server --launch=gpgsql --config`),
all settings related to that backend (and their defaults) are included in the dump.

# Virtual Hosting
It may be advantageous to run multiple separate PowerDNS installations on a
single host, for example to make sure that different customers cannot affect
each others zones. PowerDNS fully supports running multiple instances on one host.

To generate additional PowerDNS instances, create a `pdns-NAME.conf` in your
configuration directory (usually `/etc/powerdns`), where `NAME` is the name of
your virtual configuration.

Following one of the following instructions, PowerDNS will read its configuration
from the `pdns-NAME.conf` instead of `pdns.conf`.

## Starting virtual instances with Sysv init-scripts
Symlink the init.d script `pdns` to `pdns-NAME`, where `NAME` is the name of your
virtual configuration. **Note**: `NAME` must not contain a '-' as this will
confuse the script.

Internally, the init script calls the binary with the
[`config-name`](settings.md#config-name) option set to `name`, setting in motion
the loading of separate configuration files.

When you launch a virtual instance of PowerDNS, the pid-file is saved inside
[`socket-dir`](settings.md#socket-dir) as `pdns-name.pid`.

**Warning**: Be aware however that the init.d `force-stop` will kill all
PowerDNS instances!

## Starting virtual instances with systemd
With systemd it is as simple as calling the correct service instance. Assuming your
instance is called `myinstance` and `pdns-myinstance.conf` exists in the configuration
directory, the following command will start the service:
```
systemctl start pdns@myinstance.service
```

Similarly you can enable it at boot:
```
systemctl enable pdns@myinstance.service
```

# Internals
## How PowerDNS translates DNS queries into backend queries
A DNS query is not a straightforward lookup. Many DNS queries need to check the
backend for additional data, for example to determine if an unfound record should
lead to an NXDOMAIN ('we know about this domain, but that record does not exist')
or an unauthoritative response.

Simplified, without CNAME processing, wildcards, referrals and DNSSEC, the
algorithm is like this:

When a query for a `qname`/`qtype` tuple comes in, PowerDNS queries backends to
find the closest matching SOA, thus figuring out what backend owns this zone.
When the right backend has been found, PowerDNS issues a `qname`/`ANY` query to
the backend. If the response is empty, NXDOMAIN is concluded. If the response is
not empty, any contents matching the original qtype are added to the list of
records to return, and NOERROR is set.

Each of these records is now investigated to see if it needs 'additional processing'.
This holds for example for MX records which may point to hosts for which the PowerDNS
backends also contain data. This involves further lookups for A or AAAA records.

After all additional processing has been performed, PowerDNS sieves out all
double records which may well have appeared. The resulting set of records is
added to the answer packet, and sent out.

A zone transfer works by looking up the `domain_id` of the SOA record of the
name and then listing all records of that `domain_id`. This is why all records
in a domain need to have the same domain\_id.

If no SOA was found, a REFUSED is returned.
