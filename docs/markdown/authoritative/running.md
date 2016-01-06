# Running PowerDNS
PDNS is normally controlled via a SysV-style init.d script, often located in
`/etc/init.d` or `/etc/rc.d/init.d`. For Linux distributions with systemd, a
service file is provided (either in the package or in the contrib directory of
the tarball).

Furthermore, PowerDNS can be run on the foreground for testing or in other init-
systems that supervise processes.

# SysV init
This script supplied with the PowerDNS source accepts the following commands:

* `monitor`: Monitor is a special way to view the daemon. It executes PDNS in the foreground with a lot of logging turned on, which helps in determining startup problems. Besides running in the foreground, the raw PDNS control socket is made available. All external communication with the daemon is normally sent over this socket. While useful, the control console is not an officially supported feature. Commands which work are: `QUIT`, [`SHOW *`](internals.md#show-variable), `SHOW varname`, [`RPING`](internals.md#rping).
* `start`: Start PDNS in the background. Launches the daemon but makes no special effort to determine success, as making database connections may take a while. Use `status` to query success. You can safely run `start` many times, it will not start additional PDNS instances.
* `restart`: Restarts PDNS if it was running, starts it otherwise.
* `status`: Query PDNS for status. This can be used to figure out if a launch was successful. The status found is prefixed by the PID of the main PDNS process.
* `stop`: Requests that PDNS stop. Again, does not confirm success. Success can be ascertained with the `status` command.
* `dump`: Dumps a lot of statistics of a running PDNS daemon. It is also possible to single out specific variable by using the `show` command.
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
