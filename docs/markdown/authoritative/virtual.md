# Virtual Hosting
It may be advantageous to run multiple separate PowerDNS installations on a
single host, for example to make sure that different customers cannot affect
each others zones. PowerDNS fully supports running multiple instances on one host.

To generate additional PowerDNS instances, copy the init.d script `pdns` to
`pdns-name`, where `name` is the name of your virtual configuration. Must not
contain a - as this will confuse the script.

When you launch PowerDNS via this renamed script, it will seek configuration
instructions not in `pdns.conf` but in `pdns-name.conf`, allowing for separate
specification of parameters.

Internally, the init script calls the binary with the
[`config-name`](settings.md#config-name) option set to `name`, setting in motion
the loading of separate configuration files.

When you launch a virtual instance of PowerDNS, the pid-file is saved inside
[`socket-dir`](settings.md#socket-dir) as `pdns-name.pid`.

**Warning**: Be aware however that the init.d `force-stop` will kill all
PowerDNS instances!

**Warning**: For systems running systemd, virtual hosting is not yet supported.
