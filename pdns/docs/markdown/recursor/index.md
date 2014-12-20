# PowerDNS Recursor
The PowerDNS recursor is part of the source tarball of the main PowerDNS distribution, but it is released separately. Starting from the version 3.0 pre-releases, there are zero known bugs or issues with the recursor. It is known to power the resolving needs of over 100 million internet connections.

The documentation is only for the 3.0 series, users of older versions are urged to upgrade!

## Notable features:
-   Uses [MTasker](http://ds9a.nl/mtasker)
-   Can handle thousands of concurrent questions. A quad Xeon 3GHz has been measured functioning very well at 40000 real life replayed packets per second, with 40% cpu idle. More testing equipment is needed to max out the recursor.
-   Powered by a highly modern DNS packet parser that should be resistant against many forms of buffer overflows.
-   Best spoofing protection that we know about, involving both source port randomisation and spoofing detection.
-   Uses 'connected' UDP sockets which allow the recursor to react quickly to unreachable hosts or hosts for which the server is running, but the nameserver is down. This makes the recursor faster to respond in case of misconfigured domains, which are sadly very frequent.
-   Special support for FreeBSD, Linux and Solaris stateful multiplexing (kqueue, epoll, completion ports, /dev/poll).
-   Very fast, and contains innovative query-throttling code to save time talking to obsolete or broken nameservers.
-   Code is written linearly, sequentially, which means that there are no problems with 'query restart' or anything.
-   Relies heavily on Standard C++ Library infrastructure, which makes for little code (406 core lines).
-   Is very verbose in showing how recursion actually works, when enabled to do so with --verbose.
-   The algorithm is simple and quite nifty.

The PowerDNS recursor is controlled and queried using the `rec_control` tool.

## Configuration
At startup, the recursing nameserver reads the file `recursor.conf` from the configuration directory, often `/etc/powerdns` or `/usr/local/etc`. Each setting can appear on the command line, prefixed by '--', or in the configuration file. The command line overrides the configuration file.

A switch can be set to on simply by passing it, like '--daemon', and turned off explicitly by '--daemon=off' or '--daemon=no'.

All settings can be found [here](settings.md)

# `pdns_recursor` command line
All configuration settings from the previous section can also be passed on the command line, and will override the configuration file. In addition, the following options make sense on the command line:

* --config: Emit a default configuration file.
* --help: Output all configuration settings and command line flags.
