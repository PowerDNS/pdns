pdns_server
===========

Synopsis
--------

:program:`pdns_server` [*OPTION*]

Description
-----------

The PowerDNS Authoritative Server is a versatile nameserver which
supports a large number of backends. These backends can either be plain
zone files or be more dynamic in nature. Please see the online
documentation for more information.

Options
-------

See the online documentation for all options. The most important ones are:

--daemon                Indicate if the server should run in the background as a real
                        daemon, or in the foreground.
--guardian              Run :program:`pdns_server` inside a guardian. This guardian monitors the
                        performance of the inner :program:`pdns_server` instance. It is also this
                        guardian that :program:`pdns_control` talks to.
--control-console       Run the server in a special monitor mode. This enables detailed
                        logging and exposes the raw control socket.
--loglevel=<LEVEL>      Set the logging level.
--config                Show the current configuration. There are three optional values:

                        --config=default       show the default configuration.
                        --config=diff          show modified options in the current configuration.
                        --config=check         parse the current configuration, with error checking.
--help                  Display the list of all the available options.

See also
--------

pdns_control(1), pdnsutil(1), `<https://doc.powerdns.com/>`__
