Some notes on running and extending the recursor tests

SYSTEM CONFIG
-------------

The recursor regression suite requires a series of available IPs to bind to.

Debian/Ubuntu example:

    $ grep -w lo /etc/network/interfaces 
    auto lo
    iface lo inet loopback
        up /sbin/ip addr add 10.0.3.0/24 dev lo

The suite also requires `bind()` access to port 53. The example config
relies on authbind for this:

    $ ls -al /etc/authbind/byport/53
    -rwxr-xr-x 1 you you 0 May 31  2012 /etc/authbind/byport/53

Note that this file needs to be executable by the user you run as for
authbind to work!

Other dependencies: daemontools, lua-posix

SETTING UP
----------

Copy `vars.sample` to `vars`

    $ cp vars.sample vars

Edit `vars`:

The /24 to bind the various daemons in:

    PREFIX=10.0.3

How to run the auth server (usually no need to change this):

    AUTHRUN="exec authbind ../../../pdns/pdns_server --config-dir=. > logfile 2>&1"

How to run the recursor (usually, again, no need to change this):

    RECRUN="exec authbind ../../../pdns/recursordist/pdns_recursor --config-dir=. --socket-dir=. --daemon=no --trace=yes --dont-query= --local-address=$PREFIX.9 --hint-file=hintfile --packetcache-ttl=0 --max-cache-ttl=15 --threads=1 > logfile 2>&1"


RUNNING
-------

Write out the various configuration files, create the service dirs (this uses
`vars`):

    $ ./config.sh

Start all daemons:

    $ ./start.sh

Check that they are all up:

    $ svstat configs/*
    configs/10.0.3.10: up (pid 1145) 13 seconds
    configs/10.0.3.11: up (pid 1141) 13 seconds
    configs/10.0.3.12: up (pid 1137) 13 seconds
    ...
    configs/10.0.3.8: up (pid 1138) 13 seconds
    configs/recursor-service: up (pid 1140) 13 seconds

(They all need to be up more than a few seconds; otherwise, they might be
crashing on startup. Check the per-service `logfile` if something is wrong).

Run the tests:

    $ ./runtests

Various things might go wrong the first time you run the tests. Correct them
and try again. If you think you have fixed everything and you still have some
tests failing (most importantly the ghost-* tests), run `svc -t configs/*` and
try again.

Eventually:

    12 out of 12 (100.00%) tests passed, 0 were skipped

CLEANING UP 
-----------

Stop all daemons:

    $ ./stop.sh

Remove config dirs:

    $ ./clean.sh

ADDING TESTS
------------

The testing setup consists of one recursor (at .9), one auth for our fake root
zone (at .8) and another bunch of auths for deeper zones (at .10 and up).

`config.sh` creates all the daemon configs, zonefiles, and, where necessary,
Lua prequery scripts to emulate behaviour that `pdns_server` cannot produce
natively.

Figure out whether your new test needs another zone, and edit config.sh accordingly.

Create a new directory for your test. It should at least have `command` (don't forget
chmod +x), `description`, and an `expected_result` file (often empty at this stage).

When you have that set up, run `./runtests` again. Your test will fail; check the
`real_result` file. If it looks alright, copy it to `expected_result`.

Congratulations, you have just written a test!
