These tests can be used to verify standards compliance of PowerDNS and to
spot regressions.

Dependencies
------------
We need very recent versions of:

 * validns (http://www.validns.net/)
 * ldns-verify-zone (part of ldns)
 * jdnssec-verifyzone (http://www.verisignlabs.com/dnssec-tools/)
 * named-checkzone (part of BIND9)
 * unbound-host (part of unbound)
 * drill (part of ldns)

Nice to have:
 * godns q

If you omit the tools above, some tests fail, but you can still run the
tests. 



Automated tests
---------------

For a more hands-off approach, make sure PowerDNS is built with suitable
modules, and use:

```sh
./start-test-stop 5300 gmysql
```

To start PowerDNS in gmysql mode (including DNSSEC), run all tests, and
write reports, using udp port 5300 in the process. Use:

```sh
./start-test-stop help
```

to see all available suites.

In addition to diff-files in all test dirs, start-test-stop generates a jUnit-
compatible XML report.

Manual testing
--------------

Start PowerDNS with `--no-shuffle` for best results - the 'too-big-udp' test
fails otherwise, for cosmetical reasons.

Method of operation
-------------------

Each directory contains a command that, when executed, process the 'cleandig'
output for the answer the nameserver sent. This output is stored in the file
`real_result`, and compared to `expected_result` or one of its replacement
files.

Then, `diff -u` is run on those two files, and the output sent to the file
`diff`. If everything is as it should be, this diff file is empty, and
PowerDNS passed the test.

Caveats
-------

Optional features of the DNS standard can cause a difference to arise. For
example, "Bind 8" appears to fail on nearly all our tests, whereas it is in
compliance (except for one case).

Study the diff output to be sure if there is a problem.

How to run
----------

See beyond this section for information on how to run automatically.

First make sure PowerDNS has access to the testing zones, which are all
referred in the `named.conf` file. Use the `zone2sql` tool to create SQL and
feed it to your database if you want to test one of the sql backends.

Run PowerDNS as (to test gmysql):

```sh
../pdns/pdns_server --daemon=no --local-port=5300 --socket-dir=./  \
--no-shuffle --launch=gmysql --gmysql-dbname=pdnstest --gmysql-user=root \
--fancy-records --query-logging --loglevel=9 \
--cache-ttl=0 --no-config
```

or (to test bind, without DNSSEC):
```sh
../pdns/pdns_server --daemon=no --local-port=5300 --socket-dir=./  \
--no-shuffle --launch=bind --bind-config=./named.conf                \
--fancy-records --query-logging --loglevel=9    \
--cache-ttl=0 --no-config
```

or (to test bind with DNSSEC):

```sh
./bind-dnssec-setup
../pdns/pdns_server --daemon=no --local-port=5300 --socket-dir=./  \
--no-shuffle --launch=bind --bind-config=./named.conf                \
--query-logging --loglevel=9                    \
--cache-ttl=0 --no-config
```

Or only sqlite3:
```sh
rm powerdns.sqlite3
sqlite3 powerdns.sqlite3 < ../pdns/no-dnssec.schema.sqlite3.sql
sqlite3 powerdns.sqlite3 < ../pdns/dnssec.schema.sqlite3.sql
../pdns/backends/bind/zone2sql --named-conf=./named.conf --gsqlite \
--transactions --dnssec | sqlite3 powerdns.sqlite3
echo 'analyze;' | sqlite3 powerdns.sqlite3

../pdns/pdns_server --daemon=no --local-port=5300 --socket-dir=./  \
--no-shuffle --launch=gsqlite3 \
--gsqlite3-database=./powerdns.sqlite3 --gsqlite3-dnssec             \
--query-logging --loglevel=9                    \
--cache-ttl=0 --no-config
```

Set the `nameserver` and `port` variables to point to your pdns\_server
instance:

```sh
nameserver=127.0.0.1 port=5300 ./runtests
```


Analysing results
-----------------

Failed tests appear in the file `failed_tests`, passed tests in
`passed_tests`. A complete log is in the file `log`. Examine the `diff`
files in all subdirectories to see what happened.


Debian Jessie notes
-------------------
On debian-jessie, most of these tools can be retrieved with:
```sh
sudo apt-get install validns ldnsutils bind9utils libnet-dns-perl
sudo apt-get -t jessie-backports install unbound-host libunbound2
```

libnet-dns-perl is needed for one dyndns test.

This does not install the jdnssec-verifyzone tools. The test that will break without that can be disabled with:
```sh
touch tests/verify-dnssec-zone/allow-missing
```

Getting required daemons from Docker
------------------------------------

Please keep in mind that databases may need a few seconds to start up.

'MySQL':
```sh
docker run -p 3306:3306 --rm -d -e MYSQL_ALLOW_EMPTY_PASSWORD=1 mariadb
GMYSQLHOST=127.0.0.1 ./start-test-stop 5300 gmysql
```

Postgres:
```sh
docker run -p 5432:5432 --rm -d postgres
GPGSQLUSER=postgres PGHOST=127.0.0.1  ./start-test-stop 5300 gpgsql
```
