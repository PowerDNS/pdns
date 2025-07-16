These tests can be used to verify standards compliance of PowerDNS and to
spot regressions.

Dependencies
------------
We need very recent versions of:

 * validns (https://www.validns.net/)
 * ldns-verify-zone (part of ldns)
 * jdnssec-verifyzone (https://github.com/dblacka/jdnssec-tools)
 * named-checkzone (part of BIND9)
 * unbound-host (part of unbound)
 * drill (part of ldns)

Nice to have:
 * godns q

If you omit the tools above, some tests fail, but you can still run the
tests. 



Automated tests
---------------

Make sure PowerDNS is built with suitable modules, and use:

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

---

If you used meson to build, export `PDNS_BUILD_PATH` and point it to your
build directory. Also make sure you configured with `-Dtools=true`, and have
built `pdns-auth`, `pdns-auth-util`, `zone2sql` and `sdig`.
Example for invoking the tests:

```sh
export PDNS_BUILD_PATH=/home/you/pdns/buildDir
./start-test-stop 5300 gmysql
```


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

(`mysql:5` and `mysql:8` work too. Version 8 may need `--default-authentication-plugin=mysql_native_password` at the end if your client is older.)

Postgres:
```sh
docker run -p 5432:5432 --rm -e POSTGRES_HOST_AUTH_METHOD=trust -d postgres
GPGSQLUSER=postgres PGHOST=127.0.0.1  ./start-test-stop 5300 gpgsql
```
