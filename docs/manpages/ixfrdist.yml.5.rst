ixfrdist.yml
============

Synopsis
--------

ixfrdist.yml

Description
-----------

:program:`ixfrdist` reads its configuration for a YAML file.
By default, this file is called `ixfrdist.yml` and is read from the directory configured as `SYSCONFDIR` when building the software.
This directory is usually one of `/etc/pdns`, `/etc/powerdns`.
Run `ixfrdist --help` to see the default.

Example
-------

.. code-block:: yaml

  listen:
    - 192.0.2.2
    - '[2001:DB8:ABCD::2]:5300'
    - 127.0.0.1

  acl:
    - 127.0.0.1
    - '192.0.2.0/24'
    - '2001:DB8:ABCD:1234::/64'

  work-dir: /var/lib/ixfrdist

  uid: ixfrdist
  gid: ixfrdist

  domains:
    - domain: example.com
      master: 192.0.2.18:5301
    - domain: example.net
      master: 2001:DB8:ABCD::2

Options
-------

:listen:
  The list of addresses to listen on.
  :program:`ixfrdist` listens on both TCP and UDP.
  When no port is specified, 53 is used. When specifying ports for IPv6, use the "bracket" notation.
  By default, :program:`ixfrdist` listens on ``127.0.0.1:53`` and ``[::1]:53``.

:acl:
  A list of netmasks that are allowed to query :program:`ixfrdist` and request AXFRs and IXFRs
  Entries without a netmask will be interpreted as a single address.
  By default, the ACL is set is ``127.0.0.0/8`` and ``::1/128``.

:axfr-max-records:
  Maximum number of records allowed in an AXFR transaction requested by :program:`ixfrdist`.
  This may prevent untrusted sources from using all the process memory.
  By default, this setting is ``0``, which means "unlimited".

:axfr-timeout:
  Timeout in seconds an AXFR transaction requested by :program:`ixfrdist` may take.
  Increase this when the network to the authoritative servers is slow or the domains are very large and you experience timeouts.
  Defaults to 20.

:failed-soa-retry:
  Time in seconds between retries of the SOA query for a zone we have never transferred. Defaults to 30.

:compress:
  Whether record compression should be enabled, leading to smaller answers at the cost of an increased CPU and memory usage.
  Defaults to false.

:work-dir:
  The directory where the domain data is stored.
  When not set, the current working directory is used.
  This working directory has the following structure: ``work-dir/ZONE/SERIAL``, e.g. ``work-dir/rpz.example./2018011902``.
  It is highly recommended to set this option, as the current working directory might change between invocations.
  This directory must be writable for the user or group :program:`ixfrdist` runs as.

:keep:
  Amount of older copies/IXFR diffs to keep for every domain.
  This is set to 20 by default.

:tcp-in-threads:
  Number of threads to spawn for TCP connections (AXFRs) from downstream hosts.
  This limits the number of concurrent AXFRs to clients.
  Set to 10 by default.

:gid:
  Group name or numeric ID to drop privileges to after binding the listen sockets.
  By default, :program:`ixfrdist` runs as the user that started the process.

:uid:
  User name or numeric ID to drop privileges to after binding the listen sockets.
  By default, :program:`ixfrdist` runs as the user that started the process.

:domains:
  A list of domains to redistribute.
  This option is mandatory.

  :domain: The domain name to transfer from the ``master``.
           Mandatory.
  :master: IP address of the server to transfer this domain from.
           Mandatory.

:webserver-address:
  IP address to listen on for the built-in webserver.
  When not set, no webserver is started.

:webserver-acl:
  A list of networks that are allowed to access the :program:`ixfrdist` webserver.
  Entries without a netmask will be interpreted as a single address.
  By default, this list is set to ``127.0.0.0/8`` and ``::1/128``.

:webserver-loglevel:
  How much the webserver should log: 'none', 'normal' or 'detailed'.
  When logging, each log-line contains the UUID of the request, this allows finding errors caused by certain requests.
  With 'none', nothing is logged except for errors.
  With 'normal' (the default), one line per request is logged in the style of the common log format::

    [NOTICE] [webserver] 46326eef-b3ba-4455-8e76-15ec73879aa3 127.0.0.1:57566 "GET /metrics HTTP/1.1" 200 1846

  with 'detailed', the full requests and responses (including headers) are logged along with the regular log-line from 'normal'.

See also
--------

:manpage:`ixfrdist(1)`
