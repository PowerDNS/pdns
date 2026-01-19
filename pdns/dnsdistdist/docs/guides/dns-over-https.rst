DNS-over-HTTPS (DoH)
====================

.. note::
  This guide is about DNS over HTTP/1 and DNS over HTTP/2. For DNS over HTTP/3, please see :doc:`dns-over-http3`

:program:`dnsdist` supports DNS-over-HTTPS (DoH, standardized in RFC 8484) for incoming queries since 1.4.0, and for outgoing queries since 1.7.0.
To see if the installation supports this, run ``dnsdist --version``.
If the output shows ``dns-over-https(DOH)`` (``dns-over-https(nghttp2)`` since 1.9.0) , incoming DNS-over-HTTPS is supported. If ``outgoing-dns-over-https(nghttp2)`` shows up then outgoing DNS-over-HTTPS is supported.

Incoming
--------

Adding a listen port for DNS-over-HTTPS can be done with the :func:`addDOHLocal` function, e.g.::

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key')

This will make :program:`dnsdist` listen on [2001:db8:1:f00::1]:443 on TCP, and will use the provided certificate and key to serve incoming TLS connections.

In order to support multiple certificates and keys, for example an ECDSA and an RSA one, the following syntax may be used instead::

  addDOHLocal('2001:db8:1:f00::1', {'/etc/ssl/certs/example.com.rsa.pem', '/etc/ssl/certs/example.com.ecdsa.pem'}, {'/etc/ssl/private/example.com.rsa.key', '/etc/ssl/private/example.com.ecdsa.key'})

The certificate chain presented by the server to an incoming client will then be selected based on the algorithms this client advertised support for.

A fourth parameter may be added to specify the URL path(s) used by DoH. If you want your DoH server to handle ``https://example.com/dns-query-endpoint``, you have to add ``"/dns-query-endpoint"`` to
the call to :func:`addDOHLocal`. It is optional and defaults to ``/`` in 1.4.0, and ``/dns-query`` since 1.5.0.

The fifth parameter, if present, indicates various options. For instance, you use it to indicate custom HTTP headers. An example is::

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', "/dns", {customResponseHeaders={["x-foo"]="bar"}})

A more complicated (and more realistic) example is when you want to indicate metainformation about the server, such as the stated policy (privacy statement and so on). We use the link types of RFC 8631::

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', "/", {customResponseHeaders={["link"]="<https://example.com/policy.html> rel=\\"service-meta\\"; type=\\"text/html\\""}})

Or in ``yaml``:

.. code-block:: yaml

  - listen_address: "2001:db8:1:f00::1"
    protocol: "DoH"
    tls:
      certificates:
        - certificate: "/etc/ssl/certs/example.com.pem"
          key: "/etc/ssl/private/example.com.key"
    doh:
      provider: "nghttp2"
      paths:
        - "/"
      custom_response_headers:
        - key: "link"
          value: "<https://example.com/policy.html> rel=\\"service-meta\\"; type=\\"text/html\\""


A particular attention should be taken to the permissions of the certificate and key files. Many ACME clients used to get and renew certificates, like CertBot, set permissions assuming that services are started as root, which is no longer true for dnsdist as of 1.5.0. For that particular case, making a copy of the necessary files in the /etc/dnsdist directory is advised, using for example CertBot's ``--deploy-hook`` feature to copy the files with the right permissions after a renewal.

More information about sessions management can also be found in :doc:`../advanced/tls-sessions-management`.

Advertising DNS over HTTP/3 support
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If DNS over HTTP/3 is also enabled in the configuration via :func:`addDOH3Local` (see :doc:`dns-over-http3` for more information), it might be useful to advertise this support via the ``Alt-Svc`` header::

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', "/dns", {customResponseHeaders={["alt-svc"]="h3=\":443\""}})

This will advertise that HTTP/3 is available on the same IP, port UDP/443.

Custom responses
^^^^^^^^^^^^^^^^

It is also possible to set HTTP response rules to intercept HTTP queries early, before the DNS payload, if any, has been processed, to send custom responses including error pages, redirects or even serve static content. First a rule needs to be defined using :func:`newDOHResponseMapEntry`, then a set of rules can be applied to a DoH frontend via :meth:`DOHFrontend:setResponsesMap`.
For example, to send an HTTP redirect to queries asking for ``/rfc``, the following configuration can be used::

  map = { newDOHResponseMapEntry("^/rfc$", 307, "https://www.rfc-editor.org/info/rfc8484") }
  dohFE = getDOHFrontend(0)
  dohFE:setResponsesMap(map)

DNS over HTTP
^^^^^^^^^^^^^

In case you want to run DNS-over-HTTPS behind a reverse proxy you probably don't want to encrypt your traffic between reverse proxy and dnsdist.
To let dnsdist listen for DoH queries over HTTP on localhost at port 8053 add one of the following to your config::

  addDOHLocal("127.0.0.1:8053")
  addDOHLocal("127.0.0.1:8053", nil, nil, "/", { reusePort=true })

HTTP/1 support
^^^^^^^^^^^^^^

dnsdist initially relied on the ``h2o`` library to support incoming DNS over HTTPS. Since 2.1.0, ``h2o`` is no longer in use and ``nghttp2`` is the
preferred library for incoming DoH support, because ``h2o`` has unfortunately really never been maintained in a way that is suitable for use as a library
(see https://github.com/h2o/h2o/issues/3230). While we took great care to make the migration as painless as possible, ``h2o`` supported HTTP/1 while ``nghttp2``
does not. This is not an issue for actual DNS over HTTPS clients that support HTTP/2, but might be one in setups running dnsdist behind a reverse-proxy that
does not support HTTP/2, like nginx. We do not plan on implementing HTTP/1, and recommend using HTTP/2 between the reverse-proxy and dnsdist for performance reasons.

For nginx in particular, a possible work-around is to use the `grpc_pass <https://nginx.org/r/grpc_pass>`_ directive as suggested in their `bug tracker <https://trac.nginx.org/nginx/ticket/1875>`_ e.g.::

  location /dns-query {
    set $upstream_app dnsdist;
    set $upstream_port 443;
    set $upstream_proto grpcs;
    grpc_pass $upstream_proto://$upstream_app:$upstream_port;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Protocol $scheme;
    proxy_set_header Range $http_range;
    proxy_set_header If-Range $http_if_range;
  }

Internal design
^^^^^^^^^^^^^^^

The internal design used for DoH handling uses two threads per :func:`addDOHLocal` directive. The first thread will handle the HTTP/2 communication with the client and pass the received DNS queries to a second thread which will apply the rules and pass the query to a backend, over **UDP** (except if the backend is TCP-only, or uses DNS over TLS, see the second schema below). The response will be received by the regular UDP response handler for that backend and passed back to the first thread. That allows the first thread to be low-latency dealing with TLS and HTTP/2 only and never blocking.

.. figure:: ../imgs/DNSDistDoH.png
   :align: center
   :alt: DNSDist DoH design before 1.7

The fact that the queries are forwarded over UDP means that a large UDP payload size should be configured between dnsdist and the backend to avoid most truncation issues, and dnsdist will advise a 4096-byte UDP Payload Buffer size. UDP datagrams can still be larger than the MTU as long as fragmented datagrams are not dropped on the path between dnsdist and the backend.
Since 1.7.0, truncated answers received over UDP for a DoH query will lead to a retry over TCP, passing the query to a TCP worker, as illustrated below.

.. figure:: ../imgs/DNSDistDoH17.png
   :align: center
   :alt: DNSDist DoH design since 1.7

Investigating issues
^^^^^^^^^^^^^^^^^^^^

dnsdist provides a lot of counters to investigate issues:

 * :func:`showTCPStats` will display a lot of information about current and passed connections
 * :func:`showTLSErrorCounters` some metrics about why TLS sessions failed to establish
 * :func:`showDOHResponseCodes` returns metrics about HTTP response codes sent by dnsdist

Outgoing
--------

:program:`dnsdist` also supports outgoing DNS-over-HTTPS since 1.7.0. This way, all queries, regardless of whether they were initially received by dnsdist over UDP, TCP, DoT or DoH, are forwarded to the backend over a secure DNS-over-HTTPS channel.
Such that support can be enabled via the ``dohPath`` parameter of the :func:`newServer` command. Additional parameters control the TLS provider used (``tls``), the validation of the certificate presented by the backend (``caStore``, ``validateCertificates``), the actual TLS ciphers used (``ciphers``, ``ciphersTLS13``) and the SNI value sent (``subjectName``).

.. code-block:: lua

  newServer({address="[2001:DB8::1]:443", tls="openssl", subjectName="doh.powerdns.com", dohPath="/dns-query", validateCertificates=true})

.. code-block:: yaml

  backends:
    - address: "127.0.0.1:%d"
      protocol: "DoH"
      tls:
        provider: "openssl"
        validate_certificate: true
        subject_name: "doh.powerdns.com"
      doh:
        path: "/dns-query"


Internal design
^^^^^^^^^^^^^^^

The incoming queries, after the processing of rules if any, are passed to one of the DoH workers over a pipe. The DoH worker handles the communication with the backend, retrieves the response, and either responds directly to the client (queries coming over UDP) or pass it back over a pipe to the initial thread (queries coming over TCP, DoT or DoH).
The number of outgoing DoH worker threads can be configured using :func:`setOutgoingDoHWorkerThreads`.

.. figure:: ../imgs/DNSDistOutgoingDoH.png
   :align: center
   :alt: DNSDist outgoing DoH design
