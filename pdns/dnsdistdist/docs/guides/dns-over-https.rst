DNS-over-HTTPS (DoH)
====================

:program:`dnsdist` supports DNS-over-HTTPS (DoH, standardized in RFC 8484).
To see if the installation supports this, run ``dnsdist --version``.
If the output shows ``dns-over-https(DOH)``, DNS-over-HTTPS is supported.

Adding a listen port for DNS-over-HTTPS can be done with the :func:`addDOHLocal` function, e.g.::

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key')

This will make :program:`dnsdist` listen on [2001:db8:1:f00::1]:443 on TCP, and will use the provided certificate and key to serve incoming TLS connections.

In order to support multiple certificates and keys, for example an ECDSA and an RSA one, the following syntax may be used instead::

  addDOHLocal('2001:db8:1:f00::1', {'/etc/ssl/certs/example.com.rsa.pem', '/etc/ssl/certs/example.com.ecdsa.pem'}, {'/etc/ssl/private/example.com.rsa.key', '/etc/ssl/private/example.com.ecdsa.key'})

The certificate chain presented by the server to an incoming client will then be selected based on the algorithms this client advertised support for.

A fourth parameter may be added to specify the URL path(s) used by
DoH. If you want your DoH server to handle
``https://example.com/dns-query``, you have to add ``"/dns-query"`` to
the call to :func:`addDOHLocal`. It is optional and defaults to ``/``, the root of your HTTP site.

The fifth parameter, if present, indicates various options. For
instance, you use it to indicate custom HTTP headers. An example is::

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', "/dns", {customResponseHeaders={["x-foo"]="bar"}}

A more complicated (and more realistic) example is when you want to indicate metainformation about the server, such as the stated policy (privacy statement and so on). We use the link types of RFC 8631::

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', "/", {customResponseHeaders={["link"]="<https://example.com/policy.html> rel=\\"service-meta\\"; type=\\"text/html\\""}})

In case you want to run DNS-over-HTTPS behind a reverse proxy you probably don't want to encrypt your traffic between reverse proxy and dnsdist.
To let dnsdist listen for DoH queries over HTTP on localhost at port 8053 add one of the following to your config::

  addDOHLocal("127.0.0.1:8053")
  addDOHLocal("127.0.0.1:8053", nil, nil, "/", { reusePort=true })

A particular attention should be taken to the permissions of the certificate and key files. Many ACME clients used to get and renew certificates, like CertBot, set permissions assuming that services are started as root, which is no longer true for dnsdist as of 1.5.0. For that particular case, making a copy of the necessary files in the /etc/dnsdist directory is advised, using for example CertBot's ``--deploy-hook`` feature to copy the files with the right permissions after a renewal.
