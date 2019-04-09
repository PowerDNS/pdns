jsonstat endpoint
=================

.. http:get:: /jsonstat

  Get statistics from recursor in JSON format.
  The ``Accept`` request header is ignored.
  This endpoint accepts a ``command`` and ``name`` query for different statistics:

  * ``get-query-ring``: Retrieve statistics from the query subsection. ``name`` can be ``servfail-queries`` or ``queries``. Supports optional argument ``public-filtered`` which if set to any value will group queries by the public suffix list.
  * ``get-remote-ring``: Retrieve statistics from the remotes subsection. ``name`` can be ``remotes``, ``servfail-remotes``, ``bogus-remotes`` (added in 4.2.0), ``large-answer-remotes``, or ``timeouts`` (added in 4.2.0).

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-query-ring&name=servfail-queries HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript
      X-API-Key: examplekey

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 94
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.1.11
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[2, "wpad.americas.hpecorp.net", "A"], [1, "wpad.americas.hpecorp.net", "AAAA"]]}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-query-ring&name=queries HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript
      X-API-Key: examplekey

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 69
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.1.11
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[1, "a.powerdns.com", "A"], [1, "b.powerdns.com", "A"]]}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-query-ring&name=queries&public-filtered=true HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript
      X-API-Key: examplekey

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 39
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.1.11
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[2, "powerdns.com", "A"]]}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=remotes HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript
      X-API-Key: examplekey

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 62
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.1.11
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[11, "10.0.2.15"], [7, "::1"], [4, "127.0.0.1"]]}

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 43
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.1.11
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[2, "::1"], [1, "127.0.0.1"]]}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=bogus-remotes HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript
      X-API-Key: examplekey

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 32
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.2.0-alpha1
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[20, "127.0.0.1"]]}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=servfail-remotes HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript
      X-API-Key: examplekey

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 31
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.1.11
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[4, "127.0.0.1"]]}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=large-answer-remotes HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript
      X-API-Key: examplekey

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 43
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.1.11
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[2, "127.0.0.1"], [1, "::1"]]}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=timeouts HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript
      X-API-Key: examplekey

  **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Access-Control-Allow-Origin: *
      Connection: close
      Content-Length: 189
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Server: PowerDNS/4.2.0-alpha1
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"entries": [[3, "15.219.145.20"], [3, "15.211.192.20"], [2, "15.219.160.20"], [2, "15.203.224.20"], [2, "15.219.145.21"], [2, "15.219.160.21"], [2, "15.211.192.21"], [2, "15.203.224.21"]]}
