OCSP Stapling
=============

dnsdist supports OCSP stapling for DNS over HTTPS and DNS over TLS since 1.4.0-rc1. OCSP, Online Certificate Status Protocol (:rfc:`6960`) is a protocol allowing a client to check the expiration status of a certificate from the certification authority (CA) that delivered it.
Since the requirement for the client to first retrieve the certificate then do additional steps to gather an OCSP response is not very efficient, and also discloses to the CA which certificate is validated, a mechanism has been designed to allow the server to retrieve the OCSP response from the CA and provide it to the client during the TLS exchange. This mechanism is named the TLS Certificate Status Request extension (:rfc:`6066`), also known as OCSP stapling.

While OCSP stapling is a net win for the client, it means that the server needs to retrieve the OCSP response itself and update it at regular interval, since the OCSP response tends to be short-lived by design.

dnsdist, as for example haproxy, only supports loading the OCSP response from a file, and has no embedded HTTP client to retrieve the OCSP response and refresh it, leaving it to the administrator to regularly retrieve the OCSP response and feed it to dnsdist.

Local PKI
---------

When a local PKI is used to issue the certificate, or for testing purposes, dnsdist provides the :func:`generateOCSPResponse` function to generate an OCSP response file for a certificate, using the certificate and private key of the certification authority that signed that certificate:

.. code-block:: lua

    generateOCSPResponse(pathToServerCertificate, pathToCACertificate, pathToCAPrivateKey, outputFile, numberOfDaysOfValidity, numberOfMinutesOfValidity)

The resulting file can be directly used with the :func:`addDOHLocal` or the :func:`addTLSLocal` functions:

.. code-block:: lua

    addDOHLocal("127.0.0.1:443", "/path/to/the/server/certificate", "/path/to/the/server/private/key", { "/" }, { ocspResponses={"/path/to/generated/ocsp/response"}})
    addTLSLocal("127.0.0.1:853", "/path/to/the/server/certificate", "/path/to/the/server/private/key", { ocspResponses={"/path/to/generated/ocsp/response"}})

After starting dnsdist, it is possible to update the OCSP response by connecting to the :ref:`console<Console>`, generating a new OCSP response and calling :func:`reloadAllCertificates` so that dnsdist reloads the certificates, keys and OCSP responses associated to the DNS over TLS and DNS over HTTPS contexts.

Certificate signed by an external authority
-------------------------------------------

When the certificate has been signed by an external certification authority, the process is a bit more complicated because the OCSP needs to be retrieved from that CA, and there are very few options available to do that at the moment.

One of those options is to the use the OpenSSL ocsp command-line tool, although it's a bit cumbersome to use.

The first step is to retrieve the URL at which the CA provides an OCSP responder. This can be done via the OpenSSL x509 command:

.. code-block:: sh

    openssl x509 -noout -ocsp_uri -in /path/to/the/server/certificate

It will output something like "http://ocsp.int-x3.letsencrypt.org".

Now we can use the OCSP tool to request an OCSP response for this certificate from the CA, provided that we have the certificate of the CA at hand, but it's usually needed to get a correct chain of certificates anyway:

.. code-block:: sh

    openssl ocsp -issuer /path/to/the/ca/certificate -cert /path/to/the/server/certificate -text -url url/we/retrieved/earlier -respout /path/to/write/the/OCSP/response

If everything goes well, this results in an OCSP response for the server certificate being written to /path/to/write/the/OCSP/response. It seems that earlier versions of OpenSSL did not properly handle the URL, and one needed to split the host and path parts of the OCSP URL, and use the ``-header`` option of the ocsp command:

.. code-block:: sh

    openssl ocsp -issuer /path/to/the/ca/certificate -cert /path/to/the/server/certificate -text -url <path> -header 'Host' <host> -respout /path/to/write/the/OCSP/response

We can now use it directly with the :func:`addDOHLocal` or the :func:`addTLSLocal` functions:

.. code-block:: lua

    addDOHLocal("127.0.0.1:443", "/path/to/the/server/certificate", "/path/to/the/server/private/key", { "/" }, { ocspResponses={"/path/to/write/the/OCSP/response"}})
    addTLSLocal("127.0.0.1:853", "/path/to/the/server/certificate", "/path/to/the/server/private/key", { ocspResponses={"/path/to/write/the/OCSP/response"}})

Since this response will be only valid for a while, a script needs to be written to retrieve it regularly via ``cron`` or any other mechanism. Once the new response has been retrieved, it is possible to tell dnsdist to reload it by connecting to the :ref:`console<Console>` and calling :func:`reloadAllCertificates` so that it reloads the certificates, keys and OCSP responses associated to the DNS over TLS and DNS over HTTPS contexts.

Testing
-------

Once a valid OCSP response has retrieved and loaded into dnsdist, it is possible to test that everything is working fine using the OpenSSL s_client command:

.. code-block:: sh

    openssl s_client -connect <IP:port> -status -servername <SNI name to use> | grep -F 'OCSP Response Status'

should return something like ``OCSP Response Status: successful (0x0)``, indicating that the client received a valid OCSP stapling response from the server.
