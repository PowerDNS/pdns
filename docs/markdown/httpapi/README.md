PowerDNS API
============

PowerDNS features a built-in API. For the Authoritative Server, starting with
version 3.4, for the Recursor starting with version 3.6.

The released versions use the standard webserver password for authentication,
while newer versions use a static API key mechanism (shown below).

Try it
------

Install PowerDNS Authoritative with one of the gsql backends (i.e. MySQL,
PostgreSQL or SQLite3).

Then configure as follows:

    api=yes
    api-key=changeme
    webserver=yes


After restarting `pdns_server`, the following examples should start working:

    # List zones
    curl -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost/zones | jq .
    
    # Create new zone "example.org" with nameservers ns1.example.org, ns2.example.org
    curl -X POST --data '{"name":"example.org.", "kind": "Native", "masters": [], "nameservers": ["ns1.example.org.", "ns2.example.org."]}' -v -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost/zones | jq .
    
    # Show the new zone
    curl -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost/zones/example.org. | jq .
    
    # Add a new record to the new zone (would replace any existing test.example.org/A records)
    curl -X PATCH --data '{"rrsets": [ {"name": "test.example.org.", "type": "A", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": "192.0.5.4", "disabled": false } ] } ] }' -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost/zones/example.org. | jq .

    # Combined replacement of multiple RRsets
    curl -X PATCH --data '{"rrsets": [
      {"name": "test1.example.org.",
       "type": "A",
       "ttl": 86400,
       "changetype": "REPLACE",
       "records": [ {"content": "192.0.2.5", "disabled": false} ]
      },
      {"name": "test2.example.org.",
       "type": "AAAA",
       "ttl": 86400,
       "changetype": "REPLACE",
       "records": [ {"content": "2001:db8::6/32", "disabled": false} ]
      }
      ] }' -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost/zones/example.org. | jq .

`jq` is a highly recommended tool for pretty-printing JSON. If you don't have
`jq`, try `json_pp` or `python -mjson.tool` instead.

When running multiple instances you might want to specify on which address the web server should run:

    # IP Address of web server to listen on
    webserver-address=127.0.0.1
    # Port of web server to listen on
    webserver-port=8081
    # Web server access is only allowed from these subnets
    webserver-allow-from=0.0.0.0/0,::/0

Try it (Recursor edition)
-------------------------

Install PowerDNS Recursor, configured as follows:

    webserver=yes
    api-key=changeme
    auth-zones=
    forward-zones=
    forward-zones-recurse=


After restarting `pdns_recursor`, the following examples should start working:

    curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8082/api/v1/servers/localhost | jq .
    curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8082/api/v1/servers/localhost/zones | jq .


API Specification
-----------------

The complete API docs are available in [`api_spec.md`](http://doc.powerdns.com/md/httpapi/api_spec/).


Additional help
---------------

For additional help, come to the `#powerdns` IRC channel on `irc.oftc.net`.


Examples (Authoritative Server)
===============================

Show zone information and records
---------------------------------

    curl -H 'X-API-Key: changeme' \
        http://127.0.0.1:8081/api/v1/servers/localhost/zones/example.org. | jq .

Response:

    {
      "id": "example.org.",
      "url": "api/v1/servers/localhost/zones/example.org.",
      "name": "example.org.",
      "kind": "Master",
      "dnssec": false,
      "account": "",
      "masters": [],
      "serial": 2015120401,
      "notified_serial": 0,
      "last_check": 0,
      "soa_edit_api": "",
      "soa_edit": "",
      "rrsets": [
        {
          "comments": [],
          "name": "example.org.",
          "records": [
            {
              "content": "ns2.example.org.",
              "disabled": false
            },
            {
              "content": "ns1.example.org.",
              "disabled": false
            }
          ],
          "ttl": 86400,
          "type": "NS"
        },
        {
          "comments": [],
          "name": "example.org.",
          "type": "SOA",
          "ttl": 86400,
          "records": [
            {
              "disabled": false,
              "content": "ns1.example.org. hostmaster.example.org. 2015120401 10800 15 604800 10800"
            }
          ]
        },
        {
          "comments": [],
          "name": "ns1.example.org.",
          "type": "A",
          "ttl": 86400,
          "records": [
            {
              "content": "192.168.0.1",
              "disabled": false
            }
          ]
        },
        {
          "comments": [],
          "name": "www.example.org.",
          "type": "A",
          "ttl": 86400,
          "records": [
            {
              "disabled": false,
              "content": "192.168.0.2"
            }
          }
        }
      ]
    }


Replace ns1.example.org
-----------------------

Based on the example.org zone above, replace the ns1.example.org A record with
192.0.2.5:

    curl -X PATCH --data '{"rrsets": [{
      "name": "ns1.example.org.",
      "type": "A",
      "changetype": "REPLACE",
      "records": [ {
        "content": "192.0.2.5",
        "disabled": false,
        "name": "ns1.example.org.",
        "ttl": 86400,
        "type": "A"
      }]
    }]}' -H 'X-API-Key: changeme' \
    http://127.0.0.1:8081/api/v1/servers/localhost/zones/example.org. | jq .

Response:

    {
      "id": "example.org.",
      ...
      "records": [
        {
          "name": "ns1.example.org.",
          "type": "A",
          "ttl": 86400,
          "disabled": false,
          "content": "192.0.2.5"
        },
        ...
      ],
      ...
    }
