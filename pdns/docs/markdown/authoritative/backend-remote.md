# Remote Backend
**Warning**: The Remote Backend is available since PowerDNS Authoritative Server 3.2. This backend is stable on version 3.3, not before.

| | |
|:--|:--|
|Native|Yes|
|Master|Yes\*|
|Slave|Yes\*|
|Superslave|Yes\*|
|Autoserial|Yes\*|
|DNSSEC|Yes\*|
|Multiple instances|Yes|

\* If provided by the responder (your script).

This backend provides unix socket / pipe / http remoting for powerdns. You should think this as normal RPC thin client, which converts native C++ calls into JSON/RPC and passes them to you via connector.

## Important notices
Please do not use remotebackend shipped before version 3.3. This version has severe bug that can crash the entire process.

## Compiling
To compile this backend, you need to configure `--with-modules="remote"`.

If you want to use http connector, you need libcurl and use `--enable-remotebackend-http`.

If you want to use ZeroMQ connector, you need libzmq-dev or libzmq3-dev and use `--enable-remotebackend-zeromq`.

## Usage
The only configuration options for backend are remote-connection-string and remote-dnssec.

```
remote-connection-string=<type>:<param>=<value>,<param>=<value>...
```

You can pass as many parameters as you want. For unix and pipe connectors, these are passed along to the remote end as initialization. See [Section 16.4, “API”](remotebackend.html#remotebackend-api "16.4. API"). Initialize is not called for http connector.

#### Unix connector

parameters: path, timeout (default 2000ms)

``` {.programlisting}
remote-connection-string=unix:path=/path/to/socket
```

#### Pipe connector

parameters: command,timeout (default 2000ms)

``` {.programlisting}
remote-connection-string=pipe:command=/path/to/executable,timeout=2000
```

#### HTTP connector

parameters: url, url-suffix, post, post\_json, cafile, capath, timeout (default 2000)

``` {.programlisting}
remote-connection-string=http:url=http://localhost:63636/dns,url-suffix=.php
```

HTTP connector tries to do RESTful requests to your server. See examples. You can also use post to change behaviour so that it will send POST request to url/method + url\_suffix with parameters=json-formatted-parameters. If you use post and post\_json, it will POST url with text/javascript containing JSON formatted RPC request, just like for pipe and unix. You can use '1', 'yes', 'on' or 'true' to turn these features on.

URL should not end with /, and url-suffix is optional, but if you define it, it's up to you to write the ".php" or ".json". Lack of dot causes lack of dot in URL. Timeout is divided by 1000 because libcurl only supports seconds, but this is given in milliseconds for consistency with other connectors.

You can use HTTPS requests. If cafile and capath is left empty, remote SSL certificate is not checked. HTTP Authentication is not supported. SSL support requires that your cURL is compiled with it.

#### ZeroMQ connector

parameters: endpoint, timeout (default 2000ms)

``` {.programlisting}
remote-connection-string=zmq:endpoint=ipc:///tmp/tmp.sock
```

0MQ connector implements a REQ/REP RPC model. Please see <http://zeromq.org/> for more information.

### 16.4. API

#### Queries

Unix and Pipe connector sends JSON formatted string to the remote end. Each JSON query has two sections, 'method' and 'parameters'.

HTTP connector calls methods based on URL and has parameters in the query string. Most calls are GET; see the methods listing for details. You can change this with post and post\_json attributes.

#### Replies

You \*must\* always reply with JSON hash with at least one key, 'result'. This must be boolean false if the query failed. Otherwise it must conform to the expected result. For HTTP connector, to signal bare success, you can just reply with HTTP 200 OK, and omit any output. This will result in same outcome as sending {"result":true}.

You can optionally add 'log' array, each line in this array will be logged in PowerDNS.

#### Methods

##### Method: initialize

Mandatory:  
Yes (except HTTP connector)

Parameters:  
all parameters in connection string

Reply:  
true on success / false on failure

Description  
Called to initialize the backend. This is not called for HTTP connector. You should do your initializations here.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"initialize", "parameters":{"command":"/path/to/something", "timeout":"2000", "something":"else"}}
```

Response:

``` {.programlisting}
{"result":true}
```

##### Method: lookup

Mandatory:  
Yes

Parameters:  
qtype, qname, zone\_id

Optional parameters:  
remote, local, real-remote

Reply:  
array of \<qtype,qname,content,ttl,domain\_id,priority,scopeMask,auth\>

Optional values:  
domain\_id, scopeMask and auth

Description  
This method is used to do the basic query. You can omit auth, but if you are using DNSSEC this can lead into trouble.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"lookup", "parameters":{"qtype":"ANY", "qname":"www.example.com", "remote":"192.168.0.24", "local":"192.168.0.1", "real-remote":"192.168.0.24", "zone-id":-1}}
```

Response:

``` {.programlisting}
{"result":[{"qtype":"A", "qname":"www.example.com", "content":"192.168.1.2", "ttl": 60}]}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
GET /dnsapi/lookup/www.example.com/ANY HTTP/1.1
X-RemoteBackend-remote: 192.168.0.24
X-RemoteBackend-local: 192.168.0.1
X-RemoteBackend-real-remote: 192.168.0.24
X-RemoteBackend-zone-id: -1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":[{"qtype":"A", "qname":"www.example.com", "content":"192.168.1.2", "ttl": 60}]}
```

##### Method: list

Mandatory:  
No (Gives AXFR support)

Parameters:  
zonename, domain\_id

Optional parameters:  
domain\_id

Reply:  
array of \<qtype,qname,content,ttl,domain\_id,priority,scopeMask,auth\>

Optional values:  
domain\_id, scopeMask and auth

Description  
Lists all records for the zonename. If you are running dnssec, you should take care of setting auth to appropriate value, otherwise things can go wrong.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"list", "parameters":{"zonename":"example.com","domain_id":-1}}
```

Response (split into lines for ease of reading)

``` {.programlisting}
{"result":[
  {"qtype":"SOA", "qname":"example.com", "content":"dns1.icann.org. hostmaster.icann.org. 2012081600 7200 3600 1209600 3600", "ttl": 3600},
  {"qtype":"NS", "qname":"example.com", "content":"ns1.example.com", "ttl": 60},
  {"qtype":"MX", "qname":"example.com", "content":"mx1.example.com.", "ttl": 60, "priority":10},
  {"qtype":"A", "qname":"www.example.com", "content":"192.168.1.2", "ttl": 60},
  {"qtype":"A", "qname":"ns1.example.com", "content":"192.168.0.2", "ttl": 60},
  {"qtype":"A", "qname":"mx1.example.com", "content":"192.168.0.3", "ttl": 60} 
]}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
GET /dnsapi/list/-1/example.com HTTP/1.1
X-RemoteBackend-domain-id: -1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":[{"qtype":"SOA", "qname":"example.com", "content":"dns1.icann.org. hostmaster.icann.org. 2012081600 7200 3600 1209600 3600", "ttl": 3600},{"qtype":"NS", "qname":"example.com", "content":"ns1.example.com", "ttl": 60},{"qtype":"MX", "qname":"example.com", "content":"mx1.example.com.", "ttl": 60, "priority":10},{"qtype":"A", "qname":"www.example.com", "content":"192.168.1.2", "ttl": 60},{"qtype":"A", "qname":"ns1.example.com", "content":"192.168.0.2", "ttl": 60},{"qtype":"A", "qname":"mx1.example.com", "content":"192.168.0.3", "ttl": 60}]}
```

##### Method: getBeforeAndAfterNamesAbsolute

Mandatory:  
for NSEC/NSEC3 non-narrow

Parameters:  
id, qname

Reply:  
before, after

Description  
Asks the names before and after qname. qname is given without dots or domain part. The query will be hashed when using NSEC3. Care must be taken to handle wrap-around when qname is first or last in the ordered list. Do not return nil for either one.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"getbeforeandafternamesabsolute", "params":{"id":0,"qname":"www.example.com"}}
```

Response:

``` {.programlisting}
{”result":{"before":"ns1","after":""}}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
/dnsapi/getbeforeandafternamesabsolute/0/www.example.com
```

Response:

``` {.programlisting}
{”result":{"before":"ns1","after":""}}
```

##### Method: getAllDomainMetadata

Mandatory:  
No

Parameters:  
name

Reply:  
hash of key to array of strings

Description  
Returns the value(s) for variable kind for zone name. You \*must\* always return something, if there are no values, you shall return empty set or false.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"getalldomainmetadata", "parameters":{"name":"example.com"}}
```

Response:

``` {.programlisting}
{"result":{"PRESIGNED":["NO"]}}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
GET /dnsapi/getalldomainmetadata/example.com HTTP/1.1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":{"PRESIGNED":["NO"]}}
```

##### Method: getDomainMetadata

Mandatory:  
No

Parameters:  
name, kind

Reply:  
array of strings

Description  
Returns the value(s) for variable kind for zone name. Most commonly it's one of NSEC3PARAM, PRESIGNED, SOA-EDIT. Can be others, too. You \*must\* always return something, if there are no values, you shall return empty array or false.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"getdomainmetadata", "parameters":{"name":"example.com","kind":"PRESIGNED"}}
```

Response:

``` {.programlisting}
{"result":["NO"]}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
GET /dnsapi/getdomainmetadata/example.com/PRESIGNED HTTP/1.1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":["NO"]}
```

##### Method: setDomainMetadata

Mandatory:  
No

Parameters:  
name, kind, value

Reply:  
true on success, false on failure

Description  
Replaces the value(s) on domain name for variable kind to string(s) on array value. The old value is discarded. Value can be an empty array, which can be interprepted as deletion request.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"setdomainmetadata","parameters":{"name":"example.com","kind":"PRESIGNED","value":["YES"]}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
PATCH /dnsapi/setdomainmetadata/example.com/PRESIGNED HTTP/1.1
Content-Type: application/x-www-form-urlencoded 
Content-Length: 12

value[]=YES&
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: getDomainKeys

Mandatory:  
for DNSSEC

Parameters:  
name, kind

Reply:  
array of \<id, flags, active, content\>

Description  
Retrieves any keys of kind. The id, flags are unsigned integers, and active is boolean. Content must be valid key record in format that PowerDNS understands. You are encouraged to implement [the section called “Method: addDomainKey”](remotebackend.html#remotebackend-api-method-adddomainkey "Method: addDomainKey"), as you can use [Section 5, “'pdnssec' for PowerDNSSEC command & control”](pdnssec.html "5. 'pdnssec' for PowerDNSSEC command & control") to provision keys.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"getdomainkeys","parameters":{"name":"example.com","kind":0}}
```

Response:

``` {.programlisting}
{"result":[{"id":1,"flags":256,"active":true,"content":"Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: r+vmQll38ndQqNSCx9eqRBUbSOLcH4PZFX824sGhY2NSQChqt1G4ZfndzRwgjXMUwiE7GkkqU2Vbt/g4iP67V/+MYecMV9YHkCRnEzb47nBXvs9JCf8AHMCnma567GQjPECh4HevPE9wmcOfpy/u7UN1oHKSKRWuZJadUwcjbp8=
PublicExponent: AQAB
PrivateExponent: CYC93UtVnOM6wrFJZ+qA9+Yx+p5yk0CSi0Q7c+/6EVMuABQ5gNyTuu0j65lU3X81bwUk2wHPx6smfgoVDRAW5jjO4jgIFV6nE4inzk5YQKycQSL8YG3Nm9GciLFya1KUXs81sHsQpkvK7MNaSbvkaHZQ6iv16bZ4t73Wascwa/E=
Prime1: 6a165cIC0nNsGlTW/s2jRu7idq5+U203iE1HzSIddmWgx5KIKE/s3I+pwfmXYRUmq+4H9ASd/Yot1lSYW98szw==
Prime2: wLoCPKxxnuxDx6/9IKOYz8t9ZNLY74iCeQ85koqvTctkFmB9jpOUHTU9BhecaFY2euP9CuHV7z3PLtCoO8s1MQ==
Exponent1: CuzJaiR/7UboLvL4ekEy+QYCIHpX/Z6FkiHK0ZRevEJUGgCHzRqvgEBXN3Jr2WYbwL4IMShmGoxzSCn8VY9BkQ==
Exponent2: LDR9/tyu0vzuLwc20B22FzNdd5rFF2wAQTQ0yF/3Baj5NAi9w84l0u07KgKQZX4g0N8qUyypnU5YDyzc6ZoagQ==
Coefficient: 6S0vhIQITWzqfQSLj+wwRzs6qCvJckHb1+SD1XpwYjSgMTEUlZhf96m8WiaE1/fIt4Zl2PC3fF7YIBoFLln22w=="}]}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
GET /dnsapi/getdomainkeys/example.com/0 HTTP/1.1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":[{"id":1,"flags":256,"active":true,"content":"Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: r+vmQll38ndQqNSCx9eqRBUbSOLcH4PZFX824sGhY2NSQChqt1G4ZfndzRwgjXMUwiE7GkkqU2Vbt/g4iP67V/+MYecMV9YHkCRnEzb47nBXvs9JCf8AHMCnma567GQjPECh4HevPE9wmcOfpy/u7UN1oHKSKRWuZJadUwcjbp8=
PublicExponent: AQAB
PrivateExponent: CYC93UtVnOM6wrFJZ+qA9+Yx+p5yk0CSi0Q7c+/6EVMuABQ5gNyTuu0j65lU3X81bwUk2wHPx6smfgoVDRAW5jjO4jgIFV6nE4inzk5YQKycQSL8YG3Nm9GciLFya1KUXs81sHsQpkvK7MNaSbvkaHZQ6iv16bZ4t73Wascwa/E=
Prime1: 6a165cIC0nNsGlTW/s2jRu7idq5+U203iE1HzSIddmWgx5KIKE/s3I+pwfmXYRUmq+4H9ASd/Yot1lSYW98szw==
Prime2: wLoCPKxxnuxDx6/9IKOYz8t9ZNLY74iCeQ85koqvTctkFmB9jpOUHTU9BhecaFY2euP9CuHV7z3PLtCoO8s1MQ==
Exponent1: CuzJaiR/7UboLvL4ekEy+QYCIHpX/Z6FkiHK0ZRevEJUGgCHzRqvgEBXN3Jr2WYbwL4IMShmGoxzSCn8VY9BkQ==
Exponent2: LDR9/tyu0vzuLwc20B22FzNdd5rFF2wAQTQ0yF/3Baj5NAi9w84l0u07KgKQZX4g0N8qUyypnU5YDyzc6ZoagQ==
Coefficient: 6S0vhIQITWzqfQSLj+wwRzs6qCvJckHb1+SD1XpwYjSgMTEUlZhf96m8WiaE1/fIt4Zl2PC3fF7YIBoFLln22w=="}]}
```

##### Method: addDomainKey

Mandatory:  
No

Parameters:  
name, key=\<flags,active,content\>

Reply:  
true for success, false for failure

Description  
Adds key into local storage. See [the section called “Method: getDomainKeys”](remotebackend.html#remotebackend-api-method-getdomainkeys "Method: getDomainKeys") for more information.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"adddomainkey", "parameters":{"key":{"id":1,"flags":256,"active":true,"content":"Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: r+vmQll38ndQqNSCx9eqRBUbSOLcH4PZFX824sGhY2NSQChqt1G4ZfndzRwgjXMUwiE7GkkqU2Vbt/g4iP67V/+MYecMV9YHkCRnEzb47nBXvs9JCf8AHMCnma567GQjPECh4HevPE9wmcOfpy/u7UN1oHKSKRWuZJadUwcjbp8=
PublicExponent: AQAB
PrivateExponent: CYC93UtVnOM6wrFJZ+qA9+Yx+p5yk0CSi0Q7c+/6EVMuABQ5gNyTuu0j65lU3X81bwUk2wHPx6smfgoVDRAW5jjO4jgIFV6nE4inzk5YQKycQSL8YG3Nm9GciLFya1KUXs81sHsQpkvK7MNaSbvkaHZQ6iv16bZ4t73Wascwa/E=
Prime1: 6a165cIC0nNsGlTW/s2jRu7idq5+U203iE1HzSIddmWgx5KIKE/s3I+pwfmXYRUmq+4H9ASd/Yot1lSYW98szw==
Prime2: wLoCPKxxnuxDx6/9IKOYz8t9ZNLY74iCeQ85koqvTctkFmB9jpOUHTU9BhecaFY2euP9CuHV7z3PLtCoO8s1MQ==
Exponent1: CuzJaiR/7UboLvL4ekEy+QYCIHpX/Z6FkiHK0ZRevEJUGgCHzRqvgEBXN3Jr2WYbwL4IMShmGoxzSCn8VY9BkQ==
Exponent2: LDR9/tyu0vzuLwc20B22FzNdd5rFF2wAQTQ0yF/3Baj5NAi9w84l0u07KgKQZX4g0N8qUyypnU5YDyzc6ZoagQ==
Coefficient: 6S0vhIQITWzqfQSLj+wwRzs6qCvJckHb1+SD1XpwYjSgMTEUlZhf96m8WiaE1/fIt4Zl2PC3fF7YIBoFLln22w=="}}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
PUT /dnsapi/adddomainkey/example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 965

flags=256&active=1&content=Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: r+vmQll38ndQqNSCx9eqRBUbSOLcH4PZFX824sGhY2NSQChqt1G4ZfndzRwgjXMUwiE7GkkqU2Vbt/g4iP67V/+MYecMV9YHkCRnEzb47nBXvs9JCf8AHMCnma567GQjPECh4HevPE9wmcOfpy/u7UN1oHKSKRWuZJadUwcjbp8=
PublicExponent: AQAB
PrivateExponent: CYC93UtVnOM6wrFJZ+qA9+Yx+p5yk0CSi0Q7c+/6EVMuABQ5gNyTuu0j65lU3X81bwUk2wHPx6smfgoVDRAW5jjO4jgIFV6nE4inzk5YQKycQSL8YG3Nm9GciLFya1KUXs81sHsQpkvK7MNaSbvkaHZQ6iv16bZ4t73Wascwa/E=
Prime1: 6a165cIC0nNsGlTW/s2jRu7idq5+U203iE1HzSIddmWgx5KIKE/s3I+pwfmXYRUmq+4H9ASd/Yot1lSYW98szw==
Prime2: wLoCPKxxnuxDx6/9IKOYz8t9ZNLY74iCeQ85koqvTctkFmB9jpOUHTU9BhecaFY2euP9CuHV7z3PLtCoO8s1MQ==
Exponent1: CuzJaiR/7UboLvL4ekEy+QYCIHpX/Z6FkiHK0ZRevEJUGgCHzRqvgEBXN3Jr2WYbwL4IMShmGoxzSCn8VY9BkQ==
Exponent2: LDR9/tyu0vzuLwc20B22FzNdd5rFF2wAQTQ0yF/3Baj5NAi9w84l0u07KgKQZX4g0N8qUyypnU5YDyzc6ZoagQ==
Coefficient: 6S0vhIQITWzqfQSLj+wwRzs6qCvJckHb1+SD1XpwYjSgMTEUlZhf96m8WiaE1/fIt4Zl2PC3fF7YIBoFLln22w==
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: removeDomainKey

Mandatory:  
No

Parameters:  
name, id

Reply:  
true for success, false for failure

Description  
Removes key id from domain name.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"removedomainkey","parameters":"{"name":"example.com","id":1}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
DELETE /dnsapi/removedomainkey/example.com/1 HTTP/1.1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: activateDomainKey

Mandatory:  
No

Parameters:  
name, id

Reply:  
true for success, false for failure

Description  
Activates key id for domain name.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"activatedomainkey","parameters":{"name":"example.com","id":1}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
POST /dnsapi/activatedomainkey/example.com/1 HTTP/1.1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; utf-8

{"result": true}
```

##### Method deactivateDomainKey

Mandatory:  
No

Parameters:  
name, id

Reply:  
true for success, false for failure

Description  
Deactivates key id for domain name.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"deactivatedomainkey","parameters":{"name":"example.com","id":1}}
```

Response:

``` {.programlisting}
{"result": true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
POST /dnsapi/deactivatedomainkey/example.com/1 HTTP/1.1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; utf-8

{"result": true}
```

##### Method: getTSIGKey

Mandatory:  
No

Parameters:  
name

Reply:  
algorithm, content

Description  
Retrieves the key needed to sign AXFR.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"gettsigkey","parameters":{"name":"example.com"}}
```

Response:

``` {.programlisting}
{"result":{"algorithm":"hmac-md5","content:"kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys="}}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
GET /dnsapi/gettsigkey/example.com
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":{"algorithm":"hmac-md5","content:"kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys="}}
```

##### Method: getDomainInfo

Mandatory:  
No

Parameters:  
name

Reply:  
zone

Optional values:  
serial, kind, id, notified\_serial, last\_check, masters

Description  
Retrieves information about given domain from the backend. If your return value has no zone attribute, the backend will signal error. Everything else will default to something. Default values: serial:0, kind:NATIVE, id:-1, notified\_serial:-1, last\_check:0, masters: []. Masters, if present, must be array of strings.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"getdomaininfo","parameters":{"name":"example.com"}}
```

Response:

``` {.programlisting}
{"result":{id:1,"zone":"example.com","kind":"NATIVE","serial":2002010100}}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
GET /dnsapi/getdomaininfo/example.com HTTP/1.1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
content-Type: text/javascript: charset=utf-8

{"result":{id:1,"zone":"example.com","kind":"NATIVE","serial":2002010100}}
```

##### Method: setNotified

Mandatory:  
No

Parameters:  
id, serial

Reply:  
true for success, false for failure

Description  
Updates last notified serial for the domain id. Any errors are ignored.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"setnotified","parameters":{"id":1,"serial":2002010100}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
PATCH /dnsapi/setnotified/1
Content-Type: application/x-www-form-urlencoded
Content-Length: 17

serial=2002010100
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: isMaster

Mandatory:  
No

Parameters:  
name,ip

Reply:  
true for success, false for failure.

Description  
Determines whether given IP is master for given domain name.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"isMaster","parameters":{"name":"example.com","ip":"10.0.0.1"}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
GET /dnsapi/isMaster/example.com/10.0.0.1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: superMasterBackend

Mandatory:  
No

Parameters:  
ip,domain,nsset,account

Reply:  
true for success, false for failure. can also return account=\>name of account

Description  
Creates new domain with given record(s) as master servers. IP address is the address where notify is received from. nsset is array of NS resource records.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"superMasterBackend","parameters":{"ip":"10.0.0.1","domain":"example.com","nsset":[{"qtype":"NS","qname":"example.com","qclass":1,"content":"ns1.example.com","ttl":300,"priority":0,"auth":true},{"qtype":"NS","qname":"example.com","qclass":1,"content":"ns2.example.com","ttl":300,"priority":0,"auth":true}]}}
```

Response:

``` {.programlisting}
{"result":true}
```

Alternative response:

``` {.programlisting}
{"result":{"account":"my account"}}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
POST /dnsapi/supermasterbackend/10.0.0.1/example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 317

nsset[1][qtype]=NS&nsset[1][qname]=example.com&nsset[1][qclass]=1&nsset[1][content]=ns1.example.com&nsset[1][ttl]=300&nsset[1][priority]=0&nsset[1][auth]=true&nsset[2][qtype]=NS&nsset[2][qname]=example.com&nsset[2][qclass]=1&nsset[2][content]=ns2.example.com&nsset[2][ttl]=300&nsset[2][priority]=0&nsset[2][auth]=true
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

Alternative response

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":{"account":"my account}}
```

##### Method: createSlaveDomain

Mandatory:  
No

Parameters:  
ip, domain

Optional parameters:  
account

Reply:  
true for success, false for failure

Description  
Creates new domain. This method is called when NOTIFY is received and you are superslaving.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"createSlaveDomain","parameters":{"ip":"10.0.0.1","domain":"pirate.unit.test"}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
POST /dnsapi/createslavedomain/10.0.0.1/pirate.unit.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: replaceRRSet

Mandatory:  
No

Parameters:  
domain\_id, qname, qtype, rrset

Reply:  
true for success, false for failure

Description  
This method replaces a given resource record with new set. The new qtype can be different from the old.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"replaceRRSet","parameters":{"domain_id":2,"qname":"replace.example.com","qtype":"A","trxid":1370416133,"rrset":[{"qtype":"A","qname":"replace.example.com","qclass":1,"content":"1.1.1.1","ttl":300,"priority":0,"auth":true}]}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
PATCH /dnsapi/replacerrset/2/replace.example.com/A
Content-Type: application/x-www-form-urlencoded
Content-Length: 135

trxid=1370416133&rrset[qtype]=A&rrset[qname]=replace.example.com&rrset[qclass]=1&rrset[content]=1.1.1.1&rrset[priority]=0&rrset[auth]=1
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: feedRecord

Mandatory:  
No

Parameters:  
rr, trxid

Reply:  
true for success, false for failure

Description  
Asks to feed new record into system. If startTransaction was called, trxId identifies a transaction. It is not always called by PowerDNS.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"feedRecord","parameters":{"rr":{"qtype":"A","qname":"replace.example.com","qclass":1,"content":"127.0.0.1","ttl":300,"priority":0,"auth":true},"trxid":1370416133}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
PATCH /dnsapi/feedrecord/1370416133
Content-Type: application/x-www-form-urlencoded
Content-Length: 117

rr[qtype]=A&rr[qname]=replace.example.com&rr[qclass]=1&rr[content]=127.0.0.1&rr[ttl]=300&rr[priority]=0&rr[auth]=true
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: feedEnts

Mandatory:  
No

Parameters:  
nonterm, trxid

Reply:  
true for success, false for failure

Description  
This method is used by pdnssec rectify-zone to populate missing non-terminals. This is used when you have, say, record like \_sip.\_upd.example.com, but no \_udp.example.com. PowerDNS requires that there exists a non-terminal in between, and this instructs you to add one. If startTransaction is called, trxid identifies a transaction.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"feedEnts","parameters":{"domain_id":2,"trxid":1370416133,"nonterm":["_sip._udp","_udp"]}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
PATCH /dnsapi/feedents/2
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

trxid=1370416133&nonterm[]=_udp&nonterm[]=_sip.udp
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: feedEnts3

Mandatory:  
No

Parameters:  
trxid, domain\_id, domain, times, salt, narrow, nonterm

Reply:  
true for success, false for failure

Description  
Same as [the section called “Method: feedEnts”](remotebackend.html#remotebackend-api-method-feedents "Method: feedEnts"), but provides NSEC3 hashing parameters. Note that salt is BYTE value, and can be non-readable text.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"feedEnts3","parameters":{"domain_id":2,"domain":"example.com","times":1,"salt":"9642","narrow":false,"trxid":1370416356,"nonterm":["_sip._udp","_udp"]}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
PATCH /dnsapi/2/example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

trxid=1370416356&times=1&salt=9642&narrow=0&nonterm[]=_sip._udp&nonterm[]=_udp
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: startTransaction

Mandatory:  
No

Parameters:  
domain\_id, domain, trxid

Reply:  
true for success, false for failure

Description  
Starts a new transaction. Transaction ID is chosen for you. Used to identify f.ex. AXFR transfer.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"startTransaction","parameters":{"trxid":1234,"domain_id":1,"domain":"example.com"}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
POST /dnsapi/starttransaction/1/example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

trxid=1234
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: commitTransaction

Mandatory:  
No

Parameters:  
trxid

Reply:  
true for success, false for failure

Description  
Signals successful transfer and asks to commit data into permanent storage.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"commitTransaction","parameters":{"trxid":1234}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
POST /dnsapi/committransaction/1234
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: abortTransaction

Mandatory:  
No

Parameters:  
trxid

Reply:  
true for success, false for failure

Description  
Signals failed transaction, and that you should rollback any changes.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"abortTransaction","parameters":{"trxid":1234}}
```

Response:

``` {.programlisting}
{"result":true}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
POST /dnsapi/aborttransaction/1234
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":true}
```

##### Method: calculateSOASerial

Mandatory:  
No

Parameters:  
domain,sd

Reply:  
true for success, false for failure

Description  
Asks you to calculate a new serial based on the given data and update the serial.

Example JSON/RPC:  
Query:

``` {.programlisting}
{"method":"calculateSOASerial","parameters":{"domain":"unit.test","sd":{"qname":"unit.test","nameserver":"ns.unit.test","hostmaster":"hostmaster.unit.test","ttl":300,"serial":1,"refresh":2,"retry":3,"expire":4,"default_ttl":5,"domain_id":-1,"scopeMask":0}}}
```

Response:

``` {.programlisting}
{"result":2013060501}
```

Example HTTP/RPC:  
Query:

``` {.programlisting}
POST /dnsapi/calculatesoaserial/unit.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 198

sd[qname]=unit.test&sd[nameserver]=ns.unit.test&sd[hostmaster]=hostmaster.unit.test&sd[ttl]=300&sd[serial]=1&sd[refresh]=2&sd[retry]=3&sd[expire]=4&sd[default_ttl]=5&sd[domain_id]=-1&sd[scopemask]=0
```

Response:

``` {.programlisting}
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=utf-8

{"result":2013060501}
```

### 16.5. Examples

Scenario: SOA lookup via pipe or unix connector

Query:

``` {.programlisting}
{ 
  "method": "lookup",
  "parameters": {
     "qname": "example.com", 
     "qtype": "SOA",
     "zone_id": "-1"
  }
}
```

Reply:

``` {.programlisting}
{
  "result": 
   [ 
     { "qtype": "SOA",
       "qname": "example.com", 
       "content": "dns1.icann.org. hostmaster.icann.org. 2012080849 7200 3600 1209600 3600",
       "ttl": 3600,
       "priority": 0,
       "domain_id": -1
     }
   ]
}
```

Scenario: SOA lookup with HTTP connector

Query:

``` {.programlisting}
/dns/lookup/example.com/SOA
```

Reply:

``` {.programlisting}
{
  "result":
   [
     { "qtype": "SOA",
       "qname": "example.com",
       "content": "dns1.icann.org. hostmaster.icann.org. 2012080849 7200 3600 1209600 3600",
       "ttl": 3600,
       "priority": 0,
       "domain_id": -1
     }
   ]
}
```

* * * * *

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><a href="tinydnsbackend.html">Prev</a> 
<a href="backends-detail.html">Up</a>
 <a href="pdns-internals.html">Next</a></td>
<td align="left">15. TinyDNS Backend 
<a href="index.html">Home</a>
 Appendix B. PDNS internals</td>
</tr>
</tbody>
</table>


