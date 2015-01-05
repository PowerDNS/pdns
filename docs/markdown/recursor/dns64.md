# DNS64 support in the PowerDNS Recursor
DNS64 is a technology to allow IPv6-only clients to receive special IPv6 addresses that are proxied to IPv4 addresses. This proxy service is then called NAT64.

So, as an example, let's say an IPv6 only client would want to connect to www.example.com, it would request the AAAA records for that name. However, if example.com does not actually have an IPv6 address, what we do is 'fake up' an IPv6 address. We do this by retrieving the A records for www.example.com, and translating them to AAAA records.

Elsewhere, a NAT64 device listens on these IPv6 addresses, and extracts the IPv4 address from each packet, and proxies it on.

DNS64 is described in RFC 6147, and is supported by the PowerDNS Recursor since version 3.4.

For maximum flexibility, DNS64 support is included in the Lua scripting engine. This allows for example to hand out custom IPv6 gateway ranges depending on the location of the requestor, enabling the use of NAT64 services close to the user.

To setup DNS64, create the following Lua script and save it to a file called dns64.lua:

```
    function nodata ( remoteip, domain, qtype, records )
             if qtype ~= pdns.AAAA then return pdns.PASS, {} end  --  only AAAA records
             setvariable()
             return "getFakeAAAARecords", domain, "fe80::21b:77ff:0:0"
        end
```

Where fe80::21b::77ff:0:0 is your "Pref64" translation prefix. Next, make sure your script gets loaded by specifying it with `lua-pdns-script=dns64.lua`.

In addition, since PowerDNS Recursor 3.6, it is also possible to also generate the associated PTR records. This makes sure that reverse lookup of DNS64-generated IPv6 addresses generate the right name. The procedure is similar, a request for an IPv6 PTR is converted into one for the corresponding IPv4 address.

To hook up the generation of PTR records, include:

```
      function endswith(s, send)
             return #s >= #send and s:find(send, #s-#send+1, true) and true or false
      end

      function preresolve ( remoteip, domain, qtype )
         if qtype ==pdns.PTR and endswith(domain, "f.f.7.7.b.1.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.")
             then
                return "getFakePTRRecords", domain, "fe80::21b::77ff:0:0"
             end
         return pdns.PASS, {}
      end
```

Where the "ip6.arpa" string is the reversed form of your Pref64 address.
