-- == Generic Configuration ==

-- only accept queries (Do53, DNSCrypt,  DoT or DoH) from a few subnets
-- see https://dnsdist.org/advanced/acl.html for more details
-- please be careful when dnsdist is deployed in front of a server
-- server granting access based on the source IP, as all queries will
-- seem to originate from dnsdist, which might be especially relevant for
-- AXFR, IXFR, NOTIFY and UPDATE
-- https://dnsdist.org/advanced/axfr.html
-- setACL({'192.0.2.0/28', '2001:DB8:1::/56'})

-- listen for console connection with the given secret key
-- https://dnsdist.org/guides/console.html
-- controlSocket("127.0.0.1:5900")
-- setKey("please generate a fresh private key with makeKey()")

-- start the web server on port 8083, using password 'set a random password here'
-- https://dnsdist.org/guides/webserver.html
-- webserver("127.0.0.1:8083", "set a random password here")

-- send statistics to PowerDNS metronome server https://metronome1.powerdns.com/
-- https://dnsdist.org/guides/carbon.html
-- carbonServer("37.252.122.50", 'unique-name')

-- accept plain DNS (Do53) queries on UDP/5200 and TCP/5200
-- addLocal("127.0.0.1:5200")

-- accept DNSCrypt queries on UDP/8443 and TCP/8443
-- https://dnsdist.org/guides/dnscrypt.html
-- addDNSCryptBind("127.0.0.1:8443", "2.provider.name", "DNSCryptResolver.cert", "DNSCryptResolver.key")

-- accept DNS over TLS (DoT) queries on TCP/9443
-- https://dnsdist.org/guides/dns-over-tls.html
-- addTLSLocal("127.0.0.1:9443", {"server.crt"}, {"server.key"}, { provider="openssl" })

-- accept DNS over HTTPS (DoH) queries on TCP/443
-- https://dnsdist.org/guides/dns-over-https.html
-- addDOHLocal("127.0.0.1:443", {"server.crt"}, {"server.key"})

-- define downstream servers, aka backends
-- https://dnsdist.org/guides/downstreams.html
-- https://dnsdist.org/guides/serverpools.html
-- https://dnsdist.org/guides/serverselection.html
-- newServer("192.0.2.1")
-- newServer({address="192.0.2.1:5300", pool="abuse"})

-- == Tuning ==

-- Increase the in-memory rings size (the default, 10000, is only one second at 10k qps) used by
-- live-traffic inspection features like grepq, and use 100 shards to improve performance
-- setRingBuffersSize(1000000, 100)

-- increase the number of TCP workers, each one being capable of handling a large number
-- of TCP connections since 1.4.0
-- setMaxTCPClientThreads(20)

-- == Sample Actions ==

-- https://dnsdist.org/rules-actions.html

-- send the queries for selected domain suffixes to the servers
-- in the 'abuse' pool
-- addAction(SuffixMatchNodeRule({"abuse.example.org.", "xxx."}), PoolAction("abuse"))

-- drop queries for this exact qname
-- addAction(QNameRule("drop-me.example.org."), DropAction())

-- send the queries from a selected subnet to the
-- abuse pool
-- addAction(NetmaskGroupRule("192.0.2.0/24"), PoolAction("abuse"))

-- Refuse incoming AXFR, IXFR, NOTIFY and UPDATE
-- Add trusted sources (secondaries, primaries) explicitely in front of this rule
-- addAction(OrRule({OpcodeRule(DNSOpcode.Notify), OpcodeRule(DNSOpcode.Update), QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), RCodeAction(DNSRCode.REFUSED))

-- == Dynamic Blocks ==

-- define a dynamic block rules group object, set a few limits and apply it
-- see https://dnsdist.org/guides/dynblocks.html for more details

-- local dbr = dynBlockRulesGroup()
-- dbr:setQueryRate(30, 10, "Exceeded query rate", 60)
-- dbr:setRCodeRate(DNSRCode.NXDOMAIN, 20, 10, "Exceeded NXD rate", 60)
-- dbr:setRCodeRate(DNSRCode.SERVFAIL, 20, 10, "Exceeded ServFail rate", 60)
-- dbr:setQTypeRate(DNSQType.ANY, 5, 10, "Exceeded ANY rate", 60)
-- dbr:setResponseByteRate(10000, 10, "Exceeded resp BW rate", 60)
-- function maintenance()
--  dbr:apply()
-- end

-- == Logging ==

-- connect to a remote protobuf logger and export queries and responses
-- https://dnsdist.org/reference/protobuf.html
-- rl = newRemoteLogger('127.0.0.1:4242')
-- addAction(AllRule(), RemoteLogAction(rl))
-- addResponseAction(AllRule(), RemoteLogResponseAction(rl))

-- DNSTAP is also supported
-- https://dnsdist.org/reference/dnstap.html
-- fstr = newFrameStreamUnixLogger(/path/to/unix/socket)
-- or
-- fstr = newFrameStreamTcpLogger('192.0.2.1:4242')
-- addAction(AllRule(), DnstapLogAction(fstr))
-- addResponseAction(AllRule(), DnstapLogResponseAction(fstr))

-- == Caching ==

-- https://dnsdist.org/guides/cache.html
-- create a packet cache of at most 100k entries,
-- and apply it to the default pool
-- pc = newPacketCache(100000)
-- getPool(""):setCache(pc)
