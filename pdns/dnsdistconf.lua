-- listen for console connection with the given secret key
controlSocket("0.0.0.0")
setKey("MXNeLFWHUe4363BBKrY06cAsH8NWNb+Se2eXU5+Bb74=")

-- start the web server on port 8083, using password 'geheim2'
webserver("0.0.0.0:8083", "geheim2")

-- accept DNS queries on UDP/5200 and TCP/5200
addLocal("0.0.0.0:5200")

-- send statistics to PowerDNS metronome server
-- carbonServer("2001:888:2000:1d::2")

-- fix up possibly badly truncated answers from pdns 2.9.22
truncateTC(true)

warnlog(string.format("Script starting %s", "up!"))

-- define the good servers
newServer("8.8.8.8", 2)  -- 2 qps
newServer("8.8.4.4", 2)
newServer("208.67.222.222", 1)
newServer("208.67.220.220", 1)
newServer("2001:4860:4860::8888", 1)
newServer("2001:4860:4860::8844",1)
newServer("2620:0:ccc::2", 10)
newServer("2620:0:ccd::2", 10)
newServer({address="192.168.1.2", qps=1000, order=2})
newServer({address="192.168.1.79:5300", order=2})
newServer({address="127.0.0.1:5300", order=3})
newServer({address="192.168.1.30:5300", pool="abuse"})

-- switch the server balancing policy to round robin,
-- the default being least outstanding queries
-- setServerPolicy(roundrobin)

-- send the queries for selected domain suffixes to the server
-- in the 'abuse' pool
addPoolRule({"ezdns.it.", "xxx."}, "abuse")

-- send the queries from a selected subnet to the
-- abuse pool
addPoolRule("192.168.1.0/24", "abuse")

-- send the queries for the "com" suffix to the "abuse"
-- pool, but only up to 100 qps
addQPSPoolRule("com.", 100, "abuse")

-- declare a Lua action function, routing NAPTR queries
-- to the abuse pool
function luarule(dq)
	if(dq.qtype==dnsdist.NAPTR)
	then
		return DNSAction.Pool, "abuse" -- send to abuse pool
	else
		return DNSAction.None, ""      -- no action
	end
end
-- send only queries from the selected subnet to
-- the luarule function
addLuaAction("192.168.1.0/24", luarule)

-- drop queries exceeding 5 qps, grouped by /24 for IPv4
-- and /64 for IPv6
addAction(MaxQPSIPRule(5, 24, 64), DropAction())

-- move the last rule to the first position
topRule()

-- drop queries for the following suffixes:
addDomainBlock("powerdns.org.")
addDomainBlock("spectre.")
-- this is equivalent to addAction("isis.", DropAction())
addDomainBlock("isis.")

-- called before we distribute a question
block=newDNSName("powerdns.org.")
truncateNMG = newNMG()
truncateNMG:addMask("213.244.0.0/16")
truncateNMG:addMask("2001:503:ba3e::2:30")
truncateNMG:addMask("fe80::/16")

print(string.format("Have %d entries in truncate NMG", truncateNMG:size()))

-- we define a Lua function named blockFilter, which is automatically called
-- when a query is received
-- this example reply with TC=1 for ANY queries, and for queries coming from
-- the specified subnets
-- it also blocks (by returning true) queries for "*.powerdns.org."
function blockFilter(dq)
	 print(string.format("Got query from %s, (%s) port number: %d", dq.remoteaddr:toString(), dq.remoteaddr:toStringWithPort(), dq.remoteaddr:getPort()))
	 if(dq.qtype==dnsdist.ANY or truncateNMG:match(dq.remoteaddr))
	 then
--	        print("any query, tc=1")
		dq.dh:setTC(true)
		dq.dh:setQR(true)
	 end

	 if(dq.qname:isPartOf(block))
	 then
		print("Blocking *.powerdns.org")
		return true
	 end
	 return false
end

-- this is how you disable a filter
blockFilter = nil


-- called to pick a downstream server, ignores 'up' status
counter=0
function luaroundrobin(servers, dq)
	 counter=counter+1;
	 return servers[1+(counter % #servers)]
end
-- setServerPolicyLua("luaroundrobin", luaroundrobin)

newServer({address="2001:888:2000:1d::2", pool={"auth", "dnssec"}})
newServer({address="2a01:4f8:110:4389::2", pool={"auth", "dnssec"}})
--setDNSSECPool("dnssec")
--topRule()

-- split queries between the 'auth' pool and the regular one,
-- based on the RD flag
function splitSetup(servers, dq)
	 if(dq.dh:getRD() == false)
	 then
		return firstAvailable.policy(getPoolServers("auth"), dq)
	 else
		return firstAvailable.policy(servers, dq)
	 end
end
-- setServerPolicyLua("splitSetup", splitSetup)

-- the 'maintenance' function is called every second
function maintenance()
	 -- block all hosts that exceeded 20 qps over the past 10s,
	 -- for 60s
	 addDynBlocks(exceedQRate(20, 10), "Exceeded query rate", 60)
end

-- allow queries for the domain powerdns.com., drop everything else
-- addAction(makeRule("powerdns.com."), AllowAction())
-- addAction(AllRule(), DropAction())

-- clear the RD flag in queries for powerdns.com.
-- addNoRecurseRule("powerdns.com.")
-- another way to do the exact same thing:
-- addAction("powerdns.com.", NoRecurseAction())

-- set the CD flag in queries for powerdns.com.
-- addDisableValidationRule("powerdns.com.")
-- or:
-- addAction("powerdns.com.", DisableValidationAction())

-- delay all responses for 1000ms
-- addAction(AllRule(), DelayAction(1000))

-- truncate ANY queries over UDP only
-- addAnyTCRule()

-- truncate ANY queries over TCP only
-- addAction(AndRule({QTypeRule(dnsdist.ANY), TCPRule(true)}), TCAction())
-- can also be written as:
-- addAction(AndRule({QTypeRule("ANY"), TCPRule(true)}), TCAction())

-- return 'not implemented' for qtype != A over UDP
-- addAction(AndRule({NotRule(QTypeRule("A")), TCPRule(false)}), RCodeAction(dnsdist.NOTIMP))

-- return 'not implemented' for qtype == A OR received over UDP
-- addAction(OrRule({QTypeRule("A"), TCPRule(false)}), RCodeAction(dnsdist.NOTIMP))

-- log all queries to a 'dndist.log' file, in text-mode (not binary)
-- addAction(AllRule(), LogAction("dnsdist.log", false))

-- drop all queries with the DO flag set
-- addAction(DNSSECRule(), DropAction())

-- drop all queries for the CHAOS class
-- addAction(QClassRule(3), DropAction())
-- addAction(QClassRule(DNSClass.CHAOS), DropAction())

-- drop all queries with the UPDATE opcode
-- addAction(OpcodeRule(DNSOpcode.Update), DropAction())

-- refuse all queries not having exactly one question
-- addAction(NotRule(RecordsCountRule(DNSSection.Question, 1, 1)), RCodeAction(dnsdist.REFUSED))

-- return 'refused' for domains matching the regex evil[0-9]{4,}.powerdns.com$
-- addAction(RegexRule("evil[0-9]{4,}\\.powerdns\\.com$"), RCodeAction(dnsdist.REFUSED))

-- spoof responses for A, AAAA and ANY for spoof.powerdns.com.
-- A queries will get 192.0.2.1, AAAA 2001:DB8::1 and ANY both
-- addDomainSpoof("spoof.powerdns.com.", "192.0.2.1", "2001:DB8::1")

-- spoof responses will multiple records
-- A will get 192.0.2.1 and 192.0.2.2, AAAA 20B8::1 and 2001:DB8::2
-- ANY all of that
-- addDomainSpoof("spoof.powerdns.com", {"192.0.2.1", "192.0.2.2", "20B8::1", "2001:DB8::2"})

-- spoof responses with a CNAME
-- addDomainCNAMESpoof("cnamespoof.powerdns.com.", "cname.powerdns.com.")

-- spoof responses in Lua
--[[
    function spoof1rule(dq)
        if(dq.qtype==1) -- A
        then
                return DNSAction.Spoof, "192.0.2.1"
        elseif(dq.qtype == 28) -- AAAA
        then
                return DNSAction.Spoof, "2001:DB8::1"
        else
                return DNSAction.None, ""
        end
    end
    function spoof2rule(dq)
        return DNSAction.Spoof, "spoofed.powerdns.com."
    end
    addLuaAction("luaspoof1.powerdns.com.", spoof1rule)
    addLuaAction("luaspoof2.powerdns.com.", spoof2rule)

--]]
