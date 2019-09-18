-- listen for console connection with the given secret key
-- controlSocket("0.0.0.0")
-- setKey(please generate a fresh private key with makeKey())

-- start the web server on port 8083, using password 'set a random password here'
-- webserver("0.0.0.0:8083", "set a random password here")

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
addAction({"ezdns.it.", "xxx."}, PoolAction("abuse"))

-- send the queries from a selected subnet to the
-- abuse pool
addAction("192.168.1.0/24", PoolAction("abuse"))

-- send the queries for the "com" suffix to the "abuse"
-- pool, but only up to 100 qps
addAction("com.", QPSPoolAction(100, "abuse"))

-- declare a Lua action function, routing NAPTR queries
-- to the abuse pool
function luarule(dq)
	if(dq.qtype==DNSQType.NAPTR)
	then
		return DNSAction.Pool, "abuse" -- send to abuse pool
	else
		return DNSAction.None, ""      -- no action
	end
end
-- send only queries from the selected subnet to
-- the luarule function
addAction("192.168.1.0/24", LuaAction(luarule))

-- drop queries exceeding 5 qps, grouped by /24 for IPv4
-- and /64 for IPv6
addAction(MaxQPSIPRule(5, 24, 64), DropAction())

-- move the last rule to the first position
topRule()

-- drop queries for the following suffixes:
addAction("powerdns.org.", DropAction())
addAction("spectre.", DropAction())

-- called before we distribute a question
block=newDNSName("powerdns.org.")
truncateNMG = newNMG()
truncateNMG:addMask("213.244.0.0/16")
truncateNMG:addMask("2001:503:ba3e::2:30")
truncateNMG:addMask("fe80::/16")

print(string.format("Have %d entries in truncate NMG", truncateNMG:size()))

-- called to pick a downstream server, ignores 'up' status
counter=0
function luaroundrobin(servers, dq)
	 counter=counter+1;
	 return servers[1+(counter % #servers)]
end
-- setServerPolicyLua("luaroundrobin", luaroundrobin)

newServer({address="2001:888:2000:1d::2", pool={"auth", "dnssec"}})
newServer({address="2a01:4f8:110:4389::2", pool={"auth", "dnssec"}})
--addAction(DNSSECRule(), PoolAction("dnssec"))
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
-- addAction("powerdns.com.", NoRecurseAction())

-- set the CD flag in queries for powerdns.com.
-- addAction("powerdns.com.", DisableValidationAction())

-- delay all responses for 1000ms
-- addAction(AllRule(), DelayAction(1000))

-- truncate ANY queries over UDP only
-- addAction(AndRule{QTypeRule(DNSQType.ANY), TCPRule(false)}, TCAction())

-- truncate ANY queries over TCP only
-- addAction(AndRule({QTypeRule(DNSQType.ANY), TCPRule(true)}), TCAction())
-- can also be written as:
-- addAction(AndRule({QTypeRule("ANY"), TCPRule(true)}), TCAction())

-- return 'not implemented' for qtype != A over UDP
-- addAction(AndRule({NotRule(QTypeRule("A")), TCPRule(false)}), RCodeAction(DNSRCode.NOTIMP))

-- return 'not implemented' for qtype == A OR received over UDP
-- addAction(OrRule({QTypeRule("A"), TCPRule(false)}), RCodeAction(DNSRCode.NOTIMP))

-- log all queries to a 'dndist.log' file, in text-mode (not binary) appending and unbuffered
-- addAction(AllRule(), LogAction("dnsdist.log", false, true, false))

-- drop all queries with the DO flag set
-- addAction(DNSSECRule(), DropAction())

-- drop all queries for the CHAOS class
-- addAction(QClassRule(3), DropAction())
-- addAction(QClassRule(DNSClass.CHAOS), DropAction())

-- drop all queries with the UPDATE opcode
-- addAction(OpcodeRule(DNSOpcode.Update), DropAction())

-- refuse all queries not having exactly one question
-- addAction(NotRule(RecordsCountRule(DNSSection.Question, 1, 1)), RCodeAction(DNSRCode.REFUSED))

-- return 'refused' for domains matching the regex evil[0-9]{4,}.powerdns.com$
-- addAction(RegexRule("evil[0-9]{4,}\\.powerdns\\.com$"), RCodeAction(DNSRCode.REFUSED))

-- spoof responses for A, AAAA and ANY for spoof.powerdns.com.
-- A queries will get 192.0.2.1, AAAA 2001:DB8::1 and ANY both
-- addAction("spoof.powerdns.com.", SpoofAction({"192.0.2.1", "2001:DB8::1"}))

-- spoof responses will multiple records
-- A will get 192.0.2.1 and 192.0.2.2, AAAA 20B8::1 and 2001:DB8::2
-- ANY all of that
-- addAction("spoof.powerdns.com", SpoofAction({"192.0.2.1", "192.0.2.2", "20B8::1", "2001:DB8::2"}))

-- spoof responses with a CNAME
-- addAction("cnamespoof.powerdns.com.", SpoofCNAMEAction("cname.powerdns.com."))

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
    addAction("luaspoof1.powerdns.com.", LuaAction(spoof1rule))
    addAction("luaspoof2.powerdns.com.", LuaAction(spoof2rule))

--]]

-- alter a protobuf response for anonymization purposes
--[[
function alterProtobuf(dq, protobuf)
    requestor = newCA(dq.remoteaddr:toString())
    if requestor:isIPv4() then
        requestor:truncate(24)
    else
        requestor:truncate(56)
    end
    protobuf:setRequestor(requestor)
end

rl = newRemoteLogger("127.0.0.1:4242")
addAction(AllRule(), RemoteLogAction(rl, alterProtobuf))
--]]
