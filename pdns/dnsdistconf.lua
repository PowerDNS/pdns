controlSocket("0.0.0.0")
webserver("0.0.0.0:8083", "geheim2")
addLocal("0.0.0.0:5200")
setKey("MXNeLFWHUe4363BBKrY06cAsH8NWNb+Se2eXU5+Bb74=")
truncateTC(true) -- fix up possibly badly truncated answers from pdns 2.9.22
carbonServer("2001:888:2000:1d::2")

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
newServer{address="192.168.1.2", qps=1000, order=2}
newServer{address="192.168.1.79:5300", order=2}
newServer{address="127.0.0.1:5300", order=3}
newServer{address="192.168.1.30:5300", pool="abuse"}

addPoolRule({"ezdns.it.", "xxx."}, "abuse")
addPoolRule("192.168.1.0/24", "abuse")

addQPSPoolRule("com.", 100, "abuse")

function luarule(remote, qname, qtype, dh, len)
	if(qtype==35) -- NAPTR
	then
		return DNSAction.Pool, "abuse" -- send to abuse pool
	else
		return DNSAction.None, ""      -- no action
	end
end
addLuaAction("192.168.1.0/24", luarule)

addAction(MaxQPSIPRule(5, 24, 64), DropAction())

topRule()

addDomainBlock("powerdns.org.")
addDomainBlock("spectre.")
addDomainBlock("isis.")

block=newDNSName("powerdns.org.")
-- called before we distribute a question
function blockFilter(remote, qname, qtype, dh)
	 if(qtype==255) 
	 then
--	        print("any query, tc=1")
		dh:setTC(true)
		dh:setQR(true)
	 end

	 if(qname:isPartOf(block))
	 then
		print("Blocking *.powerdns.org")
		return true
	 end
	 return false
end

blockFilter = nil -- this is how you disable a filter

counter=0

-- called to pick a downstream server, ignores 'up' status
function luaroundrobin(servers, remote, qname, qtype, dh) 
	 counter=counter+1;
	 return servers[1+(counter % #servers)]
end

-- setServerPolicyLua("luaroundrobin", luaroundrobin)

newServer{address="2001:888:2000:1d::2", pool={"auth", "dnssec"}}
newServer{address="2a01:4f8:110:4389::2", pool={"auth", "dnssec"}}
--setDNSSECPool("dnssec")
--topRule()

function splitSetup(servers, remote, qname, qtype, dh)
	 if(dh:getRD() == false)
	 then
		return firstAvailable.policy(getPoolServers("auth"), remote, qname, qtype, dh)
	 else
		return firstAvailable.policy(servers, remote, qname, qtype, dh)
	 end
end

-- setServerPolicyLua("splitSetup", splitSetup)