-- controlSocket("0.0.0.0")
setKey("MXNeLFWHUe4363BBKrY06cAsH8NWNb+Se2eXU5+Bb74=")

-- define the good servers
newServer("8.8.8.8", 2)  -- 2 qps
newServer("8.8.4.4", 2) 
newServer("208.67.222.222", 1)
newServer("208.67.220.220", 1)	
newServer("2001:4860:4860::8888", 1)
newServer("2001:4860:4860::8844",1) 
newServer("2620:0:ccc::2", 10) 
newServer("2620:0:ccd::2", 10) 
newServer2{address="192.168.1.2", qps=1000, order=2}

newServer2{address="127.0.0.1:5300", order=3}
abuse=newServer2{address="192.168.1.30:5300", order=4}

abuseServer(abuse)
abuseShuntSMN("ezdns.it.")
abuseShuntSMN("xxx.")
abuseShuntNM("192.168.1.0/24")


block=newDNSName("powerdns.org.")
-- called before we distribute a question
function blockFilter(remote, qname, qtype)
	 if(qname:isPartOf(block))
	 then
		print("Blocking *.powerdns.org")
		return true
	 end
	 return false
end

counter=0
servers=getServers()

-- called to pick a downstream server
function luaroundrobin(remote, qname, qtype) 
	 counter=counter+1;
	 return servers[1+(counter % #servers)]
end

-- setServerPolicy(luaroundrobin)

