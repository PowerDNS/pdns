function preresolve ( ip, domain, qtype )
	print ("prequery handler called for: ", ip, domain, qtype)

	if domain == "www.ds9c.nl." 
	then
		ret={}
		ret[1]= {qtype=pdns.A, content="9.8.7.6", ttl=3601}
		ret[2]= {qtype=pdns.A, content="1.2.3.4", ttl=3601}
		print "dealing!"
		return 0, ret
	elseif domain == "www.baddomain.com."
	then
		print "dealing - faking nx"
	       	return pdns.NXDOMAIN, {}
	elseif domain == "echo."
	then
		print "dealing with echo!"
		return 0, {{qtype=pdns.A, content=ip}}
	elseif domain == "echo6."
	then
		print "dealing with echo6!"
		return 0, {{qtype=pdns.AAAA, content=ip}}
	else
		print "not dealing!"
		return -1, {}
	end
end

function nxdomain ( ip, domain, qtype )
	print ("nxhandler called for: ", ip, domain, qtype, pdns.AAAA)
	if qtype ~= pdns.A then return -1, {} end  --  only A records
	if not string.find(domain, "^www.") then return -1, {} end  -- only things that start with www.
	
	if matchnetmask(ip, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "::/0")
	then 
		print "dealing"
		ret={}
		ret[1]={qtype=pdns.CNAME, content="www.webserver.com", ttl=3602}
		ret[2]={qname="www.webserver.com", qtype=pdns.A, content="1.2.3.4", ttl=3602}
		ret[3]={qname="webserver.com", qtype=pdns.NS, content="ns1.webserver.com", place=2}
--		ret[1]={15, "25 ds9a.nl", 3602}
		return 0, ret
	else
		print "not dealing"
		return -1, ret
	end
end
