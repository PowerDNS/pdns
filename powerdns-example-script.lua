function preresolve ( ip, domain, qtype )
	print ("prequery handler called for: ", ip, domain, qtype)

	if domain == "www.powerdns.org." 
	then
		ret={}
		ret[1]= {qtype=pdns.A, content="85.17.219.141", ttl=86400}
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
	if not string.find(domain, "^www%.") then return -1, {} end  -- only things that start with www.
	
	if matchnetmask(ip, {"127.0.0.1/32", "10.1.0.0/16"}) 
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
