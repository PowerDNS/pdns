function preresolve ( ip, domain, qtype )
	print ("prequery handler called for: ", ip, domain, qtype)

	if domain == "www.ds9c.nl." 
	then
		ret={}
		ret[1]= {qtype=1, content="9.8.7.6", ttl=3601}
		ret[2]= {qtype=1, content="1.2.3.4", ttl=3601}
		print "dealing!"
		return 0, ret
	elseif domain == "www.baddomain.com."
	then
		print "dealing - faking nx"
	       	return 3, {}
	elseif domain == "echo."
	then
		print "dealing with echo!"
		return 0, {{qtype=1, content=ip}}
	elseif domain == "echo6."
	then
		print "dealing with echo6!"
		return 0, {{qtype=28, content=ip}}
	else
		print "not dealing!"
		return -1, {}
	end
end

function nxdomain ( ip, domain, qtype )
	print ("nxhandler called for: ", ip, domain, qtype)
	if qtype ~= 1 then return -1, {} end  --  only A records
	if not string.find(domain, "^www.") then return -1, {} end  -- only things that start with www.
	
	if matchnetmask(ip, "127.0.0.1/8")
	then 
		print "dealing"
		ret={}
		ret[1]={qtype="5", content="www.webserver.com", ttl=3602}
		ret[2]={qname="www.webserver.com", qtype="1", content="1.2.3.4", ttl=3602}
		ret[3]={qname="webserver.com", qtype="2", content="ns1.webserver.com", place=2}
--		ret[1]={15, "25 ds9a.nl", 3602}
		return 0, ret
	else
		print "not dealing"
		return -1, ret
	end
end
