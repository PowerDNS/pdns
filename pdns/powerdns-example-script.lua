function prequery ( ip, domain, qtype )
	print ("prequery handler called for: ", ip, domain, qtype)
	ret = {}
	
--	ret[1]= {1, "10.11.12.13", 3601};
--	ret[2]= {1, "11.12.13.14", 3601};
	if domain == "www.ds9c.nl." 
	then
		ret[0]= {qtype=1, content="9.8.7.6", ttl=3601}
		ret[1]= {qtype=1, content="1.2.3.4", ttl=3601}
		print "dealing!"
		return 0, ret
	elseif domain == "www.baddomain.com."
	then
		print "dealing - nx"
	       	return 3, ret
	else
		print "not dealing!"
		return -1, ret
	end
end

function nxdomain ( ip, domain, qtype )
	print ("nxhandler called for: ", ip, domain, qtype)
	ret={}
	if qtype ~= 1 then return false, ret end  --  only A records
--	if not string.match(domain, "^www.") then return false, ret end  -- only things that start with www.
	
	if matchnetmask(ip, "127.0.0.1/8")
	then 
		print "dealing"
		ret[0]={qtype="5", content="www.webserver.com", ttl=3602}
		ret[1]={qname="www.webserver.com", qtype="1", content="1.2.3.4", ttl=3602}
		ret[2]={qname="webserver.com", qtype="2", content="ns1.webserver.com", place=2}
--		ret[1]={15, "25 ds9a.nl", 3602}
		return 0, ret
	else
		print "not dealing"
		return -1, ret
	end
end
