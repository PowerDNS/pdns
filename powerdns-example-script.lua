function prequery ( ip, domain, qtype )
	print ("prequery handler called for: ", ip, domain, qtype)
	ret = {}
	
	ret[0]= {1, "9.8.7.6", 3601};
	ret[1]= {1, "10.11.12.13", 3601};
	ret[2]= {1, "11.12.13.14", 3601};

	if domain == "www.ds9c.nl." 
	then
		print "dealing!"
		return 1, ret
	else
		print "not dealing!"
		return false, ret
	end
end

function nxdomain ( ip, domain, qtype )
	print ("nxhandler called for: ", ip, domain, qtype)
	ret={}
	if qtype ~= 1 then return false, ret end  --  only A records
	if not string.match(domain, "^www.") then return false, ret end  -- only things that start with www.
	
	if matchnetmask(ip, "127.0.0.1/8")
	then 
		print "dealing"
		ret[0]={1, "127.1.2.3", 3602}
		ret[1]={15, "25 ds9a.nl", 3602}
		return 1, ret
	else
		print "not dealing"
		return false, ret
	end
end
