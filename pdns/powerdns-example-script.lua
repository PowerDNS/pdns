function preresolve ( remoteip, domain, qtype )
	print ("prequery handler called for: ", remoteip, getlocaladdress(), domain, qtype)
	pdnslog("a test message.. received query from "..remoteip.." on "..getlocaladdress());

	if domain == "www.donotcache.org."
	then
		print("making sure www.donotcache.org will never end up in the cache")
		setvariable()
		return -1, {}
	end

	if domain == "www.powerdns.org."
	then
		ret={}
		ret[1]= {qtype=pdns.A, content="85.17.220.215", ttl=86400}
		print "dealing!"
		return 0, ret
	elseif domain == "www.baddomain.com."
	then
		print "dealing - faking nx"
	       	return pdns.NXDOMAIN, {}
	elseif domain == "echo."
	then
		print "dealing with echo!"
		return 0, {{qtype=pdns.A, content=remoteip}}
	elseif domain == "echo6."
	then
		print "dealing with echo6!"
		return 0, {{qtype=pdns.AAAA, content=remoteip}}
	else
		print "not dealing!"
		return -1, {}
	end
end

function nxdomain ( remoteip, domain, qtype )
	print ("nxhandler called for: ", remoteip, getlocaladdress(), domain, qtype, pdns.AAAA)
	if qtype ~= pdns.A then return -1, {} end  --  only A records
	if not string.find(domain, "^www%.") then return -1, {} end  -- only things that start with www.

	setvariable()
	if matchnetmask(remoteip, {"127.0.0.1/32", "10.1.0.0/16"})
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

function axfrfilter(remoteip, zone, qname, qtype, ttl, priority, content)
	if qtype ~= pdns.SOA or zone ~= "secured-by-gost.org"
	then
		ret = {}
		return -1, ret
	end

	print "got soa!"
	ret={}
	ret[1]={qname=qname, qtype=qtype, content=content, ttl=ttl}
	ret[2]={qname=qname, qtype=pdns.TXT, content=os.date("Retrieved at %Y-%m-%d %H:%M"), ttl=ttl}
	return 0, ret
end

function nodata ( remoteip, domain, qtype, records )
	print ("nodata called for: ", remoteip, getlocaladdress(), domain, qtype)
	if qtype ~= pdns.AAAA then return -1, {} end  --  only AAAA records

	setvariable()
    return "getFakeAAAARecords", domain, "fe80::21b:77ff:0:0"
end

-- records contains the entire packet, ready for your modifying pleasure
function postresolve ( remoteip, domain, qtype, records, origrcode )
	print ("postresolve called for: ", remoteip, getlocaladdress(), domain, qtype, origrcode)

	for key,val in ipairs(records)
	do
		if(val.content == '173.201.188.46' and val.qtype == pdns.A)
		then
			val.content = '127.0.0.1'
			setvariable()
		end
		if val.qtype == pdns.A and matchnetmask(remoteip, "192.168.0.0/16") and matchnetmask(val.content, "85.17.219.0/24")
		then
			val.content = string.gsub(val.content, "^85.17.219.", "192.168.219.", 1)
			setvariable()
		end

	--	print(val.content)
	end
	return origrcode, records
end

function prequery ( dnspacket )
	-- pdnslog ("prequery called for ".. tostring(dnspacket) )
	qname, qtype = dnspacket:getQuestion()
	pdnslog ("q: ".. qname.." "..qtype)
	if qtype == pdns.A and qname == "www.domain.com"
	then
		pdnslog ("calling dnspacket:setRcode")
		dnspacket:setRcode(pdns.NXDOMAIN)
		pdnslog ("called dnspacket:setRcode")
		pdnslog ("adding records")
		ret = {}
		ret[1] = {qname=qname, qtype=qtype, content="1.2.3.4", place=2}
		ret[2] = {qname=qname, qtype=pdns.TXT, content=os.date("Retrieved at %Y-%m-%d %H:%M"), ttl=ttl}
		dnspacket:addRecords(ret)
		pdnslog ("returning true")
		return true
	end
	pdnslog ("returning false")
	return false
end
