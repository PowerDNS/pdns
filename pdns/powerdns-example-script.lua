pdnslog("pdns-recursor Lua script starting!", pdns.loglevels.Warning)

blockset = newDS()
blockset:add{"powerdns.org", "xxx"}

dropset = newDS();
dropset:add("123.cn")

malwareset = newDS()
malwareset:add("nl")

magic2 = newDN("www.magic2.com")


magicMetric = getMetric("magic")

-- shows the various ways of blocking, dropping, changing questions
-- return false to say you did not take over the question, but we'll still listen to 'variable'
-- to selectively disable the cache
function preresolve(dq)
	print("Got question for "..dq.qname:toString().." from "..dq.remoteaddr:toString().." to "..dq.localaddr:toString())

        local ednssubnet=dq:getEDNSSubnet()
	if(ednssubnet) then
        	print("Packet EDNS subnet source: "..ednssubnet:toString()..", "..ednssubnet:getNetwork():toString())
        end
                                        

	local a=dq:getEDNSOption(3)
	if(a) then
		print("There is an EDNS option 3 present: "..a)
	end

	loc = newCA("127.0.0.1")
	if(dq.remoteaddr:equal(loc))
	then
		print("Query from loopback")
	end

	-- note that the comparisons below are CaSe InSensiTivE and you don't have to worry about trailing dots
	if(dq.qname:equal("magic.com"))
	then
		magicMetric:inc()
		print("Magic!")
	else
		print("not magic..")
	end

	if(dq.qname:__eq(magic2)) -- we hope to improve this syntax
	then
		print("Faster magic") -- compares against existing DNSName
	end                           -- sadly, dq.qname == magic2 won't work yet
        
        if blockset:check(dq.qname) then
                dq.variable = true  -- disable packet cache in any case
                if dq.qtype == pdns.A then
	        	dq:addAnswer(pdns.A, "1.2.3.4")
        		dq:addAnswer(pdns.TXT, "\"Hello!\"", 3601) -- ttl    	
        		return true;
        	end
        end
        
        if dropset:check(dq.qname) then
        	dq.rcode = pdns.DROP  
        	return true;
        end

	        
        
        if malwareset:check(dq.qname) then
		dq:addAnswer(pdns.CNAME, "xs.powerdns.com.")
        	dq.rcode = 0
        	dq.followupFunction="followCNAMERecords"    -- this makes PowerDNS lookup your CNAME
        	return true;
        end        
        
	return false; 
end


-- this implements DNS64

function nodata(dq)
        if dq.qtype == pdns.AAAA then
        	dq.followupFunction="getFakeAAAARecords"
        	dq.followupName=dq.qname
        	dq.followupPrefix="fe80::"
        	return true
        end
        
        if dq.qtype == pdns.PTR then
        	dq.followupFunction="getFakePTRRecords"
        	dq.followupName=dq.qname
        	dq.followupPrefix="fe80::"
        	return true
        end        
	return false
end


badips = newNMG()
badips:addMask("127.1.0.0/16")

-- this check is applied before any packet parsing is done
function ipfilter(rem, loc, dh)
	print("ipfilter called, rem: ", rem:toStringWithPort(), "loc: ",loc:toStringWithPort(),"match:", badips:match(rem))
	print("id: ",dh:getID(), "aa: ", dh:getAA(), "ad: ", dh:getAD(), "arcount: ", dh:getARCOUNT())
	print("ports: ",rem:getPort(),loc:getPort())
	return badips:match(rem)
end

-- postresolve runs after the packet has been answered, and can be used to change things
-- or still drop
function postresolve(dq)
	print("postresolve called for ",dq.qname:toString())
	local records = dq:getRecords()
	for k,v in pairs(records) do
		print(k, v.name:toString(), v:getContent())
		if v.type == pdns.A and v:getContent() == "185.31.17.73"
		then
			print("Changing content!")
			v:changeContent("130.161.252.29")
			v.ttl=1
		end
	end
	dq:setRecords(records)
	return true
end

nxdomainsuffix=newDN("com")

function nxdomain(dq)
	print("Hooking: ",dq.qname:toString())
	if dq.qname:isPartOf(nxdomainsuffix)
	then
		dq.rcode=0 -- make it a normal answer
		dq:addAnswer(pdns.CNAME, "ourhelpfulservice.com")
		dq:addAnswer(pdns.A, "1.2.3.4", 60, "ourhelpfulservice.com")
		return true
	end
	return false
end