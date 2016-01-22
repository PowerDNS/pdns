
--[[ 
This implements a two-step domain filtering solution where the status of an IP address
and a domain name need to be looked up.
To do so, we use the udpQuestionResponse answers which generically allows us to do asynchronous
lookups via UDP.
Such lookups can be slow, but they won't block PowerDNS while we wait for them.

To benefit from this hook, 
..

To test, use the 'kvresp' example program provided.
--]]

function preresolve (dq)
	print ("prereesolve handler called for: "..dq.remoteaddr:toString().. ", local: ".. dq.localaddr:toString()..", ".. dq.qname:toString()..", ".. dq.qtype)
	dq.followupFunction="udpQueryResponse"
	dq.udpCallback="gotipdetails"
	dq.udpQueryDest=newCA("127.0.0.1:5555")
	dq.udpQuery = "IP "..dq.remoteaddr:toString()
        dq.variable = true;
	return true;
end

function gotipdetails(dq)
	print("gotipdetails called, got: "..dq.udpAnswer)
        if(dq.udpAnswer ~= "1") 
        then
                print("IP address wants no filtering, not looking up this domain")
                dq.followupFunction=""   
                return false
        end
	local data={}
	data["ipdetails"]= dq.udpAnswer
	dq.data=data 
	dq.udpQuery="DOMAIN "..dq.qname:toString()
	dq.udpCallback="gotdomaindetails"
	print("returning true in gotipdetails")
	return true
end

function gotdomaindetails(dq)
        dq.followupFunction=""
	print("So status of domain is "..dq.udpAnswer.." and status of IP is "..dq.data.ipdetails)
	if(dq.data.ipdetails=="1" and dq.udpAnswer=="1")
	then
		print("IP wants filtering and domain is of the filtered kind")
		dq:addAnswer(pdns.CNAME, "blocked.powerdns.com")
		return true
	else
                print("Returning false (normal resolution should proceed)")
		return false
	end
end



