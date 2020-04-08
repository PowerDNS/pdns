
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
	print ("preresolve handler called for: "..dq.remoteaddr:toString().. ", local: ".. dq.localaddr:toString()..", ".. dq.qname:toString()..", ".. dq.qtype)
	dq.followupFunction="udpQueryResponse"
	dq.udpCallback="gotdomaindetails"
	dq.udpQueryDest=newCA("127.0.0.1:5555")
	dq.udpQuery = "DOMAIN "..dq.qname:toString()
	return true;
end

function gotdomaindetails(dq)
	print("gotdomaindetails called, got: "..dq.udpAnswer)
        if(dq.udpAnswer == "0") 
        then
                print("This domain needs no filtering, not looking up this domain")
                dq.followupFunction=""   
                return false
        end
        print("Domain might need filtering for some users")
        dq.variable = true -- disable packet cache
	local data={}
	data["domaindetails"]= dq.udpAnswer
	dq.data=data 
	dq.udpQuery="IP "..dq.remoteaddr:toString()
	dq.udpCallback="gotipdetails"
	print("returning true in gotipdetails")
	return true
end

function gotipdetails(dq)
        dq.followupFunction=""
	print("So status of IP is "..dq.udpAnswer.." and status of domain is "..dq.data.domaindetails)
	if(dq.data.domaindetails=="1" and dq.udpAnswer=="1")
	then
		print("IP wants filtering and domain is of the filtered kind")
		dq:addAnswer(pdns.CNAME, "blocked.powerdns.com")
		return true
	else
                print("Returning false (normal resolution should proceed, for this user)")
		return false
	end
end



