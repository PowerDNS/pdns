
--[[ 
This implements a two-step domain filtering solution where the status of an IP address
and a domain name need to be looked up.
To do so, we use the udpQuestionResponse answers which generically allows us to do asynchronous
lookups via UDP.
Such lookups can be slow, they won't block PowerDNS while we wait for them.

To benefit from this hook, return: "udpQueryResponse", UDP-server, data 
from preresolve (or other hooks).
The 'data' third return value should be a table with the query in there, plus the callback
that needs to be called once the data is in.

We'll add more parameters, like 'timeout' and perhaps 'protocol' as we improve this feature
over time. 

To test, use the 'kvresp' example program provided.
--]]

function preresolve ( remoteip, domain, qtype )
	print ("preresolve handler called for: "..remoteip.. ", local: ".. getlocaladdress()..", ".. domain..", ".. qtype)
	return "udpQueryResponse", "127.0.0.1:5555", {query="IP "..remoteip, callback="getipdetails"}
end

function getipdetails(remoteip, domain, qtype, data)
	 print("In getipdetails, got ".. data.response.. " from '"..remoteip.."',  for '"..remoteip.."'")
	 data.ipstatus=data.response
	 data.query="DOMAIN "..domain
	 data.callback="getdomaindetails"
	 return "udpQueryResponse", "127.0.0.1:5555", data
end

function getdomaindetails(remoteip, domain, qtype, data)
	 print("In getipdetails, got ".. data.response.. " from '"..remoteip.."',  for '"..domain.."'")
	 print("So status of domain is "..data.response.." and status of IP is "..data.ipstatus)
	 if(data.ipstatus=="1" and data.response=="1")
	 then
		print("IP wants filtering and domain is of the filtered kind")
		return 0,{{qtype=pdns.CNAME, content="www.blocked.com", ttl=3602},
		          {qname="www.webserver.com", qtype=pdns.A, content="1.2.3.4", ttl=3602}}
	 else
	        return pdns.PASS, {}
	 end
end



