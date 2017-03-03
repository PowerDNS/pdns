
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

function gettag()
    print "gettag"
    local kvresp = newCA("127.0.0.1:5555")
    print "calling kvquery"
    local res = kvquery(kvresp, "DOMAIN www.example.com")
    print ("kvquery "..res)
end

function preresolve (dq)
    print ("prereesolve handler called for: "..dq.remoteaddr:toString().. ", local: ".. dq.localaddr:toString()..", ".. dq.qname:toString()..", ".. dq.qtype)
    local kvresp = newCA("127.0.0.1:5555")
    local domaindetails = kvquery(kvresp, "DOMAIN "..dq.qname:toString())
    if(domaindetails == "0") 
        then
        print("This domain needs no filtering, not looking up this domain")
        return false
    end
    print("Domain might need filtering for some users")
    dq.variable = true -- disable packet cache

    local ipdetails = kvquery(kvresp, "IP "..dq.remoteaddr:toString())
    print("So status of IP is "..ipdetails.." and status of domain is "..domaindetails)
    if(domaindetails=="1" and ipdetails=="1")
        then
        print("IP wants filtering and domain is of the filtered kind")
        dq:addAnswer(pdns.CNAME, "blocked.powerdns.com")
        return true
    else
        print("Returning false (normal resolution should proceed, for this user)")
        return false
    end
end


