--[[ 
	Sometimes, domains break when IPv6 is used. A common example is
	Netflix via an IPv6 tunnel, which Netflix interprets as a proxying 
	attempt.
	
	This function strips IPv6 from one or more subdomains. It can be called
	with a single domain, like "netflix.com", or with a domain set, which
	is more efficient and scales very well.
	
	This file is meant for including, so you can call it from your preresolve.
	Alternatively, uncomment the activation code below and you can load it
	directly into your resolver with 'lua-dns-script=strip-ipv6-from-domains.lua'.
]]--

function preventIPv6ForDomains(dq, domain)
	local ds=newDS()
	if(type(domain) == "string") then
		ds:add{domain}
	else
		ds=domain
	end
	if(dq.qtype ~= pdns.AAAA) then return false end
	if(ds:check(dq.qname)) then
		dq.rcode = 0
		return true
	end
	return false
end

-- To activate, uncomment the block below:

--[[
netflix=newDS()
netflix:add{"netflix.com"}

function preresolve(dq)
	return preventIPv6ForDomains(dq, netflix)
end
]]--