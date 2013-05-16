-- this small script implements dns64 without any specials or customization
-- the pref64 is "fe80::21b::77ff:0:0", and it appears twice, plus once reversed

function nodata ( remoteip, domain, qtype, records )
	if qtype ~= pdns.AAAA then return -1, {} end  --  only AAAA records
        setvariable()
        return "getFakeAAAARecords", domain, "fe80::21b:77ff:0:0"
end     

function endswith(s, send)
	return #s >= #send and s:find(send, #s-#send+1, true) and true or false
end

-- note that the ip6.arpa string ends on a .
-- it is the reverse of the pref64 address above

function preresolve ( remoteip, domain, qtype )
	if qtype ==pdns.PTR and endswith(domain, "f.f.7.7.b.1.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.")
        then
        	return "getFakePTRRecords", domain, "fe80::21b::77ff:0:0"
	end
	return -1, {}
end
