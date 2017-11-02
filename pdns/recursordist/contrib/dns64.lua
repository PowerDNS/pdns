-- this small script implements dns64 without any specials or customization
prefix = "fe80::21b:77ff:0:0"

function nodata ( dq )
  if dq.qtype ~= pdns.AAAA then
    return false
  end  --  only AAAA records

  -- don't fake AAAA records if DNSSEC validation failed
  if dq.validationState == pdns.validationstates.Bogus then
     return false
  end

  dq.followupFunction = "getFakeAAAARecords"
  dq.followupPrefix = prefix
  dq.followupName = dq.qname
  return true
end

-- the ip6.arpa address is the reverse of the prefix address above
function preresolve ( dq )
  if dq.qtype == pdns.PTR and dq.qname:isPartOf(newDN("f.f.7.7.b.1.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.")) then
    dq.followupFunction = "getFakePTRRecords"
    dq.followupPrefix = prefix
    dq.followupName = dq.qname
    return true
  end
  return false
end
