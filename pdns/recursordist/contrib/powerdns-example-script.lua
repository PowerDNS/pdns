pdnslog("pdns-recursor Lua script starting!", pdns.loglevels.Warning)

blockset = newDS()
blockset:add{"powerdns.org", "xxx"}

dropset = newDS()
dropset:add("123.cn")

malwareset = newDS()
malwareset:add("nl")

magic2 = newDN("www.magic2.com")

magicMetric = getMetric("magic")

badips = newNMG()
badips:addMask("127.1.0.0/16")

-- this check is applied before any packet parsing is done
function ipfilter(rem, loc, dh)
  pdnslog("ipfilter called, rem: "..rem:toStringWithPort().." loc: "..loc:toStringWithPort().." match:"..tostring(badips:match(rem)))
  pdnslog("id: "..dh:getID().." aa: "..tostring(dh:getAA()).." ad: "..tostring(dh:getAD()).." arcount: "..dh:getARCOUNT())
  pdnslog("ports: "..rem:getPort().." "..loc:getPort())
  return badips:match(rem)
end

-- shows the various ways of blocking, dropping, changing questions
-- return false to say you did not take over the question, but we'll still listen to 'variable'
-- to selectively disable the cache
function preresolve(dq)
  pdnslog("Got question for "..dq.qname:toString().." from "..dq.remoteaddr:toString().." to "..dq.localaddr:toString())

  local ednssubnet = dq:getEDNSSubnet()
  if ednssubnet then
    pdnslog("Packet EDNS subnet source: "..ednssubnet:toString()..", "..ednssubnet:getNetwork():toString())
  end

  local a = dq:getEDNSOption(3)
  if a then
    pdnslog("There is an EDNS option 3 present: "..a)
  end

  loc = newCA("127.0.0.1")
  if dq.remoteaddr:equal(loc) then
    pdnslog("Query from loopback")
  end

  -- note that the comparisons below are CaSe InSensiTivE and you don't have to worry about trailing dots
  if dq.qname:equal("magic.com") then
    magicMetric:inc()
    pdnslog("Magic!")
  else
    pdnslog("not magic..")
  end

  if dq.qname == magic2 then
    pdnslog("Faster magic") -- compares against existing DNSName
  end

  if blockset:check(dq.qname) then
    dq.variable = true      -- disable packet cache in any case
    if dq.qtype == pdns.A then
      dq:addAnswer(pdns.A, "1.2.3.4")
      dq:addAnswer(pdns.TXT, "\"Hello!\"", 3601) -- ttl
      return true
    end
  end

  if dropset:check(dq.qname) then
   pdnslog("dopping query")
   dq.appliedPolicy.policyKind = pdns.policykinds.Drop
   return false -- recursor still needs to handle the policy
  end

  if malwareset:check(dq.qname) then
    dq:addAnswer(pdns.CNAME, "blog.powerdns.com.")
    dq.rcode = 0
    dq.followupFunction = "followCNAMERecords"    -- this makes PowerDNS lookup your CNAME
    return true
  end

  return false
end

-- this implements DNS64

function nodata(dq)
  if dq.qtype == pdns.AAAA then
    dq.followupFunction = "getFakeAAAARecords"
    dq.followupName = dq.qname
    dq.followupPrefix="fe80::"
    return true
  end

  if dq.qtype == pdns.PTR then
    dq.followupFunction = "getFakePTRRecords"
    dq.followupName = dq.qname
    dq.followupPrefix = "fe80::"
    return true
  end
  return false
end

-- postresolve runs after the packet has been answered, and can be used to change things
-- or still drop
function postresolve(dq)
  pdnslog("postresolve called for "..dq.qname:toString())
  local records = dq:getRecords()
  for k,v in pairs(records) do
    pdnslog(k.." "..v.name:toString().." "..v:getContent())
    if v.type == pdns.A and v:getContent() == "185.31.17.73" then
      pdnslog("Changing content!")
      v:changeContent("130.161.252.29")
      v.ttl = 1
    end
  end
  dq:setRecords(records)
  return true
end

nxdomainsuffix = newDN("com")

function nxdomain(dq)
  pdnslog("nxdomain called for: "..dq.qname:toString())
  if dq.qname:isPartOf(nxdomainsuffix) then
    dq.rcode = 0 -- make it a normal answer
    dq:addAnswer(pdns.CNAME, "ourhelpfulservice.com")
    dq:addAnswer(pdns.A, "1.2.3.4", 60, "ourhelpfulservice.com")
    return true
  end
  return false
end
