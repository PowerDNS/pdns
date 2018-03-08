domains = { "test.invalid.", "test.unit." }

records = {}

records["test.invalid."] = {
  SOA = { "ns1.test.invalid. root.test.invalid. 20180115 1 2 3 4" },
  NS = { "ns1.test.invalid.", "ns2.test.invalid." },
  TXT = { "\"this is a test record\" \"in two parts\"" }
}

records["ns1.test.invalid."] = {
  A = { "127.0.0.1" },
  AAAA = { "fe80::1" }
}

records["ns2.test.invalid."] = {
  A = { "127.0.0.2" },
  AAAA = { "fe80::2" }
}

records["www.test.invalid."] = {
  A = { "127.0.0.3" },
  AAAA = { "fe80::3" }
}

records["shell.test.invalid."] = {
  A = { "127.0.0.4" },
  AAAA = { "fe80::4" }
}

records["_ssh._tcp.service.test.invalid."] = {
  SRV = { "0 0 22 shell.test.invalid." }
}

records["test.unit."] = {
  SOA = { "ns1.test.invalid. root.test.invalid. 20180115 1 2 3 4" },
  NS = { "ns1.test.invalid.", "ns2.test.invalid." },
}

function get_domain_id(qname)
  for id, dom in ipairs(domains) do
    if qname == newDN(dom) or qname:isPartOf(newDN(dom)) then
      return id
    end
  end
  return -1
end

--function dns_get_domaininfo(dom)
--  if dom == newDN("test.invalid") then
--    return { id=1, serial=20180115 }
--  end
--  if dom == newDN("test.unit") then
--    return { id=2, serial=20180115 }
--  end
--
--  return false
--end

function dns_lookup(qtype, qname, d_id, ctx)
  ret = {}

  d_id = get_domain_id(qname)

  if d_id == -1 then
    return {}
  end

  rr = records[tostring(qname)]
  if rr ~= nil then
     if qtype:getName() == "ANY" then
       for k, v in pairs(rr) do
         for idx,row in ipairs(v) do
           table.insert(ret, { name = qname, type = newQType(k), content = row, ttl = 60, domain_id = d_id })
         end
       end
     elseif rr[qtype:getName()] ~= nil then
       for idx,row in ipairs(rr[qtype:getName()]) do
         table.insert(ret, { name = qname, type = qtype, content = row, ttl = 60, domain_id = d_id })
       end
     end
  end

  return ret
end

function dns_list(qname, id)
  if id == -1 then
    id = get_domain_id(qname)
    if id == -1 then
      return false
    end
  end
  qname = newDN(domains[id])

  ret = {}

  for name,rr in pairs(records) do
    if newDN(name):isPartOf(qname) then
      for k, v in pairs(rr) do
        for idx,row in ipairs(v) do
          table.insert(ret, { name = newDN(name), type = newQType(k), content = row, ttl = 60, domain_id = d_id })
        end
      end
    end
  end

  return ret
end
