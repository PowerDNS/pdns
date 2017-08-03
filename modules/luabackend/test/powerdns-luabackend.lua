-- An example of the minimal functions needed to test the lua backend

local logger = logger
local pairs, ipairs = pairs, ipairs
local type = type

local log_error = log_error
local log_debug = log_debug
local dnspacket = dnspacket

local remote_ip, remote_port, local_ip

local origin, ttl
local domains = {}

-- shared state between lookup and get functions
local domain_id, q_name, q_type
local c, r, size


function content_from_soatab(t)
    return ("%s %s %u %u %u %u %u"):format(
            t.nameserver, t.hostmaster,
            t.serial, t.refresh, t.retry,
            t.expire, t.default_ttl
        )
end

ttl = 3600
origin = "test.com."
domains[origin] = {
    domain_id = 1 + #domains,
    name = origin,
    soa = {
        ttl = ttl,
        nameserver = "ns1."..origin,
        hostmaster = "ahu.example.com.",
        serial = 2005092501,
        refresh = 28800,
        retry = 7200,
        expire = 604800,
        default_ttl = 86400,
    },
    records = {},
}
domains[domains[origin].domain_id] = domains[origin]


domains[origin].records[origin] = {
    --{qtype = "SOA", ttl = domains[origin].soa.ttl, content = content_from_soatab(domains[origin].soa)},
    {qtype = "NS", ttl = ttl, content = "ns1."..origin},
    {qtype = "NS", ttl = ttl, content = "ns2."..origin},
    {qtype = "MX", ttl = ttl, content = "10 ."},
    {qtype = "MX", ttl = ttl, content = "15 smtp-servers."..origin},
}
domains[origin].records["ns1."..origin] = {
    {qtype = "A", ttl = ttl, content = "1.1.1.1"},
}
domains[origin].records["ns2."..origin] = {
    {qtype = "A", ttl = ttl, content = "2.2.2.2"},
}

domains[origin].records["toroot."..origin] = {
    {qtype = "CNAME", ttl = ttl, content = "."},
}
domains[origin].records["www."..origin] = {
    {qtype = "CNAME", ttl = ttl, content = "server1."..origin},
}
domains[origin].records["server1."..origin] = {
    {qtype = "A", ttl = ttl, content = "1.2.3.4"},
    {qtype = "RP", ttl = ttl, content = "ahu.ds9a.nl. counter"},
}
domains[origin].records["*.test."..origin] = {
    {qtype = "CNAME", ttl = ttl, content = "server1."..origin},
}
domains[origin].records["www.test."..origin] = {
    {qtype = "A", ttl = ttl, content = "4.3.2.1"},
}
domains[origin].records["sub.test."..origin] = {
    {qtype = "NS", ttl = ttl, content = "ns-test.example.net."},
}
domains[origin].records["enum."..origin] = {
    {qtype = "NAPTR", ttl = ttl, content = [=[100 50 "u" "e2u+sip" "" testuser.domain.com.]=]},
}
domains[origin].records["counter."..origin] = {
    {qtype = "A", ttl = ttl, content = "1.1.1.5"},
}
domains[origin].records["_ldap._tcp.dc."..origin] = {
    {qtype = "SRV", ttl = ttl, content = "0 100 389 server2.example.net."},
}
domains[origin].records["_double._tcp.dc."..origin] = {
    {qtype = "SRV", ttl = ttl, content = "0 100 389 server1"..origin},
    {qtype = "SRV", ttl = ttl, content = "1 100 389 server1"..origin},
}
domains[origin].records["_root._tcp.dc."..origin] = {
    {qtype = "SRV", ttl = ttl, content = "0 0 0 ."},
}
domains[origin].records["blah."..origin] = {
    {qtype = "NS", ttl = ttl, content = "blah."..origin},
    {qtype = "A", ttl = ttl, content = "192.168.6.1"},
}
domains[origin].records["very-long-txt."..origin] = {
    {qtype = "TXT", ttl = ttl, content = [=["A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long!"]=]},
}
domains[origin].records["within-server."..origin] = {
    {qtype = "CNAME", ttl = ttl, content = "outpost.example.com."},
}
domains[origin].records["_underscore."..origin] = {
    {qtype = "TXT", ttl = ttl, content = [=["underscores are terrible"]=]},
}
domains[origin].records["b.c."..origin] = {
    {qtype = "A", ttl = ttl, content = "5.6.7.8"},
}
domains[origin].records["*.a.b.c."..origin] = {
    {qtype = "A", ttl = ttl, content = "8.7.6.5"},
}
domains[origin].records["aland."..origin] = {
    {qtype = "TXT", ttl = ttl, content = [=["\195\133LAND ISLANDS"]=]},
}
domains[origin].records["hightxt."..origin] = {
    {qtype = "TXT", ttl = ttl, content = [=["v=spf1 mx ip4:78.46.192.210 -all"]=]},
    {qtype = "SPF", ttl = ttl, content = [=["v=spf1 mx ip4:78.46.192.210 -all"]=]},
}
domains[origin].records["d."..origin] = {
    {qtype = "DNAME", ttl = ttl, content = "d2.test2.com."},
}
domains[origin].records["interrupted-rrset."..origin] = {
    {qtype = "A", ttl = ttl, content = "1.1.1.1"},
    {qtype = "TXT", ttl = ttl, content = [=["check AXFR signpipe"]=]},
    {qtype = "A", ttl = ttl, content = "2.2.2.2"},
}


ttl = 120
origin = "example.com."
domains[origin] = {
    domain_id = 1 + #domains,
    name = origin,
    soa = {
        ttl = 100000,
        nameserver = "ns1."..origin,
        hostmaster = "ahu."..origin,
        serial = 2017080201,
        refresh = 28800,
        retry = 7200,
        expire = 604800,
        default_ttl = 86400,
    },
    records = {},
}
domains[domains[origin].domain_id] = domains[origin]


domains[origin].records[origin] = {
    --{qtype = "SOA", ttl = domains[origin].soa.ttl, content = content_from_soatab(domains[origin].soa)},
    {qtype = "NS", ttl = ttl, content = "ns1."..origin},
    {qtype = "A", ttl = ttl, content = "10.9.8.7" },
    {qtype = "AAAA", ttl = ttl, content = "10:9:8::7" },
}
domains[origin].records["ns1."..origin] = {
    {qtype = "A", ttl = 120, content = "10.9.8.6" },
    {qtype = "AAAA", ttl = 120, content = "10:9:8::6" },
}


function table_deepjoin(tab1, tab2)
    local new = {}
    local seen = {}

    if tab1 then
        seen[tab1] = new
    end
    if tab2 then
        seen[tab2] = new
    end

    local function dj(ret, tab)
        if not tab then
            return ret
        end

        local k, v
        for k,v in pairs(tab) do
            if ("table" ~= type(v)) then
                if not ret[k] then
                    ret[k] = v
                end
            elseif seen[v] then
                ret[k] = seen[v]
            elseif ("table" == type(v)) then
                if not ret[k] then
                    ret[k] = table_deepjoin(v, nil)
                else
                    ret[k] = table_deepjoin(ret[k], v)
                end
                seen[v] = ret[k]
            end
        end

        return ret
    end

    new = dj(new, tab1)
    new = dj(new, tab2)

    return new
end

-- Args:
--    qname string: "test.com."
--    domainid number: 1
function list(qname, domainid)
    logger(log_debug, "(l_list) begin")
    q_type = "ANY"
    q_name = qname
    domain_id = domainid
    logger(log_debug, "(l_list)", "target:", q_name, "domain_id:", domain_id)

    c = 0
    r = nil
    size = 0

    local tab = domains[domain_id] or domains[q_name:lower()]
    if (("table" == type(tab)) and ("table" == type(tab.records))) then
        r = {}
        local k, v, kk, vv
        for k, v in pairs(tab.records) do
            for kk, vv in ipairs(v) do
                r[1 + #r] = table_deepjoin(vv, {domain_id = domain_id, qname = k, name = k})
            end
        end
    end

    if ("table" == type(r)) then
        size = #r
        logger(log_debug, "(l_getsoa)", "size:", size)
        logger(log_debug, "(l_getsoa) end: success")
        return true
    end

    logger(log_debug, "(l_getsoa) end: not found")
    return false
end

-- Args:
--    qtype table: { name = "SOA", code = 6 }
--    qname string: "test.com."
--    domainid number: 1
function lookup(qtype, qname, domainid)
    logger(log_debug, "(l_lookup) begin")
    q_type = ("table" == type(qtype)) and qtype.name or qtype
    q_name = qname
    domain_id = domainid
    logger(log_debug, "(l_lookup)", "q_type:", q_type, "q_name:", q_name, "domain_id:", domain_id)

    if (0 < domain_id) then
        r = domains[domain_id].records[q_name:lower()]
    else
        -- domain_id of -1 means we need to search all the records
        local k, v, kk, vv
        for k, v in ipairs(domains) do
            if ("table" == type(v.records)) then
                for kk, vv in ipairs(v.records) do
                    if (q_name:lower() == kk) then
                        r = vv
                        domain_id = v.domain_id
                    end
                end
            end
        end
    end

    c = 0
    size = 0

    -- remote_ip, remote_port, local_ip = dnspacket()
    -- logger(log_debug, "(l_lookup)", "dnspacket", "remote:", remote_ip, "port:", remote_port, "local:", local_ip)

    if ("table" == type(r)) then
        size = #r
    end
    logger(log_debug, "(l_lookup)", "size:", size)
    logger(log_debug, "(l_lookup) end")
end

function get()
    logger(log_debug, "(l_get) begin")

    local tab
    local kk, vv
    while c < size do
        c = c + 1
        if (("ANY" == q_type) or (r[c].qtype == q_type)) then
            for kk,vv in ipairs(r[c]) do
                logger(log_debug, "(l_get)", kk, type(vv), vv)
            end
            tab = table_deepjoin(r[c], {domain_id = domain_id, qname = q_name:lower(), name = q_name:lower()})
            logger(log_debug, "(l_get)", tab.domain_id, tab.qname, tab.ttl, "IN", tab.qtype, tab.content)
            logger(log_debug, "(l_get) end: success")
            return tab
        end
    end

    logger(log_debug, "(l_get) end: not found")
    return false
end

-- Args:
--    qname string: "test.com."
function getsoa(qname)
    logger(log_debug, "(l_getsoa) begin")
    logger(log_debug, "(l_getsoa)", q_type, "qname:", qname)

    local tab
    r = domains[qname:lower()]
    if (("table" == type(r)) and ("table" == type(r.soa))) then
        tab = table_deepjoin({qname = qname, domain_id = r.domain_id}, r.soa)
        logger(log_debug, "(l_getsoa)", r.domain_id, r.name, r.soa.ttl, content_from_soatab(tab))
        logger(log_debug, "(l_getsoa) end: success")
        return tab
    end

    logger(log_debug, "(l_getsoa) end: not found")
end

logger(log_debug, "the powerdns-luabackend is starting up!")

--for k,v in pairs(QTypes) do
--    logger(log_debug, k, v)
--end
