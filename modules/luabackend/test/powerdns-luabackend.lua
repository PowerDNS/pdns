--remember, this is just a test case to see that the minimal backend does work...

local logger = logger
local pairs = pairs
local type = type

local log_error = log_error
local dnspacket = dnspacket


local domains_id = {}
local domains_name = {}
local records = {}


domains_name["test.com"] = {domain_id = 11, name = "test.com", type = "NATIVE", soa = { hostmaster = "ahu.test.com", nameserver = "ns1.test.com", serial = 2005092501, refresh = 28800, retry = 7200, expire = 604800, default_ttl = 86400, ttl = 3600 } }
domains_id["11"] = domains_name["test.com"]


records["test.com"] = {
    {domain_id = 11, name = "test.com", type = "NS", ttl = 120, content = "ns1.test.com"},
    {domain_id = 11, name = "test.com", type = "NS", ttl = 120, content = "ns2.test.com"},
}
records["ns1.test.com"] = {
    {domain_id = 11, name = "ns1.test.com", type = "A", ttl = 120, content = "10.11.12.14"},
    {domain_id = 11, name = "ns1.test.com", type = "AAAA", ttl = 120, content = "1:2:3:4:5:6:7:9"}
}
records["ns2.test.com"] = {
    {domain_id = 11, name = "ns2.test.com", type = "A", ttl = 120, content = "10.11.12.15"},
    {domain_id = 11, name = "ns2.test.com", type = "AAAA", ttl = 120, content = "1:2:3:4:5:6:7:10"}
}

records["www.test.com"] = { {domain_id = 11, name = "www.test.com", type = "CNAME", ttl = 120, content = "host.test.com"} }
records["host.test.com"] = {
    {domain_id = 11, name = "host.test.com", type = "A", ttl = 120, content = "10.11.12.13"},
    {domain_id = 11, name = "host.test.com", type = "AAAA", ttl = 120, content = "1:2:3:4:5:6:7:8"}
}



function list(target, domain_id)
    logger(log_error, "(l_list)", "target:", target, " domain_id:", domain_id )

    return false
end

local size, c, r, n, nn, q_type, q_name, domainid
local remote_ip, remote_port, local_ip

function lookup(qtype, qname, domain_id)
--    logger(log_error, "(l_lookup)", "qtype:", qtype, " qname:", qname, " domain_id:", domain_id )
    q_type = qtype
    q_name = qname
    domainid = domain_id

    r = records[q_name]

    c = 0
    size = 0

    remote_ip, remote_port, local_ip = dnspacket()
--    logger(log_error, "(l_lookup) dnspacket", "remote:", remote_ip, " port:", remote_port, " local:", local_ip)

    if type(r) == "table" then
        size = #r
    end
--    logger(log_error, "(l_lookup)", "size:", size)
end

function get()
--    logger(log_error, "(l_get) BEGIN")

    while c < size do
        c = c + 1
        if (q_type == "ANY" or q_type == r[c]["type"]) then
--            for kk,vv in pairs(r[c]) do
--                logger(log_error, kk, type(vv), vv)
--            end
            return r[c]
        end
    end

--    logger(log_error, "(l_get) END")
    return false
end

local k,v,kk,vv

function getsoa(name)
--    logger(log_error, "(l_getsoa) BEGIN", "name:", name)

    r = domains_name[name]
    if type(r) == "table" then
--        logger(log_error, type(r), type(r["soa"]))
        return r["soa"]
    end

--    logger(log_error, "(l_getsoa) END NOT FOUND")
end

logger(log_error, "powerdns-luabackend starting up!")


for k,v in pairs(QTypes) do
--    logger(log_error, k, v)
end

for k,v in pairs(records) do
    for kk,vv in pairs(v) do
--        logger(log_error, kk, type(vv), vv["type"])
    end
end
