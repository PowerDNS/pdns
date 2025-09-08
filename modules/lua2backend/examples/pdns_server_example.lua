-- Powerdns server lua example
-- $Id: pdns_server_example.lua,v 1643ea3f7d25 2025/09/08 17:47:01 grin $
--
-- Simulates a "smart" country lookup DNSBL, handling multiple
-- countries for matching in the query, also a lot of log spam.
--
-- contributed by Peter 'grin' Gervai, 2025
--
-- test: dig 4.3.2.1.aa-td-bq.666666.c.example.hu
--       dig 4.3.2.1.aa-td-qq-bq.666666.c.example.hu
--
-- config:
--  launch += lua2
--  lua2-api = 2
--  # lua2-query-logging = yes
--  lua2-filename = /etc/powerdns/pdns_server_example.lua

pdnslog( "lua: starting the backend")

local base_labels = { "c", "example", "hu" } -- this is our base zone, word by word
local base_domain = ""
for _, val in ipairs(base_labels) do -- generate stringy base domain
	base_domain = base_domain .. val .. "."
end

-- required function: the lookup
function dns_lookup(qtype, qname, domain_id, ctx)
        pdnslog("Got a request for " .. tostring(qname))

        local peer_ip = ctx.source_address
        if peer_ip ~= nil and peer_ip ~= "127.0.0.1" then -- state of the art access control
            pdnslog("Access denied for the ip "..peer_ip)
            return {}
        end

        if qtype:getName() ~= "A" and qtype:getName() ~= "ANY" then
                -- we only serve A/ANY here (only get ANY from pdns_server)
                pdnslog("We only server A/ANY! not "..qtype:getName())
                return {}
        end

        if qname:toString() == base_domain then
            -- we got a query for the base domain, let's fake a SOA to keep subqueries coming
        	return generate_SOA(qname)
        end

        if qname:countLabels() ~= 9 then -- we need exactly 9 words
                pdnslog("We need the Right Length, not "..qname:countLabels())
                return {}
        end

        local labels = qname:getRawLabels() -- split words into a table
        -- skip wildcard queries (both external and internal)
        if labels[1] == "*" then return {} end

        for i, lbl in ipairs(base_labels) do -- verify fixed word positions
                if lbl ~= labels[i+6] then
                        pdnslog("Label pos:" .. i .. " mismatch: "..labels[i+6].." vs "..lbl)
                        return {}
                end
        end

        -- check API key
        if not verified_api_key(labels[6], peer_ip) then
                pdnslog("API key mismatch: " .. labels[6] .. " from " .. peer_ip)
                return {}
        end

        -- generate a table of countries from the query
        local countries = {}
        for c in string.gmatch(labels[5], "[^-]+") do -- split by '-'
                if not string.find(c, "^%a%a%a?%a?$") then -- 2-4 letters
                        pdnslog("Illegal country: " ..c)
                        return {}
                end
                countries[string.lower(c)] = true -- a "set"
        end

        -- get ip from query (the lazy way)
        local ip_numbers={}
        for i = 1,4 do table.insert(ip_numbers, labels[5-i]) end
        local query_ip = table.concat(ip_numbers, ".")

        -- lookup ip
        local ip_country = string.lower(lookup_ip_country(query_ip))
        if countries[ip_country] ~= nil then
                -- match! return A and AAAA, and let pdns_server to pick what it wants
                -- (which will be ipv4, v6 is useless here)
                return {
                	{ name=qname, type=newQType("A"), content="127.0.0.1", ttl=86400 },
                	{ name=qname, type=newQType("AAAA"), content="2001:db8::42", ttl=6 },
                }
        end
        return {}
end

function generate_SOA(qname) -- generate a fake soa, also set domain_id to something (not required, -1 is default)
	return {{ name=qname, type="SOA", content="local. admin.local. 1 7200 3600 86400 3600", ttl=6, domain_id=3 }}
end

function verified_api_key(key, ip) -- very secure best industrial practice method (shall use some db backend for example)
        if key == "666666" then return true end
        pdnslog("API key wrongy-wrongy!")
        return false
end

function lookup_ip_country(ip) -- this would do some lookups, too.
	return "QQ"
end

-- this is kind of optional, but used by the next function
function dns_get_domaininfo(domain)
	if tostring(domain) == base_domain then return { serial=os.time() } end -- we use all the defaults
	return nil
end

-- this is required if you want to serve the domain!
-- returns all the domains served by this backend.
function dns_get_all_domains()
	local domains={}
	domains[newDN(base_domain)] = dns_get_domaininfo(newDN(base_domain))
	return domains
end
