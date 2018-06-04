-- test script for luabackend

-- the test 'database'

local info = {}
info["example.com."] = {
	id = 11,
	zone = "example.com.",
	serial = '2005092501',
	kind = "NATIVE",
}
info["example.org."] = {
	id = 22,
	zone = "example.org.",
	serial = '2016020516',
	kind = "NATIVE",
}

local keys = {}
keys['example.org.'] = {
	{
		id = '1',
		flags = '256',
		active = 'true',
		content = [[
Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: xU8TVNmCfHfOaWXQ1K503cpf13BOncXJffLl6ZFsLv1YFr1IyX+RSLvZuQ3krLGrAThgZhG1AepOBVGEKKMHlSvlEMHjS3Ef9u+KSUnhf6WLEUste8LBqqWuKqwtBNjgaiJBTP/woanA0CgDZQUua131jrhVwKObTbNHxJTRlHE=
PublicExponent: AQAB
PrivateExponent: H/Lx+mdODcGIluB5tDabjd5bLpNs53dDbTWLrQpzLhivzt7PjnEtoU1pr+FkCeKrAgOS+HQdjzXVdF8Cu2HKtEAbya+2/miH8X/+ZuduB13GH/aGEnwSJ1e6kNSwg6O8f2DfwFGp7ZKI4/fN3ad8BJB7BxUKsO96kTsDvyVmMQE=
Prime1: 5tLkvaua998MARoNTDr80DHe+qmfYVKcFbhFa7Deo0aAmIZhi9LjNvG30F0pn2PIOp0kaL8k9JBt2ganu6acKQ==
Prime2: 2tRfRF636knXuwJaiRACNf/+YoKtuNerzZMSVTLm5yXZxrxWn/eM74RZEs3z3NNSEhUrTFx4geUgwFXOkEg/CQ==
Exponent1: M12K+YpOmgpQqY4al3Qo/kuayz0j8oxnn426JRTe9oah509ANdVgKsHvnbadpJKX5DND/utKVgIt7+67NM8GwQ==
Exponent2: lb7EXnXupv3XCZrnt2lkCe3e9yxzkszLPUcKQZEunziwmSWipZ7yK6lGhu62lQNq4wLneT7CHCleSx+s1eEKeQ==
Coefficient: pOUqrMzliuwVzjlIvpK1kw4gt0Q+C9kt5QwuX+qYQ0Cqlggm1Gpn1sORmq/cSfKWlr5Dk8FpsmfJiXYNbzEpvw==
]]				
	},
	{
		id = '2',
		flags = '257',
		active = 'true',
		content = [[
Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: yjPoq6ffoOnXlU0/45ObxZFrXjQm2q88IehCnwqQBeEwzp+gjxshnz3UKYw7vlh3sRNngddzALCGDW8NUXI8XjbCquThfrt2NWvjSeU2/JkOoWt9JrPiDwCLDazVg4FyIe1hkVyli4zs3VGDgaesxB2KZd+1xsIeZfgFUHzbB4k=
PublicExponent: AQAB
PrivateExponent: M8sWFxoaEyqy2QB/k/iUVwgHu4qaRTvLqFfI8NoQyCDFkreate1aMGLy/G16RCh/CDGTOtQIFi4hOEGw5KLhST+g5Q0aBI3JPEtzj6EhkWEzpC4zxc7UATekIOh3/F4WzHzq7zsRyCusmu2sxl5qf8UvuZvTn9tlOPeFxIbfn3E=
Prime1: +lK3n337+P+kP/bMShKKddRdf/3r69ColakGxlszXNrZ7HxE6/ZrV6SVJN5KzPlbfvggJVNlrQZOABiHuMwtVQ==
Prime2: zsnSouZn6FT0f7ljE243kPcs2WVlaTtSQzZxJwg/D9k6b3dcHfQFbB/YY21x2m2nHkgdgXPvymYfL3/mNCCRZQ==
Exponent1: gPLbZG2hv0LxeYHI+t9SNCCRib1kKrXyIiZQNx4D93FFkWzylBr8cMl3iuZ34d8SIvXumUu8tMTqqWH5iFilgQ==
Exponent2: MFUv7G9aHg2tUCUuqR370uBTFUUD3QLGiXsyG2NsCfJGHEOTvlSI5+rRkvvDvsAebY+Bhf5pL6+K3nlQfyKVmQ==
Coefficient: PL3s7CSTjHmxhutEbN7S1MiBDnYAtr1P8sdf2/dA81qjcRtuZA2IGSXRo3pQBE5gFer5dAyEmeNwzdQhujPhrQ==
]]				
	}
}

local meta = {}
meta['example.org.'] = {
	NSEC3NARROW =  {'1'},
	NSEC3PARAM = {'1 0 100 abba'},
	['SOA-EDIT'] = {},
}

local domains_name = {} 
domains_name["example.com."] = {
	domain_id = 11,
	name = "example.com.",
	type = "NATIVE",
	soa = {
		nameserver = "ns1.example.com.",
		hostmaster = "ahu.example.com.",
		serial = 2005092501,
		refresh = 7200,
		retry = 3600,
		expire = 1209600,
		default_ttl = 3600,
		ttl = 3600
	}
}
domains_name["example.org."] = {
	domain_id = 22,
	name = "example.org.",
	type = "NATIVE",
	soa = {
		nameserver = "nsa.example.org.",
		hostmaster = "ahu.example.org.",
		serial = 2016020516,
		refresh = 7200,
		retry = 3600,
		expire = 1209600,
		default_ttl = 3600,
		ttl = 36000
	}
}

local records = {}
records["example.com."] = {
	{domain_id = 11, name = "example.com.", type = "NS", ttl = 120, content = "ns1.example.com."},
	{domain_id = 11, name = "example.com.", type = "NS", ttl = 120, content = "ns2.example.com."},
}
records["ns1.example.com."] = {
	{domain_id = 11, name = "ns1.example.com.", type = "A", ttl = 120, content = "10.11.12.14"},
	{domain_id = 11, name = "ns1.example.com.", type = "AAAA", ttl = 120, content = "1:2:3:4:5:6:7:9"}
}
records["ns2.example.com."] = {
	{domain_id = 11, name = "ns2.example.com.", type = "A", ttl = 120, content = "10.11.12.15"},
	{domain_id = 11, name = "ns2.example.com.", type = "AAAA", ttl = 120, content = "1:2:3:4:5:6:7:10"}
}
records["www.example.com."] = {
	{domain_id = 11, name = "www.example.com.", type = "CNAME", ttl = 120, content = "host.example.com."} }
records["host.example.com."] = {
	{domain_id = 11, name = "host.example.com.", type = "A", ttl = 120, content = "10.11.12.13"},
	{domain_id = 11, name = "host.example.com.", type = "AAAA", ttl = 120, content = "1:2:3:4:5:6:7:8"}
}
records["example.org."] = { 
	{domain_id = 22, name = "example.org.", type = "NS", ttl = 123, content = "nsa.example.org."},
	{domain_id = 22, name = "example.org.", type = "NS", ttl = 123, content = "nsb.example.org."},
}
records["nsa.example.org."] = {
	{domain_id = 22, name = "nsa.example.org.", type = "A", ttl = 123, content = "192.168.100.100"},
	{domain_id = 22, name = "nsa.example.org.", type = "AAAA", ttl = 123, content = "1:2:3:4:5:6:7:100"}
}
records["nsb.example.org."] = {
	{domain_id = 22, name = "nsb.example.org.", type = "A", ttl = 123, content = "192.168.200.200"},
	{domain_id = 22, name = "nsb.example.org.", type = "AAAA", ttl = 123, content = "1:2:3:4:5:6:7:200"}
}
records["www.example.org."] = {
	{domain_id = 22, name = "www.example.org.", type = "CNAME", ttl = 123, content = "host.example.org."} }
records["host.example.org."] = {
	{domain_id = 22, name = "host.example.org.", type = "A", ttl = 123, content = "192.168.150.150"},
	{domain_id = 22, name = "host.example.org.", type = "AAAA", ttl = 123, content = "1:2:3:4:5:6:7:150"}
}

-- 'global' state:
local rrset -- the rrset we found for this query
local rrsetsize -- number of records in the rrset
local rrsetidx  -- loop counter for looping over rrset

function list(name, domain_id)
end


function lookup(qtype, qname, domain_id)
	qtype = tostring(qtype)
	logger(log_debug, "(l_lookup)", "qtype:", qtype, " qname:", qname, " domain_id:", domain_id )

	rrset = {}
	rrsetidx = 0
	rrsetsize = 0

	local r = records[qname]
	if not r then
		return
	end

	for k,v in pairs(r) do
		if (qtype == "ANY" or qtype == v["type"]) then
			table.insert(rrset, v)
		end
	end

	rrsetsize = #rrset

	logger(log_debug, "(l_lookup)", "size:", rrsetsize)
end


function get()
	logger(log_debug, "(l_get) begin")
	while rrsetidx < rrsetsize do
		rrsetidx = rrsetidx + 1
		logger(log_debug, "(l_get) rrset ", rrsetidx)
		return rrset[rrsetidx]
	end
	logger(log_debug, "(l_get) done")
	return false
end


function getsoa(name)
	logger(log_debug, "(l_getsoa) begin", "name:", name)
	r = domains_name[name]
	if type(r) == "table" then
		logger(log_debug, "(l_getsoa) end: ", type(r), type(r["soa"]))
		return r["soa"]
	end
	logger(log_debug, "(l_getsoa) end: not found")
end


function getdomaininfo(name)
	logger(log_debug, "(l_getdomaininfo) name:", name)
	return info[name]
end


function getdomainmetadata(name, kind)
	-- ignore kind
	logger(log_debug, "(l_getdomainmetadata) name:", name, 'kind: ', kind)
	if meta[name] then
		return meta[name][kind]
	end
end


function getdomainkeys(name)
	logger(log_debug, "(l_getdomainkeys) name:", name)
	return keys[name]
end

logger(log_debug, "the powerdns-luabackend is starting up!")
