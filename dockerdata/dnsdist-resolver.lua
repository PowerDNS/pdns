-- testing oneliner:
-- resolver = require 'dnsdist-resolver' resolver.maintenance() resolver.servers['www.7bits.nl']={pool='blabla'} resolver.maintenance() os.execute('sleep 3') resolver.maintenance() showServers() resolver.servers['www.7bits.nl']=nil resolver.maintenance() os.execute('sleep 3') resolver.maintenance() showServers()
local _M = {}

-- these are the servers we want - somebody should populate it
-- example:
--  resolver.servers['ns.example.com'] = { pool='auths', order=3 }
-- do not set name, address, id
_M.servers = {}

-- Whether or not we should log everything we do
_M.verbose = false

-- these are the servers we have
-- key = name
-- value = {address, serverObject} (should make these named members)
local ourservers = {}

-- Global variable for store results for getAddressInfo() function
local resout = {}

local function resolveCB(hostname, ips)
    resout[hostname] = {}
    for _, ip in ipairs(ips) do
        table.insert(resout[hostname], ip:toString())
    end
end

local function tablecopy(t)
    local t2 = {}
    for k, v in pairs(t) do
        t2[k] = v
    end
    return t2
end

local function has_value(tab, val)
    for _, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

local function removeServer(name)
    if _M.verbose then
        infolog("removing " .. name)
    end

    rmServer(ourservers[name][2])
    ourservers[name] = nil
end

local function setServer(name, ip)
    -- adds a server or changes its IP
    local existing = ourservers[name .. "#" .. ip]
    if existing ~= nil then
        if _M.verbose then
            infolog(string.format("existing[1] [%s] == ip [%s] ??", existing[1], ip))
        end
        -- it exists, check IP
        if existing[1] == ip then
            -- IP is correct, done!
            return
        else
            -- IP is wrong, drop and re-add it
            removeServer(name .. "#" .. ip)
        end
    end

    -- it does not exist, let's add it
    local settings = tablecopy(_M.servers[name])
    settings.name = name .. "#" .. ip
    settings.address = ip
    ourservers[name .. "#" .. ip] = {ip, newServer(settings)}
end

function _M.maintenance()
    for k in pairs(_M.servers) do
        getAddressInfo(k, resolveCB)
    end

    local activeservers = {}
    -- check for servers removed by controller
    for ourserver in pairs(ourservers) do
        activeservers[ourserver] = false
        for server in pairs(_M.servers) do
            -- use plain because a dash is a special character ..
            if ourserver:find(server, 1, true) == 1 then
                activeservers[ourserver] = true
            end
        end
    end

    for name, active in pairs(activeservers) do
        if active == false then
            removeServer(name)
        end
    end

    for name, ips in pairs(resout) do
        if _M.verbose then
            infolog("name=" .. name)
            for _, ip in ipairs(ips) do
                infolog("  ip=" .. ip)
            end
        end

        -- remove servers if they are no longer present
        for ourserver, server in pairs(ourservers) do
            -- check if we match the prefix and the ip is gone
            if ourserver:find(name, 1, true) == 1 and has_value(ips, server[1]) == false then
                if _M.verbose then
                    infolog("ip address not found anymore " .. server[1])
                end
                removeServer(ourserver)
            end
        end
        for _, ip in ipairs(ips) do
            -- it has IPs
            if _M.servers[name] ~= nil then
                -- we want this server
                setServer(name, ip)
            end
        end
    end
    collectgarbage()
    collectgarbage()
end

return _M
