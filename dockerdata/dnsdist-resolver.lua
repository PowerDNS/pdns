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

local resolverpipe = io.popen('/usr/local/bin/dnsdist-resolver', 'w')

local function tablecopy(t)
    local t2 = {}
    for k, v in pairs(t)
    do
        t2[k] = v
    end
    return t2
end

local function removeServer(name)
    rmServer(ourservers[name][2])
    ourservers[name] = nil
end

local function setServer(name, ip)
    -- adds a server or changes its IP
    local existing = ourservers[name]
    if existing ~= nil
    then
        if _M.verbose then
          infolog(string.format("existing[1] [%s] == ip [%s] ??", existing[1], ip))
        end
        -- it exists, check IP
        if existing[1] == ip
        then
            -- IP is correct, done!
            return
        else
            -- IP is wrong, drop and re-add it
            removeServer(name)
        end
    end

    -- it does not exist, let's add it
    local settings = tablecopy(_M.servers[name])
    settings.name = name
    -- TODO: we only take the first IP
    settings.address = ip
    ourservers[name] = {ip, newServer(settings)}
end

function _M.maintenance()
    -- TODO: only do this if the list has changed
    -- TODO: check return values
    for k, v in pairs(_M.servers)
    do
        resolverpipe:write(k..' ')
    end
    resolverpipe:write('\n')
    resolverpipe:flush()

    -- TODO: maybe this failure should be quiet for the first X seconds?
    local ret, resout = pcall(loadfile, '/tmp/dnsdist-resolver.out')
    if not ret
    then
        error(resout)
    end

    -- on purpose no pcall, an error here is a bug
    resout = resout()

    -- check for servers removed by controller
    for name, v in pairs(ourservers)
    do
        if _M.servers[name] == nil
        then
            removeServer(name)
        end
    end

    for name, ips in pairs(resout)
    do
        if _M.verbose then
          infolog("name="..name)
          for _, ip in ipairs(ips)
          do
              infolog("  ip="..ip)
          end
        end

        if #ips == 0
        then
            -- server has left the building
            if ourservers[name] ~= nil
            then
                removeServer(name)
            end
        else
            -- it has IPs
            if _M.servers[name] ~= nil
            then
                -- we want this server
                setServer(name, ips[1])
            end
        end
    end
end

return _M
