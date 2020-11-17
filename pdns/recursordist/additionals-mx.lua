local function nameFromMX(s)
    return string.match(s, '%d+ (.+)')
end

function postresolve(dq)
    print(dq.qname)
    local mxes = {}
    for k,v in pairs(dq:getRecords())
    do
        if v.type == pdns.MX
        then
            table.insert(mxes, v:getContent())
        end
    end

    for i,v in ipairs(mxes)
    do
        -- print('lookup', v)
        local name = newDN(nameFromMX(v))
        l = cacheLookup(name, pdns.A)
        for k,v in pairs(l)
        do
            dq:addRecord(pdns.A, v, 3, nil, name:toString()) -- FIXME docs say DNSName not string
        end
    end
-- print(l)
-- for k,v in pairs(l)
-- do
--  print(k,v)
-- end
    -- dq:addRecord(pdns.A, '1.2.3.4', 3)
    return true
end
