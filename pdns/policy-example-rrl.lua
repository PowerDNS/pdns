-- Lua policy engine example
--
-- intended to be a faithful implementation of http://ss.vix.su/~vixie/isc-tn-2012-1.txt

conf = {}
conf.rps = 5
conf.eps = 5
conf.logonly = false
conf.window = 5
conf.v4len = 24
conf.v6len = 56
conf.leakrate = 3
conf.tcrate = 2

window = {}
timechanged = false

function getslot (ts)
	idx = (ts % conf.window) + 1
	if window[idx]
	then
		if window[idx][1] == ts
		then
			return window[idx][2]
		end
	end

	newslot = {}
	window[idx] = {ts, newslot}
	timechanged = true
	return newslot
end

function getwindow ()
	mywindow = {}
	now = os.time()
	for i = now, now-conf.window+1, -1
	do
		table.insert(mywindow, getslot(i))
	end

	return mywindow
end

function mask (host)
	-- assumes /24 and ipv4
	f = host:gmatch('%d+')
	return f().."."..f().."."..f()
end

function submit (slot, token)
	if slot[token]
	then
		slot[token] = slot[token] + 1
	else
		slot[token] = 1
	end
	print("submit: count for "..token.." now "..slot[token])
end

function count (window, token)
	total = 0
	for i,v in ipairs(window)
	do
		if v[token]
		then
			total = total + v[token]
		end
	end

	return total / conf.window
end

function police (req, resp, isTcp)

	timechanged = false
	mywindow = getwindow()

	if resp
	then
		qname, qtype = resp:getQuestion()
		remote = resp:getRemote()
		wild = resp:getWild()
		zone = resp:getZone()
		reqsize = req:getSize()
		respsize = resp:getSize()
		rcode = resp:getRcode()
		print ("< ", qname, qtype, remote, "wild: "..(wild or "EMPTY"), "zone: "..(zone or "EMPTY"), reqsize.."/"..respsize, rcode, isTcp )
		if isTcp then return pdns.PASS end

		-- mywindow[1][1] = mywindow[1][1]+1
		-- mywindow[1][2] = mywindow[1][2]+req:getSize()
		-- mywindow[1][3] = mywindow[1][3]+resp:getSize()
		an, ns, ar = resp:getRRCounts()
		imputedname = qname
		errorstatus = (rcode == pdns.REFUSED or rcode == pdns.FORMERR or rcode == pdns.SERVFAIL or rcode == pdns.NOTIMP)

		if wild
		then
			imputedname = wild
		elseif rcode == pdns.NXDOMAIN or errorstatus
		then
			imputedname = zone or "EMPTY"
		end
		token = mask(remote).."/"..imputedname.."/"..tostring(errorstatus)
		submit(mywindow[1], token) -- FIXME: only submit when doing PASS/TRUNCATE?
		qps = count(mywindow, token)
		print("qps for token "..token.." is "..qps)

		limit = conf.rps
		if errorstatus then limit = conf.eps end

		if qps > limit
		then
			print( "considering a drop")

			-- LEAK-RATE's intention is to give the victim (real owner of spoofed IP)
			-- some kind of chance to receive a reply. When the leakrate is set to
			-- 5, effectively 1 out of 5 queries probably get an answer. The lucky
			-- query has to draw a 1 from our pseudo-random uniformly distributed lottery.
			-- Note: the higher leakrate is set, the more queries will be dropped to the floor!
			if conf.leakrate > 0 and math.random(conf.leakrate) == 1
			then
			    print ("leaking instead")
			    return pdns.PASS
			end
			if conf.tcrate > 0 and math.random(conf.tcrate) == 1
			then
				print ("truncating instead")
				return pdns.TRUNCATE
			end
			return pdns.DROP
		end
		-- token = { mask(resp:getRemote()), }
	else
		qname, qtype = req:getQuestion()
		remote = req:getRemote()
		print ("> ", qname, qtype, remote)
		if isTcp then return pdns.PASS end
	end
	if timechanged
	then
		print("lua memory usage is "..collectgarbage("count"))
	end
	-- then
	-- 	print("qps stats last", conf.window, "seconds: ")
	-- 	for i = 1, conf.window
	-- 	do
	-- 		print(mywindow[i][1], mywindow[i][2], mywindow[i][3])
	-- 	end
	-- end

	-- print("--")
	return pdns.PASS
end

function policycmd(cmd, arg)
	if cmd ~= "get" then return "unknown command "..cmd end

	mywindow = getwindow()
	qps = count(mywindow, arg)

	-- return "qps for token "..arg.." is "..qps
	return qps
end
