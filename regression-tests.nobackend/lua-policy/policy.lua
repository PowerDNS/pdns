print("policy.lua loaded")
io.flush()
function police (req, resp, isTcp)
	qname, qtype = req:getQuestion()

	if qname == 'drop.minimal.com.' then print 'dropping!' io.flush() return pdns.DROP end
	if qname == 'truncate.minimal.com.' then print 'truncating!' io.flush() return pdns.TRUNCATE end

	return pdns.PASS
end
