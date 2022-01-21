This is designed to test a situation where the ZONEMD RDATA is correct,
but the ZONEMD DNSSEC signature is wrong.  To create the zone, the
Makefile issues queries for all the records in the test zone, reassembles
the zone file, and then alters the RRSIG with a simple awk command.
