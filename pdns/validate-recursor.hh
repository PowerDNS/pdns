#pragma once
#include "dnsparser.hh"
#include "namespaces.hh"
#include "validate.hh"

vState validateRecords(const vector<DNSRecord>& recs);
