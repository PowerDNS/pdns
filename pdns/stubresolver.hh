#pragma once
#include "namespaces.hh"
#include "dnsparser.hh"

void secPollParseResolveConf();
int doResolve(const string& qname, uint16_t qtype, vector<DNSResourceRecord>& ret);
