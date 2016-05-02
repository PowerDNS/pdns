#pragma once
#include "namespaces.hh"
#include "dnsparser.hh"

void stubParseResolveConf();
int stubDoResolve(const string& qname, uint16_t qtype, vector<DNSResourceRecord>& ret);
