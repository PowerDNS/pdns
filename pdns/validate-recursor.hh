#pragma once
#include "dnsparser.hh"
#include "namespaces.hh"
#include "validate.hh"

vState validateRecords(const vector<DNSRecord>& recs);

/* Off: 3.x behaviour, we do no DNSSEC, no EDNS
   Process: we gather DNSSEC records on all queries, of you do do=1, we'll validate for you (unless you set cd=1)
   ValidateForLog: Process + validate all answers, but only log failures
   ValidateAll: DNSSEC issue -> servfail
*/

enum class DNSSECMode { Off, Process, ValidateForLog, ValidateAll };
extern DNSSECMode g_dnssecmode;
