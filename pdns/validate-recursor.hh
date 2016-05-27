#pragma once
#include "dnsparser.hh"
#include "namespaces.hh"
#include "validate.hh"

vState validateRecords(const vector<DNSRecord>& recs);

/* Off: 3.x behaviour, we do no DNSSEC, no EDNS
   ProcessNoValidate: we gather DNSSEC records on all queries, but we will never validate
   Process: we gather DNSSEC records on all queries, if you do ad=1, we'll validate for you (unless you set cd=1)
   ValidateForLog: Process + validate all answers, but only log failures
   ValidateAll: DNSSEC issue -> servfail
*/

enum class DNSSECMode { Off, Process, ProcessNoValidate, ValidateForLog, ValidateAll };
extern DNSSECMode g_dnssecmode;
