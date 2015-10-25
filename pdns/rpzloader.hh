#pragma once
#include "filterpo.hh"
#include <string>
#include "dnsrecords.hh"

int loadRPZFromFile(const std::string& fname, DNSFilterEngine& target, int place);
std::shared_ptr<SOARecordContent> loadRPZFromServer(const ComboAddress& master, const DNSName& zone, DNSFilterEngine& target, int place);
void RPZRecordToPolicy(const DNSRecord& dr, DNSFilterEngine& target, bool addOrRemove, int place);
