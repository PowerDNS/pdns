#pragma once
#include "filterpo.hh"
#include <string>
#include "dnsrecords.hh"

int loadRPZFromFile(const std::string& fname, DNSFilterEngine& target, std::shared_ptr<const std::string> policyName, boost::optional<DNSFilterEngine::Policy> defpol, int place);
std::shared_ptr<SOARecordContent> loadRPZFromServer(const ComboAddress& master, const DNSName& zone, DNSFilterEngine& target, std::shared_ptr<const std::string> policyName, boost::optional<DNSFilterEngine::Policy> defpol, int place, const TSIGTriplet& tt, size_t maxReceivedBytes);
void RPZRecordToPolicy(const DNSRecord& dr, DNSFilterEngine& target, std::shared_ptr<const std::string> policyName, bool addOrRemove, boost::optional<DNSFilterEngine::Policy> defpol, int place);
void RPZIXFRTracker(const ComboAddress& master, const DNSName& zone, std::shared_ptr<const std::string> policyName, const TSIGTriplet &tt, shared_ptr<SOARecordContent> oursr, size_t maxReceivedBytes);
