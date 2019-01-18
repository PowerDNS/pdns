#ifndef DNSDIST_SNMP_HH
#define DNSDIST_SNMP_HH

#pragma once

#include "snmp-agent.hh"

class DNSDistSNMPAgent;

#include "dnsdist.hh"

class DNSDistSNMPAgent: public SNMPAgent
{
public:
  DNSDistSNMPAgent(const std::string& name, const std::string& masterSocket);
  bool sendBackendStatusChangeTrap(const std::shared_ptr<DownstreamState>&);
  bool sendCustomTrap(const std::string& reason);
  bool sendDNSTrap(const DNSQuestion&, const std::string& reason="");
};

#endif /* DNSDIST_SNMP_HH */
