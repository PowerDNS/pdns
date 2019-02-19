#ifndef REC_SNMP_HH
#define REC_SNMP_HH

#pragma once

#include "snmp-agent.hh"

class RecursorSNMPAgent;

class RecursorSNMPAgent: public SNMPAgent
{
public:
  RecursorSNMPAgent(const std::string& name, const std::string& masterSocket, bool enableExpensiveStatistics);
  bool sendCustomTrap(const std::string& reason);
};

extern std::shared_ptr<RecursorSNMPAgent> g_snmpAgent;

#endif /* REC_SNMP_HH */
