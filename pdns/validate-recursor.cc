#include "validate.hh"
#include "validate-recursor.hh"
#include "syncres.hh"
#include "logger.hh"

DNSSECMode g_dnssecmode{DNSSECMode::ProcessNoValidate};
bool g_dnssecLogBogus;

bool checkDNSSECDisabled() {
  return warnIfDNSSECDisabled("");
}

bool warnIfDNSSECDisabled(const string& msg) {
  if(g_dnssecmode == DNSSECMode::Off) {
    if (!msg.empty())
      L<<Logger::Warning<<msg<<endl;
    return true;
  }
  return false;
}

vState increaseDNSSECStateCounter(const vState& state)
{
  g_stats.dnssecResults[state]++;
  return state;
}
