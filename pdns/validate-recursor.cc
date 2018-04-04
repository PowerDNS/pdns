#include "validate.hh"
#include "validate-recursor.hh"
#include "syncres.hh"
#include "logger.hh"

DNSSECValidationMode g_dnssecMode{DNSSECValidationMode::Process};
DNSSECBogusServfailMode g_dnssecBogusServfailMode{DNSSECBogusServfailMode::Off};

bool checkDNSSECDisabled() {
  return warnIfDNSSECDisabled("");
}

bool warnIfDNSSECDisabled(const string& msg) {
  if(g_dnssecMode == DNSSECValidationMode::Off) {
    if (!msg.empty())
      g_log<<Logger::Warning<<msg<<endl;
    return true;
  }
  return false;
}

vState increaseDNSSECStateCounter(const vState& state)
{
  g_stats.dnssecResults[state]++;
  return state;
}
