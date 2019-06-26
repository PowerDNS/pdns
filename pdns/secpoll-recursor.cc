#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "secpoll-recursor.hh"
#include "syncres.hh"
#include "logger.hh"
#include "arguments.hh"
#include "version.hh"
#include "validate-recursor.hh"
#include "secpoll.hh"

#include <stdint.h>
#ifndef PACKAGEVERSION 
#define PACKAGEVERSION getPDNSVersion()
#endif

uint32_t g_security_status;
string g_security_message;

void doSecPoll(time_t* last_secpoll)
{
  if(::arg()["security-poll-suffix"].empty())
    return;

  string pkgv(PACKAGEVERSION);
  struct timeval now;
  gettimeofday(&now, 0);

  /* update last_secpoll right now, even if it fails
     we don't want to retry right away and hammer the server */
  *last_secpoll=now.tv_sec;

  SyncRes sr(now);
  if (g_dnssecmode != DNSSECMode::Off) {
    sr.setDoDNSSEC(true);
    sr.setDNSSECValidationRequested(true);
  }

  vector<DNSRecord> ret;

  string version = "recursor-" +pkgv;
  string qstring(version.substr(0, 63)+ ".security-status."+::arg()["security-poll-suffix"]);

  if(*qstring.rbegin()!='.')
    qstring+='.';

  boost::replace_all(qstring, "+", "_");
  boost::replace_all(qstring, "~", "_");

  vState state = Indeterminate;
  DNSName query(qstring);
  int res = sr.beginResolve(query, QType(QType::TXT), 1, ret);

  if (g_dnssecmode != DNSSECMode::Off && res) {
    state = sr.getValidationState();
  }

  if(state == Bogus) {
    g_log<<Logger::Error<<"Could not retrieve security status update for '" +pkgv+ "' on '"<<query<<"', DNSSEC validation result was Bogus!"<<endl;
    if(g_security_status == 1) // If we were OK, go to unknown
      g_security_status = 0;
    return;
  }

  if (res == RCode::NXDomain && !isReleaseVersion(pkgv)) {
    g_log<<Logger::Warning<<"Not validating response for security status update, this is a non-release version"<<endl;
    return;
  }

  string security_message;
  int security_status = g_security_status;

  try {
    processSecPoll(res, ret, security_status, security_message);
  } catch(const PDNSException &pe) {
    g_security_status = security_status;
    g_log<<Logger::Warning<<"Could not retrieve security status update for '" << pkgv << "' on '"<< query << "': "<<pe.reason<<endl;
    return;
  }

  g_security_message = security_message;

  if(g_security_status != 1 && security_status == 1) {
    g_log<<Logger::Warning << "Polled security status of version "<<pkgv<<", no known issues reported: " <<g_security_message<<endl;
  }
  if(security_status == 2) {
    g_log<<Logger::Error<<"PowerDNS Security Update Recommended: "<<g_security_message<<endl;
  }
  if(security_status == 3) {
    g_log<<Logger::Error<<"PowerDNS Security Update Mandatory: "<<g_security_message<<endl;
  }

  g_security_status = security_status;
}
