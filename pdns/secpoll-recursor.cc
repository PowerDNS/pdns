#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "secpoll-recursor.hh"
#include "syncres.hh"
#include "logger.hh"
#include "arguments.hh"
#include "version.hh"
#include "validate-recursor.hh"

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
  int res=sr.beginResolve(query, QType(QType::TXT), 1, ret);

  if (g_dnssecmode != DNSSECMode::Off && res) {
    state = sr.getValidationState();
  }

  if(state == Bogus) {
    g_log<<Logger::Error<<"Could not retrieve security status update for '" +pkgv+ "' on '"<<query<<"', DNSSEC validation result was Bogus!"<<endl;
    if(g_security_status == 1) // If we were OK, go to unknown
      g_security_status = 0;
    return;
  }

  if (res != 0) { // Not NOERROR
    if(g_security_status == 1) // it was ok, now it is unknown
      g_security_status = 0;

    if (std::count(pkgv.begin(), pkgv.end(), '.') > 2) {
      g_log<<Logger::Warning<<"Ignoring response for security status update, this is a non-release version."<<endl;
      return;
    }
    g_log<<Logger::Warning<<"Could not retrieve security status update for '" +pkgv+ "' on '"<<query<<"', RCODE = "<< RCode::to_s(res)<<endl;
    return;
  }

  if (ret.empty()) { // Empty NOERROR
    if(g_security_status == 1) // it was ok, now it is unknown
      g_security_status = 0;
    g_log<<Logger::Warning<<"Could not retrieve security status update for '" +pkgv+ "' on '"<<query<<"', had empty answer, RCODE = "<< RCode::to_s(res)<<endl;
    return;
  }

  string content;
  for(const auto&r : ret) {
    if(r.d_type == QType::TXT)
      content = r.d_content->getZoneRepresentation();
  }

  if(!content.empty() && content[0]=='"' && content[content.size()-1]=='"') {
    content=content.substr(1, content.length()-2);
  }

  pair<string, string> split = splitField(content, ' ');

  g_security_status = std::stoi(split.first);
  g_security_message = split.second;

  if(g_security_status == 2) {
    g_log<<Logger::Error<<"PowerDNS Security Update Recommended: "<<g_security_message<<endl;
  }
  else if(g_security_status == 3) {
    g_log<<Logger::Error<<"PowerDNS Security Update Mandatory: "<<g_security_message<<endl;
  }
}
