#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "logger.hh"
#include "arguments.hh"
#include "version.hh"
#include "dnsparser.hh"
#include "misc.hh"

#include "sstuff.hh"
#include "dnswriter.hh"
#include "dns_random.hh"
#include "namespaces.hh"
#include "statbag.hh"
#include "stubresolver.hh"
#include "secpoll.hh"
#include "dnsrecords.hh"
#include <stdint.h>
#ifndef PACKAGEVERSION
#define PACKAGEVERSION getPDNSVersion()
#endif

#include "secpoll-auth.hh"

static string g_security_message;

extern StatBag S;

/** Do an actual secpoll for the current version
 * @param first bool that tells if this is the first secpoll run since startup
 */
void doSecPoll(Logr::log_t slog, bool first)
{
  if(::arg()["security-poll-suffix"].empty())
    return;

  struct timeval now;
  gettimeofday(&now, nullptr);
  string pkgv(PACKAGEVERSION);

  string version = "auth-" + pkgv;
  string query = version.substr(0, 63) +".security-status."+::arg()["security-poll-suffix"];

  if(*query.rbegin()!='.')
    query+='.';

  std::replace(query.begin(), query.end(), '+', '_');
  std::replace(query.begin(), query.end(), '~', '_');

  int security_status = std::stoi(S.getValueStr("security-status"));

  vector<DNSRecord> ret;
  int res = stubDoResolve(slog, DNSName(query), QType::TXT, ret);

  if (res == RCode::NXDomain && !isReleaseVersion(pkgv)) {
    SLOG(g_log<<Logger::Warning<<"Not validating response for security status update, this is a non-release version"<<endl,
         slog->info(Logr::Warning, "Not validating response for security status update, this is a non-release version"));
    return;
  }

  string security_message;

  try {
    processSecPoll(res, ret, security_status, security_message);
  } catch(const PDNSException &pe) {
    S.set("security-status", security_status);
    SLOG(g_log<<Logger::Warning<<"Failed to retrieve security status update for '" + pkgv + "' on '"+ query + "': "<<pe.reason<<endl,
         slog->error(Logr::Warning, pe.reason, "Failed to retrieve security status update", "package", Logging::Loggable(pkgv), "query", Logging::Loggable(query)));
    return;
  }


  S.set("security-status", security_status);
  g_security_message = security_message;

  if(security_status == 1 && first) {
    SLOG(g_log<<Logger::Warning << "Polled security status of version "<<PACKAGEVERSION<<" at startup, no known issues reported: " <<g_security_message<<endl,
         slog->info(Logr::Warning, "Polled security status at startup, no known issues reported", "package", Logging::Loggable(PACKAGEVERSION), "status", Logging::Loggable(g_security_message)));
  }
  if(security_status == 2) {
    SLOG(g_log<<Logger::Error<<"PowerDNS Security Update Recommended: "<<g_security_message<<endl,
         slog->info(Logr::Error, "PowerDNS Security Update Recommended", "status", Logging::Loggable(g_security_message)));
  }
  if(security_status == 3) {
    SLOG(g_log<<Logger::Error<<"PowerDNS Security Update Mandatory: "<<g_security_message<<endl,
         slog->info(Logr::Error, "PowerDNS Security Update Mandatory", "status", Logging::Loggable(g_security_message)));
  }
}
