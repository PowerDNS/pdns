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

#include <cstdint>
#ifndef PACKAGEVERSION
#define PACKAGEVERSION getPDNSVersion()
#endif

uint32_t g_security_status;
string g_security_message;

void doSecPoll(time_t* last_secpoll, Logr::log_t log)
{
  if (::arg()["security-poll-suffix"].empty()) {
    return;
  }

  string pkgv(PACKAGEVERSION);
  struct timeval now
  {
  };
  Utility::gettimeofday(&now);

  /* update last_secpoll right now, even if it fails
     we don't want to retry right away and hammer the server */
  *last_secpoll = now.tv_sec;

  SyncRes resolver(now);
  if (g_dnssecmode != DNSSECMode::Off) {
    resolver.setDoDNSSEC(true);
    resolver.setDNSSECValidationRequested(true);
  }
  resolver.setId("SecPoll");

  vector<DNSRecord> ret;

  string version = "recursor-" + pkgv;
  string qstring(version.substr(0, 63) + ".security-status." + ::arg()["security-poll-suffix"]);

  if (*qstring.rbegin() != '.') {
    qstring += '.';
  }

  std::replace(qstring.begin(), qstring.end(), '+', '_');
  std::replace(qstring.begin(), qstring.end(), '~', '_');

  vState state = vState::Indeterminate;
  DNSName query(qstring);
  int res = resolver.beginResolve(query, QType(QType::TXT), 1, ret);

  if (g_dnssecmode != DNSSECMode::Off && res != 0) {
    state = resolver.getValidationState();
  }

  auto vlog = log->withValues("version", Logging::Loggable(pkgv), "query", Logging::Loggable(query));
  if (vStateIsBogus(state)) {
    SLOG(g_log << Logger::Error << "Failed to retrieve security status update for '" + pkgv + "' on '" << query << "', DNSSEC validation result was Bogus!" << endl,
         vlog->info(Logr::Error, "Failed to retrieve security status update", "validationResult", Logging::Loggable(vStateToString(state))));
    if (g_security_status == 1) { // If we were OK, go to unknown
      g_security_status = 0;
    }
    return;
  }

  if (res == RCode::NXDomain && !isReleaseVersion(pkgv)) {
    SLOG(g_log << Logger::Warning << "Not validating response for security status update, this is a non-release version" << endl,
         vlog->info(Logr::Warning, "Not validating response for security status update, this is a non-release version"));
    return;
  }

  string security_message;
  int security_status = static_cast<int>(g_security_status);

  try {
    processSecPoll(res, ret, security_status, security_message);
  }
  catch (const PDNSException& pe) {
    g_security_status = security_status;
    SLOG(g_log << Logger::Warning << "Failed to retrieve security status update for '" << pkgv << "' on '" << query << "': " << pe.reason << endl,
         vlog->error(Logr::Warning, pe.reason, "Failed to retrieve security status update"));
    return;
  }

  g_security_message = std::move(security_message);

  auto rlog = vlog->withValues("securitymessage", Logging::Loggable(g_security_message), "status", Logging::Loggable(security_status));
  if (g_security_status != 1 && security_status == 1) {
    SLOG(g_log << Logger::Warning << "Polled security status of version " << pkgv << ", no known issues reported: " << g_security_message << endl,
         rlog->info(Logr::Notice, "Polled security status of version, no known issues reported"));
  }
  if (security_status == 2) {
    SLOG(g_log << Logger::Error << "PowerDNS Security Update Recommended: " << g_security_message << endl,
         rlog->info(Logr::Error, "PowerDNS Security Update Recommended"));
  }
  if (security_status == 3) {
    SLOG(g_log << Logger::Error << "PowerDNS Security Update Mandatory: " << g_security_message << endl,
         rlog->info(Logr::Error, "PowerDNS Security Update Mandatory"));
  }

  g_security_status = security_status;
}
