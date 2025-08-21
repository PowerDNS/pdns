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

pdns::stat_t g_security_status;

void doSecPoll(time_t* last_secpoll, Logr::log_t log)
{
  if (::arg()["security-poll-suffix"].empty()) {
    return;
  }

  string pkgv(PACKAGEVERSION);
  struct timeval now{};
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
    vlog->info(Logr::Error, "Failed to retrieve security status update", "validationResult", Logging::Loggable(vStateToString(state)));
    if (g_security_status == 1) { // If we were OK, go to unknown
      g_security_status = 0;
    }
    return;
  }

  if (res == RCode::NXDomain && !isReleaseVersion(pkgv)) {
    vlog->info(Logr::Warning, "Not validating response for security status update, this is a non-release version");
    return;
  }

  string security_message;
  int security_status = static_cast<int>(g_security_status);

  try {
    processSecPoll(res, ret, security_status, security_message);
  }
  catch (const PDNSException& pe) {
    g_security_status = security_status;
    vlog->error(Logr::Warning, pe.reason, "Failed to retrieve security status update");
    return;
  }

  auto rlog = vlog->withValues("securitymessage", Logging::Loggable(security_message), "status", Logging::Loggable(security_status));
  if (g_security_status != 1 && security_status == 1) {
    rlog->info(Logr::Notice, "Polled security status of version, no known issues reported");
  }
  if (security_status == 2) {
    rlog->info(Logr::Error, "PowerDNS Security Update Recommended");
  }
  if (security_status == 3) {
    rlog->info(Logr::Error, "PowerDNS Security Update Mandatory");
  }

  g_security_status = security_status;
}
