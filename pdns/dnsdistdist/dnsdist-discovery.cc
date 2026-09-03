/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include "dnsdist-discovery.hh"
#include "dnsdist-backend.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist.hh"
#include "dnsdist-random.hh"
#include "dnsparser.hh"
#include "dolog.hh"
#include "logging.hh"
#include "sstuff.hh"
#include "threadname.hh"
#include <unordered_set>

namespace dnsdist
{

const DNSName ServiceDiscovery::s_discoveryDomain{"_dns.resolver.arpa."};
const QType ServiceDiscovery::s_discoveryType{QType::SVCB};
const uint16_t ServiceDiscovery::s_defaultDoHSVCKey{7};

bool ServiceDiscovery::addUpgradeableServer(std::shared_ptr<DownstreamState>& server, uint32_t interval, std::string poolAfterUpgrade, uint16_t dohSVCKey, bool keepAfterUpgrade, bool enableRedirection, uint32_t redirectInterval, std::string poolAfterRedirect, uint16_t redirectDohSVCKey, bool keepAfterRedirect, uint32_t redirectMaxFollowCount)
{
  s_upgradeableBackends.lock()->push_back(std::make_shared<UpgradeableBackend>(UpgradeableBackend{server, std::move(poolAfterUpgrade), 0, interval, dohSVCKey, keepAfterUpgrade, enableRedirection, std::move(poolAfterRedirect), redirectInterval, redirectDohSVCKey, keepAfterRedirect, redirectMaxFollowCount}));
  return true;
}

bool ServiceDiscovery::addRedirectableServer(std::shared_ptr<DownstreamState>& server, uint32_t interval, std::string poolAfterUpgrade, uint16_t dohSVCKey, bool keepAfterRedirect, uint32_t maxFollowCount)
{
  s_redirectableBackends.lock()->push_back(std::make_shared<RedirectableBackend>(RedirectableBackend{server, server, std::move(poolAfterUpgrade), 0, interval, dohSVCKey, keepAfterRedirect, maxFollowCount}));
  return true;
}

struct DesignatedResolvers
{
  DNSName target;
  std::set<SvcParam> params;
  std::vector<ComboAddress> hints;
  uint32_t ttl;
};

static bool parseSVCParams(const PacketBuffer& answer, std::map<uint16_t, DesignatedResolvers>& resolvers)
{
  std::map<DNSName, std::vector<ComboAddress>> hints;
  const dnsheader_aligned dh(answer.data());
  PacketReader pr(std::string_view(reinterpret_cast<const char*>(answer.data()), answer.size()));
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t nscount = ntohs(dh->nscount);
  uint16_t arcount = ntohs(dh->arcount);

  DNSName rrname;
  uint16_t rrtype;
  uint16_t rrclass;

  size_t idx = 0;
  /* consume qd */
  for (; idx < qdcount; idx++) {
    rrname = pr.getName();
    rrtype = pr.get16BitInt();
    rrclass = pr.get16BitInt();
    (void)rrtype;
    (void)rrclass;
  }

  /* parse AN */
  for (idx = 0; idx < ancount; idx++) {
    string blob;
    struct dnsrecordheader ah;
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type == QType::SVCB) {
      auto prio = pr.get16BitInt();
      auto target = pr.getName();
      std::set<SvcParam> params;

      if (prio != 0) {
        pr.xfrSvcParamKeyVals(params);
      }

      resolvers[prio] = {std::move(target), std::move(params), {}, ah.d_ttl};
    }
    else {
      pr.xfrBlob(blob);
    }
  }

  /* parse NS */
  for (idx = 0; idx < nscount; idx++) {
    string blob;
    struct dnsrecordheader ah;
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pr.xfrBlob(blob);
  }

  /* parse additional for hints */
  for (idx = 0; idx < arcount; idx++) {
    string blob;
    struct dnsrecordheader ah;
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type == QType::A) {
      ComboAddress addr;
      pr.xfrCAWithoutPort(4, addr);
      hints[rrname].push_back(addr);
    }
    else if (ah.d_type == QType::AAAA) {
      ComboAddress addr;
      pr.xfrCAWithoutPort(6, addr);
      hints[rrname].push_back(addr);
    }
    else {
      pr.xfrBlob(blob);
    }
  }

  for (auto& resolver : resolvers) {
    auto hint = hints.find(resolver.second.target);
    if (hint != hints.end()) {
      resolver.second.hints = hint->second;
    }
  }

  return !resolvers.empty();
}

static bool handleSVCResult(const Logr::Logger& logger, const PacketBuffer& answer, const ComboAddress& existingAddr, uint16_t dohSVCKey, ServiceDiscovery::DiscoveredResolverConfig& config)
{
  std::map<uint16_t, DesignatedResolvers> resolvers;
  if (!parseSVCParams(answer, resolvers)) {
    VERBOSESLOG(infolog("No configuration found in response for backend %s", existingAddr.toStringWithPort()),
                logger.info(Logr::Info, "No configuration found in response"));
    return false;
  }

  for (const auto& [priority, resolver] : resolvers) {
    (void)priority;
    /* do not compare the ports */
    std::set<ComboAddress, ComboAddress::addressOnlyLessThan> tentativeAddresses;
    ServiceDiscovery::DiscoveredResolverConfig tempConfig;
    tempConfig.d_addr.sin4.sin_family = 0;

    for (const auto& param : resolver.params) {
      if (param.getKey() == SvcParam::alpn) {
        auto alpns = param.getALPN();
        for (const auto& alpn : alpns) {
          if (alpn == "dot") {
            tempConfig.d_protocol = dnsdist::Protocol::DoT;
            if (tempConfig.d_port == 0) {
              tempConfig.d_port = 853;
            }
          }
          else if (alpn == "h2") {
            tempConfig.d_protocol = dnsdist::Protocol::DoH;
            if (tempConfig.d_port == 0) {
              tempConfig.d_port = 443;
            }
          }
        }
      }
      else if (param.getKey() == SvcParam::port) {
        tempConfig.d_port = param.getPort();
      }
      else if (param.getKey() == SvcParam::ipv4hint || param.getKey() == SvcParam::ipv6hint) {
        if (tempConfig.d_addr.sin4.sin_family == 0) {
          auto hints = param.getIPHints();
          for (const auto& hint : hints) {
            tentativeAddresses.insert(hint);
          }
        }
      }
      else if (dohSVCKey != 0 && param.getKey() == dohSVCKey) {
        tempConfig.d_dohPath = param.getValue();
        auto expression = tempConfig.d_dohPath.find('{');
        if (expression != std::string::npos) {
          /* nuke the {?dns} expression, if any, as we only support POST anyway */
          tempConfig.d_dohPath.resize(expression);
        }
      }
    }

    if (tempConfig.d_protocol == dnsdist::Protocol::DoH) {
#ifndef HAVE_DNS_OVER_HTTPS
      continue;
#endif
      if (tempConfig.d_dohPath.empty()) {
        VERBOSESLOG(infolog("Got a DoH upgrade offered for %s but no path, skipping", existingAddr.toStringWithPort()),
                    logger.info(Logr::Info, "Got a DoH upgrade offer but no path, skipping"));
        continue;
      }
    }
    else if (tempConfig.d_protocol == dnsdist::Protocol::DoT) {
#ifndef HAVE_DNS_OVER_TLS
      continue;
#endif
    }
    else {
      continue;
    }

    /* we have a config that we can use! */
    for (const auto& hint : resolver.hints) {
      tentativeAddresses.insert(hint);
    }

    /* we prefer the address we already know, whenever possible */
    if (tentativeAddresses.empty() || tentativeAddresses.count(existingAddr) != 0) {
      tempConfig.d_addr = existingAddr;
    }
    else {
      tempConfig.d_addr = *tentativeAddresses.begin();
    }

    tempConfig.d_subjectName = resolver.target.toStringNoDot();
    tempConfig.d_addr.sin4.sin_port = tempConfig.d_port;
    tempConfig.d_ttl = resolver.ttl;

    config = std::move(tempConfig);
    return true;
  }

  return false;
}

bool ServiceDiscovery::getDiscoveredConfig(const Logr::Logger& topLogger, const std::shared_ptr<DownstreamState>& backend, uint16_t dohKey, ServiceDiscovery::DiscoveredResolverConfig& config)
{
  const auto verbose = dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose;
  const auto& addr = backend->d_config.remote;
  try {
    auto id = dnsdist::getRandomDNSID();
    PacketBuffer packet;
    GenericDNSPacketWriter pw(packet, s_discoveryDomain, s_discoveryType);
    pw.getHeader()->id = id;
    pw.getHeader()->rd = 1;
    pw.addOpt(4096, 0, 0);
    pw.commit();

    auto logger = topLogger.withValues("dns.query.id", Logging::Loggable(id), "dns.query.name", Logging::Loggable(s_discoveryDomain), "dns.query.type", Logging::Loggable(s_discoveryType));

    if (backend->getProtocol() != dnsdist::Protocol::DoH) {
      uint16_t querySize = static_cast<uint16_t>(packet.size());
      const uint8_t sizeBytes[] = {static_cast<uint8_t>(querySize / 256), static_cast<uint8_t>(querySize % 256)};
      packet.insert(packet.begin(), sizeBytes, sizeBytes + 2);
    }

    Socket sock(addr.sin4.sin_family, SOCK_STREAM);
    if (backend->getProtocol() != dnsdist::Protocol::DoH) {
      sock.setNonBlocking();

#ifdef SO_BINDTODEVICE
      if (!backend->d_config.sourceItfName.empty()) {
        (void)setsockopt(sock.getHandle(), SOL_SOCKET, SO_BINDTODEVICE, backend->d_config.sourceItfName.c_str(), backend->d_config.sourceItfName.length());
      }
#endif

      if (!IsAnyAddress(backend->d_config.sourceAddr)) {
        sock.setReuseAddr();
#ifdef IP_BIND_ADDRESS_NO_PORT
        if (backend->d_config.ipBindAddrNoPort) {
          SSetsockopt(sock.getHandle(), SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
        }
#endif
        sock.bind(backend->d_config.sourceAddr);
      }
      sock.connect(addr, backend->d_config.tcpConnectTimeout);
    }

    if (backend->getProtocol() == dnsdist::Protocol::DoT) {
      auto handler = std::make_unique<TCPIOHandler>(backend->d_config.d_tlsSubjectName, backend->d_config.d_tlsSubjectIsAddr, sock.releaseHandle(), timeval{backend->d_config.checkTimeout, 0}, backend->d_tlsCtx);
      handler->connect(backend->d_config.tcpFastOpen, backend->d_config.remote, timeval{backend->d_config.checkTimeout, 0});
      handler->write(reinterpret_cast<const char*>(packet.data()), packet.size(), timeval{backend->d_config.checkTimeout, 0});

      const struct timeval remainingTime = {.tv_sec = backend->d_config.tcpRecvTimeout, .tv_usec = 0};
      uint16_t responseSize = 0;
      auto got = handler->read(&responseSize, sizeof(responseSize), remainingTime);
      if (got != sizeof(responseSize)) {
        if (verbose) {
          SLOG(warnlog("Error while waiting for the ADD upgrade response size from backend %s: %d", addr.toStringWithPort(), got),
               logger->info(Logr::Warning, "Error while waiting for the ADD upgrade response size from backend", "value", Logging::Loggable(got), "expected", Logging::Loggable(sizeof(responseSize))));
        }
        return false;
      }

      packet.resize(ntohs(responseSize));

      got = handler->read(packet.data(), packet.size(), remainingTime);
      if (got != packet.size()) {
        if (verbose) {
          SLOG(warnlog("Error while waiting for the ADD upgrade response from backend %s: %d", addr.toStringWithPort(), got),
               logger->info(Logr::Warning, "Error while waiting for the ADD upgrade response from backend", "value", Logging::Loggable(got), "expected", Logging::Loggable(packet.size())));
        }
        return false;
      }
    }
    else if (backend->getProtocol() == dnsdist::Protocol::DoH) {
      auto sender = std::make_shared<RedirectionQuerySender>();
      auto sliced = std::shared_ptr<TCPQuerySender>(sender);
      auto multiplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());
      auto queryBuffer = packet;
      auto query = InternalQuery(std::move(queryBuffer), InternalQueryState());

      bool result = sendH2Query(backend, multiplexer, sliced, std::move(query), true);
      if (!result) {
        if (verbose) {
          SLOG(warnlog("Error sending a discovery DoH query to backend: %d", addr.toStringWithPort()),
               logger->info(Logr::Warning, "Error sending a discovery DoH query to backend"));
        }
        return false;
      }
      struct timeval now;
      gettimeofday(&now, nullptr);
      while ((multiplexer->getWatchedFDCount(false) != 0 || multiplexer->getWatchedFDCount(true) != 0) && !sender->d_error) {
        multiplexer->run(&now);
        handleH2Timeouts(*multiplexer, now);
      }
      if (sender->d_error) {
        if (verbose) {
          SLOG(warnlog("Error sending a discovery DoH query to backend: %d", addr.toStringWithPort()),
               logger->info(Logr::Warning, "Error sending a discovery DoH query to backend"));
        }
        return false;
      }
      packet = sender->d_response;
    }
    else {
      sock.writenWithTimeout(reinterpret_cast<const char*>(packet.data()), packet.size(), backend->d_config.tcpSendTimeout);

      const struct timeval remainingTime = {.tv_sec = backend->d_config.tcpRecvTimeout, .tv_usec = 0};
      uint16_t responseSize = 0;
      auto got = readn2WithTimeout(sock.getHandle(), &responseSize, sizeof(responseSize), remainingTime);
      if (got != sizeof(responseSize)) {
        if (verbose) {
          SLOG(warnlog("Error while waiting for the ADD upgrade response size from backend %s: %d", addr.toStringWithPort(), got),
               logger->info(Logr::Warning, "Error while waiting for the ADD upgrade response size from backend", "value", Logging::Loggable(got), "expected", Logging::Loggable(sizeof(responseSize))));
        }
        return false;
      }

      packet.resize(ntohs(responseSize));

      got = readn2WithTimeout(sock.getHandle(), packet.data(), packet.size(), remainingTime);
      if (got != packet.size()) {
        if (verbose) {
          SLOG(warnlog("Error while waiting for the ADD upgrade response from backend %s: %d", addr.toStringWithPort(), got),
               logger->info(Logr::Warning, "Error while waiting for the ADD upgrade response from backend", "value", Logging::Loggable(got), "expected", Logging::Loggable(packet.size())));
        }
        return false;
      }

      if (packet.size() <= sizeof(struct dnsheader)) {
        if (verbose) {
          SLOG(warnlog("Too short answer of size %d received from the backend %s", packet.size(), addr.toStringWithPort()),
               logger->info(Logr::Warning, "Too short answer received from the backend", "dns.response.size", Logging::Loggable(packet.size())));
        }
        return false;
      }
    }

    struct dnsheader d;
    memcpy(&d, packet.data(), sizeof(d));
    if (d.id != id) {
      if (verbose) {
        SLOG(warnlog("Invalid ID (%d / %d) received from the backend %s", d.id, id, addr.toStringWithPort()),
             logger->info(Logr::Warning, "Invalid ID received from the backend", "dns.response.id", Logging::Loggable(d.id)));
      }
      return false;
    }

    if (d.rcode != RCode::NoError) {
      if (verbose) {
        SLOG(warnlog("Response code '%s' received from the backend %s for '%s'", RCode::to_s(d.rcode), addr.toStringWithPort(), s_discoveryDomain),
             logger->info(Logr::Warning, "Unexpected response code received from backend", "dns.response.code", Logging::Loggable(RCode::to_s(d.rcode))));
      }

      return false;
    }

    if (ntohs(d.qdcount) != 1) {
      if (verbose) {
        SLOG(warnlog("Invalid answer (qdcount %d) received from the backend %s", ntohs(d.qdcount), addr.toStringWithPort()),
             logger->info(Logr::Warning, "Invalid qdcount in answer received from the backend", "dns.response.qdcount", Logging::Loggable(ntohs(d.qdcount))));
      }
      return false;
    }

    uint16_t receivedType;
    uint16_t receivedClass;
    DNSName receivedName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != s_discoveryDomain || receivedType != s_discoveryType || receivedClass != QClass::IN) {
      if (verbose) {
        SLOG(warnlog("Invalid answer, either the qname (%s / %s), qtype (%s / %s) or qclass (%s / %s) does not match, received from the backend %s", receivedName, s_discoveryDomain, QType(receivedType).toString(), s_discoveryType.toString(), QClass(receivedClass).toString(), QClass::IN.toString(), addr.toStringWithPort()),
             logger->info(Logr::Warning, "Response received from the backend doesn't match query", "dns.response.name", Logging::Loggable(receivedName), "dns.response.type", Logging::Loggable(receivedType), "dns.response.class", Logging::Loggable(receivedClass)));
      }
      return false;
    }

    return handleSVCResult(*logger, packet, addr, dohKey, config);
  }
  catch (const std::exception& e) {
    SLOG(warnlog("Error while trying to discover backend upgrade for %s: %s", addr.toStringWithPort(), e.what()),
         topLogger.error(Logr::Warning, e.what(), "Error while trying to discover backend upgrade"));
  }
  catch (...) {
    SLOG(warnlog("Error while trying to discover backend upgrade for %s", addr.toStringWithPort()),
         topLogger.info(Logr::Error, "Error while trying to discover backend upgrade"));
  }

  return false;
}

static bool checkBackendUsability(const Logr::Logger& logger, std::shared_ptr<DownstreamState>& ds)
{
  try {
    Socket sock(ds->d_config.remote.sin4.sin_family, SOCK_STREAM);
    sock.setNonBlocking();

    if (!IsAnyAddress(ds->d_config.sourceAddr)) {
      sock.setReuseAddr();
#ifdef IP_BIND_ADDRESS_NO_PORT
      if (ds->d_config.ipBindAddrNoPort) {
        SSetsockopt(sock.getHandle(), SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
      }
#endif

      if (!ds->d_config.sourceItfName.empty()) {
#ifdef SO_BINDTODEVICE
        (void)setsockopt(sock.getHandle(), SOL_SOCKET, SO_BINDTODEVICE, ds->d_config.sourceItfName.c_str(), ds->d_config.sourceItfName.length());
#endif
      }
      sock.bind(ds->d_config.sourceAddr);
    }

    auto handler = std::make_unique<TCPIOHandler>(ds->d_config.d_tlsSubjectName, ds->d_config.d_tlsSubjectIsAddr, sock.releaseHandle(), timeval{ds->d_config.checkTimeout, 0}, ds->d_tlsCtx);
    handler->connect(ds->d_config.tcpFastOpen, ds->d_config.remote, timeval{ds->d_config.checkTimeout, 0});
    return true;
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Exception when trying to use a newly upgraded backend %s (subject %s): %s", ds->getNameWithAddr(), ds->d_config.d_tlsSubjectName, e.what()),
                logger.error(Logr::Info, e.what(), "Exception when trying to use a newly upgraded backend", "tls-subject-name", Logging::Loggable(ds->d_config.d_tlsSubjectName)));
  }
  catch (...) {
    VERBOSESLOG(infolog("Exception when trying to use a newly upgraded backend %s (subject %s)", ds->getNameWithAddr(), ds->d_config.d_tlsSubjectName),
                logger.info(Logr::Info, "Exception when trying to use a newly upgraded backend", "tls-subject-name", Logging::Loggable(ds->d_config.d_tlsSubjectName)));
  }

  return false;
}

bool ServiceDiscovery::tryToUpgradeBackend(const Logr::Logger& logger, const UpgradeableBackend& backend, std::shared_ptr<DownstreamState>& upgradedBackend)
{
  ServiceDiscovery::DiscoveredResolverConfig discoveredConfig;

  VERBOSESLOG(infolog("Trying to discover configuration for backend %s", backend.d_ds->getNameWithAddr()),
              logger.info(Logr::Info, "Trying to discover upgrade configuration for backend"));

  if (!ServiceDiscovery::getDiscoveredConfig(logger, backend.d_ds, backend.d_dohKey, discoveredConfig)) {
    return false;
  }

  if (discoveredConfig.d_protocol != dnsdist::Protocol::DoT && discoveredConfig.d_protocol != dnsdist::Protocol::DoH) {
    return false;
  }

  DownstreamState::Config config(backend.d_ds->d_config);
  config.remote = discoveredConfig.d_addr;
  config.remote.setPort(discoveredConfig.d_port);

  if (backend.keepAfterUpgrade && config.d_availability == DownstreamState::Availability::Up) {
    /* it's OK to keep the forced state if we replace the initial
       backend, but if we are adding a new backend, it should not
       inherit that setting, especially since DoX backends are much
       more likely to fail (certificate errors, ...) */
    if (config.d_upgradeToLazyHealthChecks) {
      config.d_availability = DownstreamState::Availability::Auto;
      config.d_healthCheckMode = DownstreamState::HealthCheckMode::Lazy;
    }
    else {
      config.d_availability = DownstreamState::Availability::Auto;
      config.d_healthCheckMode = DownstreamState::HealthCheckMode::Active;
    }
  }

  ComboAddress::addressOnlyEqual comparator;
  config.d_dohPath = discoveredConfig.d_dohPath;
  if (!discoveredConfig.d_subjectName.empty() && comparator(config.remote, backend.d_ds->d_config.remote)) {
    /* same address, we can used the supplied name for validation */
    config.d_tlsSubjectName = discoveredConfig.d_subjectName;
  }
  else {
    /* different name, and draft-ietf-add-ddr-04 states that:
       "In order to be considered a verified Designated Resolver, the TLS
       certificate presented by the Designated Resolver MUST contain the IP
       address of the designating Unencrypted Resolver in a subjectAltName
       extension."
    */
    config.d_tlsSubjectName = backend.d_ds->d_config.remote.toString();
    config.d_tlsSubjectIsAddr = true;
  }
  config.d_tlsParams.d_alpn = discoveredConfig.d_protocol == dnsdist::Protocol::DoT ? TLSFrontend::ALPN::DoT : TLSFrontend::ALPN::DoH;

  if (!backend.d_poolAfterUpgrade.empty()) {
    config.pools.clear();
    config.pools.insert(backend.d_poolAfterUpgrade);
  }

  try {
    /* create new backend, put it into the right pool(s) */
    auto tlsCtx = getTLSContext(config.d_tlsParams);
    auto newServer = std::make_shared<DownstreamState>(std::move(config), std::move(tlsCtx), true);

    /* check that we can connect to the backend (including certificate validation */
    if (!checkBackendUsability(logger, newServer)) {
      VERBOSESLOG(infolog("Failed to use the automatically upgraded server %s, skipping for now", newServer->getNameWithAddr()),
                  logger.info(Logr::Info, "Failed to use the automatically upgraded server, skipping for now"));
      return false;
    }

    SLOG(infolog("Added automatically upgraded server %s", newServer->getNameWithAddr()),
         logger.info(Logr::Info, "Added automatically upgraded server"));

    if (!newServer->d_config.pools.empty()) {
      for (const auto& poolName : newServer->d_config.pools) {
        addServerToPool(poolName, newServer);
      }
    }
    else {
      addServerToPool("", newServer);
    }

    newServer->start();

    /* remove the existing backend if needed */
    if (!backend.keepAfterUpgrade) {
      dnsdist::configuration::updateRuntimeConfiguration([&backend](dnsdist::configuration::RuntimeConfiguration& runtimeConfig) {
        auto& backends = runtimeConfig.d_backends;
        for (auto backendIt = backends.begin(); backendIt != backends.end(); ++backendIt) {
          if (*backendIt == backend.d_ds) {
            backends.erase(backendIt);
            break;
          }
        }
      });

      for (const string& poolName : backend.d_ds->d_config.pools) {
        removeServerFromPool(poolName, backend.d_ds);
      }
      /* the server might also be in the default pool */
      removeServerFromPool("", backend.d_ds);
    }

    dnsdist::backend::registerNewBackend(newServer);
    upgradedBackend = newServer;

    if (!backend.keepAfterUpgrade) {
      backend.d_ds->stop();
    }

    return true;
  }
  catch (const std::exception& e) {
    SLOG(warnlog("Error when trying to upgrade a discovered backend: %s", e.what()),
         logger.error(Logr::Warning, e.what(), "Error when trying to upgrade a discovered backend"));
  }

  return false;
}

bool ServiceDiscovery::tryToRedirectBackend(const Logr::Logger& logger, RedirectableBackend& backend, uint32_t& ttl)
{
  ServiceDiscovery::DiscoveredResolverConfig discoveredConfig;

  VERBOSESLOG(infolog("Trying to discover redirection configuration for backend %s", backend.d_origDs->getNameWithAddr()),
              logger.info(Logr::Info, "Trying to discover redirection configuration for backend"));

  // Start the redirection from the original server always
  std::shared_ptr<DownstreamState> newServer = backend.d_origDs;
  ttl = std::numeric_limits<uint32_t>::max();

  uint32_t redirects = 0;
  std::unordered_set<ServiceDiscovery::DiscoveredResolverConfig> discoveredResolvers = {discoveredConfig};

  try {
    while (redirects < backend.d_maxFollowCount) {
      discoveredConfig = {};
      if (!ServiceDiscovery::getDiscoveredConfig(logger, newServer, backend.d_dohKey, discoveredConfig)) {
        return false;
      }

      if (discoveredConfig.d_protocol != dnsdist::Protocol::DoT && discoveredConfig.d_protocol != dnsdist::Protocol::DoH) {
        return false;
      }

      // Loop detected, exit
      if (discoveredResolvers.find(discoveredConfig) != discoveredResolvers.end()) {
        break;
      }

      discoveredResolvers.insert(discoveredConfig);

      DownstreamState::Config config(newServer->d_config);
      config.remote = discoveredConfig.d_addr;
      config.remote.setPort(discoveredConfig.d_port);

      if (backend.d_keepAfterRedirect && config.d_availability == DownstreamState::Availability::Up) {
        config.d_availability = DownstreamState::Availability::Auto;
        config.d_healthCheckMode = DownstreamState::HealthCheckMode::Active;
      }

      ComboAddress::addressOnlyEqual comparator;
      config.d_dohPath = discoveredConfig.d_dohPath;
      if (!discoveredConfig.d_subjectName.empty() && comparator(config.remote, newServer->d_config.remote) && !config.d_tlsSubjectIsAddr) {
        /* same address, we can used the supplied name for validation */
        config.d_tlsSubjectName = discoveredConfig.d_subjectName;
        config.d_tlsSubjectIsAddr = false;
      }
      else {
        /* different name, or using IP address and
           draft-ietf-add-encrypted-dns-server-redirection Section 6.3 states:
           When a resolver is discovered using DDR's Discovery Using Resolver IP
           Addresses mechanism defined in Section 4 of [RFC9462], the server's
           identity used for TLS purposes is its IP address, not its domain
           name.  This means servers and clients MUST use the original server's
           IP address, not the IP address of the previous server in the event of
           redirection chains, in the SAN field of destination servers to
           validate the redirection.
        */
        config.d_tlsSubjectName = backend.d_origDs->d_config.remote.toString();
        config.d_tlsSubjectIsAddr = true;
      }

      if (!backend.d_poolAfterRedirect.empty()) {
        config.pools.clear();
        config.pools.insert(backend.d_poolAfterRedirect);
      }

      /* create new backend, put it into the right pool(s) */
      auto tlsCtx = getTLSContext(config.d_tlsParams);
      auto nextServer = std::make_shared<DownstreamState>(std::move(config), std::move(tlsCtx), true);

      /* check that we can connect to the backend (including certificate validation */
      if (!checkBackendUsability(logger, nextServer)) {
        VERBOSESLOG(infolog("Failed to use the redirected server %s, skipping for now", newServer->getNameWithAddr()),
                    logger.info(Logr::Info, "Failed to use the redirected server, skipping for now"));
        break;
      }

      newServer->stop();
      newServer = nextServer;
      ttl = std::min(discoveredConfig.d_ttl, ttl);
    }

    if (newServer == backend.d_origDs) {
      return false;
    }

    if (!newServer->d_config.pools.empty()) {
      for (const auto& poolName : newServer->d_config.pools) {
        addServerToPool(poolName, newServer);
      }
    }
    else {
      addServerToPool("", newServer);
    }

    newServer->start();

    SLOG(infolog("Added redirected server %s", newServer->getNameWithAddr()),
         logger.info(Logr::Info, "Added redirected server", "server", Logging::Loggable(newServer->getNameWithAddr()), "server22", Logging::Loggable(newServer->d_config.remote.toStringWithPort())));

    /* remove the existing backend */
    if (!backend.d_keepAfterRedirect) {
      dnsdist::configuration::updateRuntimeConfiguration([&backend](dnsdist::configuration::RuntimeConfiguration& runtimeConfig) {
        auto& backends = runtimeConfig.d_backends;
        for (auto backendIt = backends.begin(); backendIt != backends.end(); ++backendIt) {
          if (*backendIt == backend.d_origDs || *backendIt == backend.d_currentDs) {
            backends.erase(backendIt);
            break;
          }
        }
      });

      // Remove the original
      for (const string& poolName : backend.d_origDs->d_config.pools) {
        removeServerFromPool(poolName, backend.d_origDs);
      }
      /* the server might also be in the default pool */
      removeServerFromPool("", backend.d_origDs);
    }

    if (backend.d_currentDs) {
      for (const string& poolName : backend.d_currentDs->d_config.pools) {
        removeServerFromPool(poolName, backend.d_currentDs);
      }
      /* the server might also be in the default pool */
      removeServerFromPool("", backend.d_currentDs);

      backend.d_currentDs->stop();
    }

    dnsdist::backend::registerNewBackend(newServer);
    if (!backend.d_keepAfterRedirect) {
      backend.d_origDs->stop();
    }
    backend.d_currentDs = newServer;

    return true;
  }
  catch (const std::exception& e) {
    SLOG(warnlog("Error when trying to redirect a backend: %s", e.what()),
         logger.error(Logr::Warning, e.what(), "Error when trying to redirect a backend"));
  }

  return false;
}

void ServiceDiscovery::worker()
{
  setThreadName("dnsdist/discove");
  auto logger = dnsdist::logging::getTopLogger("service-discovery");

  while (true) {
    dnsdist::configuration::refreshLocalRuntimeConfiguration();
    time_t now = time(nullptr);

    auto upgradeables = *(s_upgradeableBackends.lock());
    std::set<std::shared_ptr<DownstreamState>> upgradedBackends;

    for (auto backendIt = upgradeables.begin(); backendIt != upgradeables.end();) {
      auto& backend = *backendIt;
      auto backendLogger = logger->withValues("backend.name", Logging::Loggable(backend->d_ds->getName()), "backend.address", Logging::Loggable(backend->d_ds->d_config.remote));

      try {
        if (backend->d_nextCheck > now) {
          ++backendIt;
          continue;
        }

        std::shared_ptr<DownstreamState> newServer;
        auto upgraded = tryToUpgradeBackend(*backendLogger, *backend, newServer);
        if (upgraded) {
          upgradedBackends.insert(backend->d_ds);
          if (backend->d_enableRedirect) {
            addRedirectableServer(newServer, backend->d_redirectInterval, backend->d_poolAfterRedirect, backend->d_redirectDohKey, backend->d_keepAfterRedirect, backend->d_redirectMaxFollowCount);
          }
          backendIt = upgradeables.erase(backendIt);
          continue;
        }
      }
      catch (const std::exception& e) {
        VERBOSESLOG(infolog("Exception in the Service Discovery thread: %s", e.what()),
                    backendLogger->error(Logr::Info, e.what(), "Exception in the Service Discovery thread"));
      }
      catch (...) {
        VERBOSESLOG(infolog("Exception in the Service Discovery thread"),
                    backendLogger->info(Logr::Info, "Exception in the Service Discovery thread"));
      }

      backend->d_nextCheck = now + backend->d_interval;
      ++backendIt;
    }

    {
      auto backends = s_upgradeableBackends.lock();
      for (auto it = backends->begin(); it != backends->end();) {
        if (upgradedBackends.count((*it)->d_ds) != 0) {
          it = backends->erase(it);
        }
        else {
          ++it;
        }
      }
    }

    auto redirectables = *(s_redirectableBackends.lock());

    for (auto backendIt = redirectables.begin(); backendIt != redirectables.end();) {
      auto& backend = *backendIt;
      auto backendLogger = logger->withValues("backend.name", Logging::Loggable(backend->d_origDs->getName()), "backend.address", Logging::Loggable(backend->d_origDs->d_config.remote));

      if (backend->d_nextCheck > now) {
        ++backendIt;
        continue;
      }

      try {
        uint32_t ttl = 0;
        auto redirected = tryToRedirectBackend(*backendLogger, *backend, ttl);
        if (!redirected) {
          // If original server is stopped and we failed to redirect, restart the original
          if (!backend->d_keepAfterRedirect && backend->d_origDs->isStopped()) {
            auto originalServer = backend->d_origDs;
            if (!originalServer->d_config.pools.empty()) {
              for (const auto& poolName : originalServer->d_config.pools) {
                addServerToPool(poolName, originalServer);
              }
            }
            else {
              addServerToPool("", originalServer);
            }
            dnsdist::backend::registerNewBackend(originalServer);
            originalServer->start();
          }
          backend->d_nextCheck = now + backend->d_interval;
        }
        else {
          backend->d_nextCheck = now + ttl;
        }
      }
      catch (const std::exception& e) {
        VERBOSESLOG(infolog("Exception in the Service Discovery thread: %s", e.what()),
                    backendLogger->error(Logr::Info, e.what(), "Exception in the Service Discovery thread"));
      }
      catch (...) {
        VERBOSESLOG(infolog("Exception in the Service Discovery thread"),
                    backendLogger->info(Logr::Info, "Exception in the Service Discovery thread"));
      }

      ++backendIt;
    }

    /* we could sleep until the next check but a new backend
       could be added in the meantime, so let's just check every
       minute if we have something to do */
    sleep(60);
  }
}

bool ServiceDiscovery::run()
{
  s_thread = std::thread(&ServiceDiscovery::worker);
  s_thread.detach();

  return true;
}

LockGuarded<std::vector<std::shared_ptr<ServiceDiscovery::UpgradeableBackend>>> ServiceDiscovery::s_upgradeableBackends;
LockGuarded<std::vector<std::shared_ptr<ServiceDiscovery::RedirectableBackend>>> ServiceDiscovery::s_redirectableBackends;
std::thread ServiceDiscovery::s_thread;
}
