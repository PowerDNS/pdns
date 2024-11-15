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

#include "dnsdist-configuration-yaml.hh"
#include "iputils.hh"
#include "remote_logger.hh"

#if defined(HAVE_YAML_CONFIGURATION)
#include "base64.hh"
#include "dolog.hh"
#include "dnsdist-actions.hh"
#include "dnsdist-backend.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-discovery.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-kvs.hh"
#include "dnsdist-web.hh"
#include "doh.hh"
#include "rust/cxx.h"
#include "rust/lib.rs.h"

#include <boost/uuid/string_generator.hpp>
#endif /* HAVE_YAML_CONFIGURATION */

namespace dnsdist::configuration::yaml
{
#if defined(HAVE_YAML_CONFIGURATION)
void convertImmutableFlatSettingsFromRust(const dnsdist::rust::settings::GlobalConfiguration& yamlConfig);
void convertRuntimeFlatSettingsFromRust(const dnsdist::rust::settings::GlobalConfiguration& yamlConfig);

using RegisteredTypes = std::variant<std::shared_ptr<DNSDistPacketCache>, std::shared_ptr<dnsdist::rust::settings::DNSSelector>, std::shared_ptr<dnsdist::rust::settings::DNSActionWrapper>, std::shared_ptr<NetmaskGroup>, std::shared_ptr<KeyValueStore>, std::shared_ptr<KeyValueLookupKey>, std::shared_ptr<RemoteLoggerInterface>, std::shared_ptr<ServerPolicy>>;
static LockGuarded<std::unordered_map<std::string, RegisteredTypes>> s_registeredTypesMap;

template <class T>
static void registerType(const std::shared_ptr<T>& entry, const ::rust::string& rustName)
{
  std::string name(rustName);
  if (name.empty()) {
    auto uuid = getUniqueID();
    name = boost::uuids::to_string(uuid);
  }

  auto [it, inserted] = s_registeredTypesMap.lock()->try_emplace(name, entry);
  if (!inserted) {
    throw std::runtime_error("Trying to register a type named '" + name + "' while one already exists");
  }
}

template <class T>
static std::shared_ptr<T> getRegisteredTypeByName(const std::string& name)
{
  auto map = s_registeredTypesMap.lock();
  auto item = map->find(name);
  if (item == map->end()) {
    return nullptr;
  }
  if (auto* ptr = std::get_if<std::shared_ptr<T>>(&item->second)) {
    return *ptr;
  }
  return nullptr;
}

template <class T>
static std::shared_ptr<T> getRegisteredTypeByName(const ::rust::String& name)
{
  auto nameStr = std::string(name);
  return getRegisteredTypeByName<T>(nameStr);
}

template <class T>
static T checkedConversionFromStr(const std::string& context, const std::string& parameterName, const std::string& str)
{
  try {
    return pdns::checked_stoi<T>(std::string(str));
  }
  catch (const std::exception& exp) {
    throw std::runtime_error("Error converting value '" + str + "' for parameter '" + parameterName + "' in YAML directive '" + context + "': " + exp.what());
  }
}

template <class T>
static T checkedConversionFromStr(const std::string& context, const std::string& parameterName, const ::rust::string& str)
{
  return checkedConversionFromStr<T>(context, parameterName, std::string(str));
}

static std::set<int> getCPUPiningFromStr(const std::string& context, const std::string& cpuStr)
{
  std::set<int> cpus;
  std::vector<std::string> tokens;
  stringtok(tokens, cpuStr);
  for (const auto& token : tokens) {
    cpus.insert(checkedConversionFromStr<int>(context, "cpus", token));
  }
  return cpus;
}

static TLSConfig getTLSConfigFromRustIncomingTLS(const dnsdist::rust::settings::IncomingTlsConfiguration& incomingTLSConfig)
{
  TLSConfig out;
  for (const auto& certConfig : incomingTLSConfig.certificates) {
    TLSCertKeyPair pair(std::string(certConfig.certificate));
    if (!certConfig.key.empty()) {
      pair.d_key = std::string(certConfig.key);
    }
    if (!certConfig.password.empty()) {
      pair.d_password = std::string(certConfig.password);
    }
    out.d_certKeyPairs.push_back(std::move(pair));
  }
  for (const auto& ocspFile : incomingTLSConfig.ocsp_response_files) {
    out.d_ocspFiles.emplace_back(ocspFile);
  }
  out.d_ciphers = std::string(incomingTLSConfig.ciphers);
  out.d_ciphers13 = std::string(incomingTLSConfig.ciphers_tls_13);
  out.d_minTLSVersion = libssl_tls_version_from_string(std::string(incomingTLSConfig.minimum_version));
  out.d_ticketKeyFile = std::string(incomingTLSConfig.ticket_key_file);
  out.d_keyLogFile = std::string(incomingTLSConfig.key_log_file);
  out.d_maxStoredSessions = incomingTLSConfig.number_of_stored_sessions;
  out.d_sessionTimeout = incomingTLSConfig.session_timeout;
  out.d_ticketsKeyRotationDelay = incomingTLSConfig.tickets_keys_rotation_delay;
  out.d_numberOfTicketsKeys = incomingTLSConfig.number_of_tickets_keys;
  out.d_preferServerCiphers = incomingTLSConfig.prefer_server_ciphers;
  out.d_enableTickets = incomingTLSConfig.session_tickets;
  out.d_releaseBuffers = incomingTLSConfig.release_buffers;
  out.d_enableRenegotiation = incomingTLSConfig.enable_renegotiation;
  out.d_asyncMode = incomingTLSConfig.async_mode;
  out.d_ktls = incomingTLSConfig.ktls;
  out.d_readAhead = incomingTLSConfig.read_ahead;
  return out;
}

static bool validateTLSConfiguration(const dnsdist::rust::settings::BindsConfiguration& bind, const TLSConfig& tlsConfig)
{
  if (!bind.tls.ignore_configuration_errors) {
    return true;
  }

  // we are asked to try to load the certificates so we can return a potential error
  // and properly ignore the frontend before actually launching it
  try {
    std::map<int, std::string> ocspResponses = {};
    auto ctx = libssl_init_server_context(tlsConfig, ocspResponses);
  }
  catch (const std::runtime_error& e) {
    errlog("Ignoring %s frontend: '%s'", bind.protocol, e.what());
    return false;
  }

  return true;
}

static bool handleTLSConfiguration(const dnsdist::rust::settings::BindsConfiguration& bind, ClientState& state)
{
  auto tlsConfig = getTLSConfigFromRustIncomingTLS(bind.tls);
  if (!validateTLSConfiguration(bind, tlsConfig)) {
    return false;
  }

  if (bind.protocol == "DoT") {
    auto frontend = std::make_shared<TLSFrontend>(TLSFrontend::ALPN::DoT);
    frontend->d_provider = std::string(bind.tls.provider);
    boost::algorithm::to_lower(frontend->d_provider);
    frontend->d_proxyProtocolOutsideTLS = bind.tls.proxy_protocol_outside_tls;
    frontend->d_tlsConfig = std::move(tlsConfig);
    state.tlsFrontend = std::move(frontend);
  }
  else if (bind.protocol == "DoQ") {
    auto frontend = std::make_shared<DOQFrontend>();
    frontend->d_local = ComboAddress(std::string(bind.listen_address), 853);
    frontend->d_quicheParams.d_tlsConfig = std::move(tlsConfig);
    frontend->d_quicheParams.d_maxInFlight = bind.doq.max_concurrent_queries_per_connection;
    frontend->d_quicheParams.d_idleTimeout = bind.quic.idle_timeout;
    frontend->d_quicheParams.d_keyLogFile = std::string(bind.tls.key_log_file);
    if (dnsdist::doq::s_available_cc_algorithms.count(std::string(bind.quic.congestion_control_algorithm)) > 0) {
      frontend->d_quicheParams.d_ccAlgo = std::string(bind.quic.congestion_control_algorithm);
    }
    frontend->d_internalPipeBufferSize = bind.quic.internal_pipe_buffer_size;
    state.doqFrontend = std::move(frontend);
  }
  else if (bind.protocol == "DoH3") {
    auto frontend = std::make_shared<DOH3Frontend>();
    frontend->d_local = ComboAddress(std::string(bind.listen_address), 853);
    frontend->d_quicheParams.d_tlsConfig = std::move(tlsConfig);
    frontend->d_quicheParams.d_idleTimeout = bind.quic.idle_timeout;
    frontend->d_quicheParams.d_keyLogFile = std::string(bind.tls.key_log_file);
    if (dnsdist::doq::s_available_cc_algorithms.count(std::string(bind.quic.congestion_control_algorithm)) > 0) {
      frontend->d_quicheParams.d_ccAlgo = std::string(bind.quic.congestion_control_algorithm);
    }
    frontend->d_internalPipeBufferSize = bind.quic.internal_pipe_buffer_size;
    state.doh3Frontend = std::move(frontend);
  }
  else if (bind.protocol == "DoH") {
    auto frontend = std::make_shared<DOHFrontend>();
    frontend->d_tlsContext.d_provider = std::string(bind.tls.provider);
    boost::algorithm::to_lower(frontend->d_tlsContext.d_provider);
    frontend->d_library = std::string(bind.doh.provider);
    if (frontend->d_library == "h2o") {
#ifdef HAVE_LIBH2OEVLOOP
      frontend = std::make_shared<H2ODOHFrontend>();
      // we _really_ need to set it again, as we just replaced the generic frontend by a new one
      frontend->d_library = "h2o";
#else /* HAVE_LIBH2OEVLOOP */
      errlog("DOH bind %s is configured to use libh2o but the library is not available", bind.listen_address);
      return false;
#endif /* HAVE_LIBH2OEVLOOP */
    }
    else if (frontend->d_library == "nghttp2") {
#ifndef HAVE_NGHTTP2
      errlog("DOH bind %s is configured to use nghttp2 but the library is not available", bind.listen_address);
      return false;
#endif /* HAVE_NGHTTP2 */
    }
    else {
      errlog("DOH bind %s is configured to use an unknown library ('%s')", bind.listen_address, frontend->d_library);
      return false;
    }

    for (const auto& path : bind.doh.paths) {
      frontend->d_urls.emplace(path);
    }
    frontend->d_idleTimeout = bind.doh.idle_timeout;
    frontend->d_serverTokens = std::string(bind.doh.server_tokens);
    frontend->d_sendCacheControlHeaders = bind.doh.send_cache_control_headers;
    frontend->d_keepIncomingHeaders = bind.doh.keep_incoming_headers;
    frontend->d_trustForwardedForHeader = bind.doh.trust_forwarded_for_header;
    frontend->d_earlyACLDrop = bind.doh.early_acl_drop;
    frontend->d_internalPipeBufferSize = bind.doh.internal_pipe_buffer_size;
    frontend->d_exactPathMatching = bind.doh.exact_path_matching;
    for (const auto& customHeader : bind.doh.custom_response_headers) {
      auto headerResponse = std::pair(boost::to_lower_copy(std::string(customHeader.key)), std::string(customHeader.value));
      frontend->d_customResponseHeaders.insert(std::move(headerResponse));
    }

    if (!tlsConfig.d_certKeyPairs.empty()) {
      frontend->d_tlsContext.d_addr = ComboAddress(std::string(bind.listen_address), 443);
      infolog("DNS over HTTPS configured");
    }
    else {
      frontend->d_tlsContext.d_addr = ComboAddress(std::string(bind.listen_address), 80);
      infolog("No certificate provided for DoH endpoint %s, running in DNS over HTTP mode instead of DNS over HTTPS", frontend->d_tlsContext.d_addr.toStringWithPort());
    }

    frontend->d_tlsContext.d_proxyProtocolOutsideTLS = bind.tls.proxy_protocol_outside_tls;
    frontend->d_tlsContext.d_tlsConfig = std::move(tlsConfig);
    state.dohFrontend = std::move(frontend);
  }

  return true;
}

template <class T>
static bool getOptionalLuaFunction(T& destination, const ::rust::string& functionName)
{
  auto lua = g_lua.lock();
  auto function = lua->readVariable<boost::optional<T>>(std::string(functionName));
  if (!function) {
    return false;
  }
  destination = *function;
  return true;
}

static std::shared_ptr<DownstreamState> createBackendFromConfiguration(const dnsdist::rust::settings::BackendsConfiguration& config)
{
  DownstreamState::Config backendConfig;
  std::shared_ptr<TLSCtx> tlsCtx;

  backendConfig.d_numberOfSockets = config.sockets;
  backendConfig.d_qpsLimit = config.queries_per_second;
  backendConfig.order = config.order;
  backendConfig.d_weight = config.weight;
  backendConfig.d_retries = config.retries;
  backendConfig.d_maxInFlightQueriesPerConn = config.max_in_flight;
  backendConfig.d_tcpConcurrentConnectionsLimit = config.max_concurrent_tcp_connections;
  backendConfig.name = std::string(config.name);
  if (!config.id.empty()) {
    backendConfig.id = boost::uuids::string_generator()(std::string(config.id));
  }
  backendConfig.useECS = config.use_client_subnet;
  backendConfig.useProxyProtocol = config.use_proxy_protocol;
  backendConfig.d_proxyProtocolAdvertiseTLS = config.proxy_protocol_advertise_tls;
  backendConfig.disableZeroScope = config.disable_zero_scope;
  backendConfig.ipBindAddrNoPort = config.ip_bind_addr_no_port;
  backendConfig.reconnectOnUp = config.reconnect_on_up;
  backendConfig.d_cpus = getCPUPiningFromStr("backend", std::string(config.cpus));
  backendConfig.d_tcpOnly = config.tcp_only;

  backendConfig.tcpConnectTimeout = config.tcp.connect_timeout;
  backendConfig.tcpSendTimeout = config.tcp.send_timeout;
  backendConfig.tcpRecvTimeout = config.tcp.receive_timeout;
  backendConfig.tcpFastOpen = config.tcp.fast_open;

  const auto& hcConf = config.health_checks;
  backendConfig.checkInterval = hcConf.interval;
  if (!hcConf.qname.empty()) {
    backendConfig.checkName = DNSName(std::string(hcConf.qname));
  }
  backendConfig.checkType = std::string(hcConf.qtype);
  if (!hcConf.qclass.empty()) {
    backendConfig.checkClass = QClass(std::string(hcConf.qclass));
  }
  backendConfig.checkTimeout = hcConf.timeout;
  backendConfig.d_tcpCheck = hcConf.use_tcp;
  backendConfig.setCD = hcConf.set_cd;
  backendConfig.mustResolve = hcConf.must_resolve;
  backendConfig.maxCheckFailures = hcConf.max_failures;
  backendConfig.minRiseSuccesses = hcConf.rise;

  getOptionalLuaFunction<DownstreamState::checkfunc_t>(backendConfig.checkFunction, hcConf.function);

  auto availability = DownstreamState::getAvailabilityFromStr(std::string(hcConf.mode));
  if (availability) {
    backendConfig.availability = *availability;
  }

  backendConfig.d_lazyHealthCheckSampleSize = hcConf.lazy.sample_size;
  backendConfig.d_lazyHealthCheckMinSampleCount = hcConf.lazy.min_sample_count;
  backendConfig.d_lazyHealthCheckThreshold = hcConf.lazy.threshold;
  backendConfig.d_lazyHealthCheckFailedInterval = hcConf.lazy.interval;
  backendConfig.d_lazyHealthCheckUseExponentialBackOff = hcConf.lazy.use_exponential_back_off;
  backendConfig.d_lazyHealthCheckMaxBackOff = hcConf.lazy.max_back_off;
  if (hcConf.lazy.mode == "TimeoutOnly") {
    backendConfig.d_lazyHealthCheckMode = DownstreamState::LazyHealthCheckMode::TimeoutOnly;
  }
  else if (hcConf.lazy.mode == "TimeoutOrServFail") {
    backendConfig.d_lazyHealthCheckMode = DownstreamState::LazyHealthCheckMode::TimeoutOrServFail;
  }
  else if (!hcConf.lazy.mode.empty()) {
    warnlog("Ignoring unknown value '%s' for 'lazy.mode' on backend %s", hcConf.lazy.mode, std::string(config.address));
  }

  backendConfig.d_upgradeToLazyHealthChecks = config.auto_upgrade.use_lazy_health_check;

  uint16_t serverPort = 53;
  const auto& tlsConf = config.tls;
  if (!tlsConf.provider.empty()) {
    serverPort = 853;
    backendConfig.d_tlsParams.d_alpn = TLSFrontend::ALPN::DoT;
    backendConfig.d_tlsParams.d_provider = std::string(tlsConf.provider);
    backendConfig.d_tlsParams.d_ciphers = std::string(tlsConf.ciphers);
    backendConfig.d_tlsParams.d_ciphers13 = std::string(tlsConf.ciphers_tls_13);
    backendConfig.d_tlsParams.d_caStore = std::string(tlsConf.ca_store);
    backendConfig.d_tlsParams.d_validateCertificates = tlsConf.validate_certificate;
    backendConfig.d_tlsParams.d_releaseBuffers = tlsConf.release_buffers;
    backendConfig.d_tlsParams.d_enableRenegotiation = tlsConf.enable_renegotiation;
    backendConfig.d_tlsParams.d_ktls = tlsConf.ktls;
    backendConfig.d_tlsSubjectName = std::string(tlsConf.subject_name);
    if (!tlsConf.subject_address.empty()) {
      try {
        ComboAddress addr{std::string(tlsConf.subject_address)};
        backendConfig.d_tlsSubjectName = addr.toString();
        backendConfig.d_tlsSubjectIsAddr = true;
      }
      catch (const std::exception&) {
        errlog("Error creating new server: downstream subject_address value must be a valid IP address");
      }
    }

    if (!config.doh.path.empty()) {
      serverPort = 443;
      backendConfig.d_dohPath = std::string(config.doh.path);
      backendConfig.d_tlsParams.d_alpn = TLSFrontend::ALPN::DoH;
      backendConfig.d_addXForwardedHeaders = config.doh.add_x_forwarded_headers;
    }
  }

  for (const auto& pool : config.pools) {
    backendConfig.pools.emplace(pool);
  }

  backendConfig.remote = ComboAddress(std::string(config.address), serverPort);

#warning handle XSK

  auto downstream = std::make_shared<DownstreamState>(std::move(backendConfig), std::move(tlsCtx), true);

  const auto& autoUpgradeConf = config.auto_upgrade;
  if (autoUpgradeConf.enabled && downstream->getProtocol() != dnsdist::Protocol::DoT && downstream->getProtocol() != dnsdist::Protocol::DoH) {
    dnsdist::ServiceDiscovery::addUpgradeableServer(downstream, autoUpgradeConf.interval, std::string(autoUpgradeConf.pool), autoUpgradeConf.doh_key, autoUpgradeConf.keep);
  }

  return downstream;
}
#endif /* defined(HAVE_YAML_CONFIGURATION) */

bool loadConfigurationFromFile(const std::string fileName)
{
#if defined(HAVE_YAML_CONFIGURATION)
  auto file = std::ifstream(fileName);
  if (!file.is_open()) {
    errlog("Unable to open YAML file %s: %s", fileName, stringerror(errno));
    return false;
  }

  /* register built-in policies */
  for (const auto& policy : dnsdist::lbpolicies::getBuiltInPolicies()) {
    registerType<ServerPolicy>(policy, ::rust::string(policy->d_name));
  }

  try {
    auto data = std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

    auto globalConfig = dnsdist::rust::settings::from_yaml_string(data);
    for (const auto& selector : globalConfig.selectors) {
      cerr << "Selector: " << selector.selector->d_rule->toString() << endl;
    }

    for (const auto& bind : globalConfig.binds) {
      ComboAddress listeningAddress(std::string(bind.listen_address), 53);
      updateImmutableConfiguration([&bind, listeningAddress](ImmutableConfiguration& config) {
        for (size_t idx = 0; idx < bind.threads; idx++) {
          auto cpus = getCPUPiningFromStr("binds", std::string(bind.cpus));
          auto state = std::make_shared<ClientState>(listeningAddress, bind.protocol != "DoQ", bind.reuseport, bind.tcp.fast_open_queue_size, std::string(bind.interface), cpus, false);
          if (bind.tcp.listen_queue_size > 0) {
            state->tcpListenQueueSize = bind.tcp.listen_queue_size;
          }
          if (bind.tcp.max_in_flight_queries > 0) {
            state->d_maxInFlightQueriesPerConn = bind.tcp.max_in_flight_queries;
          }
          if (bind.tcp.max_concurrent_connections > 0) {
            state->d_tcpConcurrentConnectionsLimit = bind.tcp.max_concurrent_connections;
          }

          for (const auto& addr : bind.additional_addresses) {
            try {
              ComboAddress address{std::string(addr)};
              state->d_additionalAddresses.emplace_back(address, -1);
            }
            catch (const PDNSException& e) {
              errlog("Unable to parse additional address %s for %s bind: %s", std::string(addr), bind.protocol, e.reason);
            }
          }

          if (bind.protocol != "Do53") {
            if (!handleTLSConfiguration(bind, *state)) {
              continue;
            }
          }

          config.d_frontends.emplace_back(std::move(state));
          if (bind.protocol == "Do53") {
            /* also create the UDP listener */
            state = std::make_shared<ClientState>(ComboAddress(std::string(bind.listen_address), 53), false, bind.reuseport, bind.tcp.fast_open_queue_size, std::string(bind.interface), cpus, false);
            config.d_frontends.emplace_back(std::move(state));
          }
        }
      });
    }

    for (const auto& backend : globalConfig.backends) {
      auto downstream = createBackendFromConfiguration(backend);

      if (!downstream->d_config.pools.empty()) {
        for (const auto& poolName : downstream->d_config.pools) {
          addServerToPool(poolName, downstream);
        }
      }
      else {
        addServerToPool("", downstream);
      }

      dnsdist::backend::registerNewBackend(downstream);
    }

    if (!globalConfig.console.listen_address.empty()) {
      const auto& consoleConf = globalConfig.console;
      dnsdist::configuration::updateRuntimeConfiguration([consoleConf](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_consoleServerAddress = ComboAddress(std::string(consoleConf.listen_address), 5199);
        config.d_consoleEnabled = true;
        config.d_consoleACL.clear();
        for (const auto& aclEntry : consoleConf.acl) {
          config.d_consoleACL.addMask(std::string(aclEntry));
        }
        B64Decode(std::string(consoleConf.key), config.d_consoleKey);
      });
    }

    if (!globalConfig.proxy_protocol.acl.empty()) {
      dnsdist::configuration::updateRuntimeConfiguration([globalConfig](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_proxyProtocolACL.clear();
        for (const auto& aclEntry : globalConfig.proxy_protocol.acl) {
          config.d_proxyProtocolACL.addMask(std::string(aclEntry));
        }
      });
    }

#ifndef DISABLE_CARBON
    for (const auto& carbonConfig : globalConfig.metrics.carbon) {
      auto newEndpoint = dnsdist::Carbon::newEndpoint(std::string(carbonConfig.address),
                                                      std::string(carbonConfig.name),
                                                      carbonConfig.interval,
                                                      carbonConfig.name_space.empty() ? "dnsdist" : std::string(carbonConfig.name_space),
                                                      carbonConfig.instance.empty() ? "main" : std::string(carbonConfig.instance));
      dnsdist::configuration::updateRuntimeConfiguration([&newEndpoint](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_carbonEndpoints.push_back(std::move(newEndpoint));
      });
    }
#endif /* DISABLE_CARBON */

    if (!globalConfig.webserver.listen_address.empty()) {
      const auto& webConfig = globalConfig.webserver;
      ComboAddress local;
      try {
        local = ComboAddress{std::string(webConfig.listen_address)};
      }
      catch (const PDNSException& e) {
        throw std::runtime_error(std::string("Error parsing the bind address for the webserver: ") + e.reason);
      }
      dnsdist::configuration::updateRuntimeConfiguration([local, webConfig](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_webServerAddress = local;
        if (!webConfig.password.empty()) {
          auto holder = std::make_shared<CredentialsHolder>(std::string(webConfig.password), webConfig.hash_plaintext_credentials);
          if (!holder->wasHashed() && holder->isHashingAvailable()) {
            infolog("Passing a plain-text password via the 'webserver.password' parameter to is not advised, please consider generating a hashed one using 'hashPassword()' instead.");
          }
          config.d_webPassword = std::move(holder);
        }
        if (!webConfig.api_key.empty()) {
          auto holder = std::make_shared<CredentialsHolder>(std::string(webConfig.api_key), webConfig.hash_plaintext_credentials);
          if (!holder->wasHashed() && holder->isHashingAvailable()) {
            infolog("Passing a plain-text API key via the 'webserver.api_key' parameter to is not advised, please consider generating a hashed one using 'hashPassword()' instead.");
          }
          config.d_webAPIKey = std::move(holder);
        }
        if (!webConfig.acl.empty()) {
          config.d_webServerACL.clear();
          for (const auto& acl : webConfig.acl) {
            config.d_webServerACL.toMasks(std::string(acl));
          }
        }
        if (!webConfig.custom_headers.empty()) {
          if (!config.d_webCustomHeaders) {
            config.d_webCustomHeaders = std::unordered_map<std::string, std::string>();
            for (const auto& customHeader : webConfig.custom_headers) {
              auto headerResponse = std::pair(boost::to_lower_copy(std::string(customHeader.key)), std::string(customHeader.value));
              config.d_webCustomHeaders->insert(std::move(headerResponse));
            }
          }
        }

        config.d_apiRequiresAuthentication = webConfig.api_requires_authentication;
        config.d_dashboardRequiresAuthentication = webConfig.dashboard_requires_authentication;
        config.d_statsRequireAuthentication = webConfig.stats_require_authentication;
        dnsdist::webserver::setMaxConcurrentConnections(webConfig.max_concurrent_connections);
        config.d_apiConfigDirectory = std::string(webConfig.api_configuration_directory);
        config.d_apiReadWrite = webConfig.api_read_write;
      });
    }

    if (globalConfig.query_count.enabled) {
      dnsdist::configuration::updateRuntimeConfiguration([&globalConfig](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_queryCountConfig.d_enabled = true;
        if (!globalConfig.query_count.filter.empty()) {
          getOptionalLuaFunction<dnsdist::QueryCount::Configuration::Filter>(config.d_queryCountConfig.d_filter, globalConfig.query_count.filter);
        }
      });
    }

    if (!globalConfig.dynamic_rules_settings.default_action.empty()) {
      dnsdist::configuration::updateRuntimeConfiguration([default_action = globalConfig.dynamic_rules_settings.default_action](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_dynBlockAction = DNSAction::typeFromString(std::string(default_action));
      });
    }

    for (const auto& dbrg : globalConfig.dynamic_rules) {
      auto dbrgObj = std::make_shared<DynBlockRulesGroup>();
      dbrgObj->setMasks(dbrg.mask_ipv4, dbrg.mask_ipv6, dbrg.mask_port);
      for (const auto& range : dbrg.exclude_ranges) {
        dbrgObj->excludeRange(Netmask(std::string(range)));
      }
      for (const auto& range : dbrg.include_ranges) {
        dbrgObj->includeRange(Netmask(std::string(range)));
      }
      for (const auto& domain : dbrg.exclude_domains) {
        dbrgObj->excludeDomain(DNSName(std::string(domain)));
      }
      for (const auto& rule : dbrg.rules) {
        if (rule.rule_type == "query-rate") {
          DynBlockRulesGroup::DynBlockRule ruleParams(std::string(rule.comment), rule.action_duration, rule.rate, rule.warning_rate, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)));
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          dbrgObj->setQueryRate(std::move(ruleParams));
        }
        else if (rule.rule_type == "rcode-rate") {
          DynBlockRulesGroup::DynBlockRule ruleParams(std::string(rule.comment), rule.action_duration, rule.rate, rule.warning_rate, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)));
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          dbrgObj->setRCodeRate(checkedConversionFromStr<int>("dynamic-rules.rules.rcode_rate", "rcode", rule.rcode), std::move(ruleParams));
        }
        else if (rule.rule_type == "rcode-ratio") {
          DynBlockRulesGroup::DynBlockRatioRule ruleParams(std::string(rule.comment), rule.action_duration, rule.ratio, rule.warning_ratio, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)), rule.minimum_number_of_responses);
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          dbrgObj->setRCodeRatio(checkedConversionFromStr<int>("dynamic-rules.rules.rcode_ratio", "rcode", rule.rcode), std::move(ruleParams));
        }
        else if (rule.rule_type == "qtype-rate") {
          DynBlockRulesGroup::DynBlockRule ruleParams(std::string(rule.comment), rule.action_duration, rule.rate, rule.warning_rate, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)));
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          dbrgObj->setRCodeRate(checkedConversionFromStr<int>("dynamic-rules.rules.qtype_rate", "qtype", rule.qtype), std::move(ruleParams));
        }
        else if (rule.rule_type == "qtype-ratio") {
          DynBlockRulesGroup::DynBlockRatioRule ruleParams(std::string(rule.comment), rule.action_duration, rule.ratio, rule.warning_ratio, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)), rule.minimum_number_of_responses);
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          dbrgObj->setRCodeRatio(checkedConversionFromStr<int>("dynamic-rules.rules.qtype_ratio", "qtype", rule.qtype), std::move(ruleParams));
        }
        else if (rule.rule_type == "cache-miss-ratio") {
          DynBlockRulesGroup::DynBlockCacheMissRatioRule ruleParams(std::string(rule.comment), rule.action_duration, rule.ratio, rule.warning_ratio, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)), rule.minimum_number_of_responses, rule.minimum_global_cache_hit_ratio);
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          dbrgObj->setCacheMissRatio(std::move(ruleParams));
        }
        else if (rule.rule_type == "response-byte-rate") {
          DynBlockRulesGroup::DynBlockRule ruleParams(std::string(rule.comment), rule.action_duration, rule.rate, rule.warning_rate, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)));
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          dbrgObj->setResponseByteRate(std::move(ruleParams));
        }
        else if (rule.rule_type == "suffix-match") {
          DynBlockRulesGroup::DynBlockRule ruleParams(std::string(rule.comment), rule.action_duration, 0, 0, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)));
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          DynBlockRulesGroup::smtVisitor_t visitor;
          getOptionalLuaFunction<DynBlockRulesGroup::smtVisitor_t>(visitor, rule.visitor_function);
          dbrgObj->setSuffixMatchRule(std::move(ruleParams), std::move(visitor));
        }
        else if (rule.rule_type == "suffix-match-ffi") {
          DynBlockRulesGroup::DynBlockRule ruleParams(std::string(rule.comment), rule.action_duration, 0, 0, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)));
          if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
            ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
            ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
            ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
          }
          dnsdist_ffi_stat_node_visitor_t visitor;
          getOptionalLuaFunction<dnsdist_ffi_stat_node_visitor_t>(visitor, rule.visitor_function);
          dbrgObj->setSuffixMatchRuleFFI(std::move(ruleParams), std::move(visitor));
        }
      }
      dnsdist::DynamicBlocks::registerGroup(dbrgObj);
    }

    if (!globalConfig.tuning.tcp.fast_open_key.empty()) {
      std::vector<uint32_t> key(4);
      auto ret = sscanf(globalConfig.tuning.tcp.fast_open_key.c_str(), "%" SCNx32 "-%" SCNx32 "-%" SCNx32 "-%" SCNx32, &key.at(0), &key.at(1), &key.at(2), &key.at(3));
      if (ret < 0 || static_cast<size_t>(ret) != key.size()) {
        throw std::runtime_error("Invalid value passed to tuning.tcp.fast_open_key!\n");
      }
      dnsdist::configuration::updateImmutableConfiguration([&key](dnsdist::configuration::ImmutableConfiguration& config) {
        config.d_tcpFastOpenKey = std::move(key);
      });
    }

    if (!globalConfig.general.capabilities_to_retain.empty()) {
      dnsdist::configuration::updateImmutableConfiguration([capabilities = globalConfig.general.capabilities_to_retain](dnsdist::configuration::ImmutableConfiguration& config) {
        for (const auto& capability : capabilities) {
          config.d_capabilitiesToRetain.emplace(std::string(capability));
        }
      });
    }

    for (const auto& cache : globalConfig.packet_caches) {
      auto packetCacheObj = std::make_shared<DNSDistPacketCache>(cache.size, cache.max_ttl, cache.min_ttl, cache.temporary_failure_ttl, cache.max_negative_ttl, cache.stale_ttl, cache.dont_age, cache.shards, cache.deferrable_insert_lock, cache.parse_ecs);

      packetCacheObj->setKeepStaleData(cache.keep_stale_data);
      std::unordered_set<uint16_t> optionsToSkip{EDNSOptionCode::COOKIE};

      for (const auto& option : cache.options_to_skip) {
        optionsToSkip.insert(pdns::checked_stoi<uint16_t>(std::string(option)));
      }

      if (cache.cookie_hashing) {
        optionsToSkip.erase(EDNSOptionCode::COOKIE);
      }

      packetCacheObj->setSkippedOptions(optionsToSkip);
      if (cache.maximum_entry_size >= sizeof(dnsheader)) {
        packetCacheObj->setMaximumEntrySize(cache.maximum_entry_size);
      }

      registerType<DNSDistPacketCache>(packetCacheObj, cache.name);
    }

    for (const auto& policy : globalConfig.load_balancing_policies.custom_policies) {
      if (policy.ffi) {
        if (policy.per_thread) {
          auto policyObj = std::make_shared<ServerPolicy>(std::string(policy.name), std::string(policy.function));
          registerType<ServerPolicy>(policyObj, policy.name);
        }
        else {
          ServerPolicy::ffipolicyfunc_t function;

          if (!getOptionalLuaFunction<ServerPolicy::ffipolicyfunc_t>(function, policy.function)) {
            throw std::runtime_error("Custom FFI load-balancing policy '" + std::string(policy.name) + "' is referring to a non-existent Lua function '" + std::string(policy.function) + "'");
          }
          auto policyObj = std::make_shared<ServerPolicy>(std::string(policy.name), std::move(function));
          registerType<ServerPolicy>(policyObj, policy.name);
        }
      }
      else {
        ServerPolicy::policyfunc_t function;
        if (!getOptionalLuaFunction<ServerPolicy::policyfunc_t>(function, policy.function)) {
          throw std::runtime_error("Custom load-balancing policy '" + std::string(policy.name) + "' is referring to a non-existent Lua function '" + std::string(policy.function) + "'");
        }
        auto policyObj = std::make_shared<ServerPolicy>(std::string(policy.name), std::move(function), true);
        registerType<ServerPolicy>(policyObj, policy.name);
      }
    }

    for (const auto& pool : globalConfig.pools) {
      std::shared_ptr<ServerPool> poolObj = createPoolIfNotExists(std::string(pool.name));
      if (!pool.packet_cache.empty()) {
        poolObj->packetCache = getRegisteredTypeByName<DNSDistPacketCache>(pool.packet_cache);
      }
      if (!pool.policy.empty()) {
        poolObj->policy = getRegisteredTypeByName<ServerPolicy>(pool.policy);
      }
    }

    convertImmutableFlatSettingsFromRust(globalConfig);
    convertRuntimeFlatSettingsFromRust(globalConfig);
    return true;
  }
  catch (const ::rust::Error& exp) {
    errlog("Rust error while opening YAML file %s: %s", fileName, exp.what());
  }
  catch (const std::exception& exp) {
    errlog("C++ error while opening YAML file %s: %s", fileName, exp.what());
  }
  return false;
#else
  (void)fileName;
  cerr << "Unsupported YAML configuration" << endl;
  return false;
#endif /* HAVE_YAML_CONFIGURATION */
}
}

#if defined(HAVE_YAML_CONFIGURATION)
namespace dnsdist::rust::settings
{

std::shared_ptr<DNSSelector> getSelectorByName(const ::rust::String& name)
{
  return dnsdist::configuration::yaml::getRegisteredTypeByName<DNSSelector>(name);
}

const std::string& getNameFromSelector(const DNSSelector& selector)
{
  return selector.d_name;
}

static std::shared_ptr<DNSSelector> newDNSSelector(std::shared_ptr<DNSRule>&& rule, const ::rust::String& name)
{
  auto selector = std::make_shared<DNSSelector>();
  selector->d_name = std::string(name);
  selector->d_rule = std::move(rule);
  dnsdist::configuration::yaml::registerType(selector, name);
  return selector;
}

std::shared_ptr<DNSSelector> getMaxIPQPSSelector(const MaxQPSIPSelectorConfiguration& config)
{
  auto rule = std::shared_ptr<DNSRule>(new MaxQPSIPRule(config.qps, config.burst, config.ipv4_mask, config.ipv6_mask, config.expiration, config.cleanup_delay, config.scan_fraction, config.shards));
  return newDNSSelector(std::move(rule), config.name);
}

std::shared_ptr<DNSSelector> getAllSelector()
{
  auto rule = std::shared_ptr<DNSRule>(new AllRule());
  return newDNSSelector(std::move(rule), "");
}

std::shared_ptr<DNSSelector> getAndSelector(const AndSelectorConfig& config)
{
  LuaArray<std::shared_ptr<DNSRule>> selectors;
  int counter = 1;
  for (const auto& selector : config.selectors) {
    auto dnsSelector = dnsdist::configuration::yaml::getRegisteredTypeByName<DNSSelector>(std::string(selector));
    if (dnsSelector) {
      selectors.push_back({counter++, dnsSelector->d_rule});
    }
  }
  auto rule = std::shared_ptr<DNSRule>(new AndRule(selectors));
  return newDNSSelector(std::move(rule), config.name);
}

std::shared_ptr<DNSSelector> getTCPSelector(const TCPSelectorConfig& config)
{
  auto rule = std::shared_ptr<DNSRule>(new TCPRule(config.tcp));
  return newDNSSelector(std::move(rule), config.name);
}

std::shared_ptr<DNSSelector> getNetmaskGroupSelector(const NetmaskGroupSelectorConfig& config)
{
  std::shared_ptr<NetmaskGroup> nmg;
  if (!config.netmask_group.empty()) {
    nmg = dnsdist::configuration::yaml::getRegisteredTypeByName<NetmaskGroup>(std::string(config.netmask_group));
  }
  if (!nmg) {
    nmg = std::make_shared<NetmaskGroup>();
  }
  for (const auto& netmask : config.netmasks) {
    nmg->addMask(std::string(netmask));
  }
  auto rule = std::shared_ptr<DNSRule>(new NetmaskGroupRule(*nmg, config.source, config.quiet));
  return newDNSSelector(std::move(rule), config.name);
}

std::shared_ptr<DNSActionWrapper> getPoolAction(const PoolActionConfig& config)
{
  auto poolAction = std::shared_ptr<DNSAction>(new PoolAction(config.pool, config.stop_processing));
  auto action = std::make_shared<DNSActionWrapper>();
  action->d_name = std::string(config.name);
  action->d_action = std::move(poolAction);
  dnsdist::configuration::yaml::registerType(action, action->d_name);
  return action;
}

}
#endif /* defined(HAVE_YAML_CONFIGURATION) */
