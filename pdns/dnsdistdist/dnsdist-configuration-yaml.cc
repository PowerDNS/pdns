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
#include <stdexcept>

#include "dnsdist-configuration-yaml.hh"

#if defined(HAVE_YAML_CONFIGURATION)
#include "base64.hh"
#include "dolog.hh"
#include "dnscrypt.hh"
#include "dnsdist-actions-factory.hh"
#include "dnsdist-backend.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-discovery.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-rules-factory.hh"
#include "dnsdist-kvs.hh"
#include "dnsdist-web.hh"
#include "dnsdist-xsk.hh"
#include "doh.hh"
#include "fstrm_logger.hh"
#include "iputils.hh"
#include "remote_logger.hh"
#include "remote_logger_pool.hh"
#include "xsk.hh"

#include "rust/cxx.h"
#include "rust/lib.rs.h"
#include "dnsdist-configuration-yaml-internal.hh"

#include <variant>
#include <boost/optional.hpp>
#include <boost/uuid/string_generator.hpp>
#include <boost/variant.hpp>

#endif /* HAVE_YAML_CONFIGURATION */

namespace dnsdist::configuration::yaml
{
#if defined(HAVE_YAML_CONFIGURATION)

using XSKMap = std::vector<std::shared_ptr<XskSocket>>;

using RegisteredTypes = std::variant<std::shared_ptr<DNSDistPacketCache>, std::shared_ptr<dnsdist::rust::settings::DNSSelector>, std::shared_ptr<dnsdist::rust::settings::DNSActionWrapper>, std::shared_ptr<dnsdist::rust::settings::DNSResponseActionWrapper>, std::shared_ptr<NetmaskGroup>, std::shared_ptr<KeyValueStore>, std::shared_ptr<KeyValueLookupKey>, std::shared_ptr<RemoteLoggerInterface>, std::shared_ptr<ServerPolicy>, std::shared_ptr<XSKMap>>;
static LockGuarded<std::unordered_map<std::string, RegisteredTypes>> s_registeredTypesMap;
static std::atomic<bool> s_inConfigCheckMode;
static std::atomic<bool> s_inClientMode;

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

static uint8_t strToRCode(const std::string& context, const std::string& parameterName, const ::rust::String& rcode_rust_string)
{
  auto rcode_str = std::string(rcode_rust_string);
  boost::to_lower(rcode_str);
  auto rcode = RCode::from_short(rcode_str);
  if (!rcode) {
    return checkedConversionFromStr<uint8_t>(context, parameterName, rcode_rust_string);
  }
  return *rcode;
}

static uint16_t strToQType(const std::string& context, const std::string& parameterName, const ::rust::String& qtype_rust_string)
{
  auto qtype_str = std::string(qtype_rust_string);
  QType qtype;
  qtype = qtype_str;
  if (qtype.getCode() == 0) {
    return checkedConversionFromStr<uint8_t>(context, parameterName, qtype_rust_string);
  }
  return qtype;
}

static uint8_t strToOpcode(const std::string& context, const std::string& parameterName, const ::rust::String& opcode_rust_string)
{
  auto opcode_str = std::string(opcode_rust_string);
  boost::to_lower(opcode_str);
  auto opcode = Opcode::from_lowercase_string(opcode_str);
  if (!opcode) {
    return checkedConversionFromStr<uint8_t>(context, parameterName, opcode_rust_string);
  }
  return *opcode;
}

static std::optional<std::string> loadContentFromConfigurationFile(const std::string& fileName)
{
  /* no check on the file size, don't do this with just any file! */
  auto file = std::ifstream(fileName);
  if (!file.is_open()) {
    return std::nullopt;
  }
  return std::string(std::istreambuf_iterator<char>(file), {});
}

template <class FuncType>
static bool getLuaFunctionFromConfiguration(FuncType& destination, const ::rust::string& functionName, const ::rust::string& functionCode, const ::rust::string& functionFile, const std::string& context)
{
  if (!functionName.empty()) {
    auto found = getOptionalLuaFunction<FuncType>(destination, functionName);
    if (found) {
      return true;
    }
    throw std::runtime_error("Unable to locate the Lua function named '" + std::string(functionName) + "', referenced by a Lua directive in " + context + " context");
  }
  if (!functionCode.empty()) {
    auto function = dnsdist::lua::getFunctionFromLuaCode<FuncType>(std::string(functionCode), context);
    if (function) {
      destination = *function;
      return true;
    }
    throw std::runtime_error("Unable to load a Lua function from the content of lua directive in " + context + " context");
  }
  if (!functionFile.empty()) {
    auto content = loadContentFromConfigurationFile(std::string(functionFile));
    if (!content) {
      throw std::runtime_error("Unable to load content of lua-file's '" + std::string(functionFile) + "' in " + context + " context");
    }
    auto function = dnsdist::lua::getFunctionFromLuaCode<FuncType>(*content, context);
    if (function) {
      destination = *function;
      return true;
    }
    throw std::runtime_error("Unable to load a Lua function from the content of lua-file's '" + std::string(functionFile) + "' in " + context + " context");
  }
  return false;
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
#if defined(HAVE_LIBSSL)
  out.d_minTLSVersion = libssl_tls_version_from_string(std::string(incomingTLSConfig.minimum_version));
#else /* HAVE_LIBSSL */
  if (!incomingTLSConfig.minimum_version.empty()) {
    warnlog("bind.tls.minimum_version has no effect with the chosen TLS library");
  }
#endif /* HAVE_LIBSSL */
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

static bool validateTLSConfiguration(const dnsdist::rust::settings::BindConfiguration& bind, [[maybe_unused]] const TLSConfig& tlsConfig)
{
  if (!bind.tls.ignore_configuration_errors) {
    return true;
  }

#if defined(HAVE_LIBSSL)
  // we are asked to try to load the certificates so we can return a potential error
  // and properly ignore the frontend before actually launching it
  try {
    auto ctx = libssl_init_server_context(tlsConfig);
  }
  catch (const std::runtime_error& e) {
    errlog("Ignoring %s frontend: '%s'", bind.protocol, e.what());
    return false;
  }
#endif /* HAVE_LIBSSL */

  return true;
}

static bool handleTLSConfiguration(const dnsdist::rust::settings::BindConfiguration& bind, ClientState& state, const std::shared_ptr<const TLSFrontend>& parent)
{
  auto tlsConfig = getTLSConfigFromRustIncomingTLS(bind.tls);
  if (!validateTLSConfiguration(bind, tlsConfig)) {
    return false;
  }

  auto protocol = boost::to_lower_copy(std::string(bind.protocol));
  if (protocol == "dot") {
    auto frontend = std::make_shared<TLSFrontend>(TLSFrontend::ALPN::DoT);
    frontend->setParent(parent);
    frontend->d_provider = std::string(bind.tls.provider);
    boost::algorithm::to_lower(frontend->d_provider);
    frontend->d_proxyProtocolOutsideTLS = bind.tls.proxy_protocol_outside_tls;
    frontend->d_tlsConfig = std::move(tlsConfig);
    state.tlsFrontend = std::move(frontend);
  }
#if defined(HAVE_DNS_OVER_QUIC)
  else if (protocol == "doq") {
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
#endif /* HAVE_DNS_OVER_QUIC */
#if defined(HAVE_DNS_OVER_HTTP3)
  else if (protocol == "doh3") {
    auto frontend = std::make_shared<DOH3Frontend>();
    frontend->d_local = ComboAddress(std::string(bind.listen_address), 443);
    frontend->d_quicheParams.d_tlsConfig = std::move(tlsConfig);
    frontend->d_quicheParams.d_idleTimeout = bind.quic.idle_timeout;
    frontend->d_quicheParams.d_keyLogFile = std::string(bind.tls.key_log_file);
    if (dnsdist::doq::s_available_cc_algorithms.count(std::string(bind.quic.congestion_control_algorithm)) > 0) {
      frontend->d_quicheParams.d_ccAlgo = std::string(bind.quic.congestion_control_algorithm);
    }
    frontend->d_internalPipeBufferSize = bind.quic.internal_pipe_buffer_size;
    state.doh3Frontend = std::move(frontend);
  }
#endif /* HAVE_DNS_OVER_HTTP3 */
#if defined(HAVE_DNS_OVER_HTTPS)
  else if (protocol == "doh") {
    auto frontend = std::make_shared<DOHFrontend>();
    auto& tlsContext = frontend->d_tlsContext;
    tlsContext->d_provider = std::string(bind.tls.provider);
    boost::algorithm::to_lower(tlsContext->d_provider);
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

    if (!bind.doh.responses_map.empty()) {
      auto newMap = std::make_shared<std::vector<std::shared_ptr<DOHResponseMapEntry>>>();
      for (const auto& responsesMap : bind.doh.responses_map) {
        boost::optional<std::unordered_map<std::string, std::string>> headers;
        if (!responsesMap.headers.empty()) {
          headers = std::unordered_map<std::string, std::string>();
          for (const auto& header : responsesMap.headers) {
            headers->emplace(boost::to_lower_copy(std::string(header.key)), std::string(header.value));
          }
        }
        auto entry = std::make_shared<DOHResponseMapEntry>(std::string(responsesMap.expression), responsesMap.status, PacketBuffer(responsesMap.content.begin(), responsesMap.content.end()), headers);
        newMap->emplace_back(std::move(entry));
      }
      frontend->d_responsesMap = std::move(newMap);
    }

    if (!tlsConfig.d_certKeyPairs.empty()) {
      tlsContext->d_addr = ComboAddress(std::string(bind.listen_address), 443);
      infolog("DNS over HTTPS configured");
    }
    else {
      tlsContext->d_addr = ComboAddress(std::string(bind.listen_address), 80);
      infolog("No certificate provided for DoH endpoint %s, running in DNS over HTTP mode instead of DNS over HTTPS", tlsContext->d_addr.toStringWithPort());
    }

    tlsContext->d_proxyProtocolOutsideTLS = bind.tls.proxy_protocol_outside_tls;
    tlsContext->d_tlsConfig = std::move(tlsConfig);
    tlsContext->setParent(parent);
    state.dohFrontend = std::move(frontend);
  }
#endif /* defined(HAVE_DNS_OVER_HTTPS) */
  else if (protocol != "do53") {
    errlog("Bind %s is configured to use an unknown protocol ('%s')", bind.listen_address, protocol);
    return false;
  }

  return true;
}

static std::shared_ptr<DownstreamState> createBackendFromConfiguration(const dnsdist::rust::settings::BackendConfiguration& config, bool configCheck)
{
  DownstreamState::Config backendConfig;
  std::shared_ptr<TLSCtx> tlsCtx;

  backendConfig.d_numberOfSockets = config.sockets;
  backendConfig.d_qpsLimit = config.queries_per_second;
  backendConfig.order = config.order;
  backendConfig.d_weight = config.weight;
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

  backendConfig.d_retries = config.tcp.retries;
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
  backendConfig.udpTimeout = config.udp_timeout;

  getLuaFunctionFromConfiguration<DownstreamState::checkfunc_t>(backendConfig.checkFunction, hcConf.function, hcConf.lua, hcConf.lua_file, "backend health-check");

  DownstreamState::parseAvailabilityConfigFromStr(backendConfig, std::string(hcConf.mode));

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
  auto protocol = boost::to_lower_copy(std::string(config.protocol));
  if (protocol == "dot" || protocol == "doh") {
#if !defined(HAVE_DNS_OVER_TLS)
    if (protocol == "dot") {
      throw std::runtime_error("Backend " + std::string(config.address) + " is configured to use DNS over TLS but DoT support is not available");
    }
#endif /* HAVE_DNS_OVER_TLS */
#if !defined(HAVE_DNS_OVER_HTTPS)
    if (protocol == "doh") {
      throw std::runtime_error("Backend " + std::string(config.address) + " is configured to use DNS over HTTPS but DoH support is not available");
    }
#endif /* HAVE_DNS_OVER_HTTPS */

    backendConfig.d_tlsParams.d_provider = std::string(tlsConf.provider);
    boost::algorithm::to_lower(backendConfig.d_tlsParams.d_provider);
    backendConfig.d_tlsParams.d_ciphers = std::string(tlsConf.ciphers);
    backendConfig.d_tlsParams.d_ciphers13 = std::string(tlsConf.ciphers_tls_13);
    backendConfig.d_tlsParams.d_caStore = std::string(tlsConf.ca_store);
    backendConfig.d_tlsParams.d_keyLogFile = std::string(tlsConf.key_log_file);
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
    if (backendConfig.d_tlsParams.d_validateCertificates && backendConfig.d_tlsSubjectName.empty()) {
      throw std::runtime_error("Certificate validation has been requested for backend " + std::string(config.address) + " but neither 'subject_name' nor 'subject_address' are set");
    }
  }

  if (protocol == "dot") {
    serverPort = 853;
    backendConfig.d_tlsParams.d_alpn = TLSFrontend::ALPN::DoT;
  }
  else if (protocol == "doh") {
    serverPort = 443;
    backendConfig.d_tlsParams.d_alpn = TLSFrontend::ALPN::DoH;
    backendConfig.d_dohPath = std::string(config.doh.path);
    backendConfig.d_addXForwardedHeaders = config.doh.add_x_forwarded_headers;
  }

  for (const auto& pool : config.pools) {
    backendConfig.pools.emplace(pool);
  }

  backendConfig.remote = ComboAddress(std::string(config.address), serverPort);
  if (!config.source.empty()) {
    DownstreamState::parseSourceParameter(std::string(config.source), backendConfig);
  }

  if (protocol == "dot" || protocol == "doh") {
    tlsCtx = getTLSContext(backendConfig.d_tlsParams);
  }

  backendConfig.dscp = config.dscp;

  auto downstream = std::make_shared<DownstreamState>(std::move(backendConfig), std::move(tlsCtx), !configCheck);

#if defined(HAVE_XSK)
  if (!config.xsk.empty()) {
    auto xskMap = getRegisteredTypeByName<XSKMap>(config.xsk);
    if (!xskMap) {
      throw std::runtime_error("XSK map " + std::string(config.xsk) + " attached to backend " + std::string(config.address) + " not found");
    }
    if (!configCheck) {
      downstream->registerXsk(*xskMap);
      infolog("Added downstream server %s via XSK in %s mode", std::string(config.address), xskMap->at(0)->getXDPMode());
    }
  }
#endif /* defined(HAVE_XSK) */

  const auto& autoUpgradeConf = config.auto_upgrade;
  if (autoUpgradeConf.enabled && downstream->getProtocol() != dnsdist::Protocol::DoT && downstream->getProtocol() != dnsdist::Protocol::DoH) {
    dnsdist::ServiceDiscovery::addUpgradeableServer(downstream, autoUpgradeConf.interval, std::string(autoUpgradeConf.pool), autoUpgradeConf.doh_key, autoUpgradeConf.keep);
  }

  return downstream;
}

static void loadRulesConfiguration(const dnsdist::rust::settings::GlobalConfiguration& globalConfig)
{
  dnsdist::configuration::updateRuntimeConfiguration([&globalConfig](dnsdist::configuration::RuntimeConfiguration& config) {
    for (const auto& rule : globalConfig.query_rules) {
      boost::uuids::uuid ruleUniqueID = rule.uuid.empty() ? getUniqueID() : getUniqueID(std::string(rule.uuid));
      dnsdist::rules::add(config.d_ruleChains, dnsdist::rules::RuleChain::Rules, rule.selector.selector->d_rule, rule.action.action->d_action, std::string(rule.name), ruleUniqueID, 0);
    }

    for (const auto& rule : globalConfig.cache_miss_rules) {
      boost::uuids::uuid ruleUniqueID = rule.uuid.empty() ? getUniqueID() : getUniqueID(std::string(rule.uuid));
      dnsdist::rules::add(config.d_ruleChains, dnsdist::rules::RuleChain::CacheMissRules, rule.selector.selector->d_rule, rule.action.action->d_action, std::string(rule.name), ruleUniqueID, 0);
    }

    for (const auto& rule : globalConfig.response_rules) {
      boost::uuids::uuid ruleUniqueID = rule.uuid.empty() ? getUniqueID() : getUniqueID(std::string(rule.uuid));
      dnsdist::rules::add(config.d_ruleChains, dnsdist::rules::ResponseRuleChain::ResponseRules, rule.selector.selector->d_rule, rule.action.action->d_action, std::string(rule.name), ruleUniqueID, 0);
    }

    for (const auto& rule : globalConfig.cache_hit_response_rules) {
      boost::uuids::uuid ruleUniqueID = rule.uuid.empty() ? getUniqueID() : getUniqueID(std::string(rule.uuid));
      dnsdist::rules::add(config.d_ruleChains, dnsdist::rules::ResponseRuleChain::CacheHitResponseRules, rule.selector.selector->d_rule, rule.action.action->d_action, std::string(rule.name), ruleUniqueID, 0);
    }

    for (const auto& rule : globalConfig.cache_inserted_response_rules) {
      boost::uuids::uuid ruleUniqueID = rule.uuid.empty() ? getUniqueID() : getUniqueID(std::string(rule.uuid));
      dnsdist::rules::add(config.d_ruleChains, dnsdist::rules::ResponseRuleChain::CacheInsertedResponseRules, rule.selector.selector->d_rule, rule.action.action->d_action, std::string(rule.name), ruleUniqueID, 0);
    }

    for (const auto& rule : globalConfig.self_answered_response_rules) {
      boost::uuids::uuid ruleUniqueID = rule.uuid.empty() ? getUniqueID() : getUniqueID(std::string(rule.uuid));
      dnsdist::rules::add(config.d_ruleChains, dnsdist::rules::ResponseRuleChain::SelfAnsweredResponseRules, rule.selector.selector->d_rule, rule.action.action->d_action, std::string(rule.name), ruleUniqueID, 0);
    }

    for (const auto& rule : globalConfig.xfr_response_rules) {
      boost::uuids::uuid ruleUniqueID = rule.uuid.empty() ? getUniqueID() : getUniqueID(std::string(rule.uuid));
      dnsdist::rules::add(config.d_ruleChains, dnsdist::rules::ResponseRuleChain::XFRResponseRules, rule.selector.selector->d_rule, rule.action.action->d_action, std::string(rule.name), ruleUniqueID, 0);
    }

    for (const auto& rule : globalConfig.timeout_response_rules) {
      boost::uuids::uuid ruleUniqueID = rule.uuid.empty() ? getUniqueID() : getUniqueID(std::string(rule.uuid));
      dnsdist::rules::add(config.d_ruleChains, dnsdist::rules::ResponseRuleChain::TimeoutResponseRules, rule.selector.selector->d_rule, rule.action.action->d_action, std::string(rule.name), ruleUniqueID, 0);
    }
  });
}

static void loadDynamicBlockConfiguration(const dnsdist::rust::settings::DynamicRulesSettingsConfiguration& settings, const ::rust::Vec<dnsdist::rust::settings::DynamicRulesConfiguration>& dynamicRules)
{
  if (!settings.default_action.empty()) {
    dnsdist::configuration::updateRuntimeConfiguration([default_action = settings.default_action](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_dynBlockAction = DNSAction::typeFromString(std::string(default_action));
    });
  }

  for (const auto& dbrg : dynamicRules) {
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
        dbrgObj->setRCodeRate(strToRCode("dynamic-rules.rules.rcode_rate", "rcode", rule.rcode), std::move(ruleParams));
      }
      else if (rule.rule_type == "rcode-ratio") {
        DynBlockRulesGroup::DynBlockRatioRule ruleParams(std::string(rule.comment), rule.action_duration, rule.ratio, rule.warning_ratio, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)), rule.minimum_number_of_responses);
        if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
          ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
          ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
          ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
        }
        dbrgObj->setRCodeRatio(strToRCode("dynamic-rules.rules.rcode_ratio", "rcode", rule.rcode), std::move(ruleParams));
      }
      else if (rule.rule_type == "qtype-rate") {
        DynBlockRulesGroup::DynBlockRule ruleParams(std::string(rule.comment), rule.action_duration, rule.rate, rule.warning_rate, rule.seconds, rule.action.empty() ? DNSAction::Action::None : DNSAction::typeFromString(std::string(rule.action)));
        if (ruleParams.d_action == DNSAction::Action::SetTag && !rule.tag_name.empty()) {
          ruleParams.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
          ruleParams.d_tagSettings->d_name = std::string(rule.tag_name);
          ruleParams.d_tagSettings->d_value = std::string(rule.tag_value);
        }
        dbrgObj->setQTypeRate(strToQType("dynamic-rules.rules.qtype_rate", "qtype", rule.qtype), std::move(ruleParams));
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
        getLuaFunctionFromConfiguration(visitor, rule.visitor_function_name, rule.visitor_function_code, rule.visitor_function_file, "dynamic block suffix match visitor function");
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
        getLuaFunctionFromConfiguration(visitor, rule.visitor_function_name, rule.visitor_function_code, rule.visitor_function_file, "dynamic block suffix match FFI visitor function");
        dbrgObj->setSuffixMatchRuleFFI(std::move(ruleParams), std::move(visitor));
      }
    }
    dnsdist::DynamicBlocks::registerGroup(dbrgObj);
  }
}

static void handleAdditionalAddressesForFrontend(const std::shared_ptr<ClientState>& state, const std::string& protocol, const ::rust::Vec<::rust::String>& additionalAddresses)
{
  if (protocol == "dot" || protocol == "doh") {
    for (const auto& addr : additionalAddresses) {
      try {
        ComboAddress address{std::string(addr)};
        state->d_additionalAddresses.emplace_back(address, -1);
      }
      catch (const PDNSException& e) {
        errlog("Unable to parse additional address %s for %s bind: %s", std::string(addr), protocol, e.reason);
      }
    }
  }
  else if (!additionalAddresses.empty()) {
    throw std::runtime_error("Passing a non-empty additional_addresses value to a " + protocol + " frontend is not supported");
  }
}

static void loadBinds(const ::rust::Vec<dnsdist::rust::settings::BindConfiguration>& binds)
{
  for (const auto& bind : binds) {
    updateImmutableConfiguration([&bind](ImmutableConfiguration& config) {
      auto protocol = boost::to_lower_copy(std::string(bind.protocol));
      uint16_t defaultPort = 53;
      if (protocol == "dot" || protocol == "doq") {
        defaultPort = 853;
      }
      else if (protocol == "doh" || protocol == "dnscrypt" || protocol == "doh3") {
        defaultPort = 443;
      }
      ComboAddress listeningAddress(std::string(bind.listen_address), defaultPort);
      auto cpus = getCPUPiningFromStr("binds", std::string(bind.cpus));
      std::shared_ptr<XSKMap> xskMap;
      if (!bind.xsk.empty()) {
        xskMap = getRegisteredTypeByName<XSKMap>(bind.xsk);
        if (!xskMap) {
          throw std::runtime_error("XSK map " + std::string(bind.xsk) + " attached to bind " + std::string(bind.listen_address) + " not found");
        }
        if (xskMap->size() != bind.threads) {
          throw std::runtime_error("XSK map " + std::string(bind.xsk) + " attached to bind " + std::string(bind.listen_address) + " has less queues than the number of threads of the bind");
        }
      }

      std::shared_ptr<const TLSFrontend> tlsFrontendParent;
      for (size_t idx = 0; idx < bind.threads; idx++) {
#if defined(HAVE_DNSCRYPT)
        std::shared_ptr<DNSCryptContext> dnsCryptContext;
#endif /* defined(HAVE_DNSCRYPT) */

        auto state = std::make_shared<ClientState>(listeningAddress, protocol != "doq" && protocol != "doh3", bind.reuseport, bind.tcp.fast_open_queue_size, std::string(bind.interface), cpus, bind.enable_proxy_protocol);

        if (bind.tcp.listen_queue_size > 0) {
          state->tcpListenQueueSize = bind.tcp.listen_queue_size;
        }
        if (bind.tcp.max_in_flight_queries > 0) {
          state->d_maxInFlightQueriesPerConn = bind.tcp.max_in_flight_queries;
        }
        if (bind.tcp.max_concurrent_connections > 0) {
          state->d_tcpConcurrentConnectionsLimit = bind.tcp.max_concurrent_connections;
        }

        handleAdditionalAddressesForFrontend(state, protocol, bind.additional_addresses);

        if (protocol == "dnscrypt") {
#if defined(HAVE_DNSCRYPT)
          std::vector<DNSCryptContext::CertKeyPaths> certKeys;
          for (const auto& pair : bind.dnscrypt.certificates) {
            certKeys.push_back({std::string(pair.certificate), std::string(pair.key)});
          }
          dnsCryptContext = std::make_shared<DNSCryptContext>(std::string(bind.dnscrypt.provider_name), certKeys);
          state->dnscryptCtx = dnsCryptContext;
#endif /* defined(HAVE_DNSCRYPT) */
        }
        else if (protocol != "do53") {
          if (!handleTLSConfiguration(bind, *state, tlsFrontendParent)) {
            continue;
          }
          if (tlsFrontendParent == nullptr && (protocol == "dot" || protocol == "doh")) {
            tlsFrontendParent = state->getTLSFrontend();
          }
        }

        config.d_frontends.emplace_back(std::move(state));
        if (protocol == "do53" || protocol == "dnscrypt") {
          /* also create the UDP listener */
          state = std::make_shared<ClientState>(ComboAddress(std::string(bind.listen_address), defaultPort), false, bind.reuseport, bind.tcp.fast_open_queue_size, std::string(bind.interface), cpus, bind.enable_proxy_protocol);
#if defined(HAVE_DNSCRYPT)
          state->dnscryptCtx = std::move(dnsCryptContext);
#endif /* defined(HAVE_DNSCRYPT) */
#if defined(HAVE_XSK)
          if (xskMap) {
            auto xsk = xskMap->at(idx);
            state->xskInfo = XskWorker::create(XskWorker::Type::Bidirectional, xsk->sharedEmptyFrameOffset);
            xsk->addWorker(state->xskInfo);
            xsk->addWorkerRoute(state->xskInfo, listeningAddress);
            state->xskInfoResponder = XskWorker::create(XskWorker::Type::OutgoingOnly, xsk->sharedEmptyFrameOffset);
            xsk->addWorker(state->xskInfoResponder);
            vinfolog("Enabling XSK in %s mode for incoming UDP packets to %s", xsk->getXDPMode(), listeningAddress.toStringWithPort());
          }
#endif /* defined(HAVE_XSK) */
          config.d_frontends.emplace_back(std::move(state));
        }
      }
    });
  }
}

static void loadWebServer(const dnsdist::rust::settings::WebserverConfiguration& webConfig)
{
  dnsdist::configuration::updateRuntimeConfiguration([&webConfig](dnsdist::configuration::RuntimeConfiguration& config) {
    for (const auto& address : webConfig.listen_addresses) {
      try {
        config.d_webServerAddresses.emplace(ComboAddress(std::string(address)));
      }
      catch (const PDNSException& exp) {
        throw std::runtime_error(std::string("Error parsing bind address for the webserver: ") + exp.reason);
      }
    }
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

static void loadCustomPolicies(const ::rust::Vec<dnsdist::rust::settings::CustomLoadBalancingPolicyConfiguration>& customPolicies)
{
  for (const auto& policy : customPolicies) {
    if (policy.ffi) {
      if (policy.per_thread) {
        auto policyObj = std::make_shared<ServerPolicy>(std::string(policy.name), std::string(policy.function_code));
        registerType<ServerPolicy>(policyObj, policy.name);
      }
      else {
        ServerPolicy::ffipolicyfunc_t function;

        if (!getLuaFunctionFromConfiguration(function, policy.function_name, policy.function_code, policy.function_file, "FFI load-balancing policy")) {
          throw std::runtime_error("Custom FFI load-balancing policy '" + std::string(policy.name) + "' could not be created: no valid function name, Lua code or Lua file");
        }
        auto policyObj = std::make_shared<ServerPolicy>(std::string(policy.name), std::move(function));
        registerType<ServerPolicy>(policyObj, policy.name);
      }
    }
    else {
      ServerPolicy::policyfunc_t function;
      if (!getLuaFunctionFromConfiguration(function, policy.function_name, policy.function_code, policy.function_file, "load-balancing policy")) {
        throw std::runtime_error("Custom load-balancing policy '" + std::string(policy.name) + "' could not be created: no valid function name, Lua code or Lua file");
      }
      auto policyObj = std::make_shared<ServerPolicy>(std::string(policy.name), std::move(function), true);
      registerType<ServerPolicy>(policyObj, policy.name);
    }
  }
}

static void handleOpenSSLSettings(const dnsdist::rust::settings::TlsTuningConfiguration& tlsSettings)
{
  for (const auto& engine : tlsSettings.engines) {
#if defined(HAVE_LIBSSL) && !defined(HAVE_TLS_PROVIDERS)
    auto [success, error] = libssl_load_engine(std::string(engine.name), !engine.default_string.empty() ? std::optional<std::string>(engine.default_string) : std::nullopt);
    if (!success) {
      warnlog("Error while trying to load TLS engine '%s': %s", std::string(engine.name), error);
    }
#else
    warnlog("Ignoring TLS engine '%s' because OpenSSL engine support is not compiled in", std::string(engine.name));
#endif /* HAVE_LIBSSL && !HAVE_TLS_PROVIDERS */
  }

  for (const auto& provider : tlsSettings.providers) {
#if defined(HAVE_LIBSSL) && OPENSSL_VERSION_MAJOR >= 3 && defined(HAVE_TLS_PROVIDERS)
    auto [success, error] = libssl_load_provider(std::string(provider));
    if (!success) {
      warnlog("Error while trying to load TLS provider '%s': %s", std::string(provider), error);
    }
#else
    warnlog("Ignoring TLS provider '%s' because OpenSSL provider support is not compiled in", std::string(provider));
#endif /* HAVE_LIBSSL && OPENSSL_VERSION_MAJOR >= 3 && HAVE_TLS_PROVIDERS */
  }
}

static void handleLoggingConfiguration(const dnsdist::rust::settings::LoggingConfiguration& settings)
{
  if (!settings.verbose_log_destination.empty()) {
    auto dest = std::string(settings.verbose_log_destination);
    try {
      auto stream = std::ofstream(dest.c_str());
      dnsdist::logging::LoggingConfiguration::setVerboseStream(std::move(stream));
    }
    catch (const std::exception& e) {
      errlog("Error while opening the verbose logging destination file %s: %s", dest, e.what());
    }
  }

  if (!settings.syslog_facility.empty()) {
    auto facilityLevel = logFacilityFromString(std::string(settings.syslog_facility));
    if (!facilityLevel) {
      warnlog("Unknown facility '%s' passed to logging.syslog_facility", std::string(settings.syslog_facility));
    }
    else {
      setSyslogFacility(*facilityLevel);
    }
  }

  if (settings.structured.enabled) {
    auto levelPrefix = std::string(settings.structured.level_prefix);
    auto timeFormat = std::string(settings.structured.time_format);
    if (!timeFormat.empty()) {
      if (timeFormat == "numeric") {
        dnsdist::logging::LoggingConfiguration::setStructuredTimeFormat(dnsdist::logging::LoggingConfiguration::TimeFormat::Numeric);
      }
      else if (timeFormat == "ISO8601") {
        dnsdist::logging::LoggingConfiguration::setStructuredTimeFormat(dnsdist::logging::LoggingConfiguration::TimeFormat::ISO8601);
      }
      else {
        warnlog("Unknown value '%s' to logging.structured.time_format parameter", timeFormat);
      }
    }

    dnsdist::logging::LoggingConfiguration::setStructuredLogging(true, std::move(levelPrefix));
  }
}

static void handleConsoleConfiguration(const dnsdist::rust::settings::ConsoleConfiguration& consoleConf)
{
  if (!consoleConf.listen_address.empty()) {
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
}

static void handlePacketCacheConfiguration(const ::rust::Vec<dnsdist::rust::settings::PacketCacheConfiguration>& caches)
{
  for (const auto& cache : caches) {
    DNSDistPacketCache::CacheSettings settings{
      .d_maxEntries = cache.size,
      .d_maxTTL = cache.max_ttl,
      .d_minTTL = cache.min_ttl,
      .d_tempFailureTTL = cache.temporary_failure_ttl,
      .d_maxNegativeTTL = cache.max_negative_ttl,
      .d_staleTTL = cache.stale_ttl,
      .d_shardCount = cache.shards,
      .d_dontAge = cache.dont_age,
      .d_deferrableInsertLock = cache.deferrable_insert_lock,
      .d_parseECS = cache.parse_ecs,
      .d_keepStaleData = cache.keep_stale_data,
      .d_shuffle = cache.shuffle,
    };
    std::unordered_set<uint16_t> ranks;
    if (!cache.options_to_skip.empty()) {
      settings.d_optionsToSkip.clear();
      settings.d_optionsToSkip.insert(EDNSOptionCode::COOKIE);
      for (const auto& option : cache.options_to_skip) {
        settings.d_optionsToSkip.insert(pdns::checked_stoi<uint16_t>(std::string(option)));
      }
    }
    if (cache.cookie_hashing) {
      settings.d_optionsToSkip.erase(EDNSOptionCode::COOKIE);
    }
    if (cache.maximum_entry_size >= sizeof(dnsheader)) {
      settings.d_maximumEntrySize = cache.maximum_entry_size;
    }
    for (const auto& rank : cache.payload_ranks) {
      if (rank < 512 || rank > settings.d_maximumEntrySize) {
        continue;
      }
      ranks.insert(rank);
    }
    if (!ranks.empty()) {
      settings.d_payloadRanks.assign(ranks.begin(), ranks.end());
      std::sort(settings.d_payloadRanks.begin(), settings.d_payloadRanks.end());
    }
    auto packetCacheObj = std::make_shared<DNSDistPacketCache>(settings);

    registerType<DNSDistPacketCache>(packetCacheObj, cache.name);
  }
}

static void handleEBPFConfiguration([[maybe_unused]] const dnsdist::rust::settings::EbpfConfiguration& ebpf, [[maybe_unused]] bool configCheck)
{
#if defined(HAVE_EBPF)
  if (!configCheck && ebpf.ipv4.max_entries > 0 && ebpf.ipv6.max_entries > 0 && ebpf.qnames.max_entries > 0) {
    BPFFilter::MapFormat format = ebpf.external ? BPFFilter::MapFormat::WithActions : BPFFilter::MapFormat::Legacy;
    std::unordered_map<std::string, BPFFilter::MapConfiguration> mapsConfig;

    const auto convertParamsToConfig = [&mapsConfig](const std::string& name, BPFFilter::MapType type, const dnsdist::rust::settings::EbpfMapConfiguration& mapConfig) {
      if (mapConfig.max_entries == 0) {
        return;
      }
      BPFFilter::MapConfiguration config;
      config.d_type = type;
      config.d_maxItems = mapConfig.max_entries;
      config.d_pinnedPath = std::string(mapConfig.pinned_path);
      mapsConfig[name] = std::move(config);
    };

    convertParamsToConfig("ipv4", BPFFilter::MapType::IPv4, ebpf.ipv4);
    convertParamsToConfig("ipv6", BPFFilter::MapType::IPv6, ebpf.ipv6);
    convertParamsToConfig("qnames", BPFFilter::MapType::QNames, ebpf.qnames);
    convertParamsToConfig("cidr4", BPFFilter::MapType::CIDR4, ebpf.cidr_ipv4);
    convertParamsToConfig("cidr6", BPFFilter::MapType::CIDR6, ebpf.cidr_ipv6);
    auto filter = std::make_shared<BPFFilter>(mapsConfig, format, ebpf.external);
    g_defaultBPFFilter = std::move(filter);
  }
#endif /* defined(HAVE_EBPF) */
}

static void handleCarbonConfiguration([[maybe_unused]] const ::rust::Vec<dnsdist::rust::settings::CarbonConfiguration>& carbonConfigs)
{
#ifndef DISABLE_CARBON
  if (!carbonConfigs.empty()) {
    dnsdist::configuration::updateRuntimeConfiguration([&carbonConfigs](dnsdist::configuration::RuntimeConfiguration& config) {
      for (const auto& carbonConfig : carbonConfigs) {
        auto newEndpoint = dnsdist::Carbon::newEndpoint(std::string(carbonConfig.address),
                                                        std::string(carbonConfig.name),
                                                        carbonConfig.interval,
                                                        carbonConfig.name_space.empty() ? "dnsdist" : std::string(carbonConfig.name_space),
                                                        carbonConfig.instance.empty() ? "main" : std::string(carbonConfig.instance));
        config.d_carbonEndpoints.push_back(std::move(newEndpoint));
      }
    });
  }
#endif /* DISABLE_CARBON */
}

#endif /* defined(HAVE_YAML_CONFIGURATION) */

bool loadConfigurationFromFile(const std::string& fileName, [[maybe_unused]] bool isClient, [[maybe_unused]] bool configCheck)
{
#if defined(HAVE_YAML_CONFIGURATION)
  // this is not very elegant but passing a context to the functions called by the
  // Rust code would be quite cumbersome so for now let's settle for this
  s_inConfigCheckMode.store(configCheck);
  s_inClientMode.store(isClient);

  auto data = loadContentFromConfigurationFile(fileName);
  if (!data) {
    errlog("Unable to open YAML file %s: %s", fileName, stringerror(errno));
    return false;
  }

  /* register built-in policies */
  for (const auto& policy : dnsdist::lbpolicies::getBuiltInPolicies()) {
    registerType<ServerPolicy>(policy, ::rust::string(policy->d_name));
  }

  try {
    auto globalConfig = dnsdist::rust::settings::from_yaml_string(*data);

    dnsdist::configuration::updateImmutableConfiguration([&globalConfig](dnsdist::configuration::ImmutableConfiguration& config) {
      convertImmutableFlatSettingsFromRust(globalConfig, config);
    });

    dnsdist::configuration::updateRuntimeConfiguration([&globalConfig](dnsdist::configuration::RuntimeConfiguration& config) {
      convertRuntimeFlatSettingsFromRust(globalConfig, config);
    });

    handleLoggingConfiguration(globalConfig.logging);

    handleConsoleConfiguration(globalConfig.console);

    if (isClient) {
      return true;
    }

    if (!globalConfig.acl.empty()) {
      dnsdist::configuration::updateRuntimeConfiguration([&acl = globalConfig.acl](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_ACL.clear();
        for (const auto& aclEntry : acl) {
          config.d_ACL.addMask(std::string(aclEntry));
        }
      });
    }

    handleOpenSSLSettings(globalConfig.tuning.tls);

    handleEBPFConfiguration(globalConfig.ebpf, configCheck);

#if defined(HAVE_XSK)
    for (const auto& xskEntry : globalConfig.xsk) {
      auto map = std::shared_ptr<XSKMap>();
      for (size_t counter = 0; counter < xskEntry.queues; ++counter) {
        auto socket = std::make_shared<XskSocket>(xskEntry.frames, std::string(xskEntry.interface), counter, std::string(xskEntry.map_path));
        dnsdist::xsk::g_xsk.push_back(socket);
        map->push_back(std::move(socket));
      }
      registerType<XSKMap>(map, xskEntry.name);
    }
#endif /* defined(HAVE_XSK) */

    loadBinds(globalConfig.binds);

    for (const auto& backend : globalConfig.backends) {
      auto downstream = createBackendFromConfiguration(backend, configCheck);

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

    if (!globalConfig.proxy_protocol.acl.empty()) {
      dnsdist::configuration::updateRuntimeConfiguration([&globalConfig](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_proxyProtocolACL.clear();
        for (const auto& aclEntry : globalConfig.proxy_protocol.acl) {
          config.d_proxyProtocolACL.addMask(std::string(aclEntry));
        }
      });
    }

    handleCarbonConfiguration(globalConfig.metrics.carbon);

    if (!globalConfig.webserver.listen_addresses.empty()) {
      const auto& webConfig = globalConfig.webserver;
      loadWebServer(webConfig);
    }

    if (globalConfig.query_count.enabled) {
      dnsdist::configuration::updateRuntimeConfiguration([&globalConfig](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_queryCountConfig.d_enabled = true;
        getLuaFunctionFromConfiguration(config.d_queryCountConfig.d_filter, globalConfig.query_count.filter_function_name, globalConfig.query_count.filter_function_code, globalConfig.query_count.filter_function_file, "query count filter function");
      });
    }

    loadDynamicBlockConfiguration(globalConfig.dynamic_rules_settings, globalConfig.dynamic_rules);

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

    handlePacketCacheConfiguration(globalConfig.packet_caches);

    loadCustomPolicies(globalConfig.load_balancing_policies.custom_policies);

    if (!globalConfig.load_balancing_policies.default_policy.empty()) {
      auto policy = getRegisteredTypeByName<ServerPolicy>(globalConfig.load_balancing_policies.default_policy);
      if (!policy) {
        throw std::runtime_error("Unable to find a load-balancing policy named " + std::string(globalConfig.load_balancing_policies.default_policy));
      }
      dnsdist::configuration::updateRuntimeConfiguration([&policy](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_lbPolicy = std::move(policy);
      });
    }

    for (const auto& pool : globalConfig.pools) {
      dnsdist::configuration::updateRuntimeConfiguration([&pool](dnsdist::configuration::RuntimeConfiguration& config) {
        auto [poolIt, inserted] = config.d_pools.emplace(std::string(pool.name), ServerPool());
        if (inserted) {
          vinfolog("Creating pool %s", pool.name);
        }

        if (!pool.packet_cache.empty()) {
          poolIt->second.packetCache = getRegisteredTypeByName<DNSDistPacketCache>(pool.packet_cache);
          if (!poolIt->second.packetCache) {
            throw std::runtime_error("Unable to find a cache named " + std::string(pool.packet_cache));
          }
        }
        if (!pool.policy.empty()) {
          auto policy = getRegisteredTypeByName<ServerPolicy>(pool.policy);
          if (!policy) {
            throw std::runtime_error("Unable to find a load-balancing policy named " + std::string(pool.policy));
          }
          poolIt->second.policy = std::move(policy);
        }
        poolIt->second.setECS(pool.use_ecs);
        poolIt->second.setZeroScope(pool.use_zero_scope);
      });
    }

    loadRulesConfiguration(globalConfig);

    return true;
  }
  catch (const ::rust::Error& exp) {
    errlog("Error while parsing YAML file %s: %s", fileName, exp.what());
  }
  catch (const PDNSException& exp) {
    errlog("Error while processing YAML configuration from file %s: %s", fileName, exp.reason);
  }
  catch (const std::exception& exp) {
    errlog("Error while processing YAML configuration from file %s: %s", fileName, exp.what());
  }
  return false;
#else
  (void)fileName;
  throw std::runtime_error("YAML configuration is not supported by this build of dnsdist");
#endif /* HAVE_YAML_CONFIGURATION */
}

void addLuaBindingsForYAMLObjects([[maybe_unused]] LuaContext& luaCtx)
{
#if defined(HAVE_YAML_CONFIGURATION)
  using ReturnValue = boost::optional<boost::variant<std::shared_ptr<DNSDistPacketCache>, std::shared_ptr<DNSRule>, std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>, std::shared_ptr<NetmaskGroup>, std::shared_ptr<KeyValueStore>, std::shared_ptr<KeyValueLookupKey>, std::shared_ptr<RemoteLoggerInterface>, std::shared_ptr<ServerPolicy>, std::shared_ptr<XSKMap>>>;

  luaCtx.writeFunction("getObjectFromYAMLConfiguration", [](const std::string& name) -> ReturnValue {
    auto map = s_registeredTypesMap.lock();
    auto item = map->find(name);
    if (item == map->end()) {
      return boost::none;
    }
    if (auto* ptr = std::get_if<std::shared_ptr<DNSDistPacketCache>>(&item->second)) {
      return ReturnValue(*ptr);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<dnsdist::rust::settings::DNSSelector>>(&item->second)) {
      return ReturnValue((*ptr)->d_rule);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<dnsdist::rust::settings::DNSActionWrapper>>(&item->second)) {
      return ReturnValue((*ptr)->d_action);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<dnsdist::rust::settings::DNSResponseActionWrapper>>(&item->second)) {
      return ReturnValue((*ptr)->d_action);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<NetmaskGroup>>(&item->second)) {
      return ReturnValue(*ptr);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<KeyValueStore>>(&item->second)) {
      return ReturnValue(*ptr);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<KeyValueLookupKey>>(&item->second)) {
      return ReturnValue(*ptr);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<RemoteLoggerInterface>>(&item->second)) {
      return ReturnValue(*ptr);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<ServerPolicy>>(&item->second)) {
      return ReturnValue(*ptr);
    }
    if (auto* ptr = std::get_if<std::shared_ptr<XSKMap>>(&item->second)) {
      return ReturnValue(*ptr);
    }

    return boost::none;
  });
#endif /* HAVE_YAML_CONFIGURATION */
}
}

#if defined(HAVE_YAML_CONFIGURATION)
namespace dnsdist::rust::settings
{

static std::shared_ptr<DNSSelector> newDNSSelector(std::shared_ptr<DNSRule>&& rule, const ::rust::String& name)
{
  auto selector = std::make_shared<DNSSelector>();
  selector->d_name = std::string(name);
  selector->d_rule = std::move(rule);
  dnsdist::configuration::yaml::registerType(selector, name);
  return selector;
}

static std::shared_ptr<DNSActionWrapper> newDNSActionWrapper(std::shared_ptr<DNSAction>&& action, const ::rust::String& name)
{
  auto wrapper = std::make_shared<DNSActionWrapper>();
  wrapper->d_name = std::string(name);
  wrapper->d_action = std::move(action);
  dnsdist::configuration::yaml::registerType(wrapper, name);
  return wrapper;
}

static std::shared_ptr<DNSResponseActionWrapper> newDNSResponseActionWrapper(std::shared_ptr<DNSResponseAction>&& action, const ::rust::String& name)
{
  auto wrapper = std::make_shared<DNSResponseActionWrapper>();
  wrapper->d_name = std::string(name);
  wrapper->d_action = std::move(action);
  dnsdist::configuration::yaml::registerType(wrapper, name);
  return wrapper;
}

static dnsdist::ResponseConfig convertResponseConfig(const dnsdist::rust::settings::ResponseConfig& rustConfig)
{
  dnsdist::ResponseConfig cppConfig{};
  cppConfig.setAA = rustConfig.set_aa;
  cppConfig.setAD = rustConfig.set_ad;
  cppConfig.setRA = rustConfig.set_ra;
  cppConfig.ttl = rustConfig.ttl;
  return cppConfig;
}

static dnsdist::actions::SOAParams convertSOAParams(const dnsdist::rust::settings::SOAParams& soa)
{
  dnsdist::actions::SOAParams cppSOA{};
  cppSOA.serial = soa.serial;
  cppSOA.refresh = soa.refresh;
  cppSOA.retry = soa.retry;
  cppSOA.expire = soa.expire;
  cppSOA.minimum = soa.minimum;
  return cppSOA;
}

static std::vector<::SVCRecordParameters> convertSVCRecordParameters(const ::rust::Vec<dnsdist::rust::settings::SVCRecordParameters>& rustParameters)
{
  std::vector<::SVCRecordParameters> cppParameters;
  for (const auto& rustConfig : rustParameters) {
    ::SVCRecordParameters cppConfig{};
    for (auto param : rustConfig.mandatory_params) {
      cppConfig.mandatoryParams.insert(param);
    }
    for (const auto& alpn : rustConfig.alpns) {
      cppConfig.alpns.emplace_back(alpn);
    }
    for (const auto& hint : rustConfig.ipv4_hints) {
      cppConfig.ipv4hints.emplace_back(std::string(hint));
    }
    for (const auto& hint : rustConfig.ipv6_hints) {
      cppConfig.ipv6hints.emplace_back(std::string(hint));
    }
    for (const auto& param : rustConfig.additional_params) {
      cppConfig.additionalParams.emplace_back(param.key, std::string(param.value));
    }
    cppConfig.target = DNSName(std::string(rustConfig.target));
    if (rustConfig.port != 0) {
      cppConfig.port = rustConfig.port;
    }
    cppConfig.priority = rustConfig.priority;
    cppConfig.noDefaultAlpn = rustConfig.no_default_alpn;

    cppParameters.emplace_back(std::move(cppConfig));
  }
  return cppParameters;
}

std::shared_ptr<DNSActionWrapper> getLuaAction(const LuaActionConfiguration& config)
{
  dnsdist::actions::LuaActionFunction function;
  if (!dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(function, config.function_name, config.function_code, config.function_file, "Lua action")) {
    throw std::runtime_error("Lua action '" + std::string(config.name) + "' could not be created: no valid function name, Lua code or Lua file");
  }
  auto action = dnsdist::actions::getLuaAction(std::move(function));
  return newDNSActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSActionWrapper> getLuaFFIAction(const LuaFFIActionConfiguration& config)
{
  dnsdist::actions::LuaActionFFIFunction function;
  if (!dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(function, config.function_name, config.function_code, config.function_file, "Lua action")) {
    throw std::runtime_error("Lua FFI action '" + std::string(config.name) + "' could not be created: no valid function name, Lua code or Lua file");
  }
  auto action = dnsdist::actions::getLuaFFIAction(std::move(function));
  return newDNSActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSActionWrapper> getContinueAction(const ContinueActionConfiguration& config)
{
  auto action = dnsdist::actions::getContinueAction(config.action.action->d_action);
  return newDNSActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSActionWrapper> getSetProxyProtocolValuesAction(const SetProxyProtocolValuesActionConfiguration& config)
{
  std::vector<std::pair<uint8_t, std::string>> values;
  for (const auto& value : config.values) {
    values.emplace_back(value.key, std::string(value.value));
  }
  auto action = dnsdist::actions::getSetProxyProtocolValuesAction(values);
  return newDNSActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSActionWrapper> getSpoofPacketAction(const SpoofPacketActionConfiguration& config)
{
  if (config.response.size() < sizeof(dnsheader)) {
    throw std::runtime_error(std::string("SpoofPacketAction: given packet len is too small"));
  }
  auto action = dnsdist::actions::getSpoofAction(PacketBuffer(config.response.data(), config.response.data() + config.response.size()));
  return newDNSActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSActionWrapper> getSpoofAction(const SpoofActionConfiguration& config)
{
  std::vector<ComboAddress> addresses;
  for (const auto& addr : config.ips) {
    addresses.emplace_back(std::string(addr));
  }
  auto action = dnsdist::actions::getSpoofAction(addresses, convertResponseConfig(config.vars));
  return newDNSActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSActionWrapper> getSpoofCNAMEAction(const SpoofCNAMEActionConfiguration& config)
{
  auto cname = DNSName(std::string(config.cname));
  auto action = dnsdist::actions::getSpoofAction(cname, convertResponseConfig(config.vars));
  return newDNSActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSActionWrapper> getSpoofRawAction(const SpoofRawActionConfiguration& config)
{
  std::vector<std::string> raws;
  for (const auto& answer : config.answers) {
    raws.emplace_back(answer);
  }
  std::optional<uint16_t> qtypeForAny;
  if (!config.qtype_for_any.empty()) {
    QType qtype;
    qtype = std::string(config.qtype_for_any);
    qtypeForAny = qtype.getCode();
  }
  auto action = dnsdist::actions::getSpoofAction(raws, qtypeForAny, convertResponseConfig(config.vars));
  return newDNSActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSResponseActionWrapper> getLuaResponseAction(const LuaResponseActionConfiguration& config)
{
  dnsdist::actions::LuaResponseActionFunction function;
  if (!dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(function, config.function_name, config.function_code, config.function_file, "Lua action")) {
    throw std::runtime_error("Lua response action '" + std::string(config.name) + "' could not be created: no valid function name, Lua code or Lua file");
  }
  auto action = dnsdist::actions::getLuaResponseAction(std::move(function));
  return newDNSResponseActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSResponseActionWrapper> getLuaFFIResponseAction(const LuaFFIResponseActionConfiguration& config)
{
  dnsdist::actions::LuaResponseActionFFIFunction function;
  if (!dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(function, config.function_name, config.function_code, config.function_file, "Lua action")) {
    throw std::runtime_error("Lua FFI response action '" + std::string(config.name) + "' could not be created: no valid function name, Lua code or Lua file");
  }
  auto action = dnsdist::actions::getLuaFFIResponseAction(std::move(function));
  return newDNSResponseActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSResponseActionWrapper> getClearRecordTypesResponseAction(const ClearRecordTypesResponseActionConfiguration& config)
{
  std::unordered_set<QType> qtypes{};
  for (const auto& type : config.types) {
    qtypes.insert(type);
  }
  auto action = dnsdist::actions::getClearRecordTypesResponseAction(std::move(qtypes));
  return newDNSResponseActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSResponseActionWrapper> getLimitTTLResponseAction(const LimitTTLResponseActionConfiguration& config)
{
  std::unordered_set<QType> capTypes;
  for (const auto& type : config.types) {
    capTypes.insert(QType(type));
  }

  auto action = dnsdist::actions::getLimitTTLResponseAction(config.min, config.max, std::move(capTypes));
  return newDNSResponseActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSResponseActionWrapper> getSetMinTTLResponseAction(const SetMinTTLResponseActionConfiguration& config)
{
  auto action = dnsdist::actions::getLimitTTLResponseAction(config.min);
  return newDNSResponseActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSResponseActionWrapper> getSetMaxTTLResponseAction(const SetMaxTTLResponseActionConfiguration& config)
{
  auto action = dnsdist::actions::getLimitTTLResponseAction(0, config.max);
  return newDNSResponseActionWrapper(std::move(action), config.name);
}

std::shared_ptr<DNSSelector> getQNameSuffixSelector(const QNameSuffixSelectorConfiguration& config)
{
  SuffixMatchNode suffixes;
  for (const auto& suffix : config.suffixes) {
    suffixes.add(std::string(suffix));
  }
  return newDNSSelector(dnsdist::selectors::getQNameSuffixSelector(suffixes, config.quiet), config.name);
}

std::shared_ptr<DNSSelector> getQNameSetSelector(const QNameSetSelectorConfiguration& config)
{
  DNSNameSet qnames;
  for (const auto& name : config.qnames) {
    qnames.emplace(std::string(name));
  }
  return newDNSSelector(dnsdist::selectors::getQNameSetSelector(qnames), config.name);
}

std::shared_ptr<DNSSelector> getQNameSelector(const QNameSelectorConfiguration& config)
{
  return newDNSSelector(dnsdist::selectors::getQNameSelector(DNSName(std::string(config.qname))), config.name);
}

std::shared_ptr<DNSSelector> getNetmaskGroupSelector(const NetmaskGroupSelectorConfiguration& config)
{
  std::shared_ptr<NetmaskGroup> nmg;
  if (!config.netmask_group_name.empty()) {
    nmg = dnsdist::configuration::yaml::getRegisteredTypeByName<NetmaskGroup>(std::string(config.netmask_group_name));
  }
  if (!nmg) {
    nmg = std::make_shared<NetmaskGroup>();
  }
  for (const auto& netmask : config.netmasks) {
    nmg->addMask(std::string(netmask));
  }
  auto selector = dnsdist::selectors::getNetmaskGroupSelector(*nmg, config.source, config.quiet);
  return newDNSSelector(std::move(selector), config.name);
}

std::shared_ptr<DNSActionWrapper> getKeyValueStoreLookupAction([[maybe_unused]] const KeyValueStoreLookupActionConfiguration& config)
{
#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  auto kvs = dnsdist::configuration::yaml::getRegisteredTypeByName<KeyValueStore>(std::string(config.kvs_name));
  if (!kvs && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the key-value store named '" + std::string(config.kvs_name) + "'");
  }
  auto lookupKey = dnsdist::configuration::yaml::getRegisteredTypeByName<KeyValueLookupKey>(std::string(config.lookup_key_name));
  if (!lookupKey && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the key-value lookup key named '" + std::string(config.lookup_key_name) + "'");
  }
  auto action = dnsdist::actions::getKeyValueStoreLookupAction(kvs, lookupKey, std::string(config.destination_tag));
  return newDNSActionWrapper(std::move(action), config.name);
#else
  throw std::runtime_error("Unable to create KVS action: neither CDB nor LMDB support are enabled");
#endif
}

std::shared_ptr<DNSActionWrapper> getKeyValueStoreRangeLookupAction([[maybe_unused]] const KeyValueStoreRangeLookupActionConfiguration& config)
{
#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  auto kvs = dnsdist::configuration::yaml::getRegisteredTypeByName<KeyValueStore>(std::string(config.kvs_name));
  if (!kvs && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the key-value store named '" + std::string(config.kvs_name) + "'");
  }
  auto lookupKey = dnsdist::configuration::yaml::getRegisteredTypeByName<KeyValueLookupKey>(std::string(config.lookup_key_name));
  if (!lookupKey && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the key-value lookup key named '" + std::string(config.lookup_key_name) + "'");
  }
  auto action = dnsdist::actions::getKeyValueStoreRangeLookupAction(kvs, lookupKey, std::string(config.destination_tag));
  return newDNSActionWrapper(std::move(action), config.name);
#else
  throw std::runtime_error("Unable to create KVS action: neither CDB nor LMDB support are enabled");
#endif
}

std::shared_ptr<DNSSelector> getKeyValueStoreLookupSelector([[maybe_unused]] const KeyValueStoreLookupSelectorConfiguration& config)
{
#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  auto kvs = dnsdist::configuration::yaml::getRegisteredTypeByName<KeyValueStore>(std::string(config.kvs_name));
  if (!kvs && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the key-value store named '" + std::string(config.kvs_name) + "'");
  }
  auto lookupKey = dnsdist::configuration::yaml::getRegisteredTypeByName<KeyValueLookupKey>(std::string(config.lookup_key_name));
  if (!lookupKey && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the key-value lookup key named '" + std::string(config.lookup_key_name) + "'");
  }
  auto selector = dnsdist::selectors::getKeyValueStoreLookupSelector(kvs, lookupKey);
  return newDNSSelector(std::move(selector), config.name);
#else
  throw std::runtime_error("Unable to create KVS action: neither CDB nor LMDB support are enabled");
#endif
}

std::shared_ptr<DNSSelector> getKeyValueStoreRangeLookupSelector([[maybe_unused]] const KeyValueStoreRangeLookupSelectorConfiguration& config)
{
#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  auto kvs = dnsdist::configuration::yaml::getRegisteredTypeByName<KeyValueStore>(std::string(config.kvs_name));
  if (!kvs && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the key-value store named '" + std::string(config.kvs_name) + "'");
  }
  auto lookupKey = dnsdist::configuration::yaml::getRegisteredTypeByName<KeyValueLookupKey>(std::string(config.lookup_key_name));
  if (!lookupKey && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the key-value lookup key named '" + std::string(config.lookup_key_name) + "'");
  }
  auto selector = dnsdist::selectors::getKeyValueStoreRangeLookupSelector(kvs, lookupKey);
  return newDNSSelector(std::move(selector), config.name);
#else
  throw std::runtime_error("Unable to create KVS action: neither CDB nor LMDB support are enabled");
#endif
}

std::shared_ptr<DNSActionWrapper> getDnstapLogAction([[maybe_unused]] const DnstapLogActionConfiguration& config)
{
#if defined(DISABLE_PROTOBUF) || !defined(HAVE_FSTRM)
  throw std::runtime_error("Unable to create dnstap log action: dnstap support is not enabled");
#else
  auto logger = dnsdist::configuration::yaml::getRegisteredTypeByName<RemoteLoggerInterface>(std::string(config.logger_name));
  if (!logger && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the dnstap logger named '" + std::string(config.logger_name) + "'");
  }
  boost::optional<dnsdist::actions::DnstapAlterFunction> alterFuncHolder;
  dnsdist::actions::DnstapAlterFunction alterFunc;
  if (dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(alterFunc, config.alter_function_name, config.alter_function_code, config.alter_function_file, "dnstap log action")) {
    alterFuncHolder = std::move(alterFunc);
  }
  auto action = dnsdist::actions::getDnstapLogAction(std::string(config.identity), std::move(logger), alterFuncHolder ? std::move(*alterFuncHolder) : std::optional<dnsdist::actions::DnstapAlterFunction>());
  return newDNSActionWrapper(std::move(action), config.name);
#endif
}

std::shared_ptr<DNSResponseActionWrapper> getDnstapLogResponseAction([[maybe_unused]] const DnstapLogResponseActionConfiguration& config)
{
#if defined(DISABLE_PROTOBUF) || !defined(HAVE_FSTRM)
  throw std::runtime_error("Unable to create dnstap log action: dnstap support is not enabled");
#else
  auto logger = dnsdist::configuration::yaml::getRegisteredTypeByName<RemoteLoggerInterface>(std::string(config.logger_name));
  if (!logger && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the dnstap logger named '" + std::string(config.logger_name) + "'");
  }
  boost::optional<dnsdist::actions::DnstapAlterResponseFunction> alterFuncHolder;
  dnsdist::actions::DnstapAlterResponseFunction alterFunc;
  if (dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(alterFunc, config.alter_function_name, config.alter_function_code, config.alter_function_file, "dnstap log response action")) {
    alterFuncHolder = std::move(alterFunc);
  }
  auto action = dnsdist::actions::getDnstapLogResponseAction(std::string(config.identity), std::move(logger), alterFuncHolder ? std::move(*alterFuncHolder) : std::optional<dnsdist::actions::DnstapAlterResponseFunction>());
  return newDNSResponseActionWrapper(std::move(action), config.name);
#endif
}

std::shared_ptr<DNSActionWrapper> getRemoteLogAction(const RemoteLogActionConfiguration& config)
{
#if defined(DISABLE_PROTOBUF)
  throw std::runtime_error("Unable to create remote log action: protobuf support is disabled");
#else
  auto logger = dnsdist::configuration::yaml::getRegisteredTypeByName<RemoteLoggerInterface>(std::string(config.logger_name));
  if (!logger && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the protobuf logger named '" + std::string(config.logger_name) + "'");
  }
  dnsdist::actions::RemoteLogActionConfiguration actionConfig{};
  actionConfig.logger = std::move(logger);
  actionConfig.serverID = std::string(config.server_id);
  actionConfig.ipEncryptKey = std::string(config.ip_encrypt_key);
  actionConfig.ipEncryptMethod = std::string(config.ip_encrypt_method);
  for (const auto& meta : config.metas) {
    actionConfig.metas.emplace_back(std::string(meta.key), ProtoBufMetaKey(std::string(meta.value)));
  }
  if (!config.export_tags.empty()) {
    actionConfig.tagsToExport = std::unordered_set<std::string>();
    for (const auto& tag : config.export_tags) {
      actionConfig.tagsToExport->emplace(std::string(tag));
    }
  }
  dnsdist::actions::ProtobufAlterFunction alterFunc;
  if (dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(alterFunc, config.alter_function_name, config.alter_function_code, config.alter_function_file, "remote log action")) {
    actionConfig.alterQueryFunc = std::move(alterFunc);
  }
  auto action = dnsdist::actions::getRemoteLogAction(actionConfig);
  return newDNSActionWrapper(std::move(action), config.name);
#endif
}

std::shared_ptr<DNSResponseActionWrapper> getRemoteLogResponseAction(const RemoteLogResponseActionConfiguration& config)
{
#if defined(DISABLE_PROTOBUF)
  throw std::runtime_error("Unable to create remote log action: protobuf support is disabled");
#else
  auto logger = dnsdist::configuration::yaml::getRegisteredTypeByName<RemoteLoggerInterface>(std::string(config.logger_name));
  if (!logger && !(dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode)) {
    throw std::runtime_error("Unable to find the protobuf logger named '" + std::string(config.logger_name) + "'");
  }
  dnsdist::actions::RemoteLogActionConfiguration actionConfig{};
  actionConfig.logger = std::move(logger);
  actionConfig.serverID = std::string(config.server_id);
  actionConfig.ipEncryptKey = std::string(config.ip_encrypt_key);
  actionConfig.ipEncryptMethod = std::string(config.ip_encrypt_method);
  actionConfig.includeCNAME = config.include_cname;
  for (const auto& meta : config.metas) {
    actionConfig.metas.emplace_back(std::string(meta.key), ProtoBufMetaKey(std::string(meta.value)));
  }
  if (!config.export_tags.empty()) {
    actionConfig.tagsToExport = std::unordered_set<std::string>();
    for (const auto& tag : config.export_tags) {
      actionConfig.tagsToExport->emplace(std::string(tag));
    }
  }
  if (!config.export_extended_errors_to_meta.empty()) {
    actionConfig.exportExtendedErrorsToMeta = std::string(config.export_extended_errors_to_meta);
  }
  dnsdist::actions::ProtobufAlterResponseFunction alterFunc;
  if (dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(alterFunc, config.alter_function_name, config.alter_function_code, config.alter_function_file, "remote log response action")) {
    actionConfig.alterResponseFunc = std::move(alterFunc);
  }
  actionConfig.delay = config.delay;
  auto action = dnsdist::actions::getRemoteLogResponseAction(actionConfig);
  return newDNSResponseActionWrapper(std::move(action), config.name);
#endif
}

void registerProtobufLogger(const ProtobufLoggerConfiguration& config)
{
#if defined(DISABLE_PROTOBUF)
  throw std::runtime_error("Unable to create protobuf logger: protobuf support is disabled");
#else
  if (dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode) {
    auto object = std::shared_ptr<RemoteLoggerInterface>(nullptr);
    dnsdist::configuration::yaml::registerType<RemoteLoggerInterface>(object, config.name);
    return;
  }
  std::shared_ptr<RemoteLoggerInterface> object;
  if (config.connection_count > 1) {
    std::vector<std::shared_ptr<RemoteLoggerInterface>> loggers;
    loggers.reserve(config.connection_count);
    for (uint64_t i = 0; i < config.connection_count; i++) {
      loggers.push_back(std::make_shared<RemoteLogger>(ComboAddress(std::string(config.address)), config.timeout, config.max_queued_entries * 100, config.reconnect_wait_time, dnsdist::configuration::yaml::s_inClientMode));
    }
    object = std::shared_ptr<RemoteLoggerInterface>(std::make_shared<RemoteLoggerPool>(std::move(loggers)));
  }
  else {
    object = std::shared_ptr<RemoteLoggerInterface>(std::make_shared<RemoteLogger>(ComboAddress(std::string(config.address)), config.timeout, config.max_queued_entries * 100, config.reconnect_wait_time, dnsdist::configuration::yaml::s_inClientMode));
  }
  dnsdist::configuration::yaml::registerType<RemoteLoggerInterface>(object, config.name);
#endif
}

void registerDnstapLogger([[maybe_unused]] const DnstapLoggerConfiguration& config)
{
#if defined(DISABLE_PROTOBUF) || !defined(HAVE_FSTRM)
  throw std::runtime_error("Unable to create dnstap logger: dnstap support is disabled");
#else
  auto transport = boost::to_lower_copy(std::string(config.transport));
  int family{0};
  if (transport == "unix") {
    family = AF_UNIX;
  }
  else if (transport == "tcp") {
    family = AF_INET;
  }
  else {
    throw std::runtime_error("Unsupport dnstap transport type '" + transport + "'");
  }

  if (dnsdist::configuration::yaml::s_inClientMode || dnsdist::configuration::yaml::s_inConfigCheckMode) {
    auto object = std::shared_ptr<RemoteLoggerInterface>(nullptr);
    dnsdist::configuration::yaml::registerType<RemoteLoggerInterface>(object, config.name);
    return;
  }

  std::unordered_map<string, unsigned int> options;
  options["bufferHint"] = config.buffer_hint;
  options["flushTimeout"] = config.flush_timeout;
  options["inputQueueSize"] = config.input_queue_size;
  options["outputQueueSize"] = config.output_queue_size;
  options["queueNotifyThreshold"] = config.queue_notify_threshold;
  options["reopenInterval"] = config.reopen_interval;

  std::shared_ptr<RemoteLoggerInterface> object;
  if (config.connection_count > 1) {
    std::vector<std::shared_ptr<RemoteLoggerInterface>> loggers;
    loggers.reserve(config.connection_count);
    for (uint64_t i = 0; i < config.connection_count; i++) {
      loggers.push_back(std::make_shared<FrameStreamLogger>(family, std::string(config.address), !dnsdist::configuration::yaml::s_inClientMode, options));
    }
    object = std::shared_ptr<RemoteLoggerInterface>(std::make_shared<RemoteLoggerPool>(std::move(loggers)));
  }
  else {
    object = std::shared_ptr<RemoteLoggerInterface>(std::make_shared<FrameStreamLogger>(family, std::string(config.address), !dnsdist::configuration::yaml::s_inClientMode, options));
  }
  dnsdist::configuration::yaml::registerType<RemoteLoggerInterface>(object, config.name);
#endif
}

void registerKVSObjects([[maybe_unused]] const KeyValueStoresConfiguration& config)
{
#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  bool createObjects = !dnsdist::configuration::yaml::s_inClientMode && !dnsdist::configuration::yaml::s_inConfigCheckMode;
#if defined(HAVE_LMDB)
  for (const auto& lmdb : config.lmdb) {
    auto store = createObjects ? std::shared_ptr<KeyValueStore>(std::make_shared<LMDBKVStore>(std::string(lmdb.file_name), std::string(lmdb.database_name), lmdb.no_lock)) : std::shared_ptr<KeyValueStore>();
    dnsdist::configuration::yaml::registerType<KeyValueStore>(store, lmdb.name);
  }
#endif /* defined(HAVE_LMDB) */
#if defined(HAVE_CDB)
  for (const auto& cdb : config.cdb) {
    auto store = createObjects ? std::shared_ptr<KeyValueStore>(std::make_shared<CDBKVStore>(std::string(cdb.file_name), cdb.refresh_delay)) : std::shared_ptr<KeyValueStore>();
    dnsdist::configuration::yaml::registerType<KeyValueStore>(store, cdb.name);
  }
#endif /* defined(HAVE_CDB) */
  for (const auto& key : config.lookup_keys.source_ip_keys) {
    auto lookup = createObjects ? std::shared_ptr<KeyValueLookupKey>(std::make_shared<KeyValueLookupKeySourceIP>(key.v4_mask, key.v6_mask, key.include_port)) : std::shared_ptr<KeyValueLookupKey>();
    dnsdist::configuration::yaml::registerType<KeyValueLookupKey>(lookup, key.name);
  }
  for (const auto& key : config.lookup_keys.qname_keys) {
    auto lookup = createObjects ? std::shared_ptr<KeyValueLookupKey>(std::make_shared<KeyValueLookupKeyQName>(key.wire_format)) : std::shared_ptr<KeyValueLookupKey>();
    dnsdist::configuration::yaml::registerType<KeyValueLookupKey>(lookup, key.name);
  }
  for (const auto& key : config.lookup_keys.suffix_keys) {
    auto lookup = createObjects ? std::shared_ptr<KeyValueLookupKey>(std::make_shared<KeyValueLookupKeySuffix>(key.minimum_labels, key.wire_format)) : std::shared_ptr<KeyValueLookupKey>();
    dnsdist::configuration::yaml::registerType<KeyValueLookupKey>(lookup, key.name);
  }
  for (const auto& key : config.lookup_keys.tag_keys) {
    auto lookup = createObjects ? std::shared_ptr<KeyValueLookupKey>(std::make_shared<KeyValueLookupKeyTag>(std::string(key.tag))) : std::shared_ptr<KeyValueLookupKey>();
    dnsdist::configuration::yaml::registerType<KeyValueLookupKey>(lookup, key.name);
  }
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */
}

void registerNMGObjects(const ::rust::Vec<NetmaskGroupConfiguration>& nmgs)
{
  for (const auto& netmaskGroup : nmgs) {
    bool registered = true;
    auto nmg = dnsdist::configuration::yaml::getRegisteredTypeByName<NetmaskGroup>(std::string(netmaskGroup.name));
    if (!nmg) {
      nmg = std::make_shared<NetmaskGroup>();
      registered = false;
    }

    for (const auto& netmask : netmaskGroup.netmasks) {
      nmg->addMask(std::string(netmask));
    }
    if (!registered) {
      dnsdist::configuration::yaml::registerType<NetmaskGroup>(nmg, netmaskGroup.name);
    }
  }
}

std::shared_ptr<DNSSelector> getLuaSelector(const LuaSelectorConfiguration& config)
{
  dnsdist::selectors::LuaSelectorFunction function;
  if (!dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(function, config.function_name, config.function_code, config.function_file, "Lua selector")) {
    throw std::runtime_error("Unable to create a Lua selector: no valid function name, Lua code or Lua file");
  }
  auto selector = dnsdist::selectors::getLuaSelector(function);
  return newDNSSelector(std::move(selector), config.name);
}

std::shared_ptr<DNSSelector> getLuaFFISelector(const LuaFFISelectorConfiguration& config)
{
  dnsdist::selectors::LuaSelectorFFIFunction function;
  if (!dnsdist::configuration::yaml::getLuaFunctionFromConfiguration(function, config.function_name, config.function_code, config.function_file, "Lua FFI selector")) {
    throw std::runtime_error("Unable to create a Lua FFI selector: no valid function name, Lua code or Lua file");
  }
  auto selector = dnsdist::selectors::getLuaFFISelector(function);
  return newDNSSelector(std::move(selector), config.name);
}

std::shared_ptr<DNSSelector> getAndSelector(const AndSelectorConfiguration& config)
{
  std::vector<std::shared_ptr<DNSRule>> selectors;
  selectors.reserve(config.selectors.size());
  for (const auto& subSelector : config.selectors) {
    selectors.emplace_back(subSelector.selector->d_rule);
  }
  auto selector = dnsdist::selectors::getAndSelector(selectors);
  return newDNSSelector(std::move(selector), config.name);
}

std::shared_ptr<DNSSelector> getOrSelector(const OrSelectorConfiguration& config)
{
  std::vector<std::shared_ptr<DNSRule>> selectors;
  selectors.reserve(config.selectors.size());
  for (const auto& subSelector : config.selectors) {
    selectors.emplace_back(subSelector.selector->d_rule);
  }
  auto selector = dnsdist::selectors::getOrSelector(selectors);
  return newDNSSelector(std::move(selector), config.name);
}

std::shared_ptr<DNSSelector> getNotSelector(const NotSelectorConfiguration& config)
{
  auto selector = dnsdist::selectors::getNotSelector(config.selector.selector->d_rule);
  return newDNSSelector(std::move(selector), config.name);
}

std::shared_ptr<DNSSelector> getByNameSelector(const ByNameSelectorConfiguration& config)
{
  auto ptr = dnsdist::configuration::yaml::getRegisteredTypeByName<DNSSelector>(config.selector_name);
  if (!ptr) {
    throw std::runtime_error("Unable to find a selector named " + std::string(config.selector_name));
  }
  return ptr;
}

#include "dnsdist-rust-bridge-actions-generated-body.hh"
#include "dnsdist-rust-bridge-selectors-generated-body.hh"
}

#endif /* defined(HAVE_YAML_CONFIGURATION) */
