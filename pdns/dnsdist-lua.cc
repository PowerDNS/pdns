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

#include <cstdint>
#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <cinttypes>

// for OpenBSD, sys/socket.h needs to come before net/if.h
#include <sys/socket.h>
#include <net/if.h>

#include <regex>
#include <sys/types.h>
#include <sys/stat.h>
#include <thread>
#include <vector>

#include "dnsdist.hh"
#include "dnsdist-carbon.hh"
#include "dnsdist-concurrent-connections.hh"
#include "dnsdist-console.hh"
#include "dnsdist-crypto.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-discovery.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-healthchecks.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-hooks.hh"
#include "xsk.hh"
#ifdef LUAJIT_VERSION
#include "dnsdist-lua-ffi.hh"
#endif /* LUAJIT_VERSION */
#include "dnsdist-metrics.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-secpoll.hh"
#include "dnsdist-session-cache.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-web.hh"

#include "base64.hh"
#include "coverage.hh"
#include "doh.hh"
#include "doq-common.hh"
#include "dolog.hh"
#include "threadname.hh"

#ifdef HAVE_LIBSSL
#include "libssl.hh"
#endif

#include <boost/logic/tribool.hpp>
#include <boost/uuid/string_generator.hpp>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

using std::thread;

static boost::optional<std::vector<std::function<void(void)>>> g_launchWork = boost::none;

boost::tribool g_noLuaSideEffect;
static bool g_included{false};

/* this is a best effort way to prevent logging calls with no side-effects in the output of delta()
   Functions can declare setLuaNoSideEffect() and if nothing else does declare a side effect, or nothing
   has done so before on this invocation, this call won't be part of delta() output */
void setLuaNoSideEffect()
{
  if (g_noLuaSideEffect == false) // there has been a side effect already
    return;
  g_noLuaSideEffect = true;
}

void setLuaSideEffect()
{
  g_noLuaSideEffect = false;
}

bool getLuaNoSideEffect()
{
  if (g_noLuaSideEffect) {
    return true;
  }
  return false;
}

void resetLuaSideEffect()
{
  g_noLuaSideEffect = boost::logic::indeterminate;
}

using localbind_t = LuaAssociativeTable<boost::variant<bool, int, std::string, LuaArray<int>, LuaArray<std::string>, LuaAssociativeTable<std::string>, std::shared_ptr<XskSocket>>>;

static void parseLocalBindVars(boost::optional<localbind_t>& vars, bool& reusePort, int& tcpFastOpenQueueSize, std::string& interface, std::set<int>& cpus, int& tcpListenQueueSize, uint64_t& maxInFlightQueriesPerConnection, uint64_t& tcpMaxConcurrentConnections, bool& enableProxyProtocol)
{
  if (vars) {
    LuaArray<int> setCpus;

    getOptionalValue<bool>(vars, "reusePort", reusePort);
    getOptionalValue<bool>(vars, "enableProxyProtocol", enableProxyProtocol);
    getOptionalValue<int>(vars, "tcpFastOpenQueueSize", tcpFastOpenQueueSize);
    getOptionalValue<int>(vars, "tcpListenQueueSize", tcpListenQueueSize);
    getOptionalValue<int>(vars, "maxConcurrentTCPConnections", tcpMaxConcurrentConnections);
    getOptionalValue<int>(vars, "maxInFlight", maxInFlightQueriesPerConnection);
    getOptionalValue<std::string>(vars, "interface", interface);
    if (getOptionalValue<decltype(setCpus)>(vars, "cpus", setCpus) > 0) {
      for (const auto& cpu : setCpus) {
        cpus.insert(cpu.second);
      }
    }
  }
}
#ifdef HAVE_XSK
static void parseXskVars(boost::optional<localbind_t>& vars, std::shared_ptr<XskSocket>& socket)
{
  if (!vars) {
    return;
  }

  getOptionalValue<std::shared_ptr<XskSocket>>(vars, "xskSocket", socket);
}
#endif /* HAVE_XSK */

#if defined(HAVE_DNS_OVER_TLS) || defined(HAVE_DNS_OVER_HTTPS) || defined(HAVE_DNS_OVER_QUIC)
static bool loadTLSCertificateAndKeys(const std::string& context, std::vector<TLSCertKeyPair>& pairs, const boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>>& certFiles, const LuaTypeOrArrayOf<std::string>& keyFiles)
{
  if (certFiles.type() == typeid(std::string) && keyFiles.type() == typeid(std::string)) {
    auto certFile = boost::get<std::string>(certFiles);
    auto keyFile = boost::get<std::string>(keyFiles);
    pairs.clear();
    pairs.emplace_back(certFile, keyFile);
  }
  else if (certFiles.type() == typeid(std::shared_ptr<TLSCertKeyPair>)) {
    auto cert = boost::get<std::shared_ptr<TLSCertKeyPair>>(certFiles);
    pairs.clear();
    pairs.emplace_back(*cert);
  }
  else if (certFiles.type() == typeid(LuaArray<std::shared_ptr<TLSCertKeyPair>>)) {
    auto certs = boost::get<LuaArray<std::shared_ptr<TLSCertKeyPair>>>(certFiles);
    pairs.clear();
    for (const auto& cert : certs) {
      pairs.emplace_back(*(cert.second));
    }
  }
  else if (certFiles.type() == typeid(LuaArray<std::string>) && keyFiles.type() == typeid(LuaArray<std::string>)) {
    auto certFilesVect = boost::get<LuaArray<std::string>>(certFiles);
    auto keyFilesVect = boost::get<LuaArray<std::string>>(keyFiles);
    if (certFilesVect.size() == keyFilesVect.size()) {
      pairs.clear();
      for (size_t idx = 0; idx < certFilesVect.size(); idx++) {
        pairs.emplace_back(certFilesVect.at(idx).second, keyFilesVect.at(idx).second);
      }
    }
    else {
      errlog("Error, mismatching number of certificates and keys in call to %s()!", context);
      g_outputBuffer = "Error, mismatching number of certificates and keys in call to " + context + "()!";
      return false;
    }
  }
  else {
    errlog("Error, mismatching number of certificates and keys in call to %s()!", context);
    g_outputBuffer = "Error, mismatching number of certificates and keys in call to " + context + "()!";
    return false;
  }

  return true;
}

static void parseTLSConfig(TLSConfig& config, const std::string& context, boost::optional<localbind_t>& vars)
{
  getOptionalValue<std::string>(vars, "ciphers", config.d_ciphers);
  getOptionalValue<std::string>(vars, "ciphersTLS13", config.d_ciphers13);

#ifdef HAVE_LIBSSL
  std::string minVersion;
  if (getOptionalValue<std::string>(vars, "minTLSVersion", minVersion) > 0) {
    config.d_minTLSVersion = libssl_tls_version_from_string(minVersion);
  }
#else /* HAVE_LIBSSL */
  if (vars->erase("minTLSVersion") > 0)
    warnlog("minTLSVersion has no effect with chosen TLS library");
#endif /* HAVE_LIBSSL */

  getOptionalValue<std::string>(vars, "ticketKeyFile", config.d_ticketKeyFile);
  getOptionalValue<int>(vars, "ticketsKeysRotationDelay", config.d_ticketsKeyRotationDelay);
  getOptionalValue<int>(vars, "numberOfTicketsKeys", config.d_numberOfTicketsKeys);
  getOptionalValue<bool>(vars, "preferServerCiphers", config.d_preferServerCiphers);
  getOptionalValue<int>(vars, "sessionTimeout", config.d_sessionTimeout);
  getOptionalValue<bool>(vars, "sessionTickets", config.d_enableTickets);
  int numberOfStoredSessions{0};
  if (getOptionalValue<int>(vars, "numberOfStoredSessions", numberOfStoredSessions) > 0) {
    if (numberOfStoredSessions < 0) {
      errlog("Invalid value '%d' for %s() parameter 'numberOfStoredSessions', should be >= 0, dismissing", numberOfStoredSessions, context);
      g_outputBuffer = "Invalid value '" + std::to_string(numberOfStoredSessions) + "' for " + context + "() parameter 'numberOfStoredSessions', should be >= 0, dimissing";
    }
    else {
      config.d_maxStoredSessions = numberOfStoredSessions;
    }
  }

  LuaArray<std::string> files;
  if (getOptionalValue<decltype(files)>(vars, "ocspResponses", files) > 0) {
    for (const auto& file : files) {
      config.d_ocspFiles.push_back(file.second);
    }
  }

  if (vars->count("keyLogFile") > 0) {
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
    getOptionalValue<std::string>(vars, "keyLogFile", config.d_keyLogFile);
#else
    errlog("TLS Key logging has been enabled using the 'keyLogFile' parameter to %s(), but this version of OpenSSL does not support it", context);
    g_outputBuffer = "TLS Key logging has been enabled using the 'keyLogFile' parameter to " + context + "(), but this version of OpenSSL does not support it";
#endif
  }

  getOptionalValue<bool>(vars, "releaseBuffers", config.d_releaseBuffers);
  getOptionalValue<bool>(vars, "enableRenegotiation", config.d_enableRenegotiation);
  getOptionalValue<bool>(vars, "tlsAsyncMode", config.d_asyncMode);
  getOptionalValue<bool>(vars, "ktls", config.d_ktls);
  getOptionalValue<bool>(vars, "readAhead", config.d_readAhead);
}

#endif // defined(HAVE_DNS_OVER_TLS) || defined(HAVE_DNS_OVER_HTTPS)

void checkParameterBound(const std::string& parameter, uint64_t value, size_t max)
{
  if (value > max) {
    throw std::runtime_error("The value (" + std::to_string(value) + ") passed to " + parameter + " is too large, the maximum is " + std::to_string(max));
  }
}

static void LuaThread(const std::string& code)
{
  setThreadName("dnsdist/lua-bg");
  LuaContext l;

  // mask SIGTERM on threads so the signal always comes to dnsdist itself
  sigset_t blockSignals;

  sigemptyset(&blockSignals);
  sigaddset(&blockSignals, SIGTERM);

  pthread_sigmask(SIG_BLOCK, &blockSignals, nullptr);

  // submitToMainThread is camelcased, threadmessage is not.
  // This follows our tradition of hooks we call being lowercased but functions the user can call being camelcased.
  l.writeFunction("submitToMainThread", [](std::string cmd, LuaAssociativeTable<std::string> data) {
    auto lua = g_lua.lock();
    // maybe offer more than `void`
    auto func = lua->readVariable<boost::optional<std::function<void(std::string cmd, LuaAssociativeTable<std::string> data)>>>("threadmessage");
    if (func) {
      func.get()(std::move(cmd), std::move(data));
    }
    else {
      errlog("Lua thread called submitToMainThread but no threadmessage receiver is defined");
    }
  });

  // function threadmessage(cmd, data) print("got thread data:", cmd) for k,v in pairs(data) do print(k,v) end end

  for (;;) {
    try {
      l.executeCode(code);
      errlog("Lua thread exited, restarting in 5 seconds");
    }
    catch (const std::exception& e) {
      errlog("Lua thread crashed, restarting in 5 seconds: %s", e.what());
    }
    catch (...) {
      errlog("Lua thread crashed, restarting in 5 seconds");
    }
    sleep(5);
  }
}

static bool checkConfigurationTime(const std::string& name)
{
  if (!g_configurationDone) {
    return true;
  }
  g_outputBuffer = name + " cannot be used at runtime!\n";
  errlog("%s cannot be used at runtime!", name);
  return false;
}

using newserver_t = LuaAssociativeTable<boost::variant<bool, std::string, LuaArray<std::string>, LuaArray<std::shared_ptr<XskSocket>>, DownstreamState::checkfunc_t>>;

static void handleNewServerHealthCheckParameters(boost::optional<newserver_t>& vars, DownstreamState::Config& config)
{
  std::string valueStr;

  if (getOptionalValue<std::string>(vars, "checkInterval", valueStr) > 0) {
    config.checkInterval = static_cast<unsigned int>(std::stoul(valueStr));
  }

  if (getOptionalValue<std::string>(vars, "healthCheckMode", valueStr) > 0) {
    const auto& mode = valueStr;
    if (pdns_iequals(mode, "auto")) {
      config.availability = DownstreamState::Availability::Auto;
    }
    else if (pdns_iequals(mode, "lazy")) {
      config.availability = DownstreamState::Availability::Lazy;
    }
    else if (pdns_iequals(mode, "up")) {
      config.availability = DownstreamState::Availability::Up;
    }
    else if (pdns_iequals(mode, "down")) {
      config.availability = DownstreamState::Availability::Down;
    }
    else {
      warnlog("Ignoring unknown value '%s' for 'healthCheckMode' on 'newServer'", mode);
    }
  }

  if (getOptionalValue<std::string>(vars, "checkName", valueStr) > 0) {
    config.checkName = DNSName(valueStr);
  }

  getOptionalValue<std::string>(vars, "checkType", config.checkType);
  getOptionalIntegerValue("newServer", vars, "checkClass", config.checkClass);
  getOptionalValue<DownstreamState::checkfunc_t>(vars, "checkFunction", config.checkFunction);
  getOptionalIntegerValue("newServer", vars, "checkTimeout", config.checkTimeout);
  getOptionalValue<bool>(vars, "checkTCP", config.d_tcpCheck);
  getOptionalValue<bool>(vars, "setCD", config.setCD);
  getOptionalValue<bool>(vars, "mustResolve", config.mustResolve);

  if (getOptionalValue<std::string>(vars, "lazyHealthCheckSampleSize", valueStr) > 0) {
    const auto& value = std::stoi(valueStr);
    checkParameterBound("lazyHealthCheckSampleSize", value);
    config.d_lazyHealthCheckSampleSize = value;
  }

  if (getOptionalValue<std::string>(vars, "lazyHealthCheckMinSampleCount", valueStr) > 0) {
    const auto& value = std::stoi(valueStr);
    checkParameterBound("lazyHealthCheckMinSampleCount", value);
    config.d_lazyHealthCheckMinSampleCount = value;
  }

  if (getOptionalValue<std::string>(vars, "lazyHealthCheckThreshold", valueStr) > 0) {
    const auto& value = std::stoi(valueStr);
    checkParameterBound("lazyHealthCheckThreshold", value, std::numeric_limits<uint8_t>::max());
    config.d_lazyHealthCheckThreshold = value;
  }

  if (getOptionalValue<std::string>(vars, "lazyHealthCheckFailedInterval", valueStr) > 0) {
    const auto& value = std::stoi(valueStr);
    checkParameterBound("lazyHealthCheckFailedInterval", value);
    config.d_lazyHealthCheckFailedInterval = value;
  }

  getOptionalValue<bool>(vars, "lazyHealthCheckUseExponentialBackOff", config.d_lazyHealthCheckUseExponentialBackOff);

  if (getOptionalValue<std::string>(vars, "lazyHealthCheckMaxBackOff", valueStr) > 0) {
    const auto& value = std::stoi(valueStr);
    checkParameterBound("lazyHealthCheckMaxBackOff", value);
    config.d_lazyHealthCheckMaxBackOff = value;
  }

  if (getOptionalValue<std::string>(vars, "lazyHealthCheckMode", valueStr) > 0) {
    const auto& mode = valueStr;
    if (pdns_iequals(mode, "TimeoutOnly")) {
      config.d_lazyHealthCheckMode = DownstreamState::LazyHealthCheckMode::TimeoutOnly;
    }
    else if (pdns_iequals(mode, "TimeoutOrServFail")) {
      config.d_lazyHealthCheckMode = DownstreamState::LazyHealthCheckMode::TimeoutOrServFail;
    }
    else {
      warnlog("Ignoring unknown value '%s' for 'lazyHealthCheckMode' on 'newServer'", mode);
    }
  }

  getOptionalValue<bool>(vars, "lazyHealthCheckWhenUpgraded", config.d_upgradeToLazyHealthChecks);

  getOptionalIntegerValue("newServer", vars, "maxCheckFailures", config.maxCheckFailures);
  getOptionalIntegerValue("newServer", vars, "rise", config.minRiseSuccesses);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
static void setupLuaConfig(LuaContext& luaCtx, bool client, bool configCheck)
{
  luaCtx.writeFunction("inClientStartup", [client]() {
    return client && !g_configurationDone;
  });

  luaCtx.writeFunction("inConfigCheck", [configCheck]() {
    return configCheck;
  });

  luaCtx.writeFunction("newServer",
                       [client, configCheck](boost::variant<string, newserver_t> pvars, boost::optional<int> qps) {
                         setLuaSideEffect();

                         boost::optional<newserver_t> vars = newserver_t();
                         DownstreamState::Config config;

                         std::string serverAddressStr;
                         if (auto addrStr = boost::get<string>(&pvars)) {
                           serverAddressStr = *addrStr;
                           if (qps) {
                             (*vars)["qps"] = std::to_string(*qps);
                           }
                         }
                         else {
                           vars = boost::get<newserver_t>(pvars);
                           getOptionalValue<std::string>(vars, "address", serverAddressStr);
                         }

                         std::string source;
                         if (getOptionalValue<std::string>(vars, "source", source) > 0) {
                           /* handle source in the following forms:
                              - v4 address ("192.0.2.1")
                              - v6 address ("2001:DB8::1")
                              - interface name ("eth0")
                              - v4 address and interface name ("192.0.2.1@eth0")
                              - v6 address and interface name ("2001:DB8::1@eth0")
                           */
                           bool parsed = false;
                           std::string::size_type pos = source.find("@");
                           if (pos == std::string::npos) {
                             /* no '@', try to parse that as a valid v4/v6 address */
                             try {
                               config.sourceAddr = ComboAddress(source);
                               parsed = true;
                             }
                             catch (...) {
                             }
                           }

                           if (parsed == false) {
                             /* try to parse as interface name, or v4/v6@itf */
                             config.sourceItfName = source.substr(pos == std::string::npos ? 0 : pos + 1);
                             unsigned int itfIdx = if_nametoindex(config.sourceItfName.c_str());
                             if (itfIdx != 0) {
                               if (pos == 0 || pos == std::string::npos) {
                                 /* "eth0" or "@eth0" */
                                 config.sourceItf = itfIdx;
                               }
                               else {
                                 /* "192.0.2.1@eth0" */
                                 config.sourceAddr = ComboAddress(source.substr(0, pos));
                                 config.sourceItf = itfIdx;
                               }
#ifdef SO_BINDTODEVICE
                               /* we need to retain CAP_NET_RAW to be able to set SO_BINDTODEVICE in the health checks */
                               g_capabilitiesToRetain.insert("CAP_NET_RAW");
#endif
                             }
                             else {
                               warnlog("Dismissing source %s because '%s' is not a valid interface name", source, config.sourceItfName);
                             }
                           }
                         }

                         std::string valueStr;
                         if (getOptionalValue<std::string>(vars, "sockets", valueStr) > 0) {
                           config.d_numberOfSockets = std::stoul(valueStr);
                           if (config.d_numberOfSockets == 0) {
                             warnlog("Dismissing invalid number of sockets '%s', using 1 instead", valueStr);
                             config.d_numberOfSockets = 1;
                           }
                         }

                         getOptionalIntegerValue("newServer", vars, "qps", config.d_qpsLimit);
                         getOptionalIntegerValue("newServer", vars, "order", config.order);
                         getOptionalIntegerValue("newServer", vars, "weight", config.d_weight);
                         if (config.d_weight < 1) {
                           errlog("Error creating new server: downstream weight value must be greater than 0.");
                           return std::shared_ptr<DownstreamState>();
                         }

                         getOptionalIntegerValue("newServer", vars, "retries", config.d_retries);
                         getOptionalIntegerValue("newServer", vars, "tcpConnectTimeout", config.tcpConnectTimeout);
                         getOptionalIntegerValue("newServer", vars, "tcpSendTimeout", config.tcpSendTimeout);
                         getOptionalIntegerValue("newServer", vars, "tcpRecvTimeout", config.tcpRecvTimeout);

                         handleNewServerHealthCheckParameters(vars, config);

                         bool fastOpen{false};
                         if (getOptionalValue<bool>(vars, "tcpFastOpen", fastOpen) > 0) {
                           if (fastOpen) {
#ifdef MSG_FASTOPEN
                             config.tcpFastOpen = true;
#else
          warnlog("TCP Fast Open has been configured on downstream server %s but is not supported", serverAddressStr);
#endif
                           }
                         }

                         getOptionalIntegerValue("newServer", vars, "maxInFlight", config.d_maxInFlightQueriesPerConn);
                         getOptionalIntegerValue("newServer", vars, "maxConcurrentTCPConnections", config.d_tcpConcurrentConnectionsLimit);

                         getOptionalValue<std::string>(vars, "name", config.name);

                         if (getOptionalValue<std::string>(vars, "id", valueStr) > 0) {
                           config.id = boost::uuids::string_generator()(valueStr);
                         }

                         getOptionalValue<bool>(vars, "useClientSubnet", config.useECS);
                         getOptionalValue<bool>(vars, "useProxyProtocol", config.useProxyProtocol);
                         getOptionalValue<bool>(vars, "proxyProtocolAdvertiseTLS", config.d_proxyProtocolAdvertiseTLS);
                         getOptionalValue<bool>(vars, "disableZeroScope", config.disableZeroScope);
                         getOptionalValue<bool>(vars, "ipBindAddrNoPort", config.ipBindAddrNoPort);

                         getOptionalIntegerValue("newServer", vars, "addXPF", config.xpfRRCode);

                         getOptionalValue<bool>(vars, "reconnectOnUp", config.reconnectOnUp);

                         LuaArray<string> cpuMap;
                         if (getOptionalValue<decltype(cpuMap)>(vars, "cpus", cpuMap) > 0) {
                           for (const auto& cpu : cpuMap) {
                             config.d_cpus.insert(std::stoi(cpu.second));
                           }
                         }

                         getOptionalValue<bool>(vars, "tcpOnly", config.d_tcpOnly);

                         std::shared_ptr<TLSCtx> tlsCtx;
                         getOptionalValue<std::string>(vars, "ciphers", config.d_tlsParams.d_ciphers);
                         getOptionalValue<std::string>(vars, "ciphers13", config.d_tlsParams.d_ciphers13);
                         getOptionalValue<std::string>(vars, "caStore", config.d_tlsParams.d_caStore);
                         getOptionalValue<bool>(vars, "validateCertificates", config.d_tlsParams.d_validateCertificates);
                         getOptionalValue<bool>(vars, "releaseBuffers", config.d_tlsParams.d_releaseBuffers);
                         getOptionalValue<bool>(vars, "enableRenegotiation", config.d_tlsParams.d_enableRenegotiation);
                         getOptionalValue<bool>(vars, "ktls", config.d_tlsParams.d_ktls);
                         getOptionalValue<std::string>(vars, "subjectName", config.d_tlsSubjectName);

                         if (getOptionalValue<std::string>(vars, "subjectAddr", valueStr) > 0) {
                           try {
                             ComboAddress ca(valueStr);
                             config.d_tlsSubjectName = ca.toString();
                             config.d_tlsSubjectIsAddr = true;
                           }
                           catch (const std::exception& e) {
                             errlog("Error creating new server: downstream subjectAddr value must be a valid IP address");
                             return std::shared_ptr<DownstreamState>();
                           }
                         }

                         uint16_t serverPort = 53;

                         if (getOptionalValue<std::string>(vars, "tls", valueStr) > 0) {
                           serverPort = 853;
                           config.d_tlsParams.d_provider = valueStr;
                           tlsCtx = getTLSContext(config.d_tlsParams);

                           if (getOptionalValue<std::string>(vars, "dohPath", valueStr) > 0) {
#if !defined(HAVE_DNS_OVER_HTTPS) || !defined(HAVE_NGHTTP2)
                             throw std::runtime_error("Outgoing DNS over HTTPS support requested (via 'dohPath' on newServer()) but it is not available");
#endif

                             serverPort = 443;
                             config.d_dohPath = valueStr;

                             getOptionalValue<bool>(vars, "addXForwardedHeaders", config.d_addXForwardedHeaders);
                           }
                         }

                         try {
                           config.remote = ComboAddress(serverAddressStr, serverPort);
                         }
                         catch (const PDNSException& e) {
                           g_outputBuffer = "Error creating new server: " + string(e.reason);
                           errlog("Error creating new server with address %s: %s", serverAddressStr, e.reason);
                           return std::shared_ptr<DownstreamState>();
                         }
                         catch (const std::exception& e) {
                           g_outputBuffer = "Error creating new server: " + string(e.what());
                           errlog("Error creating new server with address %s: %s", serverAddressStr, e.what());
                           return std::shared_ptr<DownstreamState>();
                         }

                         if (IsAnyAddress(config.remote)) {
                           g_outputBuffer = "Error creating new server: invalid address for a downstream server.";
                           errlog("Error creating new server: %s is not a valid address for a downstream server", serverAddressStr);
                           return std::shared_ptr<DownstreamState>();
                         }

                         LuaArray<std::string> pools;
                         if (getOptionalValue<std::string>(vars, "pool", valueStr, false) > 0) {
                           config.pools.insert(valueStr);
                         }
                         else if (getOptionalValue<decltype(pools)>(vars, "pool", pools) > 0) {
                           for (auto& p : pools) {
                             config.pools.insert(p.second);
                           }
                         }

                         bool autoUpgrade = false;
                         bool keepAfterUpgrade = false;
                         uint32_t upgradeInterval = 3600;
                         uint16_t upgradeDoHKey = dnsdist::ServiceDiscovery::s_defaultDoHSVCKey;
                         std::string upgradePool;

                         getOptionalValue<bool>(vars, "autoUpgrade", autoUpgrade);
                         if (autoUpgrade) {
                           if (getOptionalValue<std::string>(vars, "autoUpgradeInterval", valueStr) > 0) {
                             try {
                               upgradeInterval = static_cast<uint32_t>(std::stoul(valueStr));
                             }
                             catch (const std::exception& e) {
                               warnlog("Error parsing 'autoUpgradeInterval' value: %s", e.what());
                             }
                           }
                           getOptionalValue<bool>(vars, "autoUpgradeKeep", keepAfterUpgrade);
                           getOptionalValue<std::string>(vars, "autoUpgradePool", upgradePool);
                           if (getOptionalValue<std::string>(vars, "autoUpgradeDoHKey", valueStr) > 0) {
                             try {
                               upgradeDoHKey = static_cast<uint16_t>(std::stoul(valueStr));
                             }
                             catch (const std::exception& e) {
                               warnlog("Error parsing 'autoUpgradeDoHKey' value: %s", e.what());
                             }
                           }
                         }

                         // create but don't connect the socket in client or check-config modes
                         auto ret = std::make_shared<DownstreamState>(std::move(config), std::move(tlsCtx), !(client || configCheck));
#ifdef HAVE_XSK
                         LuaArray<std::shared_ptr<XskSocket>> luaXskSockets;
                         if (!client && !configCheck && getOptionalValue<LuaArray<std::shared_ptr<XskSocket>>>(vars, "xskSockets", luaXskSockets) > 0 && !luaXskSockets.empty()) {
                           if (g_configurationDone) {
                             throw std::runtime_error("Adding a server with xsk at runtime is not supported");
                           }
                           std::vector<std::shared_ptr<XskSocket>> xskSockets;
                           for (auto& socket : luaXskSockets) {
                             xskSockets.push_back(socket.second);
                           }
                           ret->registerXsk(xskSockets);
                           std::string mac;
                           if (getOptionalValue<std::string>(vars, "MACAddr", mac) > 0) {
                             auto* addr = &ret->d_config.destMACAddr[0];
                             sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", addr, addr + 1, addr + 2, addr + 3, addr + 4, addr + 5);
                           }
                           else {
                             mac = getMACAddress(ret->d_config.remote);
                             if (mac.size() != ret->d_config.destMACAddr.size()) {
                               throw runtime_error("Field 'MACAddr' is not set on 'newServer' directive for '" + ret->d_config.remote.toStringWithPort() + "' and cannot be retrieved from the system either!");
                             }
                             memcpy(ret->d_config.destMACAddr.data(), mac.data(), ret->d_config.destMACAddr.size());
                           }
                           infolog("Added downstream server %s via XSK in %s mode", ret->d_config.remote.toStringWithPort(), xskSockets.at(0)->getXDPMode());
                         }
                         else if (!(client || configCheck)) {
                           infolog("Added downstream server %s", ret->d_config.remote.toStringWithPort());
                         }

                         if (client || configCheck) {
                           /* consume these in client or configuration check mode, to prevent warnings */
                           std::string mac;
                           getOptionalValue<std::string>(vars, "MACAddr", mac);
                           getOptionalValue<LuaArray<std::shared_ptr<XskSocket>>>(vars, "xskSockets", luaXskSockets);
                         }
#else /* HAVE_XSK */
      if (!(client || configCheck)) {
        infolog("Added downstream server %s", ret->d_config.remote.toStringWithPort());
      }
#endif /* HAVE_XSK */
                         if (autoUpgrade && ret->getProtocol() != dnsdist::Protocol::DoT && ret->getProtocol() != dnsdist::Protocol::DoH) {
                           dnsdist::ServiceDiscovery::addUpgradeableServer(ret, upgradeInterval, upgradePool, upgradeDoHKey, keepAfterUpgrade);
                         }

                         /* this needs to be done _AFTER_ the order has been set,
                            since the server are kept ordered inside the pool */
                         auto localPools = g_pools.getCopy();
                         if (!ret->d_config.pools.empty()) {
                           for (const auto& poolName : ret->d_config.pools) {
                             addServerToPool(localPools, poolName, ret);
                           }
                         }
                         else {
                           addServerToPool(localPools, "", ret);
                         }
                         g_pools.setState(localPools);

                         if (ret->connected) {
                           if (g_launchWork) {
                             g_launchWork->push_back([ret]() {
                               ret->start();
                             });
                           }
                           else {
                             ret->start();
                           }
                         }

                         auto states = g_dstates.getCopy();
                         states.push_back(ret);
                         std::stable_sort(states.begin(), states.end(), [](const decltype(ret)& a, const decltype(ret)& b) {
                           return a->d_config.order < b->d_config.order;
                         });
                         g_dstates.setState(states);
                         checkAllParametersConsumed("newServer", vars);
                         return ret;
                       });

  luaCtx.writeFunction("rmServer",
                       [](boost::variant<std::shared_ptr<DownstreamState>, int, std::string> var) {
                         setLuaSideEffect();
                         shared_ptr<DownstreamState> server = nullptr;
                         auto states = g_dstates.getCopy();
                         if (auto* rem = boost::get<shared_ptr<DownstreamState>>(&var)) {
                           server = *rem;
                         }
                         else if (auto str = boost::get<std::string>(&var)) {
                           const auto uuid = getUniqueID(*str);
                           for (auto& state : states) {
                             if (*state->d_config.id == uuid) {
                               server = state;
                             }
                           }
                         }
                         else {
                           int idx = boost::get<int>(var);
                           server = states.at(idx);
                         }
                         if (!server) {
                           throw std::runtime_error("unable to locate the requested server");
                         }
                         auto localPools = g_pools.getCopy();
                         for (const string& poolName : server->d_config.pools) {
                           removeServerFromPool(localPools, poolName, server);
                         }
                         try {
                           /* the server might also be in the default pool */
                           removeServerFromPool(localPools, "", server);
                         }
                         catch (const std::out_of_range& exp) {
                           /* but the default pool might not exist yet, this is fine */
                         }
                         g_pools.setState(localPools);
                         states.erase(remove(states.begin(), states.end(), server), states.end());
                         g_dstates.setState(states);
                         server->stop();
                       });

  luaCtx.writeFunction("truncateTC", [](bool tc) { setLuaSideEffect(); g_truncateTC=tc; });
  luaCtx.writeFunction("fixupCase", [](bool fu) { setLuaSideEffect(); g_fixupCase=fu; });

  luaCtx.writeFunction("addACL", [](const std::string& domain) {
    setLuaSideEffect();
    g_ACL.modify([domain](NetmaskGroup& nmg) { nmg.addMask(domain); });
  });

  luaCtx.writeFunction("rmACL", [](const std::string& netmask) {
    setLuaSideEffect();
    g_ACL.modify([netmask](NetmaskGroup& nmg) { nmg.deleteMask(netmask); });
  });

  luaCtx.writeFunction("setLocal", [client](const std::string& addr, boost::optional<localbind_t> vars) {
    setLuaSideEffect();
    if (client) {
      return;
    }

    if (!checkConfigurationTime("setLocal")) {
      return;
    }

    bool reusePort = false;
    int tcpFastOpenQueueSize = 0;
    int tcpListenQueueSize = 0;
    uint64_t maxInFlightQueriesPerConn = 0;
    uint64_t tcpMaxConcurrentConnections = 0;
    std::string interface;
    std::set<int> cpus;
    bool enableProxyProtocol = true;

    parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections, enableProxyProtocol);

    try {
      ComboAddress loc(addr, 53);
      for (auto it = g_frontends.begin(); it != g_frontends.end();) {
        /* DoH, DoT and DNSCrypt frontends are separate */
        if ((*it)->tlsFrontend == nullptr && (*it)->dnscryptCtx == nullptr && (*it)->dohFrontend == nullptr) {
          it = g_frontends.erase(it);
        }
        else {
          ++it;
        }
      }

      // only works pre-startup, so no sync necessary
      auto udpCS = std::make_unique<ClientState>(loc, false, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
      auto tcpCS = std::make_unique<ClientState>(loc, true, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
      if (tcpListenQueueSize > 0) {
        tcpCS->tcpListenQueueSize = tcpListenQueueSize;
      }
      if (maxInFlightQueriesPerConn > 0) {
        tcpCS->d_maxInFlightQueriesPerConn = maxInFlightQueriesPerConn;
      }
      if (tcpMaxConcurrentConnections > 0) {
        tcpCS->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConnections;
      }

#ifdef HAVE_XSK
      std::shared_ptr<XskSocket> socket;
      parseXskVars(vars, socket);
      if (socket) {
        udpCS->xskInfo = XskWorker::create(XskWorker::Type::Bidirectional, socket->sharedEmptyFrameOffset);
        socket->addWorker(udpCS->xskInfo);
        socket->addWorkerRoute(udpCS->xskInfo, loc);
        udpCS->xskInfoResponder = XskWorker::create(XskWorker::Type::OutgoingOnly, socket->sharedEmptyFrameOffset);
        socket->addWorker(udpCS->xskInfoResponder);
        vinfolog("Enabling XSK in %s mode for incoming UDP packets to %s", socket->getXDPMode(), loc.toStringWithPort());
      }
#endif /* HAVE_XSK */
      g_frontends.push_back(std::move(udpCS));
      g_frontends.push_back(std::move(tcpCS));

      checkAllParametersConsumed("setLocal", vars);
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Error: " + string(e.what()) + "\n";
    }
  });

  luaCtx.writeFunction("addLocal", [client](const std::string& addr, boost::optional<localbind_t> vars) {
    setLuaSideEffect();
    if (client)
      return;

    if (!checkConfigurationTime("addLocal")) {
      return;
    }
    bool reusePort = false;
    int tcpFastOpenQueueSize = 0;
    int tcpListenQueueSize = 0;
    uint64_t maxInFlightQueriesPerConn = 0;
    uint64_t tcpMaxConcurrentConnections = 0;
    std::string interface;
    std::set<int> cpus;
    bool enableProxyProtocol = true;

    parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections, enableProxyProtocol);

    try {
      ComboAddress loc(addr, 53);
      // only works pre-startup, so no sync necessary
      auto udpCS = std::make_unique<ClientState>(loc, false, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
      auto tcpCS = std::make_unique<ClientState>(loc, true, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
      if (tcpListenQueueSize > 0) {
        tcpCS->tcpListenQueueSize = tcpListenQueueSize;
      }
      if (maxInFlightQueriesPerConn > 0) {
        tcpCS->d_maxInFlightQueriesPerConn = maxInFlightQueriesPerConn;
      }
      if (tcpMaxConcurrentConnections > 0) {
        tcpCS->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConnections;
      }
#ifdef HAVE_XSK
      std::shared_ptr<XskSocket> socket;
      parseXskVars(vars, socket);
      if (socket) {
        udpCS->xskInfo = XskWorker::create(XskWorker::Type::Bidirectional, socket->sharedEmptyFrameOffset);
        socket->addWorker(udpCS->xskInfo);
        socket->addWorkerRoute(udpCS->xskInfo, loc);
        udpCS->xskInfoResponder = XskWorker::create(XskWorker::Type::OutgoingOnly, socket->sharedEmptyFrameOffset);
        socket->addWorker(udpCS->xskInfoResponder);
        vinfolog("Enabling XSK in %s mode for incoming UDP packets to %s", socket->getXDPMode(), loc.toStringWithPort());
      }
#endif /* HAVE_XSK */
      g_frontends.push_back(std::move(udpCS));
      g_frontends.push_back(std::move(tcpCS));

      checkAllParametersConsumed("addLocal", vars);
    }
    catch (std::exception& e) {
      g_outputBuffer = "Error: " + string(e.what()) + "\n";
      errlog("Error while trying to listen on %s: %s\n", addr, string(e.what()));
    }
  });

  luaCtx.writeFunction("setACL", [](LuaTypeOrArrayOf<std::string> inp) {
    setLuaSideEffect();
    NetmaskGroup nmg;
    if (auto str = boost::get<string>(&inp)) {
      nmg.addMask(*str);
    }
    else
      for (const auto& p : boost::get<LuaArray<std::string>>(inp)) {
        nmg.addMask(p.second);
      }
    g_ACL.setState(nmg);
  });

  luaCtx.writeFunction("setACLFromFile", [](const std::string& file) {
    setLuaSideEffect();
    NetmaskGroup nmg;

    ifstream ifs(file);
    if (!ifs) {
      throw std::runtime_error("Could not open '" + file + "': " + stringerror());
    }

    string::size_type pos;
    string line;
    while (getline(ifs, line)) {
      pos = line.find('#');
      if (pos != string::npos)
        line.resize(pos);
      boost::trim(line);
      if (line.empty())
        continue;

      nmg.addMask(line);
    }

    g_ACL.setState(nmg);
  });

  luaCtx.writeFunction("showACL", []() {
    setLuaNoSideEffect();
    auto aclEntries = g_ACL.getLocal()->toStringVector();

    for (const auto& entry : aclEntries) {
      g_outputBuffer += entry + "\n";
    }
  });

  luaCtx.writeFunction("shutdown", []() {
#ifdef HAVE_SYSTEMD
    sd_notify(0, "STOPPING=1");
#endif /* HAVE_SYSTEMD */
#if 0
    // Useful for debugging leaks, but might lead to race under load
    // since other threads are still running.
    for (auto& frontend : g_tlslocals) {
      frontend->cleanup();
    }
    g_tlslocals.clear();
    g_rings.clear();
#endif /* 0 */
    pdns::coverage::dumpCoverageData();
    _exit(0);
  });

  typedef LuaAssociativeTable<boost::variant<bool, std::string>> showserversopts_t;

  luaCtx.writeFunction("showServers", [](boost::optional<showserversopts_t> vars) {
    setLuaNoSideEffect();
    bool showUUIDs = false;
    getOptionalValue<bool>(vars, "showUUIDs", showUUIDs);
    checkAllParametersConsumed("showServers", vars);

    try {
      ostringstream ret;
      boost::format fmt;

      auto latFmt = boost::format("%5.1f");
      if (showUUIDs) {
        fmt = boost::format("%1$-3d %15$-36s %2$-20.20s %|62t|%3% %|107t|%4$5s %|88t|%5$7.1f %|103t|%6$7d %|106t|%7$10d %|115t|%8$10d %|117t|%9$10d %|123t|%10$7d %|128t|%11$5.1f %|146t|%12$5s %|152t|%16$5s %|158t|%13$11d %14%");
        //             1        2          3       4        5       6       7       8           9        10        11       12     13              14        15        16 (tcp latency)
        ret << (fmt % "#" % "Name" % "Address" % "State" % "Qps" % "Qlim" % "Ord" % "Wt" % "Queries" % "Drops" % "Drate" % "Lat" % "Outstanding" % "Pools" % "UUID" % "TCP") << endl;
      }
      else {
        fmt = boost::format("%1$-3d %2$-20.20s %|25t|%3% %|70t|%4$5s %|51t|%5$7.1f %|66t|%6$7d %|69t|%7$10d %|78t|%8$10d %|80t|%9$10d %|86t|%10$7d %|91t|%11$5.1f %|109t|%12$5s %|115t|%15$5s %|121t|%13$11d %14%");
        ret << (fmt % "#" % "Name" % "Address" % "State" % "Qps" % "Qlim" % "Ord" % "Wt" % "Queries" % "Drops" % "Drate" % "Lat" % "Outstanding" % "Pools" % "TCP") << endl;
      }

      uint64_t totQPS{0}, totQueries{0}, totDrops{0};
      int counter = 0;
      auto states = g_dstates.getLocal();
      for (const auto& s : *states) {
        string status = s->getStatus();
        string pools;
        for (const auto& p : s->d_config.pools) {
          if (!pools.empty()) {
            pools += " ";
          }
          pools += p;
        }
        const std::string latency = (s->latencyUsec == 0.0 ? "-" : boost::str(latFmt % (s->latencyUsec / 1000.0)));
        const std::string latencytcp = (s->latencyUsecTCP == 0.0 ? "-" : boost::str(latFmt % (s->latencyUsecTCP / 1000.0)));
        if (showUUIDs) {
          ret << (fmt % counter % s->getName() % s->d_config.remote.toStringWithPort() % status % s->queryLoad % s->qps.getRate() % s->d_config.order % s->d_config.d_weight % s->queries.load() % s->reuseds.load() % (s->dropRate) % latency % s->outstanding.load() % pools % *s->d_config.id % latencytcp) << endl;
        }
        else {
          ret << (fmt % counter % s->getName() % s->d_config.remote.toStringWithPort() % status % s->queryLoad % s->qps.getRate() % s->d_config.order % s->d_config.d_weight % s->queries.load() % s->reuseds.load() % (s->dropRate) % latency % s->outstanding.load() % pools % latencytcp) << endl;
        }
        totQPS += s->queryLoad;
        totQueries += s->queries.load();
        totDrops += s->reuseds.load();
        ++counter;
      }
      if (showUUIDs) {
        ret << (fmt % "All" % "" % "" % ""
                % (double)totQPS % "" % "" % "" % totQueries % totDrops % "" % "" % "" % "" % "" % "")
            << endl;
      }
      else {
        ret << (fmt % "All" % "" % "" % ""
                % (double)totQPS % "" % "" % "" % totQueries % totDrops % "" % "" % "" % "" % "")
            << endl;
      }

      g_outputBuffer = ret.str();
    }
    catch (std::exception& e) {
      g_outputBuffer = e.what();
      throw;
    }
  });

  luaCtx.writeFunction("getServers", []() {
    setLuaNoSideEffect();
    LuaArray<std::shared_ptr<DownstreamState>> ret;
    int count = 1;
    for (const auto& s : g_dstates.getCopy()) {
      ret.emplace_back(count++, s);
    }
    return ret;
  });

  luaCtx.writeFunction("getPoolServers", [](const string& pool) {
    const auto poolServers = getDownstreamCandidates(g_pools.getCopy(), pool);
    return *poolServers;
  });

  luaCtx.writeFunction("getServer", [client](boost::variant<int, std::string> i) {
    if (client) {
      return std::make_shared<DownstreamState>(ComboAddress());
    }
    auto states = g_dstates.getCopy();
    if (auto str = boost::get<std::string>(&i)) {
      const auto uuid = getUniqueID(*str);
      for (auto& state : states) {
        if (*state->d_config.id == uuid) {
          return state;
        }
      }
    }
    else if (auto pos = boost::get<int>(&i)) {
      return states.at(*pos);
    }

    g_outputBuffer = "Error: no rule matched\n";
    return std::shared_ptr<DownstreamState>(nullptr);
  });

#ifndef DISABLE_CARBON
  luaCtx.writeFunction("carbonServer", [](const std::string& address, boost::optional<string> ourName, boost::optional<uint64_t> interval, boost::optional<string> namespace_name, boost::optional<string> instance_name) {
    setLuaSideEffect();
    dnsdist::Carbon::Endpoint endpoint{ComboAddress(address, 2003),
                                       (namespace_name && !namespace_name->empty()) ? *namespace_name : "dnsdist",
                                       ourName ? *ourName : "",
                                       (instance_name && !instance_name->empty()) ? *instance_name : "main",
                                       (interval && *interval < std::numeric_limits<unsigned int>::max()) ? static_cast<unsigned int>(*interval) : 30};
    dnsdist::Carbon::addEndpoint(std::move(endpoint));
  });
#endif /* DISABLE_CARBON */

  luaCtx.writeFunction("webserver", [client, configCheck](const std::string& address) {
    setLuaSideEffect();
    ComboAddress local;
    try {
      local = ComboAddress(address);
    }
    catch (const PDNSException& e) {
      throw std::runtime_error(std::string("Error parsing the bind address for the webserver: ") + e.reason);
    }

    if (client || configCheck) {
      return;
    }

    try {
      int sock = SSocket(local.sin4.sin_family, SOCK_STREAM, 0);
      SSetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
      SBind(sock, local);
      SListen(sock, 5);
      auto launch = [sock, local]() {
        thread t(dnsdistWebserverThread, sock, local);
        t.detach();
      };
      if (g_launchWork) {
        g_launchWork->push_back(launch);
      }
      else {
        launch();
      }
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Unable to bind to webserver socket on " + local.toStringWithPort() + ": " + e.what();
      errlog("Unable to bind to webserver socket on %s: %s", local.toStringWithPort(), e.what());
    }
  });

  typedef LuaAssociativeTable<boost::variant<bool, std::string, LuaAssociativeTable<std::string>>> webserveropts_t;

  luaCtx.writeFunction("setWebserverConfig", [](boost::optional<webserveropts_t> vars) {
    setLuaSideEffect();

    if (!vars) {
      return;
    }

    bool hashPlaintextCredentials = false;
    getOptionalValue<bool>(vars, "hashPlaintextCredentials", hashPlaintextCredentials);

    std::string password;
    std::string apiKey;
    std::string acl;
    LuaAssociativeTable<std::string> headers;
    bool statsRequireAuthentication{true};
    bool apiRequiresAuthentication{true};
    bool dashboardRequiresAuthentication{true};
    int maxConcurrentConnections = 0;

    if (getOptionalValue<std::string>(vars, "password", password) > 0) {
      auto holder = make_unique<CredentialsHolder>(std::move(password), hashPlaintextCredentials);
      if (!holder->wasHashed() && holder->isHashingAvailable()) {
        infolog("Passing a plain-text password via the 'password' parameter to 'setWebserverConfig()' is not advised, please consider generating a hashed one using 'hashPassword()' instead.");
      }

      setWebserverPassword(std::move(holder));
    }

    if (getOptionalValue<std::string>(vars, "apiKey", apiKey) > 0) {
      auto holder = make_unique<CredentialsHolder>(std::move(apiKey), hashPlaintextCredentials);
      if (!holder->wasHashed() && holder->isHashingAvailable()) {
        infolog("Passing a plain-text API key via the 'apiKey' parameter to 'setWebserverConfig()' is not advised, please consider generating a hashed one using 'hashPassword()' instead.");
      }

      setWebserverAPIKey(std::move(holder));
    }

    if (getOptionalValue<std::string>(vars, "acl", acl) > 0) {
      setWebserverACL(acl);
    }

    if (getOptionalValue<decltype(headers)>(vars, "customHeaders", headers) > 0) {
      setWebserverCustomHeaders(headers);
    }

    if (getOptionalValue<bool>(vars, "statsRequireAuthentication", statsRequireAuthentication) > 0) {
      setWebserverStatsRequireAuthentication(statsRequireAuthentication);
    }

    if (getOptionalValue<bool>(vars, "apiRequiresAuthentication", apiRequiresAuthentication) > 0) {
      setWebserverAPIRequiresAuthentication(apiRequiresAuthentication);
    }

    if (getOptionalValue<bool>(vars, "dashboardRequiresAuthentication", dashboardRequiresAuthentication) > 0) {
      setWebserverDashboardRequiresAuthentication(dashboardRequiresAuthentication);
    }

    if (getOptionalIntegerValue("setWebserverConfig", vars, "maxConcurrentConnections", maxConcurrentConnections) > 0) {
      setWebserverMaxConcurrentConnections(maxConcurrentConnections);
    }
  });

  luaCtx.writeFunction("showWebserverConfig", []() {
    setLuaNoSideEffect();
    return getWebserverConfig();
  });

  luaCtx.writeFunction("hashPassword", [](const std::string& password, boost::optional<uint64_t> workFactor) {
    if (workFactor) {
      return hashPassword(password, *workFactor, CredentialsHolder::s_defaultParallelFactor, CredentialsHolder::s_defaultBlockSize);
    }
    return hashPassword(password);
  });

  luaCtx.writeFunction("controlSocket", [client, configCheck](const std::string& str) {
    setLuaSideEffect();
    ComboAddress local(str, 5199);

    if (client || configCheck) {
      g_serverControl = local;
      return;
    }

    g_consoleEnabled = true;
#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO)
    if (g_configurationDone && g_consoleKey.empty()) {
      warnlog("Warning, the console has been enabled via 'controlSocket()' but no key has been set with 'setKey()' so all connections will fail until a key has been set");
    }
#endif

    try {
      auto sock = std::make_shared<Socket>(local.sin4.sin_family, SOCK_STREAM, 0);
      sock->bind(local, true);
      sock->listen(5);
      auto launch = [sock = std::move(sock), local]() {
        std::thread consoleControlThread(controlThread, sock, local);
        consoleControlThread.detach();
      };
      if (g_launchWork) {
        g_launchWork->emplace_back(std::move(launch));
      }
      else {
        launch();
      }
    }
    catch (std::exception& e) {
      g_outputBuffer = "Unable to bind to control socket on " + local.toStringWithPort() + ": " + e.what();
      errlog("Unable to bind to control socket on %s: %s", local.toStringWithPort(), e.what());
    }
  });

  luaCtx.writeFunction("addConsoleACL", [](const std::string& netmask) {
    setLuaSideEffect();
#if !defined(HAVE_LIBSODIUM) && !defined(HAVE_LIBCRYPTO)
    warnlog("Allowing remote access to the console while neither libsodium not libcrypto support has been enabled is not secure, and will result in cleartext communications");
#endif

    g_consoleACL.modify([netmask](NetmaskGroup& nmg) { nmg.addMask(netmask); });
  });

  luaCtx.writeFunction("setConsoleACL", [](LuaTypeOrArrayOf<std::string> inp) {
    setLuaSideEffect();

#if !defined(HAVE_LIBSODIUM) && !defined(HAVE_LIBCRYPTO)
    warnlog("Allowing remote access to the console while neither libsodium nor libcrypto support has not been enabled is not secure, and will result in cleartext communications");
#endif

    NetmaskGroup nmg;
    if (auto str = boost::get<string>(&inp)) {
      nmg.addMask(*str);
    }
    else
      for (const auto& p : boost::get<LuaArray<std::string>>(inp)) {
        nmg.addMask(p.second);
      }
    g_consoleACL.setState(nmg);
  });

  luaCtx.writeFunction("showConsoleACL", []() {
    setLuaNoSideEffect();

#if !defined(HAVE_LIBSODIUM) && !defined(HAVE_LIBCRYPTO)
    warnlog("Allowing remote access to the console while neither libsodium nor libcrypto support has not been enabled is not secure, and will result in cleartext communications");
#endif

    auto aclEntries = g_consoleACL.getLocal()->toStringVector();

    for (const auto& entry : aclEntries) {
      g_outputBuffer += entry + "\n";
    }
  });

  luaCtx.writeFunction("setConsoleMaximumConcurrentConnections", [](uint64_t max) {
    setLuaSideEffect();
    setConsoleMaximumConcurrentConnections(max);
  });

  luaCtx.writeFunction("clearQueryCounters", []() {
    unsigned int size{0};
    {
      auto records = g_qcount.records.write_lock();
      size = records->size();
      records->clear();
    }

    boost::format fmt("%d records cleared from query counter buffer\n");
    g_outputBuffer = (fmt % size).str();
  });

  luaCtx.writeFunction("getQueryCounters", [](boost::optional<uint64_t> optMax) {
    setLuaNoSideEffect();
    auto records = g_qcount.records.read_lock();
    g_outputBuffer = "query counting is currently: ";
    g_outputBuffer += g_qcount.enabled ? "enabled" : "disabled";
    g_outputBuffer += (boost::format(" (%d records in buffer)\n") % records->size()).str();

    boost::format fmt("%-3d %s: %d request(s)\n");
    uint64_t max = optMax ? *optMax : 10U;
    uint64_t index{1};
    for (auto it = records->begin(); it != records->end() && index <= max; ++it, ++index) {
      g_outputBuffer += (fmt % index % it->first % it->second).str();
    }
  });

  luaCtx.writeFunction("setQueryCount", [](bool enabled) { g_qcount.enabled = enabled; });

  luaCtx.writeFunction("setQueryCountFilter", [](QueryCountFilter func) {
    g_qcount.filter = std::move(func);
  });

  luaCtx.writeFunction("makeKey", []() {
    setLuaNoSideEffect();
    g_outputBuffer = "setKey(" + dnsdist::crypto::authenticated::newKey() + ")\n";
  });

  luaCtx.writeFunction("setKey", [](const std::string& key) {
    if (!g_configurationDone && !g_consoleKey.empty()) { // this makes sure the commandline -k key prevails over dnsdist.conf
      return; // but later setKeys() trump the -k value again
    }
#if !defined(HAVE_LIBSODIUM) && !defined(HAVE_LIBCRYPTO)
    warnlog("Calling setKey() while neither libsodium nor libcrypto support has been enabled is not secure, and will result in cleartext communications");
#endif

    setLuaSideEffect();
    string newkey;
    if (B64Decode(key, newkey) < 0) {
      g_outputBuffer = string("Unable to decode ") + key + " as Base64";
      errlog("%s", g_outputBuffer);
    }
    else
      g_consoleKey = std::move(newkey);
  });

  luaCtx.writeFunction("clearConsoleHistory", []() {
    clearConsoleHistory();
  });

  luaCtx.writeFunction("testCrypto", [](boost::optional<string> optTestMsg) {
    setLuaNoSideEffect();
#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO)
    try {
      string testmsg;

      if (optTestMsg) {
        testmsg = *optTestMsg;
      }
      else {
        testmsg = "testStringForCryptoTests";
      }

      dnsdist::crypto::authenticated::Nonce nonce1;
      dnsdist::crypto::authenticated::Nonce nonce2;
      nonce1.init();
      nonce2 = nonce1;
      string encrypted = dnsdist::crypto::authenticated::encryptSym(testmsg, g_consoleKey, nonce1);
      string decrypted = dnsdist::crypto::authenticated::decryptSym(encrypted, g_consoleKey, nonce2);

      nonce1.increment();
      nonce2.increment();

      encrypted = dnsdist::crypto::authenticated::encryptSym(testmsg, g_consoleKey, nonce1);
      decrypted = dnsdist::crypto::authenticated::decryptSym(encrypted, g_consoleKey, nonce2);

      if (testmsg == decrypted) {
        g_outputBuffer = "Everything is ok!\n";
      }
      else {
        g_outputBuffer = "Crypto failed.. (the decoded value does not match the cleartext one)\n";
      }
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Crypto failed: " + std::string(e.what()) + "\n";
    }
    catch (...) {
      g_outputBuffer = "Crypto failed..\n";
    }
#else
      g_outputBuffer = "Crypto not available.\n";
#endif
  });

  luaCtx.writeFunction("setTCPRecvTimeout", [](int timeout) { g_tcpRecvTimeout = timeout; });

  luaCtx.writeFunction("setTCPSendTimeout", [](int timeout) { g_tcpSendTimeout = timeout; });

  luaCtx.writeFunction("setUDPTimeout", [](int timeout) { DownstreamState::s_udpTimeout = timeout; });

  luaCtx.writeFunction("setMaxUDPOutstanding", [](uint64_t max) {
    if (!checkConfigurationTime("setMaxUDPOutstanding")) {
      return;
    }

    checkParameterBound("setMaxUDPOutstanding", max);
    g_maxOutstanding = max;
  });

  luaCtx.writeFunction("setMaxTCPClientThreads", [](uint64_t max) {
    if (!checkConfigurationTime("setMaxTCPClientThreads")) {
      return;
    }
    g_maxTCPClientThreads = max;
  });

  luaCtx.writeFunction("setMaxTCPQueuedConnections", [](uint64_t max) {
    if (!checkConfigurationTime("setMaxTCPQueuedConnections")) {
      return;
    }
    g_maxTCPQueuedConnections = max;
  });

  luaCtx.writeFunction("setMaxTCPQueriesPerConnection", [](uint64_t max) {
    if (!checkConfigurationTime("setMaxTCPQueriesPerConnection")) {
      return;
    }
    g_maxTCPQueriesPerConn = max;
  });

  luaCtx.writeFunction("setMaxTCPConnectionsPerClient", [](uint64_t max) {
    if (!checkConfigurationTime("setMaxTCPConnectionsPerClient")) {
      return;
    }
    dnsdist::IncomingConcurrentTCPConnectionsManager::setMaxTCPConnectionsPerClient(max);
  });

  luaCtx.writeFunction("setMaxTCPConnectionDuration", [](uint64_t max) {
    if (!checkConfigurationTime("setMaxTCPConnectionDuration")) {
      return;
    }
    g_maxTCPConnectionDuration = max;
  });

  luaCtx.writeFunction("setMaxCachedTCPConnectionsPerDownstream", [](uint64_t max) {
    setTCPDownstreamMaxIdleConnectionsPerBackend(max);
  });

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  luaCtx.writeFunction("setMaxIdleDoHConnectionsPerDownstream", [](uint64_t max) {
    setDoHDownstreamMaxIdleConnectionsPerBackend(max);
  });

  luaCtx.writeFunction("setOutgoingDoHWorkerThreads", [](uint64_t workers) {
    if (!checkConfigurationTime("setOutgoingDoHWorkerThreads")) {
      return;
    }
    g_outgoingDoHWorkerThreads = workers;
  });
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */

  luaCtx.writeFunction("setOutgoingTLSSessionsCacheMaxTicketsPerBackend", [](uint64_t max) {
    if (!checkConfigurationTime("setOutgoingTLSSessionsCacheMaxTicketsPerBackend")) {
      return;
    }
    TLSSessionCache::setMaxTicketsPerBackend(max);
  });

  luaCtx.writeFunction("setOutgoingTLSSessionsCacheCleanupDelay", [](time_t delay) {
    if (!checkConfigurationTime("setOutgoingTLSSessionsCacheCleanupDelay")) {
      return;
    }
    TLSSessionCache::setCleanupDelay(delay);
  });

  luaCtx.writeFunction("setOutgoingTLSSessionsCacheMaxTicketValidity", [](time_t validity) {
    if (!checkConfigurationTime("setOutgoingTLSSessionsCacheMaxTicketValidity")) {
      return;
    }
    TLSSessionCache::setSessionValidity(validity);
  });

  luaCtx.writeFunction("getOutgoingTLSSessionCacheSize", []() {
    setLuaNoSideEffect();
    return g_sessionCache.getSize();
  });

  luaCtx.writeFunction("setCacheCleaningDelay", [](uint64_t delay) {
    checkParameterBound("setCacheCleaningDelay", delay, std::numeric_limits<uint32_t>::max());
    g_cacheCleaningDelay = delay;
  });

  luaCtx.writeFunction("setCacheCleaningPercentage", [](uint64_t percentage) { if (percentage < 100) g_cacheCleaningPercentage = percentage; else g_cacheCleaningPercentage = 100; });

  luaCtx.writeFunction("setECSSourcePrefixV4", [](uint64_t prefix) {
    checkParameterBound("setECSSourcePrefixV4", prefix, std::numeric_limits<uint16_t>::max());
    g_ECSSourcePrefixV4 = prefix;
  });

  luaCtx.writeFunction("setECSSourcePrefixV6", [](uint64_t prefix) {
    checkParameterBound("setECSSourcePrefixV6", prefix, std::numeric_limits<uint16_t>::max());
    g_ECSSourcePrefixV6 = prefix;
  });

  luaCtx.writeFunction("setECSOverride", [](bool override) { g_ECSOverride = override; });

#ifndef DISABLE_DYNBLOCKS
  luaCtx.writeFunction("showDynBlocks", []() {
    setLuaNoSideEffect();
    auto slow = g_dynblockNMG.getCopy();
    struct timespec now;
    gettime(&now);
    boost::format fmt("%-24s %8d %8d %-10s %-20s %-10s %s\n");
    g_outputBuffer = (fmt % "What" % "Seconds" % "Blocks" % "Warning" % "Action" % "eBPF" % "Reason").str();
    for (const auto& e : slow) {
      if (now < e.second.until) {
        uint64_t counter = e.second.blocks;
        if (g_defaultBPFFilter && e.second.bpf) {
          counter += g_defaultBPFFilter->getHits(e.first.getNetwork());
        }
        g_outputBuffer += (fmt % e.first.toString() % (e.second.until.tv_sec - now.tv_sec) % counter % (e.second.warning ? "true" : "false") % DNSAction::typeToString(e.second.action != DNSAction::Action::None ? e.second.action : g_dynBlockAction) % (g_defaultBPFFilter && e.second.bpf ? "*" : "") % e.second.reason).str();
      }
    }
    auto slow2 = g_dynblockSMT.getCopy();
    slow2.visit([&now, &fmt](const SuffixMatchTree<DynBlock>& node) {
      if (now < node.d_value.until) {
        string dom("empty");
        if (!node.d_value.domain.empty())
          dom = node.d_value.domain.toString();
        g_outputBuffer += (fmt % dom % (node.d_value.until.tv_sec - now.tv_sec) % node.d_value.blocks % (node.d_value.warning ? "true" : "false") % DNSAction::typeToString(node.d_value.action != DNSAction::Action::None ? node.d_value.action : g_dynBlockAction) % "" % node.d_value.reason).str();
      }
    });
  });

  luaCtx.writeFunction("getDynamicBlocks", []() {
    setLuaNoSideEffect();
    struct timespec now
    {
    };
    gettime(&now);

    LuaAssociativeTable<DynBlock> entries;
    auto fullCopy = g_dynblockNMG.getCopy();
    for (const auto& blockPair : fullCopy) {
      const auto& requestor = blockPair.first;
      if (!(now < blockPair.second.until)) {
        continue;
      }
      auto entry = blockPair.second;
      if (g_defaultBPFFilter && entry.bpf) {
        entry.blocks += g_defaultBPFFilter->getHits(requestor.getNetwork());
      }
      if (entry.action == DNSAction::Action::None) {
        entry.action = g_dynBlockAction;
      }
      entries.emplace(requestor.toString(), std::move(entry));
    }
    return entries;
  });

  luaCtx.writeFunction("getDynamicBlocksSMT", []() {
    setLuaNoSideEffect();
    struct timespec now
    {
    };
    gettime(&now);

    LuaAssociativeTable<DynBlock> entries;
    auto fullCopy = g_dynblockSMT.getCopy();
    fullCopy.visit([&now, &entries](const SuffixMatchTree<DynBlock>& node) {
      if (!(now < node.d_value.until)) {
        return;
      }
      auto entry = node.d_value;
      string key("empty");
      if (!entry.domain.empty()) {
        key = entry.domain.toString();
      }
      if (entry.action == DNSAction::Action::None) {
        entry.action = g_dynBlockAction;
      }
      entries.emplace(std::move(key), std::move(entry));
    });
    return entries;
  });

  luaCtx.writeFunction("clearDynBlocks", []() {
    setLuaSideEffect();
    nmts_t nmg;
    g_dynblockNMG.setState(nmg);
    SuffixMatchTree<DynBlock> smt;
    g_dynblockSMT.setState(smt);
  });

#ifndef DISABLE_DEPRECATED_DYNBLOCK
  luaCtx.writeFunction("addDynBlocks",
                       [](const std::unordered_map<ComboAddress, unsigned int, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual>& m, const std::string& msg, boost::optional<int> seconds, boost::optional<DNSAction::Action> action) {
                         if (m.empty()) {
                           return;
                         }
                         setLuaSideEffect();
                         auto slow = g_dynblockNMG.getCopy();
                         struct timespec until, now;
                         gettime(&now);
                         until = now;
                         int actualSeconds = seconds ? *seconds : 10;
                         until.tv_sec += actualSeconds;
                         for (const auto& capair : m) {
                           unsigned int count = 0;
                           /* this legacy interface does not support ranges or ports, use DynBlockRulesGroup instead */
                           AddressAndPortRange requestor(capair.first, capair.first.isIPv4() ? 32 : 128, 0);
                           auto got = slow.lookup(requestor);
                           bool expired = false;
                           if (got) {
                             if (until < got->second.until) {
                               // had a longer policy
                               continue;
                             }
                             if (now < got->second.until) {
                               // only inherit count on fresh query we are extending
                               count = got->second.blocks;
                             }
                             else {
                               expired = true;
                             }
                           }
                           DynBlock db{msg, until, DNSName(), (action ? *action : DNSAction::Action::None)};
                           db.blocks = count;
                           if (!got || expired) {
                             warnlog("Inserting dynamic block for %s for %d seconds: %s", capair.first.toString(), actualSeconds, msg);
                           }
                           slow.insert(requestor).second = std::move(db);
                         }
                         g_dynblockNMG.setState(slow);
                       });

  luaCtx.writeFunction("setDynBlocksAction", [](DNSAction::Action action) {
    if (!checkConfigurationTime("setDynBlocksAction")) {
      return;
    }
    if (action == DNSAction::Action::Drop || action == DNSAction::Action::NoOp || action == DNSAction::Action::Nxdomain || action == DNSAction::Action::Refused || action == DNSAction::Action::Truncate || action == DNSAction::Action::NoRecurse) {
      g_dynBlockAction = action;
    }
    else {
      errlog("Dynamic blocks action can only be Drop, NoOp, NXDomain, Refused, Truncate or NoRecurse!");
      g_outputBuffer = "Dynamic blocks action can only be Drop, NoOp, NXDomain, Refused, Truncate or NoRecurse!\n";
    }
  });
#endif /* DISABLE_DEPRECATED_DYNBLOCK */

  luaCtx.writeFunction("addDynBlockSMT",
                       [](const LuaArray<std::string>& names, const std::string& msg, boost::optional<int> seconds, boost::optional<DNSAction::Action> action) {
                         if (names.empty()) {
                           return;
                         }
                         setLuaSideEffect();
                         struct timespec now
                         {
                         };
                         gettime(&now);
                         unsigned int actualSeconds = seconds ? *seconds : 10;

                         bool needUpdate = false;
                         auto slow = g_dynblockSMT.getCopy();
                         for (const auto& capair : names) {
                           DNSName domain(capair.second);
                           domain.makeUsLowerCase();

                           if (dnsdist::DynamicBlocks::addOrRefreshBlockSMT(slow, now, domain, msg, actualSeconds, action ? *action : DNSAction::Action::None, false)) {
                             needUpdate = true;
                           }
                         }

                         if (needUpdate) {
                           g_dynblockSMT.setState(slow);
                         }
                       });

  luaCtx.writeFunction("addDynamicBlock",
                       [](const boost::variant<ComboAddress, std::string>& clientIP, const std::string& msg, const boost::optional<DNSAction::Action> action, const boost::optional<int> seconds, boost::optional<uint8_t> clientIPMask, boost::optional<uint8_t> clientIPPortMask) {
                         setLuaSideEffect();

                         ComboAddress clientIPCA;
                         if (clientIP.type() == typeid(ComboAddress)) {
                           clientIPCA = boost::get<ComboAddress>(clientIP);
                         }
                         else {
                           const auto& clientIPStr = boost::get<std::string>(clientIP);
                           try {
                             clientIPCA = ComboAddress(clientIPStr);
                           }
                           catch (const std::exception& exp) {
                             errlog("addDynamicBlock: Unable to parse '%s': %s", clientIPStr, exp.what());
                             return;
                           }
                           catch (const PDNSException& exp) {
                             errlog("addDynamicBlock: Unable to parse '%s': %s", clientIPStr, exp.reason);
                             return;
                           }
                         }
                         AddressAndPortRange target(clientIPCA, clientIPMask ? *clientIPMask : (clientIPCA.isIPv4() ? 32 : 128), clientIPPortMask ? *clientIPPortMask : 0);
                         unsigned int actualSeconds = seconds ? *seconds : 10;

                         struct timespec now
                         {
                         };
                         gettime(&now);
                         auto slow = g_dynblockNMG.getCopy();
                         if (dnsdist::DynamicBlocks::addOrRefreshBlock(slow, now, target, msg, actualSeconds, action ? *action : DNSAction::Action::None, false, false)) {
                           g_dynblockNMG.setState(slow);
                         }
                       });

  luaCtx.writeFunction("setDynBlocksPurgeInterval", [](uint64_t interval) {
    DynBlockMaintenance::s_expiredDynBlocksPurgeInterval = interval;
  });
#endif /* DISABLE_DYNBLOCKS */

#ifdef HAVE_DNSCRYPT
  luaCtx.writeFunction("addDNSCryptBind", [](const std::string& addr, const std::string& providerName, LuaTypeOrArrayOf<std::string> certFiles, LuaTypeOrArrayOf<std::string> keyFiles, boost::optional<localbind_t> vars) {
    if (!checkConfigurationTime("addDNSCryptBind")) {
      return;
    }
    bool reusePort = false;
    int tcpFastOpenQueueSize = 0;
    int tcpListenQueueSize = 0;
    uint64_t maxInFlightQueriesPerConn = 0;
    uint64_t tcpMaxConcurrentConnections = 0;
    std::string interface;
    std::set<int> cpus;
    std::vector<DNSCryptContext::CertKeyPaths> certKeys;
    bool enableProxyProtocol = true;

    parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections, enableProxyProtocol);
    checkAllParametersConsumed("addDNSCryptBind", vars);

    if (certFiles.type() == typeid(std::string) && keyFiles.type() == typeid(std::string)) {
      auto certFile = boost::get<std::string>(certFiles);
      auto keyFile = boost::get<std::string>(keyFiles);
      certKeys.push_back({std::move(certFile), std::move(keyFile)});
    }
    else if (certFiles.type() == typeid(LuaArray<std::string>) && keyFiles.type() == typeid(LuaArray<std::string>)) {
      auto certFilesVect = boost::get<LuaArray<std::string>>(certFiles);
      auto keyFilesVect = boost::get<LuaArray<std::string>>(keyFiles);
      if (certFilesVect.size() == keyFilesVect.size()) {
        for (size_t idx = 0; idx < certFilesVect.size(); idx++) {
          certKeys.push_back({certFilesVect.at(idx).second, keyFilesVect.at(idx).second});
        }
      }
      else {
        errlog("Error, mismatching number of certificates and keys in call to addDNSCryptBind!");
        g_outputBuffer = "Error, mismatching number of certificates and keys in call to addDNSCryptBind()!";
        return;
      }
    }
    else {
      errlog("Error, mismatching number of certificates and keys in call to addDNSCryptBind()!");
      g_outputBuffer = "Error, mismatching number of certificates and keys in call to addDNSCryptBind()!";
      return;
    }

    try {
      auto ctx = std::make_shared<DNSCryptContext>(providerName, certKeys);

      /* UDP */
      auto clientState = std::make_unique<ClientState>(ComboAddress(addr, 443), false, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
      clientState->dnscryptCtx = ctx;
      g_dnsCryptLocals.push_back(ctx);
      g_frontends.push_back(std::move(clientState));

      /* TCP */
      clientState = std::make_unique<ClientState>(ComboAddress(addr, 443), true, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
      clientState->dnscryptCtx = std::move(ctx);
      if (tcpListenQueueSize > 0) {
        clientState->tcpListenQueueSize = tcpListenQueueSize;
      }
      if (maxInFlightQueriesPerConn > 0) {
        clientState->d_maxInFlightQueriesPerConn = maxInFlightQueriesPerConn;
      }
      if (tcpMaxConcurrentConnections > 0) {
        clientState->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConnections;
      }

      g_frontends.push_back(std::move(clientState));
    }
    catch (const std::exception& e) {
      errlog("Error during addDNSCryptBind() processing: %s", e.what());
      g_outputBuffer = "Error during addDNSCryptBind() processing: " + string(e.what()) + "\n";
    }
  });

  luaCtx.writeFunction("showDNSCryptBinds", []() {
    setLuaNoSideEffect();
    ostringstream ret;
    boost::format fmt("%1$-3d %2% %|25t|%3$-20.20s");
    ret << (fmt % "#" % "Address" % "Provider Name") << endl;
    size_t idx = 0;

    std::unordered_set<std::shared_ptr<DNSCryptContext>> contexts;
    for (const auto& frontend : g_frontends) {
      const std::shared_ptr<DNSCryptContext> ctx = frontend->dnscryptCtx;
      if (!ctx || contexts.count(ctx) != 0) {
        continue;
      }
      contexts.insert(ctx);
      ret << (fmt % idx % frontend->local.toStringWithPort() % ctx->getProviderName()) << endl;
      idx++;
    }

    g_outputBuffer = ret.str();
  });

  luaCtx.writeFunction("getDNSCryptBind", [](uint64_t idx) {
    setLuaNoSideEffect();
    std::shared_ptr<DNSCryptContext> ret = nullptr;
    if (idx < g_dnsCryptLocals.size()) {
      ret = g_dnsCryptLocals.at(idx);
    }
    return ret;
  });

  luaCtx.writeFunction("getDNSCryptBindCount", []() {
    setLuaNoSideEffect();
    return g_dnsCryptLocals.size();
  });
#endif /* HAVE_DNSCRYPT */

  luaCtx.writeFunction("showPools", []() {
    setLuaNoSideEffect();
    try {
      ostringstream ret;
      boost::format fmt("%1$-20.20s %|25t|%2$20s %|25t|%3$20s %|50t|%4%");
      //             1        2         3                4
      ret << (fmt % "Name" % "Cache" % "ServerPolicy" % "Servers") << endl;

      const auto localPools = g_pools.getCopy();
      for (const auto& entry : localPools) {
        const string& name = entry.first;
        const std::shared_ptr<ServerPool> pool = entry.second;
        string cache = pool->packetCache != nullptr ? pool->packetCache->toString() : "";
        string policy = g_policy.getLocal()->getName();
        if (pool->policy != nullptr) {
          policy = pool->policy->getName();
        }
        string servers;

        const auto poolServers = pool->getServers();
        for (const auto& server : *poolServers) {
          if (!servers.empty()) {
            servers += ", ";
          }
          if (!server.second->getName().empty()) {
            servers += server.second->getName();
            servers += " ";
          }
          servers += server.second->d_config.remote.toStringWithPort();
        }

        ret << (fmt % name % cache % policy % servers) << endl;
      }
      g_outputBuffer = ret.str();
    }
    catch (std::exception& e) {
      g_outputBuffer = e.what();
      throw;
    }
  });

  luaCtx.writeFunction("getPoolNames", []() {
    setLuaNoSideEffect();
    LuaArray<std::string> ret;
    int count = 1;
    const auto localPools = g_pools.getCopy();
    for (const auto& entry : localPools) {
      const string& name = entry.first;
      ret.emplace_back(count++, name);
    }
    return ret;
  });

  luaCtx.writeFunction("getPool", [client](const string& poolName) {
    if (client) {
      return std::make_shared<ServerPool>();
    }
    auto localPools = g_pools.getCopy();
    std::shared_ptr<ServerPool> pool = createPoolIfNotExists(localPools, poolName);
    g_pools.setState(localPools);
    return pool;
  });

  luaCtx.writeFunction("setVerbose", [](bool verbose) { g_verbose = verbose; });
  luaCtx.writeFunction("getVerbose", []() { return g_verbose; });
  luaCtx.writeFunction("setVerboseHealthChecks", [](bool verbose) { g_verboseHealthChecks = verbose; });
  luaCtx.writeFunction("setVerboseLogDestination", [](const std::string& dest) {
    if (!checkConfigurationTime("setVerboseLogDestination")) {
      return;
    }
    try {
      auto stream = std::ofstream(dest.c_str());
      dnsdist::logging::LoggingConfiguration::setVerboseStream(std::move(stream));
    }
    catch (const std::exception& e) {
      errlog("Error while opening the verbose logging destination file %s: %s", dest, e.what());
    }
  });
  luaCtx.writeFunction("setStructuredLogging", [](bool enable, boost::optional<LuaAssociativeTable<std::string>> options) {
    std::string levelPrefix;
    std::string timeFormat;
    if (options) {
      getOptionalValue<std::string>(options, "levelPrefix", levelPrefix);
      if (getOptionalValue<std::string>(options, "timeFormat", timeFormat) == 1) {
        if (timeFormat == "numeric") {
          dnsdist::logging::LoggingConfiguration::setStructuredTimeFormat(dnsdist::logging::LoggingConfiguration::TimeFormat::Numeric);
        }
        else if (timeFormat == "ISO8601") {
          dnsdist::logging::LoggingConfiguration::setStructuredTimeFormat(dnsdist::logging::LoggingConfiguration::TimeFormat::ISO8601);
        }
        else {
          warnlog("Unknown value '%s' to setStructuredLogging's 'timeFormat' parameter", timeFormat);
        }
      }
      checkAllParametersConsumed("setStructuredLogging", options);
    }

    dnsdist::logging::LoggingConfiguration::setStructuredLogging(enable, levelPrefix);
  });

  luaCtx.writeFunction("setStaleCacheEntriesTTL", [](uint64_t ttl) {
    checkParameterBound("setStaleCacheEntriesTTL", ttl, std::numeric_limits<uint32_t>::max());
    g_staleCacheEntriesTTL = ttl;
  });

  luaCtx.writeFunction("showBinds", []() {
    setLuaNoSideEffect();
    try {
      ostringstream ret;
      boost::format fmt("%1$-3d %2$-20.20s %|35t|%3$-20.20s %|57t|%4%");
      //             1    2           3            4
      ret << (fmt % "#" % "Address" % "Protocol" % "Queries") << endl;

      size_t counter = 0;
      for (const auto& front : g_frontends) {
        ret << (fmt % counter % front->local.toStringWithPort() % front->getType() % front->queries) << endl;
        counter++;
      }
      g_outputBuffer = ret.str();
    }
    catch (std::exception& e) {
      g_outputBuffer = e.what();
      throw;
    }
  });

  luaCtx.writeFunction("getBind", [](uint64_t num) {
    setLuaNoSideEffect();
    ClientState* ret = nullptr;
    if (num < g_frontends.size()) {
      ret = g_frontends[num].get();
    }
    return ret;
  });

  luaCtx.writeFunction("getBindCount", []() {
    setLuaNoSideEffect();
    return g_frontends.size();
  });

  luaCtx.writeFunction("help", [](boost::optional<std::string> command) {
    setLuaNoSideEffect();
    g_outputBuffer = "";
#ifndef DISABLE_COMPLETION
    for (const auto& keyword : g_consoleKeywords) {
      if (!command) {
        g_outputBuffer += keyword.toString() + "\n";
      }
      else if (keyword.name == command) {
        g_outputBuffer = keyword.toString() + "\n";
        return;
      }
    }
#endif /* DISABLE_COMPLETION */
    if (command) {
      g_outputBuffer = "Nothing found for " + *command + "\n";
    }
  });

  luaCtx.writeFunction("showVersion", []() {
    setLuaNoSideEffect();
    g_outputBuffer = "dnsdist " + std::string(VERSION) + "\n";
  });

#ifdef HAVE_EBPF
  luaCtx.writeFunction("setDefaultBPFFilter", [](std::shared_ptr<BPFFilter> bpf) {
    if (!checkConfigurationTime("setDefaultBPFFilter")) {
      return;
    }
    g_defaultBPFFilter = std::move(bpf);
  });

  luaCtx.writeFunction("registerDynBPFFilter", [](std::shared_ptr<DynBPFFilter> dbpf) {
    if (dbpf) {
      g_dynBPFFilters.push_back(std::move(dbpf));
    }
  });

  luaCtx.writeFunction("unregisterDynBPFFilter", [](std::shared_ptr<DynBPFFilter> dbpf) {
    if (dbpf) {
      for (auto it = g_dynBPFFilters.begin(); it != g_dynBPFFilters.end(); it++) {
        if (*it == dbpf) {
          g_dynBPFFilters.erase(it);
          break;
        }
      }
    }
  });

#ifndef DISABLE_DYNBLOCKS
#ifndef DISABLE_DEPRECATED_DYNBLOCK
  luaCtx.writeFunction("addBPFFilterDynBlocks", [](const std::unordered_map<ComboAddress, unsigned int, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual>& m, std::shared_ptr<DynBPFFilter> dynbpf, boost::optional<int> seconds, boost::optional<std::string> msg) {
    if (!dynbpf) {
      return;
    }
    setLuaSideEffect();
    struct timespec until, now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    until = now;
    int actualSeconds = seconds ? *seconds : 10;
    until.tv_sec += actualSeconds;
    for (const auto& capair : m) {
      if (dynbpf->block(capair.first, until)) {
        warnlog("Inserting eBPF dynamic block for %s for %d seconds: %s", capair.first.toString(), actualSeconds, msg ? *msg : "");
      }
    }
  });
#endif /* DISABLE_DEPRECATED_DYNBLOCK */
#endif /* DISABLE_DYNBLOCKS */

#endif /* HAVE_EBPF */

  luaCtx.writeFunction<LuaAssociativeTable<uint64_t>()>("getStatisticsCounters", []() {
    setLuaNoSideEffect();
    std::unordered_map<string, uint64_t> res;
    {
      auto entries = dnsdist::metrics::g_stats.entries.read_lock();
      res.reserve(entries->size());
      for (const auto& entry : *entries) {
        if (const auto& val = std::get_if<pdns::stat_t*>(&entry.d_value)) {
          res[entry.d_name] = (*val)->load();
        }
      }
    }
    return res;
  });

  luaCtx.writeFunction("includeDirectory", [&luaCtx](const std::string& dirname) {
    if (!checkConfigurationTime("includeDirectory")) {
      return;
    }
    if (g_included) {
      errlog("includeDirectory() cannot be used recursively!");
      g_outputBuffer = "includeDirectory() cannot be used recursively!\n";
      return;
    }

    struct stat st;
    if (stat(dirname.c_str(), &st)) {
      errlog("The included directory %s does not exist!", dirname.c_str());
      g_outputBuffer = "The included directory " + dirname + " does not exist!";
      return;
    }

    if (!S_ISDIR(st.st_mode)) {
      errlog("The included directory %s is not a directory!", dirname.c_str());
      g_outputBuffer = "The included directory " + dirname + " is not a directory!";
      return;
    }

    std::vector<std::string> files;
    auto directoryError = pdns::visit_directory(dirname, [&dirname, &files]([[maybe_unused]] ino_t inodeNumber, const std::string_view& name) {
      if (boost::starts_with(name, ".")) {
        return true;
      }
      if (boost::ends_with(name, ".conf")) {
        std::ostringstream namebuf;
        namebuf << dirname << "/" << name;
        struct stat fileStat
        {
        };
        if (stat(namebuf.str().c_str(), &fileStat) == 0 && S_ISREG(fileStat.st_mode)) {
          files.push_back(namebuf.str());
        }
      }
      return true;
    });

    if (directoryError) {
      errlog("Error opening included directory: %s!", *directoryError);
      g_outputBuffer = "Error opening included directory: " + *directoryError + "!";
      return;
    }

    std::sort(files.begin(), files.end());

    g_included = true;

    for (const auto& file : files) {
      std::ifstream ifs(file);
      if (!ifs) {
        warnlog("Unable to read configuration from '%s'", file);
      }
      else {
        vinfolog("Read configuration from '%s'", file);
      }

      try {
        luaCtx.executeCode(ifs);
      }
      catch (...) {
        g_included = false;
        throw;
      }

      luaCtx.executeCode(ifs);
    }

    g_included = false;
  });

  luaCtx.writeFunction("setAPIWritable", [](bool writable, boost::optional<std::string> apiConfigDir) {
    setLuaSideEffect();
    g_apiReadWrite = writable;
    if (apiConfigDir) {
      if (!(*apiConfigDir).empty()) {
        g_apiConfigDirectory = *apiConfigDir;
      }
      else {
        errlog("The API configuration directory value cannot be empty!");
        g_outputBuffer = "The API configuration directory value cannot be empty!";
      }
    }
  });

  luaCtx.writeFunction("setServFailWhenNoServer", [](bool servfail) {
    setLuaSideEffect();
    g_servFailOnNoPolicy = servfail;
  });

  luaCtx.writeFunction("setRoundRobinFailOnNoServer", [](bool fail) {
    setLuaSideEffect();
    g_roundrobinFailOnNoServer = fail;
  });

  luaCtx.writeFunction("setConsistentHashingBalancingFactor", [](double factor) {
    setLuaSideEffect();
    if (factor >= 1.0 || factor == 0) {
      g_consistentHashBalancingFactor = factor;
    }
    else {
      errlog("Invalid value passed to setConsistentHashingBalancingFactor()!");
      g_outputBuffer = "Invalid value passed to setConsistentHashingBalancingFactor()!\n";
      return;
    }
  });

  luaCtx.writeFunction("setWeightedBalancingFactor", [](double factor) {
    setLuaSideEffect();
    if (factor >= 1.0 || factor == 0) {
      g_weightedBalancingFactor = factor;
    }
    else {
      errlog("Invalid value passed to setWeightedBalancingFactor()!");
      g_outputBuffer = "Invalid value passed to setWeightedBalancingFactor()!\n";
      return;
    }
  });

  luaCtx.writeFunction("setRingBuffersSize", [client](uint64_t capacity, boost::optional<uint64_t> numberOfShards) {
    setLuaSideEffect();
    if (!checkConfigurationTime("setRingBuffersSize")) {
      return;
    }
    if (!client) {
      g_rings.setCapacity(capacity, numberOfShards ? *numberOfShards : 10);
    }
    else {
      g_rings.setCapacity(0, 1);
    }
  });

  luaCtx.writeFunction("setRingBuffersLockRetries", [](uint64_t retries) {
    setLuaSideEffect();
    g_rings.setNumberOfLockRetries(retries);
  });

  luaCtx.writeFunction("setRingBuffersOptions", [](const LuaAssociativeTable<boost::variant<bool, uint64_t>>& options) {
    setLuaSideEffect();
    if (!checkConfigurationTime("setRingBuffersOptions")) {
      return;
    }
    if (options.count("lockRetries") > 0) {
      auto retries = boost::get<uint64_t>(options.at("lockRetries"));
      g_rings.setNumberOfLockRetries(retries);
    }
    if (options.count("recordQueries") > 0) {
      auto record = boost::get<bool>(options.at("recordQueries"));
      g_rings.setRecordQueries(record);
    }
    if (options.count("recordResponses") > 0) {
      auto record = boost::get<bool>(options.at("recordResponses"));
      g_rings.setRecordResponses(record);
    }
  });

  luaCtx.writeFunction("setWHashedPertubation", [](uint64_t perturb) {
    setLuaSideEffect();
    checkParameterBound("setWHashedPertubation", perturb, std::numeric_limits<uint32_t>::max());
    g_hashperturb = perturb;
  });

  luaCtx.writeFunction("setTCPInternalPipeBufferSize", [](uint64_t size) { g_tcpInternalPipeBufferSize = size; });
  luaCtx.writeFunction("setTCPFastOpenKey", [](const std::string& keyString) {
    setLuaSideEffect();
    uint32_t key[4] = {};
    auto ret = sscanf(keyString.c_str(), "%" SCNx32 "-%" SCNx32 "-%" SCNx32 "-%" SCNx32, &key[0], &key[1], &key[2], &key[3]);
    if (ret != 4) {
      g_outputBuffer = "Invalid value passed to setTCPFastOpenKey()!\n";
      return;
    }
    extern vector<uint32_t> g_TCPFastOpenKey;
    for (const auto i : key) {
      g_TCPFastOpenKey.push_back(i);
    }
  });

#ifdef HAVE_NET_SNMP
  luaCtx.writeFunction("snmpAgent", [client, configCheck](bool enableTraps, boost::optional<std::string> daemonSocket) {
    if (client || configCheck) {
      return;
    }
    if (!checkConfigurationTime("snmpAgent")) {
      return;
    }
    if (g_snmpEnabled) {
      errlog("snmpAgent() cannot be used twice!");
      g_outputBuffer = "snmpAgent() cannot be used twice!\n";
      return;
    }

    g_snmpEnabled = true;
    g_snmpTrapsEnabled = enableTraps;
    g_snmpAgent = new DNSDistSNMPAgent("dnsdist", daemonSocket ? *daemonSocket : std::string());
  });

  luaCtx.writeFunction("sendCustomTrap", [](const std::string& str) {
    if (g_snmpAgent && g_snmpTrapsEnabled) {
      g_snmpAgent->sendCustomTrap(str);
    }
  });
#endif /* HAVE_NET_SNMP */

#ifndef DISABLE_POLICIES_BINDINGS
  luaCtx.writeFunction("setServerPolicy", [](const std::shared_ptr<ServerPolicy>& policy) {
    setLuaSideEffect();
    g_policy.setState(*policy);
  });

  luaCtx.writeFunction("setServerPolicyLua", [](const string& name, ServerPolicy::policyfunc_t policy) {
    setLuaSideEffect();
    g_policy.setState(ServerPolicy{name, policy, true});
  });

  luaCtx.writeFunction("setServerPolicyLuaFFI", [](const string& name, ServerPolicy::ffipolicyfunc_t policy) {
    setLuaSideEffect();
    auto pol = ServerPolicy(name, policy);
    g_policy.setState(std::move(pol));
  });

  luaCtx.writeFunction("setServerPolicyLuaFFIPerThread", [](const string& name, const std::string& policyCode) {
    setLuaSideEffect();
    auto pol = ServerPolicy(name, policyCode);
    g_policy.setState(std::move(pol));
  });

  luaCtx.writeFunction("showServerPolicy", []() {
    setLuaSideEffect();
    g_outputBuffer = g_policy.getLocal()->getName() + "\n";
  });

  luaCtx.writeFunction("setPoolServerPolicy", [](const std::shared_ptr<ServerPolicy>& policy, const string& pool) {
    setLuaSideEffect();
    auto localPools = g_pools.getCopy();
    setPoolPolicy(localPools, pool, policy);
    g_pools.setState(localPools);
  });

  luaCtx.writeFunction("setPoolServerPolicyLua", [](const string& name, ServerPolicy::policyfunc_t policy, const string& pool) {
    setLuaSideEffect();
    auto localPools = g_pools.getCopy();
    setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(ServerPolicy{name, std::move(policy), true}));
    g_pools.setState(localPools);
  });

  luaCtx.writeFunction("setPoolServerPolicyLuaFFI", [](const string& name, ServerPolicy::ffipolicyfunc_t policy, const string& pool) {
    setLuaSideEffect();
    auto localPools = g_pools.getCopy();
    setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(ServerPolicy{name, std::move(policy)}));
    g_pools.setState(localPools);
  });

  luaCtx.writeFunction("setPoolServerPolicyLuaFFIPerThread", [](const string& name, const std::string& policyCode, const std::string& pool) {
    setLuaSideEffect();
    auto localPools = g_pools.getCopy();
    setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(ServerPolicy{name, policyCode}));
    g_pools.setState(localPools);
  });

  luaCtx.writeFunction("showPoolServerPolicy", [](const std::string& pool) {
    setLuaSideEffect();
    auto localPools = g_pools.getCopy();
    auto poolObj = getPool(localPools, pool);
    if (poolObj->policy == nullptr) {
      g_outputBuffer = g_policy.getLocal()->getName() + "\n";
    }
    else {
      g_outputBuffer = poolObj->policy->getName() + "\n";
    }
  });
#endif /* DISABLE_POLICIES_BINDINGS */

  luaCtx.writeFunction("setTCPDownstreamCleanupInterval", [](uint64_t interval) {
    setLuaSideEffect();
    checkParameterBound("setTCPDownstreamCleanupInterval", interval);
    setTCPDownstreamCleanupInterval(interval);
  });

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  luaCtx.writeFunction("setDoHDownstreamCleanupInterval", [](uint64_t interval) {
    setLuaSideEffect();
    checkParameterBound("setDoHDownstreamCleanupInterval", interval);
    setDoHDownstreamCleanupInterval(interval);
  });
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */

  luaCtx.writeFunction("setTCPDownstreamMaxIdleTime", [](uint64_t max) {
    setLuaSideEffect();
    checkParameterBound("setTCPDownstreamMaxIdleTime", max);
    setTCPDownstreamMaxIdleTime(max);
  });

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  luaCtx.writeFunction("setDoHDownstreamMaxIdleTime", [](uint64_t max) {
    setLuaSideEffect();
    checkParameterBound("setDoHDownstreamMaxIdleTime", max);
    setDoHDownstreamMaxIdleTime(max);
  });
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */

  luaCtx.writeFunction("setConsoleConnectionsLogging", [](bool enabled) {
    g_logConsoleConnections = enabled;
  });

  luaCtx.writeFunction("setConsoleOutputMaxMsgSize", [](uint64_t size) {
    checkParameterBound("setConsoleOutputMaxMsgSize", size, std::numeric_limits<uint32_t>::max());
    g_consoleOutputMsgMaxSize = size;
  });

  luaCtx.writeFunction("setProxyProtocolACL", [](LuaTypeOrArrayOf<std::string> inp) {
    if (!checkConfigurationTime("setProxyProtocolACL")) {
      return;
    }
    setLuaSideEffect();
    NetmaskGroup nmg;
    if (auto str = boost::get<string>(&inp)) {
      nmg.addMask(*str);
    }
    else {
      for (const auto& p : boost::get<LuaArray<std::string>>(inp)) {
        nmg.addMask(p.second);
      }
    }
    g_proxyProtocolACL = std::move(nmg);
  });

  luaCtx.writeFunction("setProxyProtocolApplyACLToProxiedClients", [](bool apply) {
    if (!checkConfigurationTime("setProxyProtocolApplyACLToProxiedClients")) {
      return;
    }
    setLuaSideEffect();
    g_applyACLToProxiedClients = apply;
  });

  luaCtx.writeFunction("setProxyProtocolMaximumPayloadSize", [](uint64_t size) {
    if (!checkConfigurationTime("setProxyProtocolMaximumPayloadSize")) {
      return;
    }
    setLuaSideEffect();
    g_proxyProtocolMaximumSize = std::max(static_cast<uint64_t>(16), size);
  });

#ifndef DISABLE_RECVMMSG
  luaCtx.writeFunction("setUDPMultipleMessagesVectorSize", [](uint64_t vSize) {
    if (!checkConfigurationTime("setUDPMultipleMessagesVectorSize")) {
      return;
    }
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
    setLuaSideEffect();
    g_udpVectorSize = vSize;
#else
      errlog("recvmmsg() support is not available!");
      g_outputBuffer = "recvmmsg support is not available!\n";
#endif
  });
#endif /* DISABLE_RECVMMSG */

  luaCtx.writeFunction("setAddEDNSToSelfGeneratedResponses", [](bool add) {
    g_addEDNSToSelfGeneratedResponses = add;
  });

  luaCtx.writeFunction("setPayloadSizeOnSelfGeneratedAnswers", [](uint64_t payloadSize) {
    if (payloadSize < 512) {
      warnlog("setPayloadSizeOnSelfGeneratedAnswers() is set too low, using 512 instead!");
      g_outputBuffer = "setPayloadSizeOnSelfGeneratedAnswers() is set too low, using 512 instead!";
      payloadSize = 512;
    }
    if (payloadSize > s_udpIncomingBufferSize) {
      warnlog("setPayloadSizeOnSelfGeneratedAnswers() is set too high, capping to %d instead!", s_udpIncomingBufferSize);
      g_outputBuffer = "setPayloadSizeOnSelfGeneratedAnswers() is set too high, capping to " + std::to_string(s_udpIncomingBufferSize) + " instead";
      payloadSize = s_udpIncomingBufferSize;
    }
    g_PayloadSizeSelfGenAnswers = payloadSize;
  });

#ifndef DISABLE_SECPOLL
  luaCtx.writeFunction("showSecurityStatus", []() {
    setLuaNoSideEffect();
    g_outputBuffer = std::to_string(dnsdist::metrics::g_stats.securityStatus) + "\n";
  });

  luaCtx.writeFunction("setSecurityPollSuffix", [](const std::string& suffix) {
    if (!checkConfigurationTime("setSecurityPollSuffix")) {
      return;
    }
    g_secPollSuffix = suffix;
  });

  luaCtx.writeFunction("setSecurityPollInterval", [](time_t newInterval) {
    if (newInterval <= 0) {
      warnlog("setSecurityPollInterval() should be > 0, skipping");
      g_outputBuffer = "setSecurityPollInterval() should be > 0, skipping";
    }

    g_secPollInterval = newInterval;
  });
#endif /* DISABLE_SECPOLL */

  luaCtx.writeFunction("setSyslogFacility", [](boost::variant<int, std::string> facility) {
    if (!checkConfigurationTime("setSyslogFacility")) {
      return;
    }
    setLuaSideEffect();
    if (facility.type() == typeid(std::string)) {
      static std::map<std::string, int> const facilities = {
        {"local0", LOG_LOCAL0},
        {"log_local0", LOG_LOCAL0},
        {"local1", LOG_LOCAL1},
        {"log_local1", LOG_LOCAL1},
        {"local2", LOG_LOCAL2},
        {"log_local2", LOG_LOCAL2},
        {"local3", LOG_LOCAL3},
        {"log_local3", LOG_LOCAL3},
        {"local4", LOG_LOCAL4},
        {"log_local4", LOG_LOCAL4},
        {"local5", LOG_LOCAL5},
        {"log_local5", LOG_LOCAL5},
        {"local6", LOG_LOCAL6},
        {"log_local6", LOG_LOCAL6},
        {"local7", LOG_LOCAL7},
        {"log_local7", LOG_LOCAL7},
        /* most of these likely make very little sense
           for dnsdist, but why not? */
        {"kern", LOG_KERN},
        {"log_kern", LOG_KERN},
        {"user", LOG_USER},
        {"log_user", LOG_USER},
        {"mail", LOG_MAIL},
        {"log_mail", LOG_MAIL},
        {"daemon", LOG_DAEMON},
        {"log_daemon", LOG_DAEMON},
        {"auth", LOG_AUTH},
        {"log_auth", LOG_AUTH},
        {"syslog", LOG_SYSLOG},
        {"log_syslog", LOG_SYSLOG},
        {"lpr", LOG_LPR},
        {"log_lpr", LOG_LPR},
        {"news", LOG_NEWS},
        {"log_news", LOG_NEWS},
        {"uucp", LOG_UUCP},
        {"log_uucp", LOG_UUCP},
        {"cron", LOG_CRON},
        {"log_cron", LOG_CRON},
        {"authpriv", LOG_AUTHPRIV},
        {"log_authpriv", LOG_AUTHPRIV},
        {"ftp", LOG_FTP},
        {"log_ftp", LOG_FTP}};
      auto facilityStr = boost::get<std::string>(facility);
      toLowerInPlace(facilityStr);
      auto it = facilities.find(facilityStr);
      if (it == facilities.end()) {
        g_outputBuffer = "Unknown facility '" + facilityStr + "' passed to setSyslogFacility()!\n";
        return;
      }
      setSyslogFacility(it->second);
    }
    else {
      setSyslogFacility(boost::get<int>(facility));
    }
  });

  typedef std::unordered_map<std::string, std::string> tlscertificateopts_t;
  luaCtx.writeFunction("newTLSCertificate", [client](const std::string& cert, boost::optional<tlscertificateopts_t> opts) {
    std::shared_ptr<TLSCertKeyPair> result = nullptr;
    if (client) {
      return result;
    }
#if defined(HAVE_DNS_OVER_TLS) || defined(HAVE_DNS_OVER_HTTPS)
    std::optional<std::string> key, password;
    if (opts) {
      if (opts->count("key")) {
        key = boost::get<const string>((*opts)["key"]);
      }
      if (opts->count("password")) {
        password = boost::get<const string>((*opts)["password"]);
      }
    }
    result = std::make_shared<TLSCertKeyPair>(cert, std::move(key), std::move(password));
#endif
    return result;
  });

  luaCtx.writeFunction("addDOHLocal", [client](const std::string& addr, boost::optional<boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>>> certFiles, boost::optional<boost::variant<std::string, LuaArray<std::string>>> keyFiles, boost::optional<LuaTypeOrArrayOf<std::string>> urls, boost::optional<localbind_t> vars) {
    if (client) {
      return;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    if (!checkConfigurationTime("addDOHLocal")) {
      return;
    }
    setLuaSideEffect();

    auto frontend = std::make_shared<DOHFrontend>();
    if (getOptionalValue<std::string>(vars, "library", frontend->d_library) == 0) {
#ifdef HAVE_NGHTTP2
      frontend->d_library = "nghttp2";
#else /* HAVE_NGHTTP2 */
        frontend->d_library = "h2o";
#endif /* HAVE_NGHTTP2 */
    }
    if (frontend->d_library == "h2o") {
#ifdef HAVE_LIBH2OEVLOOP
      frontend = std::make_shared<H2ODOHFrontend>();
      // we _really_ need to set it again, as we just replaced the generic frontend by a new one
      frontend->d_library = "h2o";
#else /* HAVE_LIBH2OEVLOOP */
        errlog("DOH bind %s is configured to use libh2o but the library is not available", addr);
        return;
#endif /* HAVE_LIBH2OEVLOOP */
    }
    else if (frontend->d_library == "nghttp2") {
#ifndef HAVE_NGHTTP2
      errlog("DOH bind %s is configured to use nghttp2 but the library is not available", addr);
      return;
#endif /* HAVE_NGHTTP2 */
    }
    else {
      errlog("DOH bind %s is configured to use an unknown library ('%s')", addr, frontend->d_library);
      return;
    }

    bool useTLS = true;
    if (certFiles && !certFiles->empty()) {
      if (!loadTLSCertificateAndKeys("addDOHLocal", frontend->d_tlsContext.d_tlsConfig.d_certKeyPairs, *certFiles, *keyFiles)) {
        return;
      }

      frontend->d_tlsContext.d_addr = ComboAddress(addr, 443);
    }
    else {
      frontend->d_tlsContext.d_addr = ComboAddress(addr, 80);
      infolog("No certificate provided for DoH endpoint %s, running in DNS over HTTP mode instead of DNS over HTTPS", frontend->d_tlsContext.d_addr.toStringWithPort());
      useTLS = false;
    }

    if (urls) {
      if (urls->type() == typeid(std::string)) {
        frontend->d_urls.insert(boost::get<std::string>(*urls));
      }
      else if (urls->type() == typeid(LuaArray<std::string>)) {
        auto urlsVect = boost::get<LuaArray<std::string>>(*urls);
        for (const auto& p : urlsVect) {
          frontend->d_urls.insert(p.second);
        }
      }
    }
    else {
      frontend->d_urls.insert("/dns-query");
    }

    bool reusePort = false;
    int tcpFastOpenQueueSize = 0;
    int tcpListenQueueSize = 0;
    uint64_t maxInFlightQueriesPerConn = 0;
    uint64_t tcpMaxConcurrentConnections = 0;
    std::string interface;
    std::set<int> cpus;
    std::vector<std::pair<ComboAddress, int>> additionalAddresses;
    bool enableProxyProtocol = true;

    if (vars) {
      parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections, enableProxyProtocol);
      getOptionalValue<int>(vars, "idleTimeout", frontend->d_idleTimeout);
      getOptionalValue<std::string>(vars, "serverTokens", frontend->d_serverTokens);
      getOptionalValue<std::string>(vars, "provider", frontend->d_tlsContext.d_provider);
      boost::algorithm::to_lower(frontend->d_tlsContext.d_provider);
      getOptionalValue<bool>(vars, "proxyProtocolOutsideTLS", frontend->d_tlsContext.d_proxyProtocolOutsideTLS);

      LuaAssociativeTable<std::string> customResponseHeaders;
      if (getOptionalValue<decltype(customResponseHeaders)>(vars, "customResponseHeaders", customResponseHeaders) > 0) {
        for (auto const& headerMap : customResponseHeaders) {
          auto headerResponse = std::pair(boost::to_lower_copy(headerMap.first), headerMap.second);
          frontend->d_customResponseHeaders.insert(headerResponse);
        }
      }

      getOptionalValue<bool>(vars, "sendCacheControlHeaders", frontend->d_sendCacheControlHeaders);
      getOptionalValue<bool>(vars, "keepIncomingHeaders", frontend->d_keepIncomingHeaders);
      getOptionalValue<bool>(vars, "trustForwardedForHeader", frontend->d_trustForwardedForHeader);
      getOptionalValue<bool>(vars, "earlyACLDrop", frontend->d_earlyACLDrop);
      getOptionalValue<int>(vars, "internalPipeBufferSize", frontend->d_internalPipeBufferSize);
      getOptionalValue<bool>(vars, "exactPathMatching", frontend->d_exactPathMatching);

      LuaArray<std::string> addresses;
      if (getOptionalValue<decltype(addresses)>(vars, "additionalAddresses", addresses) > 0) {
        for (const auto& [_, add] : addresses) {
          try {
            ComboAddress address(add);
            additionalAddresses.emplace_back(address, -1);
          }
          catch (const PDNSException& e) {
            errlog("Unable to parse additional address %s for DOH bind: %s", add, e.reason);
            return;
          }
        }
      }

      parseTLSConfig(frontend->d_tlsContext.d_tlsConfig, "addDOHLocal", vars);

      bool ignoreTLSConfigurationErrors = false;
      if (getOptionalValue<bool>(vars, "ignoreTLSConfigurationErrors", ignoreTLSConfigurationErrors) > 0 && ignoreTLSConfigurationErrors) {
        // we are asked to try to load the certificates so we can return a potential error
        // and properly ignore the frontend before actually launching it
        try {
          std::map<int, std::string> ocspResponses = {};
          auto ctx = libssl_init_server_context(frontend->d_tlsContext.d_tlsConfig, ocspResponses);
        }
        catch (const std::runtime_error& e) {
          errlog("Ignoring DoH frontend: '%s'", e.what());
          return;
        }
      }

      checkAllParametersConsumed("addDOHLocal", vars);
    }

    if (useTLS && frontend->d_library == "nghttp2") {
      if (!frontend->d_tlsContext.d_provider.empty()) {
        vinfolog("Loading TLS provider '%s'", frontend->d_tlsContext.d_provider);
      }
      else {
#ifdef HAVE_LIBSSL
        const std::string provider("openssl");
#else
          const std::string provider("gnutls");
#endif
        vinfolog("Loading default TLS provider '%s'", provider);
      }
    }

    g_dohlocals.push_back(frontend);
    auto clientState = std::make_unique<ClientState>(frontend->d_tlsContext.d_addr, true, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
    clientState->dohFrontend = std::move(frontend);
    clientState->d_additionalAddresses = std::move(additionalAddresses);

    if (tcpListenQueueSize > 0) {
      clientState->tcpListenQueueSize = tcpListenQueueSize;
    }
    if (tcpMaxConcurrentConnections > 0) {
      clientState->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConnections;
    }
    g_frontends.push_back(std::move(clientState));
#else /* HAVE_DNS_OVER_HTTPS */
      throw std::runtime_error("addDOHLocal() called but DNS over HTTPS support is not present!");
#endif /* HAVE_DNS_OVER_HTTPS */
  });

  // NOLINTNEXTLINE(performance-unnecessary-value-param): somehow clang-tidy gets confused about the fact vars could be const while it cannot
  luaCtx.writeFunction("addDOH3Local", [client](const std::string& addr, const boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>>& certFiles, const boost::variant<std::string, LuaArray<std::string>>& keyFiles, boost::optional<localbind_t> vars) {
    if (client) {
      return;
    }
#ifdef HAVE_DNS_OVER_HTTP3
    if (!checkConfigurationTime("addDOH3Local")) {
      return;
    }
    setLuaSideEffect();

    auto frontend = std::make_shared<DOH3Frontend>();
    if (!loadTLSCertificateAndKeys("addDOH3Local", frontend->d_quicheParams.d_tlsConfig.d_certKeyPairs, certFiles, keyFiles)) {
      return;
    }
    frontend->d_local = ComboAddress(addr, 443);

    bool reusePort = false;
    int tcpFastOpenQueueSize = 0;
    int tcpListenQueueSize = 0;
    uint64_t maxInFlightQueriesPerConn = 0;
    uint64_t tcpMaxConcurrentConnections = 0;
    std::string interface;
    std::set<int> cpus;
    std::vector<std::pair<ComboAddress, int>> additionalAddresses;
    bool enableProxyProtocol = true;

    if (vars) {
      parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections, enableProxyProtocol);
      if (maxInFlightQueriesPerConn > 0) {
        frontend->d_quicheParams.d_maxInFlight = maxInFlightQueriesPerConn;
      }
      getOptionalValue<int>(vars, "internalPipeBufferSize", frontend->d_internalPipeBufferSize);
      getOptionalValue<int>(vars, "idleTimeout", frontend->d_quicheParams.d_idleTimeout);
      getOptionalValue<std::string>(vars, "keyLogFile", frontend->d_quicheParams.d_keyLogFile);
      {
        std::string valueStr;
        if (getOptionalValue<std::string>(vars, "congestionControlAlgo", valueStr) > 0) {
          if (dnsdist::doq::s_available_cc_algorithms.count(valueStr) > 0) {
            frontend->d_quicheParams.d_ccAlgo = valueStr;
          }
          else {
            warnlog("Ignoring unknown value '%s' for 'congestionControlAlgo' on 'addDOH3Local'", valueStr);
          }
        }
      }
      parseTLSConfig(frontend->d_quicheParams.d_tlsConfig, "addDOH3Local", vars);

      bool ignoreTLSConfigurationErrors = false;
      if (getOptionalValue<bool>(vars, "ignoreTLSConfigurationErrors", ignoreTLSConfigurationErrors) > 0 && ignoreTLSConfigurationErrors) {
        // we are asked to try to load the certificates so we can return a potential error
        // and properly ignore the frontend before actually launching it
        try {
          std::map<int, std::string> ocspResponses = {};
          auto ctx = libssl_init_server_context(frontend->d_quicheParams.d_tlsConfig, ocspResponses);
        }
        catch (const std::runtime_error& e) {
          errlog("Ignoring DoH3 frontend: '%s'", e.what());
          return;
        }
      }

      checkAllParametersConsumed("addDOH3Local", vars);
    }
    g_doh3locals.push_back(frontend);
    auto clientState = std::make_unique<ClientState>(frontend->d_local, false, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
    clientState->doh3Frontend = frontend;
    clientState->d_additionalAddresses = std::move(additionalAddresses);

    g_frontends.push_back(std::move(clientState));
#else
      throw std::runtime_error("addDOH3Local() called but DNS over HTTP/3 support is not present!");
#endif
  });

  // NOLINTNEXTLINE(performance-unnecessary-value-param): somehow clang-tidy gets confused about the fact vars could be const while it cannot
  luaCtx.writeFunction("addDOQLocal", [client](const std::string& addr, const boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>>& certFiles, const boost::variant<std::string, LuaArray<std::string>>& keyFiles, boost::optional<localbind_t> vars) {
    if (client) {
      return;
    }
#ifdef HAVE_DNS_OVER_QUIC
    if (!checkConfigurationTime("addDOQLocal")) {
      return;
    }
    setLuaSideEffect();

    auto frontend = std::make_shared<DOQFrontend>();
    if (!loadTLSCertificateAndKeys("addDOQLocal", frontend->d_quicheParams.d_tlsConfig.d_certKeyPairs, certFiles, keyFiles)) {
      return;
    }
    frontend->d_local = ComboAddress(addr, 853);

    bool reusePort = false;
    int tcpFastOpenQueueSize = 0;
    int tcpListenQueueSize = 0;
    uint64_t maxInFlightQueriesPerConn = 0;
    uint64_t tcpMaxConcurrentConnections = 0;
    std::string interface;
    std::set<int> cpus;
    std::vector<std::pair<ComboAddress, int>> additionalAddresses;
    bool enableProxyProtocol = true;

    if (vars) {
      parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections, enableProxyProtocol);
      if (maxInFlightQueriesPerConn > 0) {
        frontend->d_quicheParams.d_maxInFlight = maxInFlightQueriesPerConn;
      }
      getOptionalValue<int>(vars, "internalPipeBufferSize", frontend->d_internalPipeBufferSize);
      getOptionalValue<int>(vars, "idleTimeout", frontend->d_quicheParams.d_idleTimeout);
      getOptionalValue<std::string>(vars, "keyLogFile", frontend->d_quicheParams.d_keyLogFile);
      {
        std::string valueStr;
        if (getOptionalValue<std::string>(vars, "congestionControlAlgo", valueStr) > 0) {
          if (dnsdist::doq::s_available_cc_algorithms.count(valueStr) > 0) {
            frontend->d_quicheParams.d_ccAlgo = std::move(valueStr);
          }
          else {
            warnlog("Ignoring unknown value '%s' for 'congestionControlAlgo' on 'addDOQLocal'", valueStr);
          }
        }
      }
      parseTLSConfig(frontend->d_quicheParams.d_tlsConfig, "addDOQLocal", vars);

      bool ignoreTLSConfigurationErrors = false;
      if (getOptionalValue<bool>(vars, "ignoreTLSConfigurationErrors", ignoreTLSConfigurationErrors) > 0 && ignoreTLSConfigurationErrors) {
        // we are asked to try to load the certificates so we can return a potential error
        // and properly ignore the frontend before actually launching it
        try {
          std::map<int, std::string> ocspResponses = {};
          auto ctx = libssl_init_server_context(frontend->d_quicheParams.d_tlsConfig, ocspResponses);
        }
        catch (const std::runtime_error& e) {
          errlog("Ignoring DoQ frontend: '%s'", e.what());
          return;
        }
      }

      checkAllParametersConsumed("addDOQLocal", vars);
    }
    g_doqlocals.push_back(frontend);
    auto clientState = std::make_unique<ClientState>(frontend->d_local, false, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
    clientState->doqFrontend = std::move(frontend);
    clientState->d_additionalAddresses = std::move(additionalAddresses);

    g_frontends.push_back(std::move(clientState));
#else
      throw std::runtime_error("addDOQLocal() called but DNS over QUIC support is not present!");
#endif
  });

  luaCtx.writeFunction("showDOQFrontends", []() {
#ifdef HAVE_DNS_OVER_QUIC
    setLuaNoSideEffect();
    try {
      ostringstream ret;
      boost::format fmt("%-3d %-20.20s %-15d %-15d %-15d %-15d");
      ret << (fmt % "#" % "Address" % "Bad Version" % "Invalid Token" % "Errors" % "Valid") << endl;
      size_t counter = 0;
      for (const auto& ctx : g_doqlocals) {
        ret << (fmt % counter % ctx->d_local.toStringWithPort() % ctx->d_doqUnsupportedVersionErrors % ctx->d_doqInvalidTokensReceived % ctx->d_errorResponses % ctx->d_validResponses) << endl;
        counter++;
      }
      g_outputBuffer = ret.str();
    }
    catch (const std::exception& e) {
      g_outputBuffer = e.what();
      throw;
    }
#else
      g_outputBuffer = "DNS over QUIC support is not present!\n";
#endif
  });

#ifdef HAVE_DNS_OVER_QUIC
  luaCtx.writeFunction("getDOQFrontend", [client](uint64_t index) {
    std::shared_ptr<DOQFrontend> result = nullptr;
    if (client) {
      return result;
    }
    setLuaNoSideEffect();
    try {
      if (index < g_doqlocals.size()) {
        result = g_doqlocals.at(index);
      }
      else {
        errlog("Error: trying to get DOQ frontend with index %d but we only have %d frontend(s)\n", index, g_doqlocals.size());
        g_outputBuffer = "Error: trying to get DOQ frontend with index " + std::to_string(index) + " but we only have " + std::to_string(g_doqlocals.size()) + " frontend(s)\n";
      }
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Error while trying to get DOQ frontend with index " + std::to_string(index) + ": " + string(e.what()) + "\n";
      errlog("Error while trying to get DOQ frontend with index %d: %s\n", index, string(e.what()));
    }
    return result;
  });

  luaCtx.writeFunction("getDOQFrontendCount", []() {
    setLuaNoSideEffect();
    return g_doqlocals.size();
  });

  luaCtx.registerFunction<void (std::shared_ptr<DOQFrontend>::*)()>("reloadCertificates", [](const std::shared_ptr<DOQFrontend>& frontend) {
    if (frontend != nullptr) {
      frontend->reloadCertificates();
    }
  });
#endif

  luaCtx.writeFunction("showDOHFrontends", []() {
#ifdef HAVE_DNS_OVER_HTTPS
    setLuaNoSideEffect();
    try {
      ostringstream ret;
      boost::format fmt("%-3d %-20.20s %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d");
      ret << (fmt % "#" % "Address" % "HTTP" % "HTTP/1" % "HTTP/2" % "GET" % "POST" % "Bad" % "Errors" % "Redirects" % "Valid" % "# ticket keys" % "Rotation delay" % "Next rotation") << endl;
      size_t counter = 0;
      for (const auto& ctx : g_dohlocals) {
        ret << (fmt % counter % ctx->d_tlsContext.d_addr.toStringWithPort() % ctx->d_httpconnects % ctx->d_http1Stats.d_nbQueries % ctx->d_http2Stats.d_nbQueries % ctx->d_getqueries % ctx->d_postqueries % ctx->d_badrequests % ctx->d_errorresponses % ctx->d_redirectresponses % ctx->d_validresponses % ctx->getTicketsKeysCount() % ctx->getTicketsKeyRotationDelay() % ctx->getNextTicketsKeyRotation()) << endl;
        counter++;
      }
      g_outputBuffer = ret.str();
    }
    catch (const std::exception& e) {
      g_outputBuffer = e.what();
      throw;
    }
#else
      g_outputBuffer = "DNS over HTTPS support is not present!\n";
#endif
  });

  luaCtx.writeFunction("showDOH3Frontends", []() {
#ifdef HAVE_DNS_OVER_HTTP3
    setLuaNoSideEffect();
    try {
      ostringstream ret;
      boost::format fmt("%-3d %-20.20s %-15d %-15d %-15d %-15d");
      ret << (fmt % "#" % "Address" % "Bad Version" % "Invalid Token" % "Errors" % "Valid") << endl;
      size_t counter = 0;
      for (const auto& ctx : g_doh3locals) {
        ret << (fmt % counter % ctx->d_local.toStringWithPort() % ctx->d_doh3UnsupportedVersionErrors % ctx->d_doh3InvalidTokensReceived % ctx->d_errorResponses % ctx->d_validResponses) << endl;
        counter++;
      }
      g_outputBuffer = ret.str();
    }
    catch (const std::exception& e) {
      g_outputBuffer = e.what();
      throw;
    }
#else
      g_outputBuffer = "DNS over HTTP3 support is not present!\n";
#endif
  });

#ifdef HAVE_DNS_OVER_HTTP3
  luaCtx.writeFunction("getDOH3Frontend", [client](uint64_t index) {
    std::shared_ptr<DOH3Frontend> result = nullptr;
    if (client) {
      return result;
    }
    setLuaNoSideEffect();
    try {
      if (index < g_doh3locals.size()) {
        result = g_doh3locals.at(index);
      }
      else {
        errlog("Error: trying to get DOH3 frontend with index %d but we only have %d frontend(s)\n", index, g_doh3locals.size());
        g_outputBuffer = "Error: trying to get DOH3 frontend with index " + std::to_string(index) + " but we only have " + std::to_string(g_doh3locals.size()) + " frontend(s)\n";
      }
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Error while trying to get DOH3 frontend with index " + std::to_string(index) + ": " + string(e.what()) + "\n";
      errlog("Error while trying to get DOH3 frontend with index %d: %s\n", index, string(e.what()));
    }
    return result;
  });

  luaCtx.writeFunction("getDOH3FrontendCount", []() {
    setLuaNoSideEffect();
    return g_doh3locals.size();
  });

  luaCtx.registerFunction<void (std::shared_ptr<DOH3Frontend>::*)()>("reloadCertificates", [](const std::shared_ptr<DOH3Frontend>& frontend) {
    if (frontend != nullptr) {
      frontend->reloadCertificates();
    }
  });
#endif

  luaCtx.writeFunction("showDOHResponseCodes", []() {
#ifdef HAVE_DNS_OVER_HTTPS
    setLuaNoSideEffect();
    try {
      ostringstream ret;
      boost::format fmt("%-3d %-20.20s %-15d %-15d %-15d %-15d %-15d %-15d");
      g_outputBuffer = "\n- HTTP/1:\n\n";
      ret << (fmt % "#" % "Address" % "200" % "400" % "403" % "500" % "502" % "Others") << endl;
      size_t counter = 0;
      for (const auto& ctx : g_dohlocals) {
        ret << (fmt % counter % ctx->d_tlsContext.d_addr.toStringWithPort() % ctx->d_http1Stats.d_nb200Responses % ctx->d_http1Stats.d_nb400Responses % ctx->d_http1Stats.d_nb403Responses % ctx->d_http1Stats.d_nb500Responses % ctx->d_http1Stats.d_nb502Responses % ctx->d_http1Stats.d_nbOtherResponses) << endl;
        counter++;
      }
      g_outputBuffer += ret.str();
      ret.str("");

      g_outputBuffer += "\n- HTTP/2:\n\n";
      ret << (fmt % "#" % "Address" % "200" % "400" % "403" % "500" % "502" % "Others") << endl;
      counter = 0;
      for (const auto& ctx : g_dohlocals) {
        ret << (fmt % counter % ctx->d_tlsContext.d_addr.toStringWithPort() % ctx->d_http2Stats.d_nb200Responses % ctx->d_http2Stats.d_nb400Responses % ctx->d_http2Stats.d_nb403Responses % ctx->d_http2Stats.d_nb500Responses % ctx->d_http2Stats.d_nb502Responses % ctx->d_http2Stats.d_nbOtherResponses) << endl;
        counter++;
      }
      g_outputBuffer += ret.str();
    }
    catch (const std::exception& e) {
      g_outputBuffer = e.what();
      throw;
    }
#else
      g_outputBuffer = "DNS over HTTPS support is not present!\n";
#endif
  });

  luaCtx.writeFunction("getDOHFrontend", [client](uint64_t index) {
    std::shared_ptr<DOHFrontend> result = nullptr;
    if (client) {
      return result;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    setLuaNoSideEffect();
    try {
      if (index < g_dohlocals.size()) {
        result = g_dohlocals.at(index);
      }
      else {
        errlog("Error: trying to get DOH frontend with index %d but we only have %d frontend(s)\n", index, g_dohlocals.size());
        g_outputBuffer = "Error: trying to get DOH frontend with index " + std::to_string(index) + " but we only have " + std::to_string(g_dohlocals.size()) + " frontend(s)\n";
      }
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Error while trying to get DOH frontend with index " + std::to_string(index) + ": " + string(e.what()) + "\n";
      errlog("Error while trying to get DOH frontend with index %d: %s\n", index, string(e.what()));
    }
#else
        g_outputBuffer="DNS over HTTPS support is not present!\n";
#endif
    return result;
  });

  luaCtx.writeFunction("getDOHFrontendCount", []() {
    setLuaNoSideEffect();
    return g_dohlocals.size();
  });

  luaCtx.registerFunction<void (std::shared_ptr<DOHFrontend>::*)()>("reloadCertificates", [](const std::shared_ptr<DOHFrontend>& frontend) {
    if (frontend != nullptr) {
      frontend->reloadCertificates();
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<DOHFrontend>::*)(boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>> certFiles, boost::variant<std::string, LuaArray<std::string>> keyFiles)>("loadNewCertificatesAndKeys", [](const std::shared_ptr<DOHFrontend>& frontend, const boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>>& certFiles, const boost::variant<std::string, LuaArray<std::string>>& keyFiles) {
#ifdef HAVE_DNS_OVER_HTTPS
    if (frontend != nullptr) {
      if (loadTLSCertificateAndKeys("DOHFrontend::loadNewCertificatesAndKeys", frontend->d_tlsContext.d_tlsConfig.d_certKeyPairs, certFiles, keyFiles)) {
        frontend->reloadCertificates();
      }
    }
#endif
  });

  luaCtx.registerFunction<void (std::shared_ptr<DOHFrontend>::*)()>("rotateTicketsKey", [](const std::shared_ptr<DOHFrontend>& frontend) {
    if (frontend != nullptr) {
      frontend->rotateTicketsKey(time(nullptr));
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<DOHFrontend>::*)(const std::string&)>("loadTicketsKeys", [](const std::shared_ptr<DOHFrontend>& frontend, const std::string& file) {
    if (frontend != nullptr) {
      frontend->loadTicketsKeys(file);
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<DOHFrontend>::*)(const std::string&)>("loadTicketsKey", [](const std::shared_ptr<DOHFrontend>& frontend, const std::string& key) {
    if (frontend != nullptr) {
      frontend->loadTicketsKey(key);
    }
  });

  luaCtx.writeFunction("loadTicketsKey", [](const std::string& key) {
    for (const auto& frontend : g_frontends) {
      if (!frontend) {
        continue;
      }
      try {
#ifdef HAVE_DNS_OVER_TLS
        if (frontend->tlsFrontend) {
          frontend->tlsFrontend->loadTicketsKey(key);
        }
#endif /* HAVE_DNS_OVER_TLS */
#ifdef HAVE_DNS_OVER_HTTPS
        if (frontend->dohFrontend) {
          frontend->dohFrontend->loadTicketsKey(key);
        }
#endif /* HAVE_DNS_OVER_HTTPS */
      }
      catch (const std::exception& e) {
        errlog("Error loading given tickets key for local %s", frontend->local.toStringWithPort());
      }
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<DOHFrontend>::*)(const LuaArray<std::shared_ptr<DOHResponseMapEntry>>&)>("setResponsesMap", [](std::shared_ptr<DOHFrontend> frontend, const LuaArray<std::shared_ptr<DOHResponseMapEntry>>& map) {
    if (frontend != nullptr) {
      auto newMap = std::make_shared<std::vector<std::shared_ptr<DOHResponseMapEntry>>>();
      newMap->reserve(map.size());

      for (const auto& entry : map) {
        newMap->push_back(entry.second);
      }

      frontend->d_responsesMap = std::move(newMap);
    }
  });

  luaCtx.writeFunction("addTLSLocal", [client](const std::string& addr, boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>> certFiles, LuaTypeOrArrayOf<std::string> keyFiles, boost::optional<localbind_t> vars) {
    if (client) {
      return;
    }
#ifdef HAVE_DNS_OVER_TLS
    if (!checkConfigurationTime("addTLSLocal")) {
      return;
    }
    setLuaSideEffect();

    auto frontend = std::make_shared<TLSFrontend>(TLSFrontend::ALPN::DoT);
    if (!loadTLSCertificateAndKeys("addTLSLocal", frontend->d_tlsConfig.d_certKeyPairs, certFiles, keyFiles)) {
      return;
    }

    bool reusePort = false;
    int tcpFastOpenQueueSize = 0;
    int tcpListenQueueSize = 0;
    uint64_t maxInFlightQueriesPerConn = 0;
    uint64_t tcpMaxConcurrentConns = 0;
    std::string interface;
    std::set<int> cpus;
    std::vector<std::pair<ComboAddress, int>> additionalAddresses;
    bool enableProxyProtocol = true;

    if (vars) {
      parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConns, enableProxyProtocol);

      getOptionalValue<std::string>(vars, "provider", frontend->d_provider);
      boost::algorithm::to_lower(frontend->d_provider);
      getOptionalValue<bool>(vars, "proxyProtocolOutsideTLS", frontend->d_proxyProtocolOutsideTLS);

      LuaArray<std::string> addresses;
      if (getOptionalValue<decltype(addresses)>(vars, "additionalAddresses", addresses) > 0) {
        for (const auto& [_, add] : addresses) {
          try {
            ComboAddress address(add);
            additionalAddresses.emplace_back(address, -1);
          }
          catch (const PDNSException& e) {
            errlog("Unable to parse additional address %s for DoT bind: %s", add, e.reason);
            return;
          }
        }
      }

      parseTLSConfig(frontend->d_tlsConfig, "addTLSLocal", vars);

      bool ignoreTLSConfigurationErrors = false;
      if (getOptionalValue<bool>(vars, "ignoreTLSConfigurationErrors", ignoreTLSConfigurationErrors) > 0 && ignoreTLSConfigurationErrors) {
        // we are asked to try to load the certificates so we can return a potential error
        // and properly ignore the frontend before actually launching it
        try {
          std::map<int, std::string> ocspResponses = {};
          auto ctx = libssl_init_server_context(frontend->d_tlsConfig, ocspResponses);
        }
        catch (const std::runtime_error& e) {
          errlog("Ignoring TLS frontend: '%s'", e.what());
          return;
        }
      }

      checkAllParametersConsumed("addTLSLocal", vars);
    }

    try {
      frontend->d_addr = ComboAddress(addr, 853);
      if (!frontend->d_provider.empty()) {
        vinfolog("Loading TLS provider '%s'", frontend->d_provider);
      }
      else {
#ifdef HAVE_LIBSSL
        const std::string provider("openssl");
#else
          const std::string provider("gnutls");
#endif
        vinfolog("Loading default TLS provider '%s'", provider);
      }
      // only works pre-startup, so no sync necessary
      auto clientState = std::make_unique<ClientState>(frontend->d_addr, true, reusePort, tcpFastOpenQueueSize, interface, cpus, enableProxyProtocol);
      clientState->tlsFrontend = frontend;
      clientState->d_additionalAddresses = std::move(additionalAddresses);
      if (tcpListenQueueSize > 0) {
        clientState->tcpListenQueueSize = tcpListenQueueSize;
      }
      if (maxInFlightQueriesPerConn > 0) {
        clientState->d_maxInFlightQueriesPerConn = maxInFlightQueriesPerConn;
      }
      if (tcpMaxConcurrentConns > 0) {
        clientState->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConns;
      }

      g_tlslocals.push_back(clientState->tlsFrontend);
      g_frontends.push_back(std::move(clientState));
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Error: " + string(e.what()) + "\n";
    }
#else
      throw std::runtime_error("addTLSLocal() called but DNS over TLS support is not present!");
#endif
  });

  luaCtx.writeFunction("showTLSContexts", []() {
#ifdef HAVE_DNS_OVER_TLS
    setLuaNoSideEffect();
    try {
      ostringstream ret;
      boost::format fmt("%1$-3d %2$-20.20s %|25t|%3$-14d %|40t|%4$-14d %|54t|%5$-21.21s");
      //             1    2           3                 4                  5
      ret << (fmt % "#" % "Address" % "# ticket keys" % "Rotation delay" % "Next rotation") << endl;
      size_t counter = 0;
      for (const auto& ctx : g_tlslocals) {
        ret << (fmt % counter % ctx->d_addr.toStringWithPort() % ctx->getTicketsKeysCount() % ctx->getTicketsKeyRotationDelay() % ctx->getNextTicketsKeyRotation()) << endl;
        counter++;
      }
      g_outputBuffer = ret.str();
    }
    catch (const std::exception& e) {
      g_outputBuffer = e.what();
      throw;
    }
#else
      g_outputBuffer = "DNS over TLS support is not present!\n";
#endif
  });

  luaCtx.writeFunction("getTLSContext", [](uint64_t index) {
    std::shared_ptr<TLSCtx> result = nullptr;
#ifdef HAVE_DNS_OVER_TLS
    setLuaNoSideEffect();
    try {
      if (index < g_tlslocals.size()) {
        result = g_tlslocals.at(index)->getContext();
      }
      else {
        errlog("Error: trying to get TLS context with index %d but we only have %d context(s)\n", index, g_tlslocals.size());
        g_outputBuffer = "Error: trying to get TLS context with index " + std::to_string(index) + " but we only have " + std::to_string(g_tlslocals.size()) + " context(s)\n";
      }
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Error while trying to get TLS context with index " + std::to_string(index) + ": " + string(e.what()) + "\n";
      errlog("Error while trying to get TLS context with index %d: %s\n", index, string(e.what()));
    }
#else
        g_outputBuffer="DNS over TLS support is not present!\n";
#endif
    return result;
  });

  luaCtx.writeFunction("getTLSFrontend", [](uint64_t index) {
    std::shared_ptr<TLSFrontend> result = nullptr;
#ifdef HAVE_DNS_OVER_TLS
    setLuaNoSideEffect();
    try {
      if (index < g_tlslocals.size()) {
        result = g_tlslocals.at(index);
      }
      else {
        errlog("Error: trying to get TLS frontend with index %d but we only have %d frontends\n", index, g_tlslocals.size());
        g_outputBuffer = "Error: trying to get TLS frontend with index " + std::to_string(index) + " but we only have " + std::to_string(g_tlslocals.size()) + " frontend(s)\n";
      }
    }
    catch (const std::exception& e) {
      g_outputBuffer = "Error while trying to get TLS frontend with index " + std::to_string(index) + ": " + string(e.what()) + "\n";
      errlog("Error while trying to get TLS frontend with index %d: %s\n", index, string(e.what()));
    }
#else
        g_outputBuffer="DNS over TLS support is not present!\n";
#endif
    return result;
  });

  luaCtx.writeFunction("getTLSFrontendCount", []() {
    setLuaNoSideEffect();
    return g_tlslocals.size();
  });

  luaCtx.registerFunction<void (std::shared_ptr<TLSCtx>::*)()>("rotateTicketsKey", [](std::shared_ptr<TLSCtx>& ctx) {
    if (ctx != nullptr) {
      ctx->rotateTicketsKey(time(nullptr));
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<TLSCtx>::*)(const std::string&)>("loadTicketsKeys", [](std::shared_ptr<TLSCtx>& ctx, const std::string& file) {
    if (ctx != nullptr) {
      ctx->loadTicketsKeys(file);
    }
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<TLSFrontend>::*)() const>("getAddressAndPort", [](const std::shared_ptr<TLSFrontend>& frontend) {
    if (frontend == nullptr) {
      return std::string();
    }
    return frontend->d_addr.toStringWithPort();
  });

  luaCtx.registerFunction<void (std::shared_ptr<TLSFrontend>::*)()>("rotateTicketsKey", [](std::shared_ptr<TLSFrontend>& frontend) {
    if (frontend == nullptr) {
      return;
    }
    auto ctx = frontend->getContext();
    if (ctx) {
      ctx->rotateTicketsKey(time(nullptr));
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<TLSFrontend>::*)(const std::string&)>("loadTicketsKeys", [](std::shared_ptr<TLSFrontend>& frontend, const std::string& file) {
    if (frontend == nullptr) {
      return;
    }
    auto ctx = frontend->getContext();
    if (ctx) {
      ctx->loadTicketsKeys(file);
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<TLSFrontend>::*)(const std::string&)>("loadTicketsKey", [](std::shared_ptr<TLSFrontend>& frontend, const std::string& key) {
    if (frontend == nullptr) {
      return;
    }
    auto ctx = frontend->getContext();
    if (ctx) {
      ctx->loadTicketsKey(key);
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<TLSFrontend>::*)()>("reloadCertificates", [](const std::shared_ptr<TLSFrontend>& frontend) {
    if (frontend == nullptr) {
      return;
    }
    frontend->setupTLS();
  });

  luaCtx.registerFunction<void (std::shared_ptr<TLSFrontend>::*)(boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>> certFiles, LuaTypeOrArrayOf<std::string> keyFiles)>("loadNewCertificatesAndKeys", [](std::shared_ptr<TLSFrontend>& frontend, boost::variant<std::string, std::shared_ptr<TLSCertKeyPair>, LuaArray<std::string>, LuaArray<std::shared_ptr<TLSCertKeyPair>>> certFiles, LuaTypeOrArrayOf<std::string> keyFiles) {
#ifdef HAVE_DNS_OVER_TLS
    if (loadTLSCertificateAndKeys("TLSFrontend::loadNewCertificatesAndKeys", frontend->d_tlsConfig.d_certKeyPairs, certFiles, keyFiles)) {
      frontend->setupTLS();
    }
#endif
  });

  luaCtx.writeFunction("reloadAllCertificates", []() {
    for (auto& frontend : g_frontends) {
      if (!frontend) {
        continue;
      }
      try {
#ifdef HAVE_DNSCRYPT
        if (frontend->dnscryptCtx) {
          frontend->dnscryptCtx->reloadCertificates();
        }
#endif /* HAVE_DNSCRYPT */
#ifdef HAVE_DNS_OVER_TLS
        if (frontend->tlsFrontend) {
          frontend->tlsFrontend->setupTLS();
        }
#endif /* HAVE_DNS_OVER_TLS */
#ifdef HAVE_DNS_OVER_HTTPS
        if (frontend->dohFrontend) {
          frontend->dohFrontend->reloadCertificates();
        }
#endif /* HAVE_DNS_OVER_HTTPS */
#ifdef HAVE_DNS_OVER_QUIC
        if (frontend->doqFrontend) {
          frontend->doqFrontend->reloadCertificates();
        }
#endif /* HAVE_DNS_OVER_QUIC */
#ifdef HAVE_DNS_OVER_HTTP3
        if (frontend->doh3Frontend) {
          frontend->doh3Frontend->reloadCertificates();
        }
#endif /* HAVE_DNS_OVER_HTTP3 */
      }
      catch (const std::exception& e) {
        errlog("Error reloading certificates for frontend %s: %s", frontend->local.toStringWithPort(), e.what());
      }
    }
  });

  luaCtx.writeFunction("setAllowEmptyResponse", [](bool allow) { g_allowEmptyResponse = allow; });
  luaCtx.writeFunction("setDropEmptyQueries", [](bool drop) { extern bool g_dropEmptyQueries; g_dropEmptyQueries = drop; });

#if defined(HAVE_LIBSSL) && defined(HAVE_OCSP_BASIC_SIGN) && !defined(DISABLE_OCSP_STAPLING)
  luaCtx.writeFunction("generateOCSPResponse", [client](const std::string& certFile, const std::string& caCert, const std::string& caKey, const std::string& outFile, int ndays, int nmin) {
    if (client) {
      return;
    }

    libssl_generate_ocsp_response(certFile, caCert, caKey, outFile, ndays, nmin);
  });
#endif /* HAVE_LIBSSL && HAVE_OCSP_BASIC_SIGN && !DISABLE_OCSP_STAPLING */

  luaCtx.writeFunction("addCapabilitiesToRetain", [](LuaTypeOrArrayOf<std::string> caps) {
    if (!checkConfigurationTime("addCapabilitiesToRetain")) {
      return;
    }
    setLuaSideEffect();
    if (caps.type() == typeid(std::string)) {
      g_capabilitiesToRetain.insert(boost::get<std::string>(caps));
    }
    else if (caps.type() == typeid(LuaArray<std::string>)) {
      for (const auto& cap : boost::get<LuaArray<std::string>>(caps)) {
        g_capabilitiesToRetain.insert(cap.second);
      }
    }
  });

  luaCtx.writeFunction("setUDPSocketBufferSizes", [client](uint64_t recv, uint64_t snd) {
    if (client) {
      return;
    }
    if (!checkConfigurationTime("setUDPSocketBufferSizes")) {
      return;
    }
    checkParameterBound("setUDPSocketBufferSizes", recv, std::numeric_limits<uint32_t>::max());
    checkParameterBound("setUDPSocketBufferSizes", snd, std::numeric_limits<uint32_t>::max());
    setLuaSideEffect();

    g_socketUDPSendBuffer = snd;
    g_socketUDPRecvBuffer = recv;
  });

  luaCtx.writeFunction("setRandomizedOutgoingSockets", [](bool randomized) {
    DownstreamState::s_randomizeSockets = randomized;
  });

  luaCtx.writeFunction("setRandomizedIdsOverUDP", [](bool randomized) {
    DownstreamState::s_randomizeIDs = randomized;
  });

#if defined(HAVE_LIBSSL) && !defined(HAVE_TLS_PROVIDERS)
  luaCtx.writeFunction("loadTLSEngine", [client](const std::string& engineName, boost::optional<std::string> defaultString) {
    if (client) {
      return;
    }

    auto [success, error] = libssl_load_engine(engineName, defaultString ? std::optional<std::string>(*defaultString) : std::nullopt);
    if (!success) {
      g_outputBuffer = "Error while trying to load TLS engine '" + engineName + "': " + error + "\n";
      errlog("Error while trying to load TLS engine '%s': %s", engineName, error);
    }
  });
#endif /* HAVE_LIBSSL && !HAVE_TLS_PROVIDERS */

#if defined(HAVE_LIBSSL) && OPENSSL_VERSION_MAJOR >= 3 && defined(HAVE_TLS_PROVIDERS)
  luaCtx.writeFunction("loadTLSProvider", [client](const std::string& providerName) {
    if (client) {
      return;
    }

    auto [success, error] = libssl_load_provider(providerName);
    if (!success) {
      g_outputBuffer = "Error while trying to load TLS provider '" + providerName + "': " + error + "\n";
      errlog("Error while trying to load TLS provider '%s': %s", providerName, error);
    }
  });
#endif /* HAVE_LIBSSL && OPENSSL_VERSION_MAJOR >= 3 && HAVE_TLS_PROVIDERS */

  luaCtx.writeFunction("newThread", [client, configCheck](const std::string& code) {
    if (client || configCheck) {
      return;
    }
    std::thread newThread(LuaThread, code);

    newThread.detach();
  });

  luaCtx.writeFunction("declareMetric", [](const std::string& name, const std::string& type, const std::string& description, boost::optional<std::string> customName) {
    auto result = dnsdist::metrics::declareCustomMetric(name, type, description, customName ? std::optional<std::string>(*customName) : std::nullopt);
    if (result) {
      g_outputBuffer += *result + "\n";
      errlog("Error in declareMetric: %s", *result);
      return false;
    }
    return true;
  });
  luaCtx.writeFunction("incMetric", [](const std::string& name, boost::optional<uint64_t> step) {
    auto result = dnsdist::metrics::incrementCustomCounter(name, step ? *step : 1);
    if (const auto* errorStr = std::get_if<dnsdist::metrics::Error>(&result)) {
      g_outputBuffer = *errorStr + "'\n";
      errlog("Error in incMetric: %s", *errorStr);
      return static_cast<uint64_t>(0);
    }
    return std::get<uint64_t>(result);
  });
  luaCtx.writeFunction("decMetric", [](const std::string& name, boost::optional<uint64_t> step) {
    auto result = dnsdist::metrics::decrementCustomCounter(name, step ? *step : 1);
    if (const auto* errorStr = std::get_if<dnsdist::metrics::Error>(&result)) {
      g_outputBuffer = *errorStr + "'\n";
      errlog("Error in decMetric: %s", *errorStr);
      return static_cast<uint64_t>(0);
    }
    return std::get<uint64_t>(result);
  });
  luaCtx.writeFunction("setMetric", [](const std::string& name, const double value) -> double {
    auto result = dnsdist::metrics::setCustomGauge(name, value);
    if (const auto* errorStr = std::get_if<dnsdist::metrics::Error>(&result)) {
      g_outputBuffer = *errorStr + "'\n";
      errlog("Error in setMetric: %s", *errorStr);
      return 0.;
    }
    return std::get<double>(result);
  });
  luaCtx.writeFunction("getMetric", [](const std::string& name) {
    auto result = dnsdist::metrics::getCustomMetric(name);
    if (const auto* errorStr = std::get_if<dnsdist::metrics::Error>(&result)) {
      g_outputBuffer = *errorStr + "'\n";
      errlog("Error in getMetric: %s", *errorStr);
      return 0.;
    }
    return std::get<double>(result);
  });
}

vector<std::function<void(void)>> setupLua(LuaContext& luaCtx, bool client, bool configCheck, const std::string& config)
{
  // this needs to exist only during the parsing of the configuration
  // and cannot be captured by lambdas
  g_launchWork = std::vector<std::function<void(void)>>();

  setupLuaActions(luaCtx);
  setupLuaConfig(luaCtx, client, configCheck);
  setupLuaBindings(luaCtx, client, configCheck);
  setupLuaBindingsDNSCrypt(luaCtx, client);
  setupLuaBindingsDNSParser(luaCtx);
  setupLuaBindingsDNSQuestion(luaCtx);
  setupLuaBindingsKVS(luaCtx, client);
  setupLuaBindingsLogging(luaCtx);
  setupLuaBindingsNetwork(luaCtx, client);
  setupLuaBindingsPacketCache(luaCtx, client);
  setupLuaBindingsProtoBuf(luaCtx, client, configCheck);
  setupLuaBindingsRings(luaCtx, client);
  dnsdist::lua::hooks::setupLuaHooks(luaCtx);
  setupLuaInspection(luaCtx);
  setupLuaRules(luaCtx);
  setupLuaVars(luaCtx);
  setupLuaWeb(luaCtx);

#ifdef LUAJIT_VERSION
  luaCtx.executeCode(getLuaFFIWrappers());
#endif

  std::ifstream ifs(config);
  if (!ifs) {
    if (configCheck) {
      throw std::runtime_error("Unable to read configuration file from " + config);
    }
    else {
      warnlog("Unable to read configuration from '%s'", config);
    }
  }
  else {
    vinfolog("Read configuration from '%s'", config);
  }

  luaCtx.executeCode(ifs);

  auto ret = *g_launchWork;
  g_launchWork = boost::none;
  return ret;
}
