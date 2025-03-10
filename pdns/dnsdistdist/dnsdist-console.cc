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

#include <fstream>
// we need this to get the home directory of the current user
#include <pwd.h>
#include <thread>

#ifdef HAVE_LIBEDIT
#if defined(__OpenBSD__) || defined(__NetBSD__)
// If this is not undeffed, __attribute__ will be redefined by /usr/include/readline/rlstdc.h
#undef __STRICT_ANSI__
#include <readline/readline.h>
#include <readline/history.h>
#else
#include <editline/readline.h>
#endif
#endif /* HAVE_LIBEDIT */

#include "ext/json11/json11.hpp"

#include "connection-management.hh"
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-console.hh"
#include "dnsdist-crypto.hh"
#include "dnsdist-lua.hh"
#include "threadname.hh"

static LockGuarded<std::vector<pair<timeval, string>>> s_confDelta;

static ConcurrentConnectionManager s_connManager(100);

class ConsoleConnection
{
public:
  ConsoleConnection(const ComboAddress& client, FDWrapper&& fileDesc) :
    d_client(client), d_fileDesc(std::move(fileDesc))
  {
    if (!s_connManager.registerConnection()) {
      throw std::runtime_error("Too many concurrent console connections");
    }
  }
  ConsoleConnection(ConsoleConnection&& rhs) noexcept :
    d_client(rhs.d_client), d_fileDesc(std::move(rhs.d_fileDesc))
  {
  }

  ConsoleConnection(const ConsoleConnection&) = delete;
  ConsoleConnection& operator=(const ConsoleConnection&) = delete;
  ConsoleConnection& operator=(ConsoleConnection&&) = delete;

  ~ConsoleConnection()
  {
    if (d_fileDesc.getHandle() != -1) {
      s_connManager.releaseConnection();
    }
  }

  [[nodiscard]] int getFD() const
  {
    return d_fileDesc.getHandle();
  }

  [[nodiscard]] const ComboAddress& getClient() const
  {
    return d_client;
  }

private:
  ComboAddress d_client;
  FDWrapper d_fileDesc;
};

static void feedConfigDelta(const std::string& line)
{
  if (line.empty()) {
    return;
  }
  timeval now{};
  gettimeofday(&now, nullptr);
  s_confDelta.lock()->emplace_back(now, line);
}

namespace dnsdist::console
{
const std::vector<std::pair<timeval, std::string>>& getConfigurationDelta()
{
  return *(s_confDelta.lock());
}
}

#ifdef HAVE_LIBEDIT
static string historyFile(const bool& ignoreHOME = false)
{
  string ret;

  passwd pwd{};
  passwd* result{nullptr};
  std::array<char, 16384> buf{};
  getpwuid_r(geteuid(), &pwd, buf.data(), buf.size(), &result);

  // NOLINTNEXTLINE(concurrency-mt-unsafe): we are not modifying the environment
  const char* homedir = getenv("HOME");
  if (result != nullptr) {
    ret = string(pwd.pw_dir);
  }
  if (homedir != nullptr && !ignoreHOME) { // $HOME overrides what the OS tells us
    ret = string(homedir);
  }
  if (ret.empty()) {
    ret = "."; // CWD if nothing works..
  }
  ret.append("/.dnsdist_history");
  return ret;
}
#endif /* HAVE_LIBEDIT */

enum class ConsoleCommandResult : uint8_t
{
  Valid = 0,
  ConnectionClosed,
  TooLarge
};

static ConsoleCommandResult getMsgLen32(int fileDesc, uint32_t* len)
{
  try {
    uint32_t raw{0};
    size_t ret = readn2(fileDesc, &raw, sizeof(raw));

    if (ret != sizeof raw) {
      return ConsoleCommandResult::ConnectionClosed;
    }

    *len = ntohl(raw);
    if (*len > dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleOutputMsgMaxSize) {
      return ConsoleCommandResult::TooLarge;
    }

    return ConsoleCommandResult::Valid;
  }
  catch (...) {
    return ConsoleCommandResult::ConnectionClosed;
  }
}

static bool putMsgLen32(int fileDesc, uint32_t len)
{
  try {
    uint32_t raw = htonl(len);
    size_t ret = writen2(fileDesc, &raw, sizeof raw);
    return ret == sizeof raw;
  }
  catch (...) {
    return false;
  }
}

static ConsoleCommandResult sendMessageToServer(int fileDesc, const std::string& line, dnsdist::crypto::authenticated::Nonce& readingNonce, dnsdist::crypto::authenticated::Nonce& writingNonce, const bool outputEmptyLine)
{
  const auto& consoleKey = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey;
  string msg = dnsdist::crypto::authenticated::encryptSym(line, consoleKey, writingNonce);
  const auto msgLen = msg.length();
  if (msgLen > std::numeric_limits<uint32_t>::max()) {
    cerr << "Encrypted message is too long to be sent to the server, " << std::to_string(msgLen) << " > " << std::numeric_limits<uint32_t>::max() << endl;
    return ConsoleCommandResult::TooLarge;
  }

  putMsgLen32(fileDesc, static_cast<uint32_t>(msgLen));

  if (!msg.empty()) {
    writen2(fileDesc, msg);
  }

  uint32_t len{0};
  auto commandResult = getMsgLen32(fileDesc, &len);
  if (commandResult == ConsoleCommandResult::ConnectionClosed) {
    cout << "Connection closed by the server." << endl;
    return commandResult;
  }
  if (commandResult == ConsoleCommandResult::TooLarge) {
    cerr << "Received a console message whose length (" << len << ") is exceeding the allowed one (" << dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleOutputMsgMaxSize << "), closing that connection" << endl;
    return commandResult;
  }

  if (len == 0) {
    if (outputEmptyLine) {
      cout << endl;
    }

    return ConsoleCommandResult::Valid;
  }

  msg.clear();
  msg.resize(len);
  readn2(fileDesc, msg.data(), len);
  msg = dnsdist::crypto::authenticated::decryptSym(msg, consoleKey, readingNonce);
  cout << msg;
  cout.flush();

  return ConsoleCommandResult::Valid;
}

namespace dnsdist::console
{
void doClient(const std::string& command)
{
  //coverity[auto_causes_copy]
  const auto consoleKey = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey;
  //coverity[auto_causes_copy]
  const auto server = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleServerAddress;
  if (!dnsdist::crypto::authenticated::isValidKey(consoleKey)) {
    cerr << "The currently configured console key is not valid, please configure a valid key using the setKey() directive" << endl;
    return;
  }

  if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose) {
    cout << "Connecting to " << server.toStringWithPort() << endl;
  }

  auto fileDesc = FDWrapper(socket(server.sin4.sin_family, SOCK_STREAM, 0));
  if (fileDesc.getHandle() < 0) {
    cerr << "Unable to connect to " << server.toStringWithPort() << endl;
    return;
  }
  SConnect(fileDesc.getHandle(), server);
  setTCPNoDelay(fileDesc.getHandle());
  dnsdist::crypto::authenticated::Nonce theirs;
  dnsdist::crypto::authenticated::Nonce ours;
  dnsdist::crypto::authenticated::Nonce readingNonce;
  dnsdist::crypto::authenticated::Nonce writingNonce;
  ours.init();

  writen2(fileDesc.getHandle(), ours.value.data(), ours.value.size());
  readn2(fileDesc.getHandle(), theirs.value.data(), theirs.value.size());
  readingNonce.merge(ours, theirs);
  writingNonce.merge(theirs, ours);

  /* try sending an empty message, the server should send an empty
     one back. If it closes the connection instead, we are probably
     having a key mismatch issue. */
  auto commandResult = sendMessageToServer(fileDesc.getHandle(), "", readingNonce, writingNonce, false);
  if (commandResult == ConsoleCommandResult::ConnectionClosed) {
    cerr << "The server closed the connection right away, likely indicating a key mismatch. Please check your setKey() directive." << endl;
    return;
  }
  if (commandResult == ConsoleCommandResult::TooLarge) {
    return;
  }

  if (!command.empty()) {
    sendMessageToServer(fileDesc.getHandle(), command, readingNonce, writingNonce, false);
    return;
  }

#ifdef HAVE_LIBEDIT
  string histfile = historyFile();
  {
    ifstream history(histfile);
    string line;
    while (getline(history, line)) {
      add_history(line.c_str());
    }
  }
  ofstream history(histfile, std::ios_base::app);
  string lastline;
  for (;;) {
    char* sline = readline("> ");
    rl_bind_key('\t', rl_complete);
    if (sline == nullptr) {
      break;
    }

    string line(sline);
    if (!line.empty() && line != lastline) {
      add_history(sline);
      history << sline << endl;
      history.flush();
    }
    lastline = line;
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory): readline
    free(sline);

    if (line == "quit") {
      break;
    }
    if (line == "help" || line == "?") {
      line = "help()";
    }

    /* no need to send an empty line to the server */
    if (line.empty()) {
      continue;
    }

    commandResult = sendMessageToServer(fileDesc.getHandle(), line, readingNonce, writingNonce, true);
    if (commandResult != ConsoleCommandResult::Valid) {
      break;
    }
  }
#else
  errlog("Client mode requested but libedit support is not available");
#endif /* HAVE_LIBEDIT */
}

#ifdef HAVE_LIBEDIT
static std::optional<std::string> getNextConsoleLine(ofstream& history, std::string& lastline)
{
  char* sline = readline("> ");
  rl_bind_key('\t', rl_complete);
  if (sline == nullptr) {
    return std::nullopt;
  }

  string line(sline);
  if (!line.empty() && line != lastline) {
    add_history(sline);
    history << sline << endl;
    history.flush();
  }

  lastline = line;
  // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory): readline
  free(sline);

  return line;
}
#else /* HAVE_LIBEDIT */
static std::optional<std::string> getNextConsoleLine()
{
  std::string line;
  if (!std::getline(std::cin, line)) {
    return std::nullopt;
  }
  return line;
}
#endif /* HAVE_LIBEDIT */

void doConsole()
{
#ifdef HAVE_LIBEDIT
  string histfile = historyFile(true);
  {
    ifstream history(histfile);
    string line;
    while (getline(history, line)) {
      add_history(line.c_str());
    }
  }
  ofstream history(histfile, std::ios_base::app);
  string lastline;
#endif /* HAVE_LIBEDIT */

  for (;;) {
#ifdef HAVE_LIBEDIT
    auto line = getNextConsoleLine(history, lastline);
#else /* HAVE_LIBEDIT */
    auto line = getNextConsoleLine();
#endif /* HAVE_LIBEDIT */
    if (!line) {
      break;
    }

    if (*line == "quit") {
      break;
    }
    if (*line == "help" || *line == "?") {
      line = "help()";
    }

    string response;
    try {
      bool withReturn = true;
    retry:;
      try {
        auto lua = g_lua.lock();
        g_outputBuffer.clear();
        resetLuaSideEffect();
        auto ret = lua->executeCode<
          boost::optional<
            boost::variant<
              string,
              shared_ptr<DownstreamState>,
              ClientState*,
              std::unordered_map<string, double>>>>(withReturn ? ("return " + *line) : *line);
        if (ret) {
          if (const auto* dsValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
            if (*dsValue) {
              cout << (*dsValue)->getName() << endl;
            }
          }
          else if (const auto* csValue = boost::get<ClientState*>(&*ret)) {
            if (*csValue != nullptr) {
              cout << (*csValue)->local.toStringWithPort() << endl;
            }
          }
          else if (const auto* strValue = boost::get<string>(&*ret)) {
            cout << *strValue << endl;
          }
          else if (const auto* mapValue = boost::get<std::unordered_map<string, double>>(&*ret)) {
            using namespace json11;
            Json::object obj;
            for (const auto& value : *mapValue) {
              obj[value.first] = value.second;
            }
            Json out = obj;
            cout << out.dump() << endl;
          }
        }
        else {
          cout << g_outputBuffer << std::flush;
        }

        if (!getLuaNoSideEffect()) {
          feedConfigDelta(*line);
        }
      }
      catch (const LuaContext::SyntaxErrorException&) {
        if (withReturn) {
          withReturn = false;
          // NOLINTNEXTLINE(cppcoreguidelines-avoid-goto)
          goto retry;
        }
        throw;
      }
    }
    catch (const LuaContext::WrongTypeException& e) {
      std::cerr << "Command returned an object we can't print: " << std::string(e.what()) << std::endl;
      // tried to return something we don't understand
    }
    catch (const LuaContext::ExecutionErrorException& e) {
      if (strcmp(e.what(), "invalid key to 'next'") == 0) {
        std::cerr << "Error parsing parameters, did you forget parameter name?";
      }
      else {
        std::cerr << e.what();
      }

      try {
        std::rethrow_if_nested(e);

        std::cerr << std::endl;
      }
      catch (const std::exception& ne) {
        // ne is the exception that was thrown from inside the lambda
        std::cerr << ": " << ne.what() << std::endl;
      }
      catch (const PDNSException& ne) {
        // ne is the exception that was thrown from inside the lambda
        std::cerr << ": " << ne.reason << std::endl;
      }
    }
    catch (const std::exception& e) {
      std::cerr << e.what() << std::endl;
    }
  }
}
}

#ifndef DISABLE_COMPLETION
/**** CARGO CULT CODE AHEAD ****/
static const std::vector<dnsdist::console::ConsoleKeyword> s_consoleKeywords{
  /* keyword, function, parameters, description */
  {"addACL", true, "netmask", "add to the ACL set who can use this server"},
  {"addAction", true, R"(DNS rule, DNS action [, {uuid="UUID", name="name"}])", "add a rule"},
  {"addBPFFilterDynBlocks", true, "addresses, dynbpf[[, seconds=10], msg]", "This is the eBPF equivalent of addDynBlocks(), blocking a set of addresses for (optionally) a number of seconds, using an eBPF dynamic filter"},
  {"addCapabilitiesToRetain", true, "capability or list of capabilities", "Linux capabilities to retain after startup, like CAP_BPF"},
  {"addConsoleACL", true, "netmask", "add a netmask to the console ACL"},
  {"addDNSCryptBind", true, R"('127.0.0.1:8443", "provider name", "/path/to/resolver.cert", "/path/to/resolver.key", {reusePort=false, tcpFastOpenQueueSize=0, interface="", cpus={}})", "listen to incoming DNSCrypt queries on 127.0.0.1 port 8443, with a provider name of `provider name`, using a resolver certificate and associated key stored respectively in the `resolver.cert` and `resolver.key` files. The fifth optional parameter is a table of parameters"},
  {"addDOHLocal", true, "addr, certFile, keyFile [, urls [, vars]]", "listen to incoming DNS over HTTPS queries on the specified address using the specified certificate and key. The last two parameters are tables"},
  {"addDOH3Local", true, "addr, certFile, keyFile [, vars]", "listen to incoming DNS over HTTP/3 queries on the specified address using the specified certificate and key. The last parameter is a table"},
  {"addDOQLocal", true, "addr, certFile, keyFile [, vars]", "listen to incoming DNS over QUIC queries on the specified address using the specified certificate and key. The last parameter is a table"},
  {"addDynamicBlock", true, "address, message[, action [, seconds [, clientIPMask [, clientIPPortMask]]]]", "block the supplied address with message `msg`, for `seconds` seconds (10 by default), applying `action` (default to the one set with `setDynBlocksAction()`)"},
  {"addDynBlocks", true, "addresses, message[, seconds[, action]]", "block the set of addresses with message `msg`, for `seconds` seconds (10 by default), applying `action` (default to the one set with `setDynBlocksAction()`)"},
  {"addDynBlockSMT", true, "names, message[, seconds [, action]]", "block the set of names with message `msg`, for `seconds` seconds (10 by default), applying `action` (default to the one set with `setDynBlocksAction()`)"},
  {"addLocal", true, R"(addr [, {doTCP=true, reusePort=false, tcpFastOpenQueueSize=0, interface="", cpus={}}])", "add `addr` to the list of addresses we listen on"},
  {"addCacheHitResponseAction", true, R"(DNS rule, DNS response action [, {uuid="UUID", name="name"}}])", "add a cache hit response rule"},
  {"addCacheInsertedResponseAction", true, R"(DNS rule, DNS response action [, {uuid="UUID", name="name"}}])", "add a cache inserted response rule"},
  {"addMaintenanceCallback", true, "callback", "register a function to be called as part of the maintenance hook, every second"},
  {"addExitCallback", true, "callback", "register a function to be called when DNSdist exits"},
  {"addResponseAction", true, R"(DNS rule, DNS response action [, {uuid="UUID", name="name"}}])", "add a response rule"},
  {"addSelfAnsweredResponseAction", true, R"(DNS rule, DNS response action [, {uuid="UUID", name="name"}}])", "add a self-answered response rule"},
  {"addXFRResponseAction", true, R"(DNS rule, DNS response action [, {uuid="UUID", name="name"}}])", "add a XFR response rule"},
  {"addTLSLocal", true, "addr, certFile(s), keyFile(s) [,params]", "listen to incoming DNS over TLS queries on the specified address using the specified certificate (or list of) and key (or list of). The last parameter is a table"},
  {"AllowAction", true, "", "let these packets go through"},
  {"AllowResponseAction", true, "", "let these packets go through"},
  {"AllRule", true, "", "matches all traffic"},
  {"AndRule", true, "list of DNS rules", "matches if all sub-rules matches"},
  {"benchRule", true, "DNS Rule [, iterations [, suffix]]", "bench the specified DNS rule"},
  {"carbonServer", true, "serverIP, [ourname], [interval]", "report statistics to serverIP using our hostname, or 'ourname' if provided, every 'interval' seconds"},
  {"clearConsoleHistory", true, "", "clear the internal (in-memory) history of console commands"},
  {"clearDynBlocks", true, "", "clear all dynamic blocks"},
  {"clearQueryCounters", true, "", "clears the query counter buffer"},
  {"clearRules", true, "", "remove all current rules"},
  {"controlSocket", true, "addr", "open a control socket on this address / connect to this address in client mode"},
  {"ContinueAction", true, "action", "execute the specified action and continue the processing of the remaining rules, regardless of the return of the action"},
  {"declareMetric", true, "name, type, description [, prometheusName]", "Declare a custom metric"},
  {"decMetric", true, "name", "Decrement a custom metric"},
  {"DelayAction", true, "milliseconds", "delay the response by the specified amount of milliseconds (UDP-only)"},
  {"DelayResponseAction", true, "milliseconds", "delay the response by the specified amount of milliseconds (UDP-only)"},
  {"delta", true, "", "shows all commands entered that changed the configuration"},
  {"DNSSECRule", true, "", "matches queries with the DO bit set"},
  {"DnstapLogAction", true, "identity, FrameStreamLogger [, alterFunction]", "send the contents of this query to a FrameStreamLogger or RemoteLogger as dnstap. `alterFunction` is a callback, receiving a DNSQuestion and a DnstapMessage, that can be used to modify the dnstap message"},
  {"DnstapLogResponseAction", true, "identity, FrameStreamLogger [, alterFunction]", "send the contents of this response to a remote or FrameStreamLogger or RemoteLogger as dnstap. `alterFunction` is a callback, receiving a DNSResponse and a DnstapMessage, that can be used to modify the dnstap message"},
  {"DropAction", true, "", "drop these packets"},
  {"DropResponseAction", true, "", "drop these packets"},
  {"DSTPortRule", true, "port", "matches questions received to the destination port specified"},
  {"dumpStats", true, "", "print all statistics we gather"},
  {"dynBlockRulesGroup", true, "", "return a new DynBlockRulesGroup object"},
  {"EDNSVersionRule", true, "version", "matches queries with the specified EDNS version"},
  {"EDNSOptionRule", true, "optcode", "matches queries with the specified EDNS0 option present"},
  {"enableLuaConfiguration", true, "", "Enable using Lua configuration directives along with a YAML configuration file. It is strongly advised not to use this directive unless absolutely necessary, and to prefer doing all the configuration in either Lua or YAML"},
  {"ERCodeAction", true, "ercode", "Reply immediately by turning the query into a response with the specified EDNS extended rcode"},
  {"ERCodeRule", true, "rcode", "matches responses with the specified extended rcode (EDNS0)"},
  {"exceedNXDOMAINs", true, "rate, seconds", "get set of addresses that exceed `rate` NXDOMAIN/s over `seconds` seconds"},
  {"exceedQRate", true, "rate, seconds", "get set of address that exceed `rate` queries/s over `seconds` seconds"},
  {"exceedQTypeRate", true, "type, rate, seconds", "get set of address that exceed `rate` queries/s for queries of type `type` over `seconds` seconds"},
  {"exceedRespByterate", true, "rate, seconds", "get set of addresses that exceeded `rate` bytes/s answers over `seconds` seconds"},
  {"exceedServFails", true, "rate, seconds", "get set of addresses that exceed `rate` servfails/s over `seconds` seconds"},
  {"firstAvailable", false, "", "picks the server with the lowest `order` that has not exceeded its QPS limit"},
  {"fixupCase", true, "bool", "if set (default to no), rewrite the first qname of the question part of the answer to match the one from the query. It is only useful when you have a downstream server that messes up the case of the question qname in the answer"},
  {"generateDNSCryptCertificate", true, R"("/path/to/providerPrivate.key", "/path/to/resolver.cert", "/path/to/resolver.key", serial, validFrom, validUntil)", "generate a new resolver private key and related certificate, valid from the `validFrom` timestamp until the `validUntil` one, signed with the provider private key"},
  {"generateDNSCryptProviderKeys", true, R"("/path/to/providerPublic.key", "/path/to/providerPrivate.key")", "generate a new provider keypair"},
  {"getAction", true, "n", "Returns the Action associated with rule n"},
  {"getBind", true, "n", "returns the listener at index n"},
  {"getBindCount", true, "", "returns the number of listeners all kinds"},
  {"getCacheHitResponseRule", true, "selector", "Return the cache-hit response rule corresponding to the selector, if any"},
  {"getCacheInsertedResponseRule", true, "selector", "Return the cache-inserted response rule corresponding to the selector, if any"},
  {"getCurrentTime", true, "", "returns the current time"},
  {"getDynamicBlocks", true, "", "returns a table of the current network-based dynamic blocks"},
  {"getDynamicBlocksSMT", true, "", "returns a table of the current suffix-based dynamic blocks"},
  {"getDNSCryptBind", true, "n", "return the `DNSCryptContext` object corresponding to the bind `n`"},
  {"getDNSCryptBindCount", true, "", "returns the number of DNSCrypt listeners"},
  {"getDOHFrontend", true, "n", "returns the DoH frontend with index n"},
  {"getDOHFrontendCount", true, "", "returns the number of DoH listeners"},
  {"getDOH3Frontend", true, "n", "returns the DoH3 frontend with index n"},
  {"getDOH3FrontendCount", true, "", "returns the number of DoH3 listeners"},
  {"getDOQFrontend", true, "n", "returns the DoQ frontend with index n"},
  {"getDOQFrontendCount", true, "", "returns the number of DoQ listeners"},
  {"getListOfAddressesOfNetworkInterface", true, "itf", "returns the list of addresses configured on a given network interface, as strings"},
  {"getListOfNetworkInterfaces", true, "", "returns the list of network interfaces present on the system, as strings"},
  {"getListOfRangesOfNetworkInterface", true, "itf", "returns the list of network ranges configured on a given network interface, as strings"},
  {"getMACAddress", true, "IP addr", "return the link-level address (MAC) corresponding to the supplied neighbour  IP address, if known by the kernel"},
  {"getMetric", true, "name", "Get the value of a custom metric"},
  {"getOutgoingTLSSessionCacheSize", true, "", "returns the number of TLS sessions (for outgoing connections) currently cached"},
  {"getPool", true, "name", "return the pool named `name`, or \"\" for the default pool"},
  {"getPoolServers", true, "pool", "return servers part of this pool"},
  {"getPoolNames", true, "", "returns a table with all the pool names"},
  {"getQueryCounters", true, "[max=10]", "show current buffer of query counters, limited by 'max' if provided"},
  {"getResponseRing", true, "", "return the current content of the response ring"},
  {"getResponseRule", true, "selector", "Return the response rule corresponding to the selector, if any"},
  {"getRespRing", true, "", "return the qname/rcode content of the response ring"},
  {"getRule", true, "selector", "Return the rule corresponding to the selector, if any"},
  {"getSelfAnsweredResponseRule", true, "selector", "Return the self-answered response rule corresponding to the selector, if any"},
  {"getServer", true, "id", "returns server with index 'n' or whose uuid matches if 'id' is an UUID string"},
  {"getServers", true, "", "returns a table with all defined servers"},
  {"getStatisticsCounters", true, "", "returns a map of statistic counters"},
  {"getTopCacheHitResponseRules", true, "[top]", "return the `top` cache-hit response rules"},
  {"getTopCacheInsertedResponseRules", true, "[top]", "return the `top` cache-inserted response rules"},
  {"getTopResponseRules", true, "[top]", "return the `top` response rules"},
  {"getTopRules", true, "[top]", "return the `top` rules"},
  {"getTopSelfAnsweredResponseRules", true, "[top]", "return the `top` self-answered response rules"},
  {"getTopXFRResponseRules", true, "[top]", "return the `top` XFR response rules"},
  {"getTLSFrontend", true, "n", "returns the TLS frontend with index n"},
  {"getTLSFrontendCount", true, "", "returns the number of DoT listeners"},
  {"getVerbose", true, "", "get whether log messages at the verbose level will be logged"},
  {"getXFRResponseRule", true, "selector", "Return the XFR response rule corresponding to the selector, if any"},
  {"grepq", true, R"(Netmask|DNS Name|100ms|{"::1", "powerdns.com", "100ms"} [, n] [,options])", "shows the last n queries and responses matching the specified client address or range (Netmask), or the specified DNS Name, or slower than 100ms"},
  {"hashPassword", true, "password [, workFactor]", "Returns a hashed and salted version of the supplied password, usable with 'setWebserverConfig()'"},
  {"HTTPHeaderRule", true, "name, regex", "matches DoH queries with a HTTP header 'name' whose content matches the regular expression 'regex'"},
  {"HTTPPathRegexRule", true, "regex", "matches DoH queries whose HTTP path matches 'regex'"},
  {"HTTPPathRule", true, "path", "matches DoH queries whose HTTP path is an exact match to 'path'"},
  {"HTTPStatusAction", true, "status, reason, body", "return an HTTP response"},
  {"inClientStartup", true, "", "returns true during console client parsing of configuration"},
  {"includeDirectory", true, "path", "include configuration files from `path`"},
  {"incMetric", true, "name", "Increment a custom metric"},
  {"KeyValueLookupKeyQName", true, "[wireFormat]", "Return a new KeyValueLookupKey object that, when passed to KeyValueStoreLookupAction or KeyValueStoreLookupRule, will return the qname of the query, either in wire format (default) or in plain text if 'wireFormat' is false"},
  {"KeyValueLookupKeySourceIP", true, "[v4Mask [, v6Mask [, includePort]]]", "Return a new KeyValueLookupKey object that, when passed to KeyValueStoreLookupAction or KeyValueStoreLookupRule, will return the (possibly bitmasked) source IP of the client in network byte-order."},
  {"KeyValueLookupKeySuffix", true, "[minLabels [,wireFormat]]", "Return a new KeyValueLookupKey object that, when passed to KeyValueStoreLookupAction or KeyValueStoreLookupRule, will return a vector of keys based on the labels of the qname in DNS wire format or plain text"},
  {"KeyValueLookupKeyTag", true, "tag", "Return a new KeyValueLookupKey object that, when passed to KeyValueStoreLookupAction or KeyValueStoreLookupRule, will return the value of the corresponding tag for this query, if it exists"},
  {"KeyValueStoreLookupAction", true, "kvs, lookupKey, destinationTag", "does a lookup into the key value store referenced by 'kvs' using the key returned by 'lookupKey', and storing the result if any into the tag named 'destinationTag'"},
  {"KeyValueStoreRangeLookupAction", true, "kvs, lookupKey, destinationTag", "does a range-based lookup into the key value store referenced by 'kvs' using the key returned by 'lookupKey', and storing the result if any into the tag named 'destinationTag'"},
  {"KeyValueStoreLookupRule", true, "kvs, lookupKey", "matches queries if the key is found in the specified Key Value store"},
  {"KeyValueStoreRangeLookupRule", true, "kvs, lookupKey", "matches queries if the key is found in the specified Key Value store"},
  {"leastOutstanding", false, "", "Send traffic to downstream server with least outstanding queries, with the lowest 'order', and within that the lowest recent latency"},
#if defined(HAVE_LIBSSL) && !defined(HAVE_TLS_PROVIDERS)
  {"loadTLSEngine", true, "engineName [, defaultString]", "Load the OpenSSL engine named 'engineName', setting the engine default string to 'defaultString' if supplied"},
#endif
#if defined(HAVE_LIBSSL) && OPENSSL_VERSION_MAJOR >= 3 && defined(HAVE_TLS_PROVIDERS)
  {"loadTLSProvider", true, "providerName", "Load the OpenSSL provider named 'providerName'"},
#endif
  {"LogAction", true, "[filename], [binary], [append], [buffered]", "Log a line for each query, to the specified file if any, to the console (require verbose) otherwise. When logging to a file, the `binary` optional parameter specifies whether we log in binary form (default) or in textual form, the `append` optional parameter specifies whether we open the file for appending or truncate each time (default), and the `buffered` optional parameter specifies whether writes to the file are buffered (default) or not."},
  {"LogResponseAction", true, "[filename], [append], [buffered]", "Log a line for each response, to the specified file if any, to the console (require verbose) otherwise. The `append` optional parameter specifies whether we open the file for appending or truncate each time (default), and the `buffered` optional parameter specifies whether writes to the file are buffered (default) or not."},
  {"LuaAction", true, "function", "Invoke a Lua function that accepts a DNSQuestion"},
  {"LuaFFIAction", true, "function", "Invoke a Lua FFI function that accepts a DNSQuestion"},
  {"LuaFFIPerThreadAction", true, "function", "Invoke a Lua FFI function that accepts a DNSQuestion, with a per-thread Lua context"},
  {"LuaFFIPerThreadResponseAction", true, "function", "Invoke a Lua FFI function that accepts a DNSResponse, with a per-thread Lua context"},
  {"LuaFFIResponseAction", true, "function", "Invoke a Lua FFI function that accepts a DNSResponse"},
  {"LuaFFIRule", true, "function", "Invoke a Lua FFI function that filters DNS questions"},
  {"LuaResponseAction", true, "function", "Invoke a Lua function that accepts a DNSResponse"},
  {"LuaRule", true, "function", "Invoke a Lua function that filters DNS questions"},
#ifdef HAVE_IPCIPHER
  {"makeIPCipherKey", true, "password", "generates a 16-byte key that can be used to pseudonymize IP addresses with IP cipher"},
#endif /* HAVE_IPCIPHER */
  {"makeKey", true, "", "generate a new server access key, emit configuration line ready for pasting"},
  {"makeRule", true, "rule", "Make a NetmaskGroupRule() or a SuffixMatchNodeRule(), depending on how it is called"},
  {"MaxQPSIPRule", true, "qps, [v4Mask=32 [, v6Mask=64 [, burst=qps [, expiration=300 [, cleanupDelay=60 [, scanFraction=10 [, shards=10]]]]]]]", "matches traffic exceeding the qps limit per subnet"},
  {"MaxQPSRule", true, "qps", "matches traffic **not** exceeding this qps limit"},
  {"mvCacheHitResponseRule", true, "from, to", "move cache hit response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule"},
  {"mvCacheHitResponseRuleToTop", true, "", "move the last cache hit response rule to the first position"},
  {"mvCacheInsertedResponseRule", true, "from, to", "move cache inserted response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule"},
  {"mvCacheInsertedResponseRuleToTop", true, "", "move the last cache inserted response rule to the first position"},
  {"mvResponseRule", true, "from, to", "move response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule"},
  {"mvResponseRuleToTop", true, "", "move the last response rule to the first position"},
  {"mvRule", true, "from, to", "move rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule, in which case the rule will be moved to the last position"},
  {"mvRuleToTop", true, "", "move the last rule to the first position"},
  {"mvSelfAnsweredResponseRule", true, "from, to", "move self-answered response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule"},
  {"mvSelfAnsweredResponseRuleToTop", true, "", "move the last self-answered response rule to the first position"},
  {"mvXFRResponseRule", true, "from, to", "move XFR response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule"},
  {"mvXFRResponseRuleToTop", true, "", "move the last XFR response rule to the first position"},
  {"NetmaskGroupRule", true, "nmg[, src]", "Matches traffic from/to the network range specified in nmg. Set the src parameter to false to match nmg against destination address instead of source address. This can be used to differentiate between clients"},
  {"newBPFFilter", true, "{ipv4MaxItems=int, ipv4PinnedPath=string, ipv6MaxItems=int, ipv6PinnedPath=string, cidr4MaxItems=int, cidr4PinnedPath=string, cidr6MaxItems=int, cidr6PinnedPath=string, qnamesMaxItems=int, qnamesPinnedPath=string, external=bool}", "Return a new eBPF socket filter with specified options."},
  {"newCA", true, "address", "Returns a ComboAddress based on `address`"},
#ifdef HAVE_CDB
  {"newCDBKVStore", true, "fname, refreshDelay", "Return a new KeyValueStore object associated to the corresponding CDB database"},
#endif
  {"newDNSName", true, "name", "make a DNSName based on this .-terminated name"},
  {"newDNSNameSet", true, "", "returns a new DNSNameSet"},
  {"newDynBPFFilter", true, "bpf", "Return a new dynamic eBPF filter associated to a given BPF Filter"},
  {"newFrameStreamTcpLogger", true, "addr [, options]", "create a FrameStream logger object writing to a TCP address (addr should be ip:port), to use with `DnstapLogAction()` and `DnstapLogResponseAction()`"},
  {"newFrameStreamUnixLogger", true, "socket [, options]", "create a FrameStream logger object writing to a local unix socket, to use with `DnstapLogAction()` and `DnstapLogResponseAction()`"},
#ifdef HAVE_LMDB
  {"newLMDBKVStore", true, "fname, dbName [, noLock]", "Return a new KeyValueStore object associated to the corresponding LMDB database"},
#endif
  {"newNMG", true, "", "Returns a NetmaskGroup"},
  {"newPacketCache", true, "maxEntries[, maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=false, numberOfShards=1, deferrableInsertLock=true, options={}]", "return a new Packet Cache"},
  {"newQPSLimiter", true, "rate, burst", "configure a QPS limiter with that rate and that burst capacity"},
  {"newRemoteLogger", true, "address:port [, timeout=2, maxQueuedEntries=100, reconnectWaitTime=1]", "create a Remote Logger object, to use with `RemoteLogAction()` and `RemoteLogResponseAction()`"},
  {"newRuleAction", true, R"(DNS rule, DNS action [, {uuid="UUID", name="name"}])", "return a pair of DNS Rule and DNS Action, to be used with `setRules()`"},
  {"newServer", true, R"({address="ip:port", qps=1000, order=1, weight=10, pool="abuse", retries=5, udpTimeout=0, tcpConnectTimeout=5, tcpSendTimeout=30, tcpRecvTimeout=30, checkName="a.root-servers.net.", checkType="A", maxCheckFailures=1, mustResolve=false, useClientSubnet=true, source="address|interface name|address@interface", sockets=1, reconnectOnUp=false})", "instantiate a server"},
  {"newServerPolicy", true, "name, function", "create a policy object from a Lua function"},
  {"newSuffixMatchNode", true, "", "returns a new SuffixMatchNode"},
  {"newSVCRecordParameters", true, "priority, target, mandatoryParams, alpns, noDefaultAlpn [, port [, ech [, ipv4hints [, ipv6hints [, additionalParameters ]]]]]", "return a new SVCRecordParameters object, to use with SpoofSVCAction"},
  {"NegativeAndSOAAction", true, "nxd, zone, ttl, mname, rname, serial, refresh, retry, expire, minimum [, options]", "Turn a query into a NXDomain or NoData answer and sets a SOA record in the additional section"},
  {"NoneAction", true, "", "Does nothing. Subsequent rules are processed after this action"},
  {"NotRule", true, "selector", "Matches the traffic if the selector rule does not match"},
  {"OpcodeRule", true, "code", "Matches queries with opcode code. code can be directly specified as an integer, or one of the built-in DNSOpcodes"},
  {"OrRule", true, "selectors", "Matches the traffic if one or more of the the selectors rules does match"},
  {"PoolAction", true, "poolname [, stop]", "set the packet into the specified pool"},
  {"PoolAvailableRule", true, "poolname", "Check whether a pool has any servers available to handle queries"},
  {"PoolOutstandingRule", true, "poolname, limit", "Check whether a pool has outstanding queries above limit"},
  {"printDNSCryptProviderFingerprint", true, R"("/path/to/providerPublic.key")", "display the fingerprint of the provided resolver public key"},
  {"ProbaRule", true, "probability", "Matches queries with a given probability. 1.0 means always"},
  {"ProxyProtocolValueRule", true, "type [, value]", "matches queries with a specified Proxy Protocol TLV value of that type, optionally matching the content of the option as well"},
  {"QClassRule", true, "qclass", "Matches queries with the specified qclass. class can be specified as an integer or as one of the built-in DNSClass"},
  {"QNameLabelsCountRule", true, "min, max", "matches if the qname has less than `min` or more than `max` labels"},
  {"QNameRule", true, "qname", "matches queries with the specified qname"},
  {"QNameSetRule", true, "set", "Matches if the set contains exact qname"},
  {"QNameWireLengthRule", true, "min, max", "matches if the qname's length on the wire is less than `min` or more than `max` bytes"},
  {"QPSAction", true, "maxqps", "Drop a packet if it does exceed the maxqps queries per second limits. Letting the subsequent rules apply otherwise"},
  {"QPSPoolAction", true, "maxqps, poolname [, stop]", "Send the packet into the specified pool only if it does not exceed the maxqps queries per second limits. Letting the subsequent rules apply otherwise"},
  {"QTypeRule", true, "qtype", "matches queries with the specified qtype"},
  {"RCodeAction", true, "rcode", "Reply immediately by turning the query into a response with the specified rcode"},
  {"RCodeRule", true, "rcode", "matches responses with the specified rcode"},
  {"RDRule", true, "", "Matches queries with the RD flag set"},
  {"RecordsCountRule", true, "section, minCount, maxCount", "Matches if there is at least minCount and at most maxCount records in the section section. section can be specified as an integer or as a DNS Packet Sections"},
  {"RecordsTypeCountRule", true, "section, qtype, minCount, maxCount", "Matches if there is at least minCount and at most maxCount records of type type in the section section"},
  {"RegexRule", true, "regex", "matches the query name against the supplied regex"},
  {"registerDynBPFFilter", true, "DynBPFFilter", "register this dynamic BPF filter into the web interface so that its counters are displayed"},
  {"reloadAllCertificates", true, "", "reload all DNSCrypt and TLS certificates, along with their associated keys"},
  {"RemoteLogAction", true, "RemoteLogger [, alterFunction [, serverID]]", "send the content of this query to a remote logger via Protocol Buffer. `alterFunction` is a callback, receiving a DNSQuestion and a DNSDistProtoBufMessage, that can be used to modify the Protocol Buffer content, for example for anonymization purposes. `serverID` is the server identifier."},
  {"RemoteLogResponseAction", true, "RemoteLogger [,alterFunction [,includeCNAME [, serverID]]]", "send the content of this response to a remote logger via Protocol Buffer. `alterFunction` is the same callback than the one in `RemoteLogAction` and `includeCNAME` indicates whether CNAME records inside the response should be parsed and exported. The default is to only exports A and AAAA records. `serverID` is the server identifier."},
  {"requestTCPStatesDump", true, "", "Request a dump of the TCP states (incoming connections, outgoing connections) during the next scan. Useful for debugging purposes only"},
  {"rmACL", true, "netmask", "remove netmask from ACL"},
  {"rmCacheHitResponseRule", true, "id", "remove cache hit response rule in position 'id', or whose uuid matches if 'id' is an UUID string, or finally whose name matches if 'id' is a string but not a valid UUID"},
  {"rmCacheInsertedResponseRule", true, "id", "remove cache inserted response rule in position 'id', or whose uuid matches if 'id' is an UUID string, or finally whose name matches if 'id' is a string but not a valid UUID"},
  {"rmResponseRule", true, "id", "remove response rule in position 'id', or whose uuid matches if 'id' is an UUID string, or finally whose name matches if 'id' is a string but not a valid UUID"},
  {"rmRule", true, "id", "remove rule in position 'id', or whose uuid matches if 'id' is an UUID string, or finally whose name matches if 'id' is a string but not a valid UUID"},
  {"rmSelfAnsweredResponseRule", true, "id", "remove self-answered response rule in position 'id', or whose uuid matches if 'id' is an UUID string, or finally whose name matches if 'id' is a string but not a valid UUID"},
  {"rmServer", true, "id", "remove server with index 'id' or whose uuid matches if 'id' is an UUID string"},
  {"rmXFRResponseRule", true, "id", "remove XFR response rule in position 'id', or whose uuid matches if 'id' is an UUID string, or finally whose name matches if 'id' is a string but not a valid UUID"},
  {"roundrobin", false, "", "Simple round robin over available servers"},
  {"sendCustomTrap", true, "str", "send a custom `SNMP` trap from Lua, containing the `str` string"},
  {"setACL", true, "{netmask, netmask}", "replace the ACL set with these netmasks. Use `setACL({})` to reset the list, meaning no one can use us"},
  {"setACLFromFile", true, "file", "replace the ACL set with netmasks in this file"},
  {"setAddEDNSToSelfGeneratedResponses", true, "add", "set whether to add EDNS to self-generated responses, provided that the initial query had EDNS"},
  {"setAllowEmptyResponse", true, "allow", "Set to true (defaults to false) to allow empty responses (qdcount=0) with a NoError or NXDomain rcode (default) from backends"},
  {"setAPIWritable", true, "bool, dir", "allow modifications via the API. if `dir` is set, it must be a valid directory where the configuration files will be written by the API"},
  {"setCacheCleaningDelay", true, "num", "Set the interval in seconds between two runs of the cache cleaning algorithm, removing expired entries"},
  {"setCacheCleaningPercentage", true, "num", "Set the percentage of the cache that the cache cleaning algorithm will try to free by removing expired entries. By default (100), all expired entries are remove"},
  {"setConsistentHashingBalancingFactor", true, "factor", "Set the balancing factor for bounded-load consistent hashing"},
  {"setConsoleACL", true, "{netmask, netmask}", "replace the console ACL set with these netmasks"},
  {"setConsoleConnectionsLogging", true, "enabled", "whether to log the opening and closing of console connections"},
  {"setConsoleMaximumConcurrentConnections", true, "max", "Set the maximum number of concurrent console connections"},
  {"setConsoleOutputMaxMsgSize", true, "messageSize", "set console message maximum size in bytes, default is 10 MB"},
  {"setDefaultBPFFilter", true, "filter", "When used at configuration time, the corresponding BPFFilter will be attached to every bind"},
  {"setDoHDownstreamCleanupInterval", true, "interval", "minimum interval in seconds between two cleanups of the idle DoH downstream connections"},
  {"setDoHDownstreamMaxIdleTime", true, "time", "Maximum time in seconds that a downstream DoH connection to a backend might stay idle"},
  {"setDynBlocksAction", true, "action", "set which action is performed when a query is blocked. Only DNSAction.Drop (the default) and DNSAction.Refused are supported"},
  {"setDynBlocksPurgeInterval", true, "sec", "set how often the expired dynamic block entries should be removed"},
  {"setDropEmptyQueries", true, "drop", "Whether to drop empty queries right away instead of sending a NOTIMP response"},
  {"setECSOverride", true, "bool", "whether to override an existing EDNS Client Subnet value in the query"},
  {"setECSSourcePrefixV4", true, "prefix-length", "the EDNS Client Subnet prefix-length used for IPv4 queries"},
  {"setECSSourcePrefixV6", true, "prefix-length", "the EDNS Client Subnet prefix-length used for IPv6 queries"},
  {"setKey", true, "key", "set access key to that key"},
  {"setLocal", true, R"(addr [, {doTCP=true, reusePort=false, tcpFastOpenQueueSize=0, interface="", cpus={}}])", "reset the list of addresses we listen on to this address"},
  {"setMaxCachedDoHConnectionsPerDownstream", true, "max", "Set the maximum number of inactive DoH connections to a backend cached by each worker DoH thread"},
  {"setMaxCachedTCPConnectionsPerDownstream", true, "max", "Set the maximum number of inactive TCP connections to a backend cached by each worker TCP thread"},
  {"setMaxTCPClientThreads", true, "n", "set the maximum of TCP client threads, handling TCP connections"},
  {"setMaxTCPConnectionDuration", true, "n", "set the maximum duration of an incoming TCP connection, in seconds. 0 means unlimited"},
  {"setMaxTCPConnectionsPerClient", true, "n", "set the maximum number of TCP connections per client. 0 means unlimited"},
  {"setMaxTCPQueriesPerConnection", true, "n", "set the maximum number of queries in an incoming TCP connection. 0 means unlimited"},
  {"setMaxTCPQueuedConnections", true, "n", "set the maximum number of TCP connections queued (waiting to be picked up by a client thread)"},
  {"setMaxUDPOutstanding", true, "n", "set the maximum number of outstanding UDP queries to a given backend server. This can only be set at configuration time and defaults to 65535"},
  {"setMetric", true, "name, value", "Set the value of a custom metric to the supplied value"},
  {"setPayloadSizeOnSelfGeneratedAnswers", true, "payloadSize", "set the UDP payload size advertised via EDNS on self-generated responses"},
  {"setPoolServerPolicy", true, "policy, pool", "set the server selection policy for this pool to that policy"},
  {"setPoolServerPolicyLua", true, "name, function, pool", "set the server selection policy for this pool to one named 'name' and provided by 'function'"},
  {"setPoolServerPolicyLuaFFI", true, "name, function, pool", "set the server selection policy for this pool to one named 'name' and provided by 'function'"},
  {"setPoolServerPolicyLuaFFIPerThread", true, "name, code", "set server selection policy for this pool to one named 'name' and returned by the Lua FFI code passed in 'code'"},
  {"setProxyProtocolACL", true, "{netmask, netmask}", "Set the netmasks who are allowed to send Proxy Protocol headers in front of queries/connections"},
  {"setProxyProtocolApplyACLToProxiedClients", true, "apply", "Whether the general ACL should be applied to the source IP address gathered from a Proxy Protocol header, in addition to being first applied to the source address seen by dnsdist"},
  {"setProxyProtocolMaximumPayloadSize", true, "max", "Set the maximum size of a Proxy Protocol payload, in bytes"},
  {"setQueryCount", true, "bool", "set whether queries should be counted"},
  {"setQueryCountFilter", true, "func", "filter queries that would be counted, where `func` is a function with parameter `dq` which decides whether a query should and how it should be counted"},
  {"SetReducedTTLResponseAction", true, "percentage", "Reduce the TTL of records in a response to a given percentage"},
  {"setRingBuffersLockRetries", true, "n", "set the number of attempts to get a non-blocking lock to a ringbuffer shard before blocking"},
  {"setRingBuffersOptions", true, "{ lockRetries=int, recordQueries=true, recordResponses=true }", "set ringbuffer options"},
  {"setRingBuffersSize", true, "n [, numberOfShards]", "set the capacity of the ringbuffers used for live traffic inspection to `n`, and optionally the number of shards to use to `numberOfShards`"},
  {"setRoundRobinFailOnNoServer", true, "value", "By default the roundrobin load-balancing policy will still try to select a backend even if all backends are currently down. Setting this to true will make the policy fail and return that no server is available instead"},
  {"setRules", true, "list of rules", "replace the current rules with the supplied list of pairs of DNS Rules and DNS Actions (see `newRuleAction()`)"},
  {"setSecurityPollInterval", true, "n", "set the security polling interval to `n` seconds"},
  {"setSecurityPollSuffix", true, "suffix", "set the security polling suffix to the specified value"},
  {"setServerPolicy", true, "policy", "set server selection policy to that policy"},
  {"setServerPolicyLua", true, "name, function", "set server selection policy to one named 'name' and provided by 'function'"},
  {"setServerPolicyLuaFFI", true, "name, function", "set server selection policy to one named 'name' and provided by the Lua FFI 'function'"},
  {"setServerPolicyLuaFFIPerThread", true, "name, code", "set server selection policy to one named 'name' and returned by the Lua FFI code passed in 'code'"},
  {"setServFailWhenNoServer", true, "bool", "if set, return a ServFail when no servers are available, instead of the default behaviour of dropping the query"},
  {"setStaleCacheEntriesTTL", true, "n", "allows using cache entries expired for at most n seconds when there is no backend available to answer for a query"},
  {"setStructuredLogging", true, "value [, options]", "set whether log messages should be in structured-logging-like format"},
  {"setSyslogFacility", true, "facility", "set the syslog logging facility to 'facility'. Defaults to LOG_DAEMON"},
  {"setTCPDownstreamCleanupInterval", true, "interval", "minimum interval in seconds between two cleanups of the idle TCP downstream connections"},
  {"setTCPFastOpenKey", true, "string", "TCP Fast Open Key"},
  {"setTCPDownstreamMaxIdleTime", true, "time", "Maximum time in seconds that a downstream TCP connection to a backend might stay idle"},
  {"setTCPInternalPipeBufferSize", true, "size", "Set the size in bytes of the internal buffer of the pipes used internally to distribute connections to TCP (and DoT) workers threads"},
  {"setTCPRecvTimeout", true, "n", "set the read timeout on TCP connections from the client, in seconds"},
  {"setTCPSendTimeout", true, "n", "set the write timeout on TCP connections from the client, in seconds"},
  {"setUDPMultipleMessagesVectorSize", true, "n", "set the size of the vector passed to recvmmsg() to receive UDP messages. Default to 1 which means that the feature is disabled and recvmsg() is used instead"},
  {"setUDPSocketBufferSizes", true, "recv, send", "Set the size of the receive (SO_RCVBUF) and send (SO_SNDBUF) buffers for incoming UDP sockets"},
  {"setUDPTimeout", true, "n", "set the maximum time dnsdist will wait for a response from a backend over UDP, in seconds"},
  {"setVerbose", true, "bool", "set whether log messages at the verbose level will be logged"},
  {"setVerboseHealthChecks", true, "bool", "set whether health check errors will be logged"},
  {"setVerboseLogDestination", true, "destination file", "Set a destination file to write the 'verbose' log messages to, instead of sending them to syslog and/or the standard output"},
  {"setWebserverConfig", true, "[{password=string, apiKey=string, customHeaders, statsRequireAuthentication}]", "Updates webserver configuration"},
  {"setWeightedBalancingFactor", true, "factor", "Set the balancing factor for bounded-load weighted policies (whashed, wrandom)"},
  {"setWHashedPertubation", true, "value", "Set the hash perturbation value to be used in the whashed policy instead of a random one, allowing to have consistent whashed results on different instance"},
  {"show", true, "string", "outputs `string`"},
  {"showACL", true, "", "show our ACL set"},
  {"showBinds", true, "", "show listening addresses (frontends)"},
  {"showCacheHitResponseRules", true, "[{showUUIDs=false, truncateRuleWidth=-1}]", "show all defined cache hit response rules, optionally with their UUIDs and optionally truncated to a given width"},
  {"showConsoleACL", true, "", "show our current console ACL set"},
  {"showDNSCryptBinds", true, "", "display the currently configured DNSCrypt binds"},
  {"showDOHFrontends", true, "", "list all the available DOH frontends"},
  {"showDOH3Frontends", true, "", "list all the available DOH3 frontends"},
  {"showDOHResponseCodes", true, "", "show the HTTP response code statistics for the DoH frontends"},
  {"showDOQFrontends", true, "", "list all the available DOQ frontends"},
  {"showDynBlocks", true, "", "show dynamic blocks in force"},
  {"showPools", true, "", "show the available pools"},
  {"showPoolServerPolicy", true, "pool", "show server selection policy for this pool"},
  {"showResponseLatency", true, "", "show a plot of the response time latency distribution"},
  {"showResponseRules", true, "[{showUUIDs=false, truncateRuleWidth=-1}]", "show all defined response rules, optionally with their UUIDs and optionally truncated to a given width"},
  {"showRules", true, "[{showUUIDs=false, truncateRuleWidth=-1}]", "show all defined rules, optionally with their UUIDs and optionally truncated to a given width"},
  {"showSecurityStatus", true, "", "Show the security status"},
  {"showSelfAnsweredResponseRules", true, "[{showUUIDs=false, truncateRuleWidth=-1}]", "show all defined self-answered response rules, optionally with their UUIDs and optionally truncated to a given width"},
  {"showServerPolicy", true, "", "show name of currently operational server selection policy"},
  {"showServers", true, "[{showUUIDs=false}]", "output all servers, optionally with their UUIDs"},
  {"showTCPStats", true, "", "show some statistics regarding TCP"},
  {"showTLSErrorCounters", true, "", "show metrics about TLS handshake failures"},
  {"showTLSFrontends", true, "", "list all the available TLS contexts"},
  {"showVersion", true, "", "show the current version"},
  {"showWebserverConfig", true, "", "Show the current webserver configuration"},
  {"shutdown", true, "", "shut down `dnsdist`"},
  {"snmpAgent", true, "enableTraps [, daemonSocket]", "enable `SNMP` support. `enableTraps` is a boolean indicating whether traps should be sent and `daemonSocket` an optional string specifying how to connect to the daemon agent"},
  {"SetAdditionalProxyProtocolValueAction", true, "type, value", "Add a Proxy Protocol TLV value of this type"},
  {"SetDisableECSAction", true, "", "Disable the sending of ECS to the backend. Subsequent rules are processed after this action."},
  {"SetDisableValidationAction", true, "", "set the CD bit in the question, let it go through"},
  {"SetECSAction", true, "v4[, v6]", "Set the ECS prefix and prefix length sent to backends to an arbitrary value"},
  {"SetECSOverrideAction", true, "override", "Whether an existing EDNS Client Subnet value should be overridden (true) or not (false). Subsequent rules are processed after this action"},
  {"SetECSPrefixLengthAction", true, "v4, v6", "Set the ECS prefix length. Subsequent rules are processed after this action"},
  {"SetMacAddrAction", true, "option", "Add the source MAC address to the query as EDNS0 option option. This action is currently only supported on Linux. Subsequent rules are processed after this action"},
  {"SetEDNSOptionAction", true, "option, data", "Add arbitrary EDNS option and data to the query. Subsequent rules are processed after this action"},
  {"SetExtendedDNSErrorAction", true, "infoCode [, extraText]", "Set an Extended DNS Error status that will be added to the response corresponding to the current query. Subsequent rules are processed after this action"},
  {"SetExtendedDNSErrorResponseAction", true, "infoCode [, extraText]", "Set an Extended DNS Error status that will be added to this response. Subsequent rules are processed after this action"},
  {"SetNoRecurseAction", true, "", "strip RD bit from the question, let it go through"},
  {"setOutgoingDoHWorkerThreads", true, "n", "Number of outgoing DoH worker threads"},
  {"SetProxyProtocolValuesAction", true, "values", "Set the Proxy-Protocol values for this queries to 'values'"},
  {"SetSkipCacheAction", true, "", "Don’t lookup the cache for this query, don’t store the answer"},
  {"SetSkipCacheResponseAction", true, "", "Don’t store this response into the cache"},
  {"SetTagAction", true, "name, value", "set the tag named 'name' to the given value"},
  {"SetTagResponseAction", true, "name, value", "set the tag named 'name' to the given value"},
  {"SetTempFailureCacheTTLAction", true, "ttl", "set packetcache TTL for temporary failure replies"},
  {"SNIRule", true, "name", "Create a rule which matches on the incoming TLS SNI value, if any (DoT or DoH)"},
  {"SNMPTrapAction", true, "[reason]", "send an SNMP trap, adding the optional `reason` string as the query description"},
  {"SNMPTrapResponseAction", true, "[reason]", "send an SNMP trap, adding the optional `reason` string as the response description"},
  {"SpoofAction", true, "ip|list of ips [, options]", "forge a response with the specified IPv4 (for an A query) or IPv6 (for an AAAA). If you specify multiple addresses, all that match the query type (A, AAAA or ANY) will get spoofed in"},
  {"SpoofCNAMEAction", true, "cname [, options]", "Forge a response with the specified CNAME value"},
  {"SpoofRawAction", true, "raw|list of raws [, options]", "Forge a response with the specified record data as raw bytes. If you specify multiple raws (it is assumed they match the query type), all will get spoofed in"},
  {"SpoofSVCAction", true, "list of svcParams [, options]", "Forge a response with the specified SVC record data"},
  {"SuffixMatchNodeRule", true, "smn[, quiet]", "Matches based on a group of domain suffixes for rapid testing of membership. Pass true as second parameter to prevent listing of all domains matched"},
  {"TagRule", true, "name [, value]", "matches if the tag named 'name' is present, with the given 'value' matching if any"},
  {"TCAction", true, "", "create answer to query with TC and RD bits set, to move to TCP"},
  {"TCPRule", true, "[tcp]", "Matches question received over TCP if tcp is true, over UDP otherwise"},
  {"TCResponseAction", true, "", "truncate a response"},
  {"TeeAction", true, "remote [, addECS [, local]]", "send copy of query to remote, optionally adding ECS info, optionally set local address"},
  {"testCrypto", true, "", "test of the crypto all works"},
  {"TimedIPSetRule", true, "", "Create a rule which matches a set of IP addresses which expire"},
  {"topBandwidth", true, "top", "show top-`top` clients that consume the most bandwidth over length of ringbuffer"},
  {"topCacheHitResponseRules", true, "[top][, vars]", "show `top` cache-hit response rules"},
  {"topCacheInsertedResponseRules", true, "[top][, vars]", "show `top` cache-inserted response rules"},
  {"topClients", true, "n", "show top-`n` clients sending the most queries over length of ringbuffer"},
  {"topQueries", true, "n[, labels]", "show top 'n' queries, as grouped when optionally cut down to 'labels' labels"},
  {"topResponses", true, "n, kind[, labels]", "show top 'n' responses with RCODE=kind (0=NO Error, 2=ServFail, 3=NXDomain), as grouped when optionally cut down to 'labels' labels"},
  {"topResponseRules", true, "[top][, vars]", "show `top` response rules"},
  {"topRules", true, "[top][, vars]", "show `top` rules"},
  {"topSelfAnsweredResponseRules", true, "[top][, vars]", "show `top` self-answered response rules"},
  {"topSlow", true, "[top][, limit][, labels]", "show `top` queries slower than `limit` milliseconds (timeouts excepted), grouped by last `labels` labels"},
  {"topTimeouts", true, "[top][, labels]", "show `top` queries that timed out, grouped by last `labels` labels"},
  {"TrailingDataRule", true, "", "Matches if the query has trailing data"},
  {"truncateTC", true, "bool", "if set (defaults to no starting with dnsdist 1.2.0) truncate TC=1 answers so they are actually empty. Fixes an issue for PowerDNS Authoritative Server 2.9.22. Note: turning this on breaks compatibility with RFC 6891."},
  {"unregisterDynBPFFilter", true, "DynBPFFilter", "unregister this dynamic BPF filter"},
  {"webserver", true, "address:port", "launch a webserver with stats on that address"},
  {"whashed", false, "", "Weighted hashed ('sticky') distribution over available servers, based on the server 'weight' parameter"},
  {"chashed", false, "", "Consistent hashed ('sticky') distribution over available servers, also based on the server 'weight' parameter"},
  {"wrandom", false, "", "Weighted random over available servers, based on the server 'weight' parameter"},
};

#if defined(HAVE_LIBEDIT)
extern "C"
{
  static char* dnsdist_completion_generator(const char* text, int state)
  {
    string textStr(text);
    /* to keep it readable, we try to keep only 4 keywords per line
       and to start a new line when the first letter changes */
    static int s_counter = 0;
    int counter = 0;
    if (state == 0) {
      s_counter = 0;
    }

    for (const auto& keyword : s_consoleKeywords) {
      if (boost::starts_with(keyword.name, textStr) && counter++ == s_counter) {
        std::string value(keyword.name);
        s_counter++;
        if (keyword.function) {
          value += "(";
          if (keyword.parameters.empty()) {
            value += ")";
          }
        }
        return strdup(value.c_str());
      }
    }
    return nullptr;
  }

  static char** dnsdist_completion_callback(const char* text, int start, int end)
  {
    (void)end;
    char** matches = nullptr;
    if (start == 0) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): readline
      matches = rl_completion_matches(const_cast<char*>(text), &dnsdist_completion_generator);
    }

    // skip default filename completion.
    rl_attempted_completion_over = 1;

    return matches;
  }
}
#endif /* HAVE_LIBEDIT */
#endif /* DISABLE_COMPLETION */

namespace dnsdist::console
{
#ifndef DISABLE_COMPLETION
const std::vector<ConsoleKeyword>& getConsoleKeywords()
{
  return s_consoleKeywords;
}
#endif /* DISABLE_COMPLETION */

void setupCompletion()
{
#ifndef DISABLE_COMPLETION
#ifdef HAVE_LIBEDIT
  rl_attempted_completion_function = dnsdist_completion_callback;
  rl_completion_append_character = 0;
#endif /* DISABLE_COMPLETION */
#endif /* HAVE_LIBEDIT */
}

void clearHistory()
{
#ifdef HAVE_LIBEDIT
  clear_history();
#endif /* HAVE_LIBEDIT */
  s_confDelta.lock()->clear();
}

static void controlClientThread(ConsoleConnection&& conn)
{
  try {
    setThreadName("dnsdist/conscli");

    setTCPNoDelay(conn.getFD());

    //coverity[auto_causes_copy]
    const auto consoleKey = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey;
    dnsdist::crypto::authenticated::Nonce theirs;
    dnsdist::crypto::authenticated::Nonce ours;
    dnsdist::crypto::authenticated::Nonce readingNonce;
    dnsdist::crypto::authenticated::Nonce writingNonce;
    ours.init();
    readn2(conn.getFD(), theirs.value.data(), theirs.value.size());
    writen2(conn.getFD(), ours.value.data(), ours.value.size());
    readingNonce.merge(ours, theirs);
    writingNonce.merge(theirs, ours);

    for (;;) {
      uint32_t len{0};
      if (getMsgLen32(conn.getFD(), &len) != ConsoleCommandResult::Valid) {
        break;
      }

      if (len == 0) {
        /* just ACK an empty message
           with an empty response */
        putMsgLen32(conn.getFD(), 0);
        continue;
      }

      std::string line;
      //coverity[tainted_data]
      line.resize(len);
      readn2(conn.getFD(), line.data(), len);

      line = dnsdist::crypto::authenticated::decryptSym(line, consoleKey, readingNonce);

      string response;
      try {
        bool withReturn = true;
      retry:;
        try {
          auto lua = g_lua.lock();

          g_outputBuffer.clear();
          resetLuaSideEffect();
          auto ret = lua->executeCode<
            boost::optional<
              boost::variant<
                string,
                shared_ptr<DownstreamState>,
                ClientState*,
                std::unordered_map<string, double>>>>(withReturn ? ("return " + line) : line);

          if (ret) {
            if (const auto* dsValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
              if (*dsValue) {
                response = (*dsValue)->getName() + "\n";
              }
              else {
                response = "";
              }
            }
            else if (const auto* csValue = boost::get<ClientState*>(&*ret)) {
              if (*csValue != nullptr) {
                response = (*csValue)->local.toStringWithPort() + "\n";
              }
              else {
                response = "";
              }
            }
            else if (const auto* strValue = boost::get<string>(&*ret)) {
              response = *strValue + "\n";
            }
            else if (const auto* mapValue = boost::get<std::unordered_map<string, double>>(&*ret)) {
              using namespace json11;
              Json::object obj;
              for (const auto& value : *mapValue) {
                obj[value.first] = value.second;
              }
              Json out = obj;
              response = out.dump() + "\n";
            }
          }
          else {
            response = g_outputBuffer;
          }
          if (!getLuaNoSideEffect()) {
            feedConfigDelta(line);
          }
        }
        catch (const LuaContext::SyntaxErrorException&) {
          if (withReturn) {
            withReturn = false;
            // NOLINTNEXTLINE(cppcoreguidelines-avoid-goto)
            goto retry;
          }
          throw;
        }
      }
      catch (const LuaContext::WrongTypeException& e) {
        response = "Command returned an object we can't print: " + std::string(e.what()) + "\n";
        // tried to return something we don't understand
      }
      catch (const LuaContext::ExecutionErrorException& e) {
        if (strcmp(e.what(), "invalid key to 'next'") == 0) {
          response = "Error: Parsing function parameters, did you forget parameter name?";
        }
        else {
          response = "Error: " + string(e.what());
        }

        try {
          std::rethrow_if_nested(e);
        }
        catch (const std::exception& ne) {
          // ne is the exception that was thrown from inside the lambda
          response += ": " + string(ne.what());
        }
        catch (const PDNSException& ne) {
          // ne is the exception that was thrown from inside the lambda
          response += ": " + string(ne.reason);
        }
      }
      catch (const LuaContext::SyntaxErrorException& e) {
        response = "Error: " + string(e.what()) + ": ";
      }
      response = dnsdist::crypto::authenticated::encryptSym(response, consoleKey, writingNonce);
      putMsgLen32(conn.getFD(), response.length());
      writen2(conn.getFD(), response.c_str(), response.length());
    }
    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_logConsoleConnections) {
      infolog("Closed control connection from %s", conn.getClient().toStringWithPort());
    }
  }
  catch (const std::exception& e) {
    infolog("Got an exception in client connection from %s: %s", conn.getClient().toStringWithPort(), e.what());
  }
}

void controlThread(Socket&& acceptFD)
{
  try {
    setThreadName("dnsdist/control");
    const ComboAddress local = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleServerAddress;
    s_connManager.setMaxConcurrentConnections(dnsdist::configuration::getImmutableConfiguration().d_consoleMaxConcurrentConnections);

    ComboAddress client;
    // make sure that the family matches the one from the listening IP,
    // so that getSocklen() returns the correct size later, otherwise
    // the first IPv6 console connection might get refused
    client.sin4.sin_family = local.sin4.sin_family;

    int sock{-1};
    infolog("Accepting control connections on %s", local.toStringWithPort());

    while ((sock = SAccept(acceptFD.getHandle(), client)) >= 0) {
      const auto& consoleKey = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey;
      FDWrapper socket(sock);
      if (!dnsdist::crypto::authenticated::isValidKey(consoleKey)) {
        vinfolog("Control connection from %s dropped because we don't have a valid key configured, please configure one using setKey()", client.toStringWithPort());
        continue;
      }

      const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
      if (!runtimeConfig.d_consoleACL.match(client)) {
        vinfolog("Control connection from %s dropped because of ACL", client.toStringWithPort());
        continue;
      }

      try {
        ConsoleConnection conn(client, std::move(socket));
        if (runtimeConfig.d_logConsoleConnections) {
          warnlog("Got control connection from %s", client.toStringWithPort());
        }

        std::thread clientThread(controlClientThread, std::move(conn));
        clientThread.detach();
      }
      catch (const std::exception& e) {
        infolog("Control connection died: %s", e.what());
      }
    }
  }
  catch (const std::exception& e) {
    errlog("Control thread died: %s", e.what());
  }
}
}
