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

#include <fstream>
#include <pwd.h>
#include <thread>

#if defined (__OpenBSD__) || defined(__NetBSD__)
#include <readline/readline.h>
#include <readline/history.h>
#else
#include <editline/readline.h>
#endif

#include "ext/json11/json11.hpp"

#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-console.hh"
#include "sodcrypto.hh"
#include "threadname.hh"

GlobalStateHolder<NetmaskGroup> g_consoleACL;
vector<pair<struct timeval, string> > g_confDelta;
std::string g_consoleKey;
bool g_logConsoleConnections{true};
bool g_consoleEnabled{false};
uint32_t g_consoleOutputMsgMaxSize{10000000};

// MUST BE CALLED UNDER A LOCK - right now the LuaLock
static void feedConfigDelta(const std::string& line)
{
  if(line.empty())
    return;
  struct timeval now;
  gettimeofday(&now, 0);
  g_confDelta.push_back({now,line});
}

static string historyFile(const bool &ignoreHOME = false)
{
  string ret;

  struct passwd pwd;
  struct passwd *result;
  char buf[16384];
  getpwuid_r(geteuid(), &pwd, buf, sizeof(buf), &result);

  const char *homedir = getenv("HOME");
  if (result)
    ret = string(pwd.pw_dir);
  if (homedir && !ignoreHOME) // $HOME overrides what the OS tells us
    ret = string(homedir);
  if (ret.empty())
    ret = "."; // CWD if nothing works..
  ret.append("/.dnsdist_history");
  return ret;
}

static bool sendMessageToServer(int fd, const std::string& line, SodiumNonce& readingNonce, SodiumNonce& writingNonce, const bool outputEmptyLine)
{
  string msg = sodEncryptSym(line, g_consoleKey, writingNonce);
  const auto msgLen = msg.length();
  if (msgLen > std::numeric_limits<uint32_t>::max()) {
    cout << "Encrypted message is too long to be sent to the server, "<< std::to_string(msgLen) << " > " << std::numeric_limits<uint32_t>::max() << endl;
    return true;
  }

  putMsgLen32(fd, static_cast<uint32_t>(msgLen));

  if (!msg.empty()) {
    writen2(fd, msg);
  }

  uint32_t len;
  if(!getMsgLen32(fd, &len)) {
    cout << "Connection closed by the server." << endl;
    return false;
  }

  if (len == 0) {
    if (outputEmptyLine) {
      cout << endl;
    }

    return true;
  }

  boost::scoped_array<char> resp(new char[len]);
  readn2(fd, resp.get(), len);
  msg.assign(resp.get(), len);
  msg = sodDecryptSym(msg, g_consoleKey, readingNonce);
  cout << msg;
  cout.flush();

  return true;
}

void doClient(ComboAddress server, const std::string& command)
{
  if (!sodIsValidKey(g_consoleKey)) {
    cerr << "The currently configured console key is not valid, please configure a valid key using the setKey() directive" << endl;
    return;
  }

  if(g_verbose) {
    cout<<"Connecting to "<<server.toStringWithPort()<<endl;
  }

  int fd=socket(server.sin4.sin_family, SOCK_STREAM, 0);
  if (fd < 0) {
    cerr<<"Unable to connect to "<<server.toStringWithPort()<<endl;
    return;
  }
  SConnect(fd, server);
  setTCPNoDelay(fd);
  SodiumNonce theirs, ours, readingNonce, writingNonce;
  ours.init();

  writen2(fd, (const char*)ours.value, sizeof(ours.value));
  readn2(fd, (char*)theirs.value, sizeof(theirs.value));
  readingNonce.merge(ours, theirs);
  writingNonce.merge(theirs, ours);

  /* try sending an empty message, the server should send an empty
     one back. If it closes the connection instead, we are probably
     having a key mismatch issue. */
  if (!sendMessageToServer(fd, "", readingNonce, writingNonce, false)) {
    cerr<<"The server closed the connection right away, likely indicating a key mismatch. Please check your setKey() directive."<<endl;
    close(fd);
    return;
  }

  if (!command.empty()) {
    sendMessageToServer(fd, command, readingNonce, writingNonce, false);

    close(fd);
    return; 
  }

  string histfile = historyFile();
  set<string> dupper;
  {
    ifstream history(histfile);
    string line;
    while(getline(history, line))
      add_history(line.c_str());
  }
  ofstream history(histfile, std::ios_base::app);
  string lastline;
  for(;;) {
    char* sline = readline("> ");
    rl_bind_key('\t',rl_complete);
    if(!sline)
      break;

    string line(sline);
    if(!line.empty() && line != lastline) {
      add_history(sline);
      history << sline <<endl;
      history.flush();
    }
    lastline=line;
    free(sline);
    
    if(line=="quit")
      break;
    if(line=="help" || line=="?")
      line="help()";

    /* no need to send an empty line to the server */
    if(line.empty())
      continue;

    if (!sendMessageToServer(fd, line, readingNonce, writingNonce, true)) {
      break;
    }
  }
  close(fd);
}

void doConsole()
{
  string histfile = historyFile(true);
  set<string> dupper;
  {
    ifstream history(histfile);
    string line;
    while(getline(history, line))
      add_history(line.c_str());
  }
  ofstream history(histfile, std::ios_base::app);
  string lastline;
  for(;;) {
    char* sline = readline("> ");
    rl_bind_key('\t',rl_complete);
    if(!sline)
      break;

    string line(sline);
    if(!line.empty() && line != lastline) {
      add_history(sline);
      history << sline <<endl;
      history.flush();
    }
    lastline=line;
    free(sline);
    
    if(line=="quit")
      break;
    if(line=="help" || line=="?")
      line="help()";

    string response;
    try {
      bool withReturn=true;
    retry:;
      try {
        std::lock_guard<std::mutex> lock(g_luamutex);
        g_outputBuffer.clear();
        resetLuaSideEffect();
        auto ret=g_lua.executeCode<
          boost::optional<
            boost::variant<
              string, 
              shared_ptr<DownstreamState>,
              ClientState*,
              std::unordered_map<string, double>
              >
            >
          >(withReturn ? ("return "+line) : line);
        if(ret) {
          if (const auto dsValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
            if (*dsValue) {
              cout<<(*dsValue)->getName()<<endl;
            }
          }
          else if (const auto csValue = boost::get<ClientState*>(&*ret)) {
            if (*csValue) {
              cout<<(*csValue)->local.toStringWithPort()<<endl;
            }
          }
          else if (const auto strValue = boost::get<string>(&*ret)) {
            cout<<*strValue<<endl;
          }
          else if(const auto um = boost::get<std::unordered_map<string, double> >(&*ret)) {
            using namespace json11;
            Json::object o;
            for(const auto& v : *um)
              o[v.first]=v.second;
            Json out = o;
            cout<<out.dump()<<endl;
          }
        }
        else 
          cout << g_outputBuffer;
        if(!getLuaNoSideEffect())
          feedConfigDelta(line);
      }
      catch(const LuaContext::SyntaxErrorException&) {
        if(withReturn) {
          withReturn=false;
          goto retry;
        }
        throw;
      }
    }
    catch(const LuaContext::WrongTypeException& e) {
      std::cerr<<"Command returned an object we can't print: "<<std::string(e.what())<<std::endl;
      // tried to return something we don't understand
    }
    catch(const LuaContext::ExecutionErrorException& e) {
      if(!strcmp(e.what(),"invalid key to 'next'"))
        std::cerr<<"Error parsing parameters, did you forget parameter name?";
      else
        std::cerr << e.what(); 
      try {
        std::rethrow_if_nested(e);

        std::cerr << std::endl;
      } catch(const std::exception& ne) {
        // ne is the exception that was thrown from inside the lambda
        std::cerr << ": " << ne.what() << std::endl;
      }
      catch(const PDNSException& ne) {
        // ne is the exception that was thrown from inside the lambda
        std::cerr << ": " << ne.reason << std::endl;
      }
    }
    catch(const std::exception& e) {
      std::cerr << e.what() << std::endl;      
    }
  }
}
/**** CARGO CULT CODE AHEAD ****/
const std::vector<ConsoleKeyword> g_consoleKeywords{
  /* keyword, function, parameters, description */
  { "addACL", true, "netmask", "add to the ACL set who can use this server" },
  { "addAction", true, "DNS rule, DNS action [, {uuid=\"UUID\"}]", "add a rule" },
  { "addConsoleACL", true, "netmask", "add a netmask to the console ACL" },
  { "addDNSCryptBind", true, "\"127.0.0.1:8443\", \"provider name\", \"/path/to/resolver.cert\", \"/path/to/resolver.key\", {reusePort=false, tcpFastOpenSize=0, interface=\"\", cpus={}}", "listen to incoming DNSCrypt queries on 127.0.0.1 port 8443, with a provider name of `provider name`, using a resolver certificate and associated key stored respectively in the `resolver.cert` and `resolver.key` files. The fifth optional parameter is a table of parameters" },
  { "addDynBlocks", true, "addresses, message[, seconds[, action]]", "block the set of addresses with message `msg`, for `seconds` seconds (10 by default), applying `action` (default to the one set with `setDynBlocksAction()`)" },
  { "addLocal", true, "addr [, {doTCP=true, reusePort=false, tcpFastOpenSize=0, interface=\"\", cpus={}}]", "add `addr` to the list of addresses we listen on" },
  { "addLuaAction", true, "x, func [, {uuid=\"UUID\"}]", "where 'x' is all the combinations from `addAction`, and func is a function with the parameter `dq`, which returns an action to be taken on this packet. Good for rare packets but where you want to do a lot of processing" },
  { "addLuaResponseAction", true, "x, func [, {uuid=\"UUID\"}]", "where 'x' is all the combinations from `addAction`, and func is a function with the parameter `dr`, which returns an action to be taken on this response packet. Good for rare packets but where you want to do a lot of processing" },
  { "addCacheHitResponseAction", true, "DNS rule, DNS response action [, {uuid=\"UUID\"}]", "add a cache hit response rule" },
  { "addResponseAction", true, "DNS rule, DNS response action [, {uuid=\"UUID\"}]", "add a response rule" },
  { "addSelfAnsweredResponseAction", true, "DNS rule, DNS response action [, {uuid=\"UUID\"}]", "add a self-answered response rule" },
  { "addTLSLocal", true, "addr, certFile(s), keyFile(s) [,params]", "listen to incoming DNS over TLS queries on the specified address using the specified certificate (or list of) and key (or list of). The last parameter is a table" },
  { "AllowAction", true, "", "let these packets go through" },
  { "AllowResponseAction", true, "", "let these packets go through" },
  { "AllRule", true, "", "matches all traffic" },
  { "AndRule", true, "list of DNS rules", "matches if all sub-rules matches" },
  { "benchRule", true, "DNS Rule [, iterations [, suffix]]", "bench the specified DNS rule" },
  { "carbonServer", true, "serverIP, [ourname], [interval]", "report statistics to serverIP using our hostname, or 'ourname' if provided, every 'interval' seconds" },
  { "controlSocket", true, "addr", "open a control socket on this address / connect to this address in client mode" },
  { "clearDynBlocks", true, "", "clear all dynamic blocks" },
  { "clearQueryCounters", true, "", "clears the query counter buffer" },
  { "clearRules", true, "", "remove all current rules" },
  { "DelayAction", true, "milliseconds", "delay the response by the specified amount of milliseconds (UDP-only)" },
  { "DelayResponseAction", true, "milliseconds", "delay the response by the specified amount of milliseconds (UDP-only)" },
  { "delta", true, "", "shows all commands entered that changed the configuration" },
  { "DisableValidationAction", true, "", "set the CD bit in the question, let it go through" },
  { "DnstapLogAction", true, "identity, FrameStreamLogger [, alterFunction]", "send the contents of this query to a FrameStreamLogger or RemoteLogger as dnstap. `alterFunction` is a callback, receiving a DNSQuestion and a DnstapMessage, that can be used to modify the dnstap message" },
  { "DnstapLogResponseAction", true, "identity, FrameStreamLogger [, alterFunction]", "send the contents of this response to a remote or FrameStreamLogger or RemoteLogger as dnstap. `alterFunction` is a callback, receiving a DNSResponse and a DnstapMessage, that can be used to modify the dnstap message" },
  { "DropAction", true, "", "drop these packets" },
  { "DropResponseAction", true, "", "drop these packets" },
  { "DSTPortRule", true, "port", "matches questions received to the destination port specified" },
  { "dumpStats", true, "", "print all statistics we gather" },
  { "dynBlockRulesGroup", true, "", "return a new DynBlockRulesGroup object" },
  { "EDNSOptionRule", true, "optcode", "matches queries with the specified EDNS0 option present" },
  { "ERCodeRule", true, "rcode", "matches responses with the specified extended rcode (EDNS0)" },
  { "exceedNXDOMAINs", true, "rate, seconds", "get set of addresses that exceed `rate` NXDOMAIN/s over `seconds` seconds" },
  { "exceedQRate", true, "rate, seconds", "get set of address that exceed `rate` queries/s over `seconds` seconds" },
  { "exceedQTypeRate", true, "type, rate, seconds", "get set of address that exceed `rate` queries/s for queries of type `type` over `seconds` seconds" },
  { "exceedRespByterate", true, "rate, seconds", "get set of addresses that exceeded `rate` bytes/s answers over `seconds` seconds" },
  { "exceedServFails", true, "rate, seconds", "get set of addresses that exceed `rate` servfails/s over `seconds` seconds" },
  { "firstAvailable", false, "", "picks the server with the lowest `order` that has not exceeded its QPS limit" },
  { "fixupCase", true, "bool", "if set (default to no), rewrite the first qname of the question part of the answer to match the one from the query. It is only useful when you have a downstream server that messes up the case of the question qname in the answer" },
  { "generateDNSCryptCertificate", true, "\"/path/to/providerPrivate.key\", \"/path/to/resolver.cert\", \"/path/to/resolver.key\", serial, validFrom, validUntil", "generate a new resolver private key and related certificate, valid from the `validFrom` timestamp until the `validUntil` one, signed with the provider private key" },
  { "generateDNSCryptProviderKeys", true, "\"/path/to/providerPublic.key\", \"/path/to/providerPrivate.key\"", "generate a new provider keypair" },
  { "getBind", true, "n", "returns the listener at index n" },
  { "getDNSCryptBind", true, "n", "return the `DNSCryptContext` object corresponding to the bind `n`" },
  { "getPool", true, "name", "return the pool named `name`, or \"\" for the default pool" },
  { "getPoolServers", true, "pool", "return servers part of this pool" },
  { "getQueryCounters", true, "[max=10]", "show current buffer of query counters, limited by 'max' if provided" },
  { "getResponseRing", true, "", "return the current content of the response ring" },
  { "getServer", true, "n", "returns server with index n" },
  { "getServers", true, "", "returns a table with all defined servers" },
  { "getTLSContext", true, "n", "returns the TLS context with index n" },
  { "getTLSFrontend", true, "n", "returns the TLS frontend with index n" },
  { "inClientStartup", true, "", "returns true during console client parsing of configuration" },
  { "grepq", true, "Netmask|DNS Name|100ms|{\"::1\", \"powerdns.com\", \"100ms\"} [, n]", "shows the last n queries and responses matching the specified client address or range (Netmask), or the specified DNS Name, or slower than 100ms" },
  { "leastOutstanding", false, "", "Send traffic to downstream server with least outstanding queries, with the lowest 'order', and within that the lowest recent latency"},
  { "LogAction", true, "[filename], [binary], [append], [buffered]", "Log a line for each query, to the specified file if any, to the console (require verbose) otherwise. When logging to a file, the `binary` optional parameter specifies whether we log in binary form (default) or in textual form, the `append` optional parameter specifies whether we open the file for appending or truncate each time (default), and the `buffered` optional parameter specifies whether writes to the file are buffered (default) or not." },
  { "makeKey", true, "", "generate a new server access key, emit configuration line ready for pasting" },
  { "MaxQPSIPRule", true, "qps, [v4Mask=32 [, v6Mask=64 [, burst=qps [, expiration=300 [, cleanupDelay=60]]]]]", "matches traffic exceeding the qps limit per subnet" },
  { "MaxQPSRule", true, "qps", "matches traffic **not** exceeding this qps limit" },
  { "mvCacheHitResponseRule", true, "from, to", "move cache hit response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule" },
  { "mvResponseRule", true, "from, to", "move response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule" },
  { "mvRule", true, "from, to", "move rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule, in which case the rule will be moved to the last position" },
  { "mvSelfAnsweredResponseRule", true, "from, to", "move self-answered response rule 'from' to a position where it is in front of 'to'. 'to' can be one larger than the largest rule" },
  { "newDNSName", true, "name", "make a DNSName based on this .-terminated name" },
  { "newFrameStreamTcpLogger", true, "addr", "create a FrameStream logger object writing to a TCP address (addr should be ip:port), to use with `DnstapLogAction()` and `DnstapLogResponseAction()`" },
  { "newFrameStreamUnixLogger", true, "socket", "create a FrameStream logger object writing to a local unix socket, to use with `DnstapLogAction()` and `DnstapLogResponseAction()`" },
  { "newPacketCache", true, "maxEntries[, maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=false, numberOfShards=1, deferrableInsertLock=true]", "return a new Packet Cache" },
  { "newQPSLimiter", true, "rate, burst", "configure a QPS limiter with that rate and that burst capacity" },
  { "newRemoteLogger", true, "address:port [, timeout=2, maxQueuedEntries=100, reconnectWaitTime=1]", "create a Remote Logger object, to use with `RemoteLogAction()` and `RemoteLogResponseAction()`" },
  { "newRuleAction", true, "DNS rule, DNS action [, {uuid=\"UUID\"}]", "return a pair of DNS Rule and DNS Action, to be used with `setRules()`" },
  { "newServer", true, "{address=\"ip:port\", qps=1000, order=1, weight=10, pool=\"abuse\", retries=5, tcpConnectTimeout=5, tcpSendTimeout=30, tcpRecvTimeout=30, checkName=\"a.root-servers.net.\", checkType=\"A\", maxCheckFailures=1, mustResolve=false, useClientSubnet=true, source=\"address|interface name|address@interface\", sockets=1}", "instantiate a server" },
  { "newServerPolicy", true, "name, function", "create a policy object from a Lua function" },
  { "newSuffixMatchNode", true, "", "returns a new SuffixMatchNode" },
  { "NoRecurseAction", true, "", "strip RD bit from the question, let it go through" },
  { "PoolAction", true, "poolname", "set the packet into the specified pool" },
  { "printDNSCryptProviderFingerprint", true, "\"/path/to/providerPublic.key\"", "display the fingerprint of the provided resolver public key" },
  { "QNameLabelsCountRule", true, "min, max", "matches if the qname has less than `min` or more than `max` labels" },
  { "QNameRule", true, "qname", "matches queries with the specified qname" },
  { "QNameWireLengthRule", true, "min, max", "matches if the qname's length on the wire is less than `min` or more than `max` bytes" },
  { "QTypeRule", true, "qtype", "matches queries with the specified qtype" },
  { "RCodeRule", true, "rcode", "matches responses with the specified rcode" },
  { "RegexRule", true, "regex", "matches the query name against the supplied regex" },
  { "registerDynBPFFilter", true, "DynBPFFilter", "register this dynamic BPF filter into the web interface so that its counters are displayed" },
  { "RemoteLogAction", true, "RemoteLogger [, alterFunction [, serverID]]", "send the content of this query to a remote logger via Protocol Buffer. `alterFunction` is a callback, receiving a DNSQuestion and a DNSDistProtoBufMessage, that can be used to modify the Protocol Buffer content, for example for anonymization purposes. `serverID` is the server identifier." },
  { "RemoteLogResponseAction", true, "RemoteLogger [,alterFunction [,includeCNAME [, serverID]]]", "send the content of this response to a remote logger via Protocol Buffer. `alterFunction` is the same callback than the one in `RemoteLogAction` and `includeCNAME` indicates whether CNAME records inside the response should be parsed and exported. The default is to only exports A and AAAA records. `serverID` is the server identifier." },
  { "rmCacheHitResponseRule", true, "id", "remove cache hit response rule in position 'id', or whose uuid matches if 'id' is an UUID string" },
  { "rmResponseRule", true, "id", "remove response rule in position 'id', or whose uuid matches if 'id' is an UUID string" },
  { "rmRule", true, "id", "remove rule in position 'id', or whose uuid matches if 'id' is an UUID string" },
  { "rmSelfAnsweredResponseRule", true, "id", "remove self-answered response rule in position 'id', or whose uuid matches if 'id' is an UUID string" },
  { "rmServer", true, "n", "remove server with index n" },
  { "roundrobin", false, "", "Simple round robin over available servers" },
  { "sendCustomTrap", true, "str", "send a custom `SNMP` trap from Lua, containing the `str` string"},
  { "setACL", true, "{netmask, netmask}", "replace the ACL set with these netmasks. Use `setACL({})` to reset the list, meaning no one can use us" },
  { "setAddEDNSToSelfGeneratedResponses", true, "add", "set whether to add EDNS to self-generated responses, provided that the initial query had EDNS" },
  { "setAPIWritable", true, "bool, dir", "allow modifications via the API. if `dir` is set, it must be a valid directory where the configuration files will be written by the API" },
  { "setConsoleACL", true, "{netmask, netmask}", "replace the console ACL set with these netmasks" },
  { "setConsoleConnectionsLogging", true, "enabled", "whether to log the opening and closing of console connections" },
  { "setConsoleOutputMaxMsgSize", true, "messageSize", "set console message maximum size in bytes, default is 10 MB" },
  { "setDNSSECPool", true, "pool name", "move queries requesting DNSSEC processing to this pool" },
  { "setDynBlocksAction", true, "action", "set which action is performed when a query is blocked. Only DNSAction.Drop (the default) and DNSAction.Refused are supported" },
  { "setECSOverride", true, "bool", "whether to override an existing EDNS Client Subnet value in the query" },
  { "setECSSourcePrefixV4", true, "prefix-length", "the EDNS Client Subnet prefix-length used for IPv4 queries" },
  { "setECSSourcePrefixV6", true, "prefix-length", "the EDNS Client Subnet prefix-length used for IPv6 queries" },
  { "setKey", true, "key", "set access key to that key" },
  { "setLocal", true, "addr [, {doTCP=true, reusePort=false, tcpFastOpenSize=0, interface=\"\", cpus={}}]", "reset the list of addresses we listen on to this address" },
  { "setMaxTCPClientThreads", true, "n", "set the maximum of TCP client threads, handling TCP connections" },
  { "setMaxTCPConnectionDuration", true, "n", "set the maximum duration of an incoming TCP connection, in seconds. 0 means unlimited" },
  { "setMaxTCPConnectionsPerClient", true, "n", "set the maximum number of TCP connections per client. 0 means unlimited" },
  { "setMaxTCPQueriesPerConnection", true, "n", "set the maximum number of queries in an incoming TCP connection. 0 means unlimited" },
  { "setMaxTCPQueuedConnections", true, "n", "set the maximum number of TCP connections queued (waiting to be picked up by a client thread)" },
  { "setMaxUDPOutstanding", true, "n", "set the maximum number of outstanding UDP queries to a given backend server. This can only be set at configuration time and defaults to 10240" },
  { "setPayloadSizeOnSelfGeneratedAnswers", true, "payloadSize", "set the UDP payload size advertised via EDNS on self-generated responses" },
  { "setPoolServerPolicy", true, "policy, pool", "set the server selection policy for this pool to that policy" },
  { "setPoolServerPolicy", true, "name, func, pool", "set the server selection policy for this pool to one named 'name' and provided by 'function'" },
  { "setQueryCount", true, "bool", "set whether queries should be counted" },
  { "setQueryCountFilter", true, "func", "filter queries that would be counted, where `func` is a function with parameter `dq` which decides whether a query should and how it should be counted" },
  { "setRingBuffersLockRetries", true, "n", "set the number of attempts to get a non-blocking lock to a ringbuffer shard before blocking" },
  { "setRingBuffersSize", true, "n [, numberOfShards]", "set the capacity of the ringbuffers used for live traffic inspection to `n`, and optionally the number of shards to use to `numberOfShards`" },
  { "setRules", true, "list of rules", "replace the current rules with the supplied list of pairs of DNS Rules and DNS Actions (see `newRuleAction()`)" },
  { "setServerPolicy", true, "policy", "set server selection policy to that policy" },
  { "setServerPolicyLua", true, "name, function", "set server selection policy to one named 'name' and provided by 'function'" },
  { "setServFailWhenNoServer", true, "bool", "if set, return a ServFail when no servers are available, instead of the default behaviour of dropping the query" },
  { "setStaleCacheEntriesTTL", true, "n", "allows using cache entries expired for at most n seconds when there is no backend available to answer for a query" },
  { "setTCPDownstreamCleanupInterval", true, "interval", "minimum interval in seconds between two cleanups of the idle TCP downstream connections" },
  { "setTCPUseSinglePipe", true, "bool", "whether the incoming TCP connections should be put into a single queue instead of using per-thread queues. Defaults to false" },
  { "setTCPRecvTimeout", true, "n", "set the read timeout on TCP connections from the client, in seconds" },
  { "setTCPSendTimeout", true, "n", "set the write timeout on TCP connections from the client, in seconds" },
  { "setUDPMultipleMessagesVectorSize", true, "n", "set the size of the vector passed to recvmmsg() to receive UDP messages. Default to 1 which means that the feature is disabled and recvmsg() is used instead" },
  { "setUDPTimeout", true, "n", "set the maximum time dnsdist will wait for a response from a backend over UDP, in seconds" },
  { "setVerboseHealthChecks", true, "bool", "set whether health check errors will be logged" },
  { "show", true, "string", "outputs `string`" },
  { "showACL", true, "", "show our ACL set" },
  { "showBinds", true, "", "show listening addresses (frontends)" },
  { "showCacheHitResponseRules", true, "[{showUUIDs=false, truncateRuleWidth=-1}]", "show all defined cache hit response rules, optionally with their UUIDs and optionally truncated to a given width" },
  { "showConsoleACL", true, "", "show our current console ACL set" },
  { "showDNSCryptBinds", true, "", "display the currently configured DNSCrypt binds" },
  { "showDynBlocks", true, "", "show dynamic blocks in force" },
  { "showPools", true, "", "show the available pools" },
  { "showPoolServerPolicy", true, "pool", "show server selection policy for this pool" },
  { "showResponseLatency", true, "", "show a plot of the response time latency distribution" },
  { "showResponseRules", true, "[{showUUIDs=false, truncateRuleWidth=-1}]", "show all defined response rules, optionally with their UUIDs and optionally truncated to a given width" },
  { "showRules", true, "[{showUUIDs=false, truncateRuleWidth=-1}]", "show all defined rules, optionally with their UUIDs and optionally truncated to a given width" },
  { "showSelfAnsweredResponseRules", true, "[{showUUIDs=false, truncateRuleWidth=-1}]", "show all defined self-answered response rules, optionally with their UUIDs and optionally truncated to a given width" },
  { "showServerPolicy", true, "", "show name of currently operational server selection policy" },
  { "showServers", true, "", "output all servers" },
  { "showTCPStats", true, "", "show some statistics regarding TCP" },
  { "showTLSContexts", true, "", "list all the available TLS contexts" },
  { "showVersion", true, "", "show the current version" },
  { "shutdown", true, "", "shut down `dnsdist`" },
  { "snmpAgent", true, "enableTraps [, masterSocket]", "enable `SNMP` support. `enableTraps` is a boolean indicating whether traps should be sent and `masterSocket` an optional string specifying how to connect to the master agent"},
  { "SNMPTrapAction", true, "[reason]", "send an SNMP trap, adding the optional `reason` string as the query description"},
  { "SNMPTrapResponseAction", true, "[reason]", "send an SNMP trap, adding the optional `reason` string as the response description"},
  { "SpoofAction", true, "{ip, ...} ", "forge a response with the specified IPv4 (for an A query) or IPv6 (for an AAAA). If you specify multiple addresses, all that match the query type (A, AAAA or ANY) will get spoofed in" },
  { "TagAction", true, "name, value", "set the tag named 'name' to the given value" },
  { "TagResponseAction", true, "name, value", "set the tag named 'name' to the given value" },
  { "TagRule", true, "name [, value]", "matches if the tag named 'name' is present, with the given 'value' matching if any" },
  { "TCAction", true, "", "create answer to query with TC and RD bits set, to move to TCP" },
  { "TeeAction", true, "remote [, addECS]", "send copy of query to remote, optionally adding ECS info" },
  { "TempFailureCacheTTLAction", true, "ttl", "set packetcache TTL for temporary failure replies" },
  { "testCrypto", true, "", "test of the crypto all works" },
  { "TimedIPSetRule", true, "", "Create a rule which matches a set of IP addresses which expire"}, 
  { "topBandwidth", true, "top", "show top-`top` clients that consume the most bandwidth over length of ringbuffer" },
  { "topCacheHitResponseRule", true, "", "move the last cache hit response rule to the first position" },
  { "topClients", true, "n", "show top-`n` clients sending the most queries over length of ringbuffer" },
  { "topQueries", true, "n[, labels]", "show top 'n' queries, as grouped when optionally cut down to 'labels' labels" },
  { "topResponses", true, "n, kind[, labels]", "show top 'n' responses with RCODE=kind (0=NO Error, 2=ServFail, 3=ServFail), as grouped when optionally cut down to 'labels' labels" },
  { "topCacheHitResponseRule", true, "", "move the last cache hit response rule to the first position" },
  { "topResponseRule", true, "", "move the last response rule to the first position" },
  { "topRule", true, "", "move the last rule to the first position" },
  { "topSelfAnsweredResponseRule", true, "", "move the last self-answered response rule to the first position" },
  { "topSlow", true, "[top][, limit][, labels]", "show `top` queries slower than `limit` milliseconds, grouped by last `labels` labels" },
  { "truncateTC", true, "bool", "if set (defaults to no starting with dnsdist 1.2.0) truncate TC=1 answers so they are actually empty. Fixes an issue for PowerDNS Authoritative Server 2.9.22. Note: turning this on breaks compatibility with RFC 6891." },
  { "unregisterDynBPFFilter", true, "DynBPFFilter", "unregister this dynamic BPF filter" },
  { "webserver", true, "address:port, password [, apiKey [, customHeaders ]])", "launch a webserver with stats on that address with that password" },
  { "whashed", false, "", "Weighted hashed ('sticky') distribution over available servers, based on the server 'weight' parameter" },
  { "chashed", false, "", "Consistent hashed ('sticky') distribution over available servers, also based on the server 'weight' parameter" },
  { "wrandom", false, "", "Weighted random over available servers, based on the server 'weight' parameter" },
};

extern "C" {
char* my_generator(const char* text, int state)
{
  string t(text);
  /* to keep it readable, we try to keep only 4 keywords per line
     and to start a new line when the first letter changes */
  static int s_counter=0;
  int counter=0;
  if(!state)
    s_counter=0;

  for(const auto& keyword : g_consoleKeywords) {
    if(boost::starts_with(keyword.name, t) && counter++ == s_counter)  {
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
  return 0;
}

char** my_completion( const char * text , int start,  int end)
{
  char **matches=0;
  if (start == 0)
    matches = rl_completion_matches ((char*)text, &my_generator);

  // skip default filename completion.
  rl_attempted_completion_over = 1;

  return matches;
}
}

static void controlClientThread(int fd, ComboAddress client)
try
{
  setThreadName("dnsdist/conscli");
  setTCPNoDelay(fd);
  SodiumNonce theirs, ours, readingNonce, writingNonce;
  ours.init();
  readn2(fd, (char*)theirs.value, sizeof(theirs.value));
  writen2(fd, (char*)ours.value, sizeof(ours.value));
  readingNonce.merge(ours, theirs);
  writingNonce.merge(theirs, ours);

  for(;;) {
    uint32_t len;
    if(!getMsgLen32(fd, &len))
      break;

    if (len == 0) {
      /* just ACK an empty message
         with an empty response */
      putMsgLen32(fd, 0);
      continue;
    }

    boost::scoped_array<char> msg(new char[len]);
    readn2(fd, msg.get(), len);

    string line(msg.get(), len);

    line = sodDecryptSym(line, g_consoleKey, readingNonce);
    //    cerr<<"Have decrypted line: "<<line<<endl;
    string response;
    try {
      bool withReturn=true;
    retry:;
      try {
        std::lock_guard<std::mutex> lock(g_luamutex);
        
        g_outputBuffer.clear();
        resetLuaSideEffect();
        auto ret=g_lua.executeCode<
          boost::optional<
            boost::variant<
              string, 
              shared_ptr<DownstreamState>,
              ClientState*,
              std::unordered_map<string, double>
              >
            >
          >(withReturn ? ("return "+line) : line);

      if(ret) {
        if (const auto dsValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
          if (*dsValue) {
            response=(*dsValue)->getName()+"\n";
          } else {
            response="";
          }
        }
        else if (const auto csValue = boost::get<ClientState*>(&*ret)) {
          if (*csValue) {
            response=(*csValue)->local.toStringWithPort()+"\n";
          } else {
            response="";
          }
        }
        else if (const auto strValue = boost::get<string>(&*ret)) {
          response=*strValue+"\n";
        }
        else if(const auto um = boost::get<std::unordered_map<string, double> >(&*ret)) {
          using namespace json11;
          Json::object o;
          for(const auto& v : *um)
            o[v.first]=v.second;
          Json out = o;
          response=out.dump()+"\n";
        }
      }
      else
	response=g_outputBuffer;
      if(!getLuaNoSideEffect())
        feedConfigDelta(line);
      }
      catch(const LuaContext::SyntaxErrorException&) {
        if(withReturn) {
          withReturn=false;
          goto retry;
        }
        throw;
      }
    }
    catch(const LuaContext::WrongTypeException& e) {
      response = "Command returned an object we can't print: " +std::string(e.what()) + "\n";
      // tried to return something we don't understand
    }
    catch(const LuaContext::ExecutionErrorException& e) {
      if(!strcmp(e.what(),"invalid key to 'next'"))
        response = "Error: Parsing function parameters, did you forget parameter name?";
      else
        response = "Error: " + string(e.what());
      try {
        std::rethrow_if_nested(e);
      } catch(const std::exception& ne) {
        // ne is the exception that was thrown from inside the lambda
        response+= ": " + string(ne.what());
      }
      catch(const PDNSException& ne) {
        // ne is the exception that was thrown from inside the lambda
        response += ": " + string(ne.reason);
      }
    }
    catch(const LuaContext::SyntaxErrorException& e) {
      response = "Error: " + string(e.what()) + ": ";
    }
    response = sodEncryptSym(response, g_consoleKey, writingNonce);
    putMsgLen32(fd, response.length());
    writen2(fd, response.c_str(), response.length());
  }
  if (g_logConsoleConnections) {
    infolog("Closed control connection from %s", client.toStringWithPort());
  }
  close(fd);
  fd=-1;
}
catch(std::exception& e)
{
  errlog("Got an exception in client connection from %s: %s", client.toStringWithPort(), e.what());
  if(fd >= 0)
    close(fd);
}

void controlThread(int fd, ComboAddress local)
try
{
  setThreadName("dnsdist/control");
  ComboAddress client;
  int sock;
  auto localACL = g_consoleACL.getLocal();
  infolog("Accepting control connections on %s", local.toStringWithPort());

  while ((sock = SAccept(fd, client)) >= 0) {

    if (!sodIsValidKey(g_consoleKey)) {
      vinfolog("Control connection from %s dropped because we don't have a valid key configured, please configure one using setKey()", client.toStringWithPort());
      close(sock);
      continue;
    }

    if (!localACL->match(client)) {
      vinfolog("Control connection from %s dropped because of ACL", client.toStringWithPort());
      close(sock);
      continue;
    }

    if (g_logConsoleConnections) {
      warnlog("Got control connection from %s", client.toStringWithPort());
    }

    std::thread t(controlClientThread, sock, client);
    t.detach();
  }
}
catch(const std::exception& e)
{
  close(fd);
  errlog("Control connection died: %s", e.what());
}

bool getMsgLen32(int fd, uint32_t* len)
try
{
  uint32_t raw;
  size_t ret = readn2(fd, &raw, sizeof raw);
  if(ret != sizeof raw)
    return false;
  *len = ntohl(raw);
  if(*len > g_consoleOutputMsgMaxSize)
    return false;
  return true;
}
catch(...) {
   return false;
}

bool putMsgLen32(int fd, uint32_t len)
try
{
  uint32_t raw = htonl(len);
  size_t ret = writen2(fd, &raw, sizeof raw);
  return ret==sizeof raw;
}
catch(...) {
  return false;
}
