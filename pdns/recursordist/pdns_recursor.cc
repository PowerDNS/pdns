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

#include "rec-main.hh"

#include "arguments.hh"
#include "dns_random.hh"
#include "ednsextendederror.hh"
#include "ednspadding.hh"
#include "query-local-address.hh"
#include "rec-taskqueue.hh"
#include "shuffle.hh"
#include "validate-recursor.hh"
#include "ratelimitedlog.hh"
#include "ednsoptions.hh"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef NOD_ENABLED
#include "nod.hh"
#include "logging.hh"
#endif /* NOD_ENABLED */

thread_local std::shared_ptr<RecursorLua4> t_pdl;
thread_local std::shared_ptr<Regex> t_traceRegex;
thread_local FDWrapper t_tracefd = -1;
thread_local ProtobufServersInfo t_protobufServers;
thread_local ProtobufServersInfo t_outgoingProtobufServers;

thread_local std::unique_ptr<MT_t> g_multiTasker; // the big MTasker
std::unique_ptr<MemRecursorCache> g_recCache;
std::unique_ptr<NegCache> g_negCache;
std::unique_ptr<RecursorPacketCache> g_packetCache;

thread_local std::unique_ptr<FDMultiplexer> t_fdm;
thread_local std::unique_ptr<addrringbuf_t> t_remotes, t_servfailremotes, t_largeanswerremotes, t_bogusremotes;
thread_local std::unique_ptr<boost::circular_buffer<pair<DNSName, uint16_t>>> t_queryring, t_servfailqueryring, t_bogusqueryring;
thread_local std::shared_ptr<NetmaskGroup> t_allowFrom;
thread_local std::shared_ptr<NetmaskGroup> t_allowNotifyFrom;
thread_local std::shared_ptr<notifyset_t> t_allowNotifyFor;
__thread struct timeval g_now; // timestamp, updated (too) frequently

using listenSocketsAddresses_t = map<int, ComboAddress>; // is shared across all threads right now

static listenSocketsAddresses_t g_listenSocketsAddresses; // is shared across all threads right now
static set<int> g_fromtosockets; // listen sockets that use 'sendfromto()' mechanism (without actually using sendfromto())
NetmaskGroup g_paddingFrom;
size_t g_proxyProtocolMaximumSize;
size_t g_maxUDPQueriesPerRound;
unsigned int g_maxMThreads;
unsigned int g_paddingTag;
PaddingMode g_paddingMode;
uint16_t g_udpTruncationThreshold;
std::atomic<bool> g_quiet;
bool g_allowNoRD;
bool g_logCommonErrors;
bool g_reusePort{false};
bool g_gettagNeedsEDNSOptions{false};
bool g_useKernelTimestamp;
std::atomic<uint32_t> g_maxCacheEntries, g_maxPacketCacheEntries;
#ifdef HAVE_BOOST_CONTAINER_FLAT_SET_HPP
boost::container::flat_set<uint16_t> g_avoidUdpSourcePorts;
#else
std::set<uint16_t> g_avoidUdpSourcePorts;
#endif
uint16_t g_minUdpSourcePort;
uint16_t g_maxUdpSourcePort;
double g_balancingFactor;

bool g_lowercaseOutgoing;
unsigned int g_networkTimeoutMsec;
uint16_t g_outgoingEDNSBufsize;

// Used in Syncres to counts DNSSEC stats for names in a different "universe"
GlobalStateHolder<SuffixMatchNode> g_xdnssec;
// Used in the Syncres to not throttle certain servers
GlobalStateHolder<SuffixMatchNode> g_dontThrottleNames;
GlobalStateHolder<NetmaskGroup> g_dontThrottleNetmasks;
GlobalStateHolder<SuffixMatchNode> g_DoTToAuthNames;
uint64_t g_latencyStatSize;

static pdns::RateLimitedLog s_rateLimitedLogger;

LWResult::Result UDPClientSocks::getSocket(const ComboAddress& toaddr, int* fileDesc)
{
  *fileDesc = makeClientSocket(toaddr.sin4.sin_family);
  if (*fileDesc < 0) { // temporary error - receive exception otherwise
    return LWResult::Result::OSLimitError;
  }

  if (connect(*fileDesc, reinterpret_cast<const struct sockaddr*>(&toaddr), toaddr.getSocklen()) < 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast))
    int err = errno;
    try {
      closesocket(*fileDesc);
    }
    catch (const PDNSException& e) {
      SLOG(g_log << Logger::Error << "Error closing UDP socket after connect() failed: " << e.reason << endl,
           g_slogout->error(Logr::Error, e.reason, "Error closing UDP socket after connect() failed", "exception", Logging::Loggable("PDNSException")));
    }

    if (err == ENETUNREACH) { // Seth "My Interfaces Are Like A Yo Yo" Arnold special
      return LWResult::Result::OSLimitError;
    }

    return LWResult::Result::PermanentError;
  }

  d_numsocks++;
  return LWResult::Result::Success;
}

// return a socket to the pool, or simply erase it
void UDPClientSocks::returnSocket(int fileDesc)
{
  try {
    t_fdm->removeReadFD(fileDesc);
  }
  catch (const FDMultiplexerException& e) {
    // we sometimes return a socket that has not yet been assigned to t_fdm
  }

  try {
    closesocket(fileDesc);
  }
  catch (const PDNSException& e) {
    SLOG(g_log << Logger::Error << "Error closing returned UDP socket: " << e.reason << endl,
         g_slogout->error(Logr::Error, e.reason, "Error closing returned UDP socket", "exception", Logging::Loggable("PDNSException")));
  }

  --d_numsocks;
}

// returns -1 for errors which might go away, throws for ones that won't
int UDPClientSocks::makeClientSocket(int family)
{
  int ret = socket(family, SOCK_DGRAM, 0); // turns out that setting CLO_EXEC and NONBLOCK from here is not a performance win on Linux (oddly enough)

  if (ret < 0 && errno == EMFILE) { // this is not a catastrophic error
    return ret;
  }
  if (ret < 0) {
    int err = errno;
    throw PDNSException("Making a socket for resolver (family = " + std::to_string(family) + "): " + stringerror(err));
  }

  // The loop below runs the body with [tries-1 tries-2 ... 1]. Last iteration with tries == 1 is special: it uses a kernel
  // allocated UDP port.
#if !defined(__OpenBSD__)
  int tries = 10;
#else
  int tries = 2; // hit the reliable kernel random case for OpenBSD immediately (because it will match tries==1 below), using sysctl net.inet.udp.baddynamic to exclude ports
#endif
  ComboAddress sin;
  while (--tries != 0) {
    in_port_t port = 0;

    if (tries == 1) { // last iteration: fall back to kernel 'random'
      port = 0;
    }
    else {
      do {
        port = g_minUdpSourcePort + dns_random(g_maxUdpSourcePort - g_minUdpSourcePort + 1);
      } while (g_avoidUdpSourcePorts.count(port) != 0);
    }

    sin = pdns::getQueryLocalAddress(family, port); // does htons for us
    if (::bind(ret, reinterpret_cast<struct sockaddr*>(&sin), sin.getSocklen()) >= 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      break;
    }
  }

  int err = errno;

  if (tries == 0) {
    closesocket(ret);
    throw PDNSException("Resolver binding to local query client socket on " + sin.toString() + ": " + stringerror(err));
  }

  try {
    setReceiveSocketErrors(ret, family);
    setNonBlocking(ret);
  }
  catch (...) {
    closesocket(ret);
    throw;
  }
  return ret;
}

static void handleGenUDPQueryResponse(int fileDesc, FDMultiplexer::funcparam_t& var)
{
  auto pident = boost::any_cast<std::shared_ptr<PacketID>>(var);
  PacketBuffer resp;
  resp.resize(512);
  ComboAddress fromaddr;
  socklen_t addrlen = sizeof(fromaddr);

  ssize_t ret = recvfrom(fileDesc, resp.data(), resp.size(), 0, reinterpret_cast<sockaddr*>(&fromaddr), &addrlen); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  if (fromaddr != pident->remote) {
    SLOG(g_log << Logger::Notice << "Response received from the wrong remote host (" << fromaddr.toStringWithPort() << " instead of " << pident->remote.toStringWithPort() << "), discarding" << endl,
         g_slog->withName("lua")->info(Logr::Notice, "Response received from the wrong remote host. discarding", "method", Logging::Loggable("GenUDPQueryResponse"), "fromaddr", Logging::Loggable(fromaddr), "expected", Logging::Loggable(pident->remote)));
  }

  t_fdm->removeReadFD(fileDesc);
  if (ret >= 0) {
    resp.resize(ret);
    g_multiTasker->sendEvent(pident, &resp);
  }
  else {
    PacketBuffer empty;
    g_multiTasker->sendEvent(pident, &empty);
  }
}

PacketBuffer GenUDPQueryResponse(const ComboAddress& dest, const string& query)
{
  Socket socket(dest.sin4.sin_family, SOCK_DGRAM);
  socket.setNonBlocking();
  ComboAddress local = pdns::getQueryLocalAddress(dest.sin4.sin_family, 0);

  socket.bind(local);
  socket.connect(dest);
  socket.send(query);

  std::shared_ptr<PacketID> pident = std::make_shared<PacketID>();
  pident->fd = socket.getHandle();
  pident->remote = dest;
  pident->type = 0;
  t_fdm->addReadFD(socket.getHandle(), handleGenUDPQueryResponse, pident);

  PacketBuffer data;
  int ret = g_multiTasker->waitEvent(pident, &data, authWaitTimeMSec(g_multiTasker));

  if (ret == 0 || ret == -1) { // timeout
    t_fdm->removeReadFD(socket.getHandle());
  }
  else if (data.empty()) { // error, EOF or other
    // we could special case this
    return data;
  }
  return data;
}

static void handleUDPServerResponse(int fileDesc, FDMultiplexer::funcparam_t& var);

thread_local std::unique_ptr<UDPClientSocks> t_udpclientsocks;

// If we have plenty of mthreads slot left, use default timeout.
// Otherwise reduce the timeout to be between g_networkTimeoutMsec/10 and g_networkTimeoutMsec
unsigned int authWaitTimeMSec(const std::unique_ptr<MT_t>& mtasker)
{
  const auto max = g_maxMThreads;
  const auto current = mtasker->numProcesses();
  const unsigned int cutoff = max / 10; // if we have less than 10% used,  do not reduce auth timeout
  if (current < cutoff) {
    return g_networkTimeoutMsec;
  }
  const auto avail = max - current;
  return std::max(g_networkTimeoutMsec / 10, g_networkTimeoutMsec * avail / (max - cutoff));
}

/* these two functions are used by LWRes */
LWResult::Result asendto(const void* data, size_t len, int /* flags */,
                         const ComboAddress& toAddress, uint16_t qid, const DNSName& domain, uint16_t qtype, const std::optional<EDNSSubnetOpts>& ecs, int* fileDesc, timeval& now)
{

  auto pident = std::make_shared<PacketID>();
  pident->domain = domain;
  pident->remote = toAddress;
  pident->type = qtype;
  if (ecs) {
    pident->ecsSubnet = ecs->source;
  }

  // See if there is an existing outstanding request we can chain on to, using partial equivalence
  // function looking for the same query (qname, qtype and ecs if applicable) to the same host, but
  // with a different message ID.
  auto chain = g_multiTasker->getWaiters().equal_range(pident, PacketIDBirthdayCompare());

  for (; chain.first != chain.second; chain.first++) {
    // Line below detected an issue with the two ways of ordering PacketIDs (birthday and non-birthday)
    assert(chain.first->key->domain == pident->domain); // NOLINT
    // don't chain onto existing chained waiter or a chain already processed
    if (chain.first->key->fd > -1 && !chain.first->key->closed) {
      auto currentChainSize = chain.first->key->authReqChain.size();
      *fileDesc = -static_cast<int>(currentChainSize + 1); // value <= -1, gets used in waitEvent / sendEvent later on
      if (g_maxChainLength > 0 && currentChainSize >= g_maxChainLength) {
        return LWResult::Result::ChainLimitError;
      }
      assert(uSec(chain.first->key->creationTime) != 0); // NOLINT
      auto age = now - chain.first->key->creationTime;
      if (uSec(age) > static_cast<uint64_t>(1000) * authWaitTimeMSec(g_multiTasker) * 2 / 3) {
        return LWResult::Result::ChainLimitError;
      }
      chain.first->key->authReqChain.emplace(*fileDesc, qid); // we can chain
      auto maxLength = t_Counters.at(rec::Counter::maxChainLength);
      if (currentChainSize + 1 > maxLength) {
        t_Counters.at(rec::Counter::maxChainLength) = currentChainSize + 1;
      }
      return LWResult::Result::Success;
    }
  }

  auto ret = t_udpclientsocks->getSocket(toAddress, fileDesc);
  if (ret != LWResult::Result::Success) {
    return ret;
  }

  pident->fd = *fileDesc;
  pident->id = qid;

  t_fdm->addReadFD(*fileDesc, handleUDPServerResponse, pident);
  ssize_t sent = send(*fileDesc, data, len, 0);

  int tmp = errno;

  if (sent < 0) {
    t_udpclientsocks->returnSocket(*fileDesc);
    errno = tmp; // this is for logging purposes only
    return LWResult::Result::PermanentError;
  }

  return LWResult::Result::Success;
}

LWResult::Result arecvfrom(PacketBuffer& packet, int /* flags */, const ComboAddress& fromAddr, size_t& len,
                           uint16_t qid, const DNSName& domain, uint16_t qtype, int fileDesc, const std::optional<EDNSSubnetOpts>& ecs, const struct timeval& now)
{
  static const unsigned int nearMissLimit = ::arg().asNum("spoof-nearmiss-max");

  auto pident = std::make_shared<PacketID>();
  pident->fd = fileDesc;
  pident->id = qid;
  pident->domain = domain;
  pident->type = qtype;
  pident->remote = fromAddr;
  pident->creationTime = now;
  if (ecs) {
    // We sent out the query using ecs
    // We expect incoming source ECS to match, see https://www.rfc-editor.org/rfc/rfc7871#section-7.3
    // But there's also section 11-2, which says we should treat absent incoming ecs as scope zero
    // We fill in the search key with the ecs we sent out, so both cases are covered and accepted here.
    pident->ecsSubnet = ecs->source;
  }
  int ret = g_multiTasker->waitEvent(pident, &packet, authWaitTimeMSec(g_multiTasker), &now);
  len = 0;

  /* -1 means error, 0 means timeout, 1 means a result from handleUDPServerResponse() which might still be an error */
  if (ret > 0) {
    /* handleUDPServerResponse() will close the socket for us no matter what */
    if (packet.empty()) { // means "error"
      return LWResult::Result::PermanentError;
    }

    len = packet.size();

    // In ecs hardening mode, we consider a missing ECS in the reply as a case for retrying without ECS
    // The actual logic to do that is in Syncres::doResolveAtThisIP()
    if (g_ECSHardening && pident->ecsSubnet && !*pident->ecsReceived) {
      t_Counters.at(rec::Counter::ecsMissingCount)++;
      return LWResult::Result::ECSMissing;
    }
    if (nearMissLimit > 0 && pident->nearMisses > nearMissLimit) {
      /* we have received more than nearMissLimit answers on the right IP and port, from the right source (we are using connected sockets),
         for the correct qname and qtype, but with an unexpected message ID. That looks like a spoofing attempt. */
      SLOG(g_log << Logger::Error << "Too many (" << pident->nearMisses << " > " << nearMissLimit << ") answers with a wrong message ID for '" << domain << "' from " << fromAddr.toString() << ", assuming spoof attempt." << endl,
           g_slogudpin->info(Logr::Error, "Too many answers with a wrong message ID, assuming spoofing attempt",
                             "nearmisses", Logging::Loggable(pident->nearMisses),
                             "nearmisslimit", Logging::Loggable(nearMissLimit),
                             "qname", Logging::Loggable(domain),
                             "from", Logging::Loggable(fromAddr)));
      t_Counters.at(rec::Counter::spoofCount)++;
      return LWResult::Result::Spoofed;
    }

    return LWResult::Result::Success;
  }
  /* getting there means error or timeout, it's up to us to close the socket */
  if (fileDesc >= 0) {
    t_udpclientsocks->returnSocket(fileDesc);
  }

  return ret == 0 ? LWResult::Result::Timeout : LWResult::Result::PermanentError;
}

// the idea is, only do things that depend on the *response* here. Incoming accounting is on incoming.
static void updateResponseStats(int res, const ComboAddress& remote, unsigned int packetsize, const DNSName* query, uint16_t qtype)
{
  if (packetsize > 1000 && t_largeanswerremotes) {
    t_largeanswerremotes->push_back(remote);
  }
  switch (res) {
  case RCode::ServFail:
    if (t_servfailremotes) {
      t_servfailremotes->push_back(remote);
      if (query != nullptr && t_servfailqueryring) { // packet cache
        t_servfailqueryring->push_back({*query, qtype});
      }
    }
    ++t_Counters.at(rec::Counter::servFails);
    break;
  case RCode::NXDomain:
    ++t_Counters.at(rec::Counter::nxDomains);
    break;
  case RCode::NoError:
    t_Counters.at(rec::Counter::noErrors)++;
    break;
  }
}

/**
 * Chases the CNAME provided by the PolicyCustom RPZ policy.
 *
 * @param spoofed: The DNSRecord that was created by the policy, should already be added to ret
 * @param qtype: The QType of the original query
 * @param sr: A SyncRes
 * @param res: An integer that will contain the RCODE of the lookup we do
 * @param ret: A vector of DNSRecords where the result of the CNAME chase should be appended to
 */
static void handleRPZCustom(const DNSRecord& spoofed, const QType& qtype, SyncRes& resolver, int& res, vector<DNSRecord>& ret)
{
  if (spoofed.d_type == QType::CNAME) {
    bool oldWantsRPZ = resolver.getWantsRPZ();
    resolver.setWantsRPZ(false);
    vector<DNSRecord> ans;
    res = resolver.beginResolve(DNSName(spoofed.getContent()->getZoneRepresentation()), qtype, QClass::IN, ans);
    for (const auto& rec : ans) {
      if (rec.d_place == DNSResourceRecord::ANSWER) {
        ret.push_back(rec);
      }
    }
    // Reset the RPZ state of the SyncRes
    resolver.setWantsRPZ(oldWantsRPZ);
  }
}

static bool addRecordToPacket(DNSPacketWriter& packetWritewr, const DNSRecord& rec, uint32_t& minTTL, uint32_t ttlCap, const uint16_t maxAnswerSize, bool& seenAuthSOA)
{
  packetWritewr.startRecord(rec.d_name, rec.d_type, (rec.d_ttl > ttlCap ? ttlCap : rec.d_ttl), rec.d_class, rec.d_place);

  if (rec.d_type == QType::SOA && rec.d_place == DNSResourceRecord::AUTHORITY) {
    seenAuthSOA = true;
  }

  if (rec.d_type != QType::OPT) { // their TTL ain't real
    minTTL = min(minTTL, rec.d_ttl);
  }

  rec.getContent()->toPacket(packetWritewr);
  if (packetWritewr.size() > static_cast<size_t>(maxAnswerSize)) {
    packetWritewr.rollback();
    if (rec.d_place != DNSResourceRecord::ADDITIONAL) {
      packetWritewr.getHeader()->tc = 1;
      packetWritewr.truncate();
    }
    return false;
  }

  return true;
}

/**
 * A helper class that handles the TCP in-flight bookkeeping on
 * destruct. This class ise used by startDoResolve() to not forget
 * that. You can also signal that the TCP connection must be closed
 * once the in-flight connections drop to zero.
 **/
class RunningResolveGuard
{
public:
  RunningResolveGuard(const RunningResolveGuard&) = default;
  RunningResolveGuard(RunningResolveGuard&&) = delete;
  RunningResolveGuard& operator=(const RunningResolveGuard&) = delete;
  RunningResolveGuard& operator=(RunningResolveGuard&&) = delete;
  RunningResolveGuard(std::unique_ptr<DNSComboWriter>& comboWriter) :
    d_dc(comboWriter)
  {
    if (d_dc->d_tcp && !d_dc->d_tcpConnection) {
      throw std::runtime_error("incoming TCP case without TCP connection");
    }
  }
  ~RunningResolveGuard()
  {
    if (!d_handled && d_dc->d_tcp) {
      try {
        finishTCPReply(d_dc, false, true);
      }
      catch (const FDMultiplexerException&) {
      }
    }
  }
  void setHandled()
  {
    d_handled = true;
  }
  void setDropOnIdle()
  {
    if (d_dc->d_tcp) {
      d_dc->d_tcpConnection->setDropOnIdle();
    }
  }

private:
  std::unique_ptr<DNSComboWriter>& d_dc; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
  bool d_handled{false};
};

enum class PolicyResult : uint8_t
{
  NoAction,
  HaveAnswer,
  Drop
};

static PolicyResult handlePolicyHit(const DNSFilterEngine::Policy& appliedPolicy, const std::unique_ptr<DNSComboWriter>& comboWriter, SyncRes& resolver, int& res, vector<DNSRecord>& ret, DNSPacketWriter& packetWriter, RunningResolveGuard& tcpGuard)
{
  /* don't account truncate actions for TCP queries, since they are not applied */
  if (appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::Truncate || !comboWriter->d_tcp) {
    ++t_Counters.at(rec::PolicyHistogram::policy).at(appliedPolicy.d_kind);
    ++t_Counters.at(rec::PolicyNameHits::policyName).counts[appliedPolicy.getName()];
  }

  if (resolver.doLog() && appliedPolicy.d_type != DNSFilterEngine::PolicyType::None) {
    SLOG(g_log << Logger::Warning << comboWriter->d_mdp.d_qname << "|" << QType(comboWriter->d_mdp.d_qtype) << appliedPolicy.getLogString() << endl,
         appliedPolicy.info(Logr::Warning, resolver.d_slog));
  }

  if (appliedPolicy.d_zoneData && appliedPolicy.d_zoneData->d_extendedErrorCode) {
    comboWriter->d_extendedErrorCode = *appliedPolicy.d_zoneData->d_extendedErrorCode;
    comboWriter->d_extendedErrorExtra = appliedPolicy.d_zoneData->d_extendedErrorExtra;
  }

  switch (appliedPolicy.d_kind) {

  case DNSFilterEngine::PolicyKind::NoAction:
    return PolicyResult::NoAction;

  case DNSFilterEngine::PolicyKind::Drop:
    tcpGuard.setDropOnIdle();
    ++t_Counters.at(rec::Counter::policyDrops);
    return PolicyResult::Drop;

  case DNSFilterEngine::PolicyKind::NXDOMAIN:
    ret.clear();
    appliedPolicy.addSOAtoRPZResult(ret);
    res = RCode::NXDomain;
    return PolicyResult::HaveAnswer;

  case DNSFilterEngine::PolicyKind::NODATA:
    ret.clear();
    appliedPolicy.addSOAtoRPZResult(ret);
    res = RCode::NoError;
    return PolicyResult::HaveAnswer;

  case DNSFilterEngine::PolicyKind::Truncate:
    if (!comboWriter->d_tcp) {
      ret.clear();
      appliedPolicy.addSOAtoRPZResult(ret);
      res = RCode::NoError;
      packetWriter.getHeader()->tc = 1;
      return PolicyResult::HaveAnswer;
    }
    return PolicyResult::NoAction;

  case DNSFilterEngine::PolicyKind::Custom:
    res = RCode::NoError;
    {
      auto spoofed = appliedPolicy.getCustomRecords(comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype);
      for (auto& record : spoofed) {
        ret.push_back(record);
        try {
          handleRPZCustom(record, QType(comboWriter->d_mdp.d_qtype), resolver, res, ret);
        }
        catch (const ImmediateServFailException& e) {
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << comboWriter->getRemote() << " during resolve of the custom filter policy '" << appliedPolicy.getName() << "' while resolving '" << comboWriter->d_mdp.d_qname << "' because: " << e.reason << endl,
                 resolver.d_slog->error(Logr::Notice, e.reason, "Sending SERVFAIL during resolve of the custom filter policy",
                                        "policyName", Logging::Loggable(appliedPolicy.getName()), "exception", Logging::Loggable("ImmediateServFailException")));
          }
          res = RCode::ServFail;
          break;
        }
        catch (const pdns::validation::TooManySEC3IterationsException& e) {
          if (g_logCommonErrors || (g_dnssecLogBogus && resolver.getDNSSECLimitHit())) {
            SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << comboWriter->getRemote() << " during resolve of the custom filter policy '" << appliedPolicy.getName() << "' while resolving '" << comboWriter->d_mdp.d_qname << "' because: " << e.what() << endl,
                 resolver.d_slog->error(Logr::Notice, e.what(), "Sending SERVFAIL during resolve of the custom filter policy",
                                        "policyName", Logging::Loggable(appliedPolicy.getName()), "exception", Logging::Loggable("TooManySEC3IterationsException"), "dnsseclimithit", Logging::Loggable(resolver.getDNSSECLimitHit())));
          }
          res = RCode::ServFail;
          break;
        }
        catch (const PolicyHitException& e) {
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << comboWriter->getRemote() << " during resolve of the custom filter policy '" << appliedPolicy.getName() << "' while resolving '" << comboWriter->d_mdp.d_qname << "' because another RPZ policy was hit" << endl,
                 resolver.d_slog->info(Logr::Notice, "Sending SERVFAIL during resolve of the custom filter policy because another RPZ policy was hit",
                                       "policyName", Logging::Loggable(appliedPolicy.getName()), "exception", Logging::Loggable("PolicyHitException")));
          }
          res = RCode::ServFail;
          break;
        }
      }

      appliedPolicy.addSOAtoRPZResult(ret);
      return PolicyResult::HaveAnswer;
    }
  }

  return PolicyResult::NoAction;
}

#ifdef NOD_ENABLED
static bool nodCheckNewDomain(Logr::log_t nodlogger, const DNSName& dname)
{
  bool ret = false;
  // First check the (sub)domain isn't ignored for NOD purposes
  if (g_nodDomainWL.check(dname)) {
    return ret;
  }
  // Now check the NODDB (note this is probabilistic so can have FNs/FPs)
  if (g_nodDBp && g_nodDBp->isNewDomain(dname)) {
    if (g_nodLog) {
      // This should probably log to a dedicated log file
      SLOG(g_log << Logger::Notice << "Newly observed domain nod=" << dname << endl,
           nodlogger->info(Logr::Notice, "New domain observed"));
    }
    t_Counters.at(rec::Counter::nodCount)++;
    ret = true;
  }
  return ret;
}

static void sendNODLookup(Logr::log_t nodlogger, const DNSName& dname)
{
  if (!(g_nodLookupDomain.isRoot())) {
    // Send a DNS A query to <domain>.g_nodLookupDomain
    DNSName qname;
    try {
      qname = dname + g_nodLookupDomain;
    }
    catch (const std::range_error& e) {
      if (g_logCommonErrors) {
        nodlogger->v(10)->error(Logr::Error, "DNSName too long", "Unable to send NOD lookup");
      }
      ++t_Counters.at(rec::Counter::nodLookupsDroppedOversize);
      return;
    }
    nodlogger->v(10)->info(Logr::Debug, "Sending NOD lookup", "nodqname", Logging::Loggable(qname));
    vector<DNSRecord> dummy;
    directResolve(qname, QType::A, QClass::IN, dummy, nullptr, false, nodlogger);
  }
}

static bool udrCheckUniqueDNSRecord(Logr::log_t nodlogger, const DNSName& dname, uint16_t qtype, const DNSRecord& record)
{
  bool ret = false;
  // First check the (sub)domain isn't ignored for UDR purposes
  if (g_udrDomainWL.check(dname)) {
    return ret;
  }
  if (record.d_place == DNSResourceRecord::ANSWER || record.d_place == DNSResourceRecord::ADDITIONAL) {
    // Create a string that represent a triplet of (qname, qtype and RR[type, name, content])
    std::stringstream strStream;
    strStream << dname.toDNSStringLC() << ":" << qtype << ":" << qtype << ":" << record.d_type << ":" << record.d_name.toDNSStringLC() << ":" << record.getContent()->getZoneRepresentation();
    if (g_udrDBp && g_udrDBp->isUniqueResponse(strStream.str())) {
      if (g_udrLog) {
        // This should also probably log to a dedicated file.
        SLOG(g_log << Logger::Notice << "Unique response observed: qname=" << dname << " qtype=" << QType(qtype) << " rrtype=" << QType(record.d_type) << " rrname=" << record.d_name << " rrcontent=" << record.getContent()->getZoneRepresentation() << endl,
             nodlogger->info(Logr::Notice, "New response observed",
                             "qtype", Logging::Loggable(QType(qtype)),
                             "rrtype", Logging::Loggable(QType(record.d_type)),
                             "rrname", Logging::Loggable(record.d_name),
                             "rrcontent", Logging::Loggable(record.getContent()->getZoneRepresentation())););
      }
      t_Counters.at(rec::Counter::udrCount)++;
      ret = true;
    }
  }
  return ret;
}
#endif /* NOD_ENABLED */

static bool dns64Candidate(uint16_t requestedType, int rcode, const std::vector<DNSRecord>& records);

int followCNAMERecords(vector<DNSRecord>& ret, const QType qtype, int rcode)
{
  vector<DNSRecord> resolved;
  DNSName target;
  for (const DNSRecord& record : ret) {
    if (record.d_type == QType::CNAME) {
      auto rec = getRR<CNAMERecordContent>(record);
      if (rec) {
        target = rec->getTarget();
        break;
      }
    }
  }

  if (target.empty()) {
    return rcode;
  }

  auto log = g_slog->withName("lua")->withValues("method", Logging::Loggable("followCNAMERecords"));
  rcode = directResolve(target, qtype, QClass::IN, resolved, t_pdl, log);

  if (g_dns64Prefix && qtype == QType::AAAA && dns64Candidate(qtype, rcode, resolved)) {
    rcode = getFakeAAAARecords(target, *g_dns64Prefix, resolved);
  }

  for (DNSRecord& record : resolved) {
    if (record.d_place == DNSResourceRecord::ANSWER) {
      ret.push_back(std::move(record));
    }
  }
  return rcode;
}

int getFakeAAAARecords(const DNSName& qname, ComboAddress prefix, vector<DNSRecord>& ret)
{
  auto log = g_slog->withName("dns64")->withValues("method", Logging::Loggable("getAAAA"));
  /* we pass a separate vector of records because we will be resolving the initial qname
     again, possibly encountering the same CNAME(s), and we don't want to trigger the CNAME
     loop detection. */
  vector<DNSRecord> newRecords;
  int rcode = directResolve(qname, QType::A, QClass::IN, newRecords, t_pdl, log);

  ret.reserve(ret.size() + newRecords.size());
  for (auto& record : newRecords) {
    ret.push_back(std::move(record));
  }

  // Remove double CNAME records
  std::set<DNSName> seenCNAMEs;
  ret.erase(std::remove_if(
              ret.begin(),
              ret.end(),
              [&seenCNAMEs](DNSRecord& record) {
                if (record.d_type == QType::CNAME) {
                  auto target = getRR<CNAMERecordContent>(record);
                  if (target == nullptr) {
                    return false;
                  }
                  if (seenCNAMEs.count(target->getTarget()) > 0) {
                    // We've had this CNAME before, remove it
                    return true;
                  }
                  seenCNAMEs.insert(target->getTarget());
                }
                return false;
              }),
            ret.end());

  bool seenA = false;
  for (DNSRecord& record : ret) {
    if (record.d_type == QType::A && record.d_place == DNSResourceRecord::ANSWER) {
      if (auto rec = getRR<ARecordContent>(record)) {
        ComboAddress ipv4(rec->getCA());
        memcpy(&prefix.sin6.sin6_addr.s6_addr[12], &ipv4.sin4.sin_addr.s_addr, sizeof(ipv4.sin4.sin_addr.s_addr));
        record.setContent(std::make_shared<AAAARecordContent>(prefix));
        record.d_type = QType::AAAA;
      }
      seenA = true;
    }
  }

  if (seenA) {
    // We've seen an A in the ANSWER section, so there is no need to keep any
    // SOA in the AUTHORITY section as this is not a NODATA response.
    ret.erase(std::remove_if(
                ret.begin(),
                ret.end(),
                [](DNSRecord& record) {
                  return (record.d_type == QType::SOA && record.d_place == DNSResourceRecord::AUTHORITY);
                }),
              ret.end());
  }
  else {
    // Remove double SOA records
    std::set<DNSName> seenSOAs;
    ret.erase(std::remove_if(
                ret.begin(),
                ret.end(),
                [&seenSOAs](DNSRecord& record) {
                  if (record.d_type == QType::SOA) {
                    if (seenSOAs.count(record.d_name) > 0) {
                      // We've had this SOA before, remove it
                      return true;
                    }
                    seenSOAs.insert(record.d_name);
                  }
                  return false;
                }),
              ret.end());
  }
  t_Counters.at(rec::Counter::dns64prefixanswers)++;
  return rcode;
}

int getFakePTRRecords(const DNSName& qname, vector<DNSRecord>& ret)
{
  /* qname has a reverse ordered IPv6 address, need to extract the underlying IPv4 address from it
     and turn it into an IPv4 in-addr.arpa query */
  ret.clear();
  vector<string> parts = qname.getRawLabels();

  if (parts.size() < 8) {
    return -1;
  }

  string newquery;
  for (size_t octet = 0; octet < 4; ++octet) {
    newquery += std::to_string(stoll(parts[octet * 2], nullptr, 16) + 16 * stoll(parts[octet * 2 + 1], nullptr, 16));
    newquery.append(1, '.');
  }
  newquery += "in-addr.arpa.";

  auto log = g_slog->withName("dns64")->withValues("method", Logging::Loggable("getPTR"));
  vector<DNSRecord> answers;
  int rcode = directResolve(DNSName(newquery), QType::PTR, QClass::IN, answers, t_pdl, log);

  DNSRecord record;
  record.d_name = qname;
  record.d_type = QType::CNAME;
  record.setContent(std::make_shared<CNAMERecordContent>(newquery));
  // Copy the TTL of the synthesized CNAME from the actual answer
  record.d_ttl = (rcode == RCode::NoError && !answers.empty()) ? answers.at(0).d_ttl : SyncRes::s_minimumTTL;
  ret.push_back(record);

  ret.insert(ret.end(), answers.begin(), answers.end());

  t_Counters.at(rec::Counter::dns64prefixanswers)++;
  return rcode;
}

// RFC 6147 section 5.1 all rcodes except NXDomain should be candidate for dns64
// for NoError, check if it is NoData
static bool dns64Candidate(uint16_t requestedType, int rcode, const std::vector<DNSRecord>& records)
{
  if (rcode == RCode::NoError) {
    return SyncRes::answerIsNOData(requestedType, rcode, records);
  }
  return rcode != RCode::NXDomain;
}

bool isAllowNotifyForZone(DNSName qname)
{
  if (t_allowNotifyFor->empty()) {
    return false;
  }

  do {
    auto ret = t_allowNotifyFor->find(qname);
    if (ret != t_allowNotifyFor->end()) {
      return true;
    }
  } while (qname.chopOff());
  return false;
}

#if defined(HAVE_FSTRM) && defined(NOD_ENABLED)
#include "dnstap.hh"
#include "fstrm_logger.hh"

static bool isEnabledForNODs(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers)
{
  if (fstreamLoggers == nullptr) {
    return false;
  }
  for (auto& logger : *fstreamLoggers) {
    if (logger->logNODs()) {
      return true;
    }
  }
  return false;
}
static bool isEnabledForUDRs(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers)
{
  if (fstreamLoggers == nullptr) {
    return false;
  }
  for (auto& logger : *fstreamLoggers) {
    if (logger->logUDRs()) {
      return true;
    }
  }
  return false;
}
#endif // HAVE_FSTRM

static void dumpTrace(const string& trace, const timeval& timev)
{
  if (trace.empty()) {
    return;
  }
  if (t_tracefd < 0) {
    std::istringstream buf(trace);
    g_log << Logger::Warning << "=== START OF FAIL TRACE ====" << endl;
    for (string line; std::getline(buf, line);) {
      g_log << Logger::Warning << line << endl;
    }
    g_log << Logger::Warning << "=== END OF FAIL TRACE ====" << endl;
    return;
  }
  timeval now{};
  Utility::gettimeofday(&now);
  int traceFd = dup(t_tracefd);
  if (traceFd == -1) {
    int err = errno;
    SLOG(g_log << Logger::Error << "Could not dup trace file: " << stringerror(err) << endl,
         g_slog->withName("trace")->error(Logr::Error, err, "Could not dup trace file"));
    return;
  }
  setNonBlocking(traceFd);
  auto filep = pdns::UniqueFilePtr(fdopen(traceFd, "a"));
  if (!filep) {
    int err = errno;
    SLOG(g_log << Logger::Error << "Could not write to trace file: " << stringerror(err) << endl,
         g_slog->withName("trace")->error(Logr::Error, err, "Could not write to trace file"));
    close(traceFd);
    return;
  }
  timebuf_t timebuf;
  isoDateTimeMillis(timev, timebuf);
  fprintf(filep.get(), " us === START OF TRACE %s ===\n", timebuf.data());
  fprintf(filep.get(), "%s", trace.c_str());
  isoDateTimeMillis(now, timebuf);
  if (ferror(filep.get()) != 0) {
    int err = errno;
    SLOG(g_log << Logger::Error << "Problems writing to trace file: " << stringerror(err) << endl,
         g_slog->withName("trace")->error(Logr::Error, err, "Problems writing to trace file"));
    // There's no guarantee the message below will end up in the stream, but we try our best
    clearerr(filep.get());
    fprintf(filep.get(), "=== TRACE %s TRUNCATED; USE FILE ARGUMENT INSTEAD OF `-' ===\n", timebuf.data());
  }
  else {
    fprintf(filep.get(), "=== END OF TRACE %s ===\n", timebuf.data());
  }
  // fclose by unique_ptr does implicit flush
}

static uint32_t capPacketCacheTTL(const struct dnsheader& hdr, uint32_t ttl, bool seenAuthSOA)
{
  if (hdr.rcode == RCode::NXDomain || (hdr.rcode == RCode::NoError && hdr.ancount == 0 && seenAuthSOA)) {
    ttl = std::min(ttl, SyncRes::s_packetcachenegativettl);
  }
  else if ((hdr.rcode != RCode::NoError && hdr.rcode != RCode::NXDomain) || (hdr.ancount == 0 && hdr.nscount == 0)) {
    ttl = min(ttl, SyncRes::s_packetcacheservfailttl);
  }
  else {
    ttl = std::min(ttl, SyncRes::s_packetcachettl);
  }
  return ttl;
}

static void addPolicyTagsToPBMessageIfNeeded(DNSComboWriter& comboWriter, pdns::ProtoZero::RecMessage& pbMessage)
{
  /* we do _not_ want to store policy tags set by the gettag hook into the packet cache,
     since the call to gettag for subsequent queries could yield the same PC tag but different policy tags */
  if (!comboWriter.d_gettagPolicyTags.empty()) {
    for (const auto& tag : comboWriter.d_gettagPolicyTags) {
      comboWriter.d_policyTags.erase(tag);
    }
  }
  if (!comboWriter.d_policyTags.empty()) {
    pbMessage.addPolicyTags(comboWriter.d_policyTags);
  }
}

void startDoResolve(void* arg) // NOLINT(readability-function-cognitive-complexity): https://github.com/PowerDNS/pdns/issues/12791
{
  auto comboWriter = std::unique_ptr<DNSComboWriter>(static_cast<DNSComboWriter*>(arg));
  SyncRes resolver(comboWriter->d_now);
  try {
    if (t_queryring) {
      t_queryring->push_back({comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype});
    }

    uint16_t maxanswersize = comboWriter->d_tcp ? 65535 : min(static_cast<uint16_t>(512), g_udpTruncationThreshold);
    EDNSOpts edo;
    std::vector<pair<uint16_t, string>> ednsOpts;
    bool variableAnswer = comboWriter->d_variable;
    bool haveEDNS = false;
    bool paddingAllowed = false;
    bool addPaddingToResponse = false;
#ifdef NOD_ENABLED
    bool hasUDR = false;
    std::shared_ptr<Logr::Logger> nodlogger{nullptr};
    if (g_udrEnabled || g_nodEnabled) {
      nodlogger = g_slog->withName("nod")->v(1)->withValues("qname", Logging::Loggable(comboWriter->d_mdp.d_qname));
    }
#endif /* NOD_ENABLED */
    DNSPacketWriter::optvect_t returnedEdnsOptions; // Here we stuff all the options for the return packet
    uint8_t ednsExtRCode = 0;
    if (getEDNSOpts(comboWriter->d_mdp, &edo)) {
      haveEDNS = true;
      if (edo.d_version != 0) {
        ednsExtRCode = ERCode::BADVERS;
      }

      if (!comboWriter->d_tcp) {
        /* rfc6891 6.2.3:
           "Values lower than 512 MUST be treated as equal to 512."
        */
        maxanswersize = min(static_cast<uint16_t>(edo.d_packetsize >= 512 ? edo.d_packetsize : 512), g_udpTruncationThreshold);
      }
      ednsOpts = edo.d_options;
      maxanswersize -= 11; // EDNS header size

      if (!comboWriter->d_responsePaddingDisabled && g_paddingFrom.match(comboWriter->d_remote)) {
        paddingAllowed = true;
        if (g_paddingMode == PaddingMode::Always) {
          addPaddingToResponse = true;
        }
      }

      for (const auto& option : edo.d_options) {
        if (option.first == EDNSOptionCode::ECS && g_useIncomingECS && !comboWriter->d_ecsParsed) {
          comboWriter->d_ecsFound = getEDNSSubnetOptsFromString(option.second, &comboWriter->d_ednssubnet);
        }
        else if (option.first == EDNSOptionCode::NSID) {
          const static string mode_server_id = ::arg()["server-id"];
          if (mode_server_id != "disabled" && !mode_server_id.empty() && maxanswersize > (EDNSOptionCodeSize + EDNSOptionLengthSize + mode_server_id.size())) {
            returnedEdnsOptions.emplace_back(EDNSOptionCode::NSID, mode_server_id);
            variableAnswer = true; // Can't packetcache an answer with NSID
            maxanswersize -= EDNSOptionCodeSize + EDNSOptionLengthSize + mode_server_id.size();
          }
        }
        else if (paddingAllowed && !addPaddingToResponse && g_paddingMode == PaddingMode::PaddedQueries && option.first == EDNSOptionCode::PADDING) {
          addPaddingToResponse = true;
        }
      }
    }

    /* the lookup will be done _before_ knowing whether the query actually
       has a padding option, so we need to use the separate tag even when the
       query does not have padding, as long as it is from an allowed source */
    if (paddingAllowed && comboWriter->d_tag == 0) {
      comboWriter->d_tag = g_paddingTag;
    }

    /* perhaps there was no EDNS or no ECS but by now we looked */
    comboWriter->d_ecsParsed = true;
    vector<DNSRecord> ret;
    vector<uint8_t> packet;

    auto luaconfsLocal = g_luaconfs.getLocal();
    // Used to tell syncres later on if we should apply NSDNAME and NSIP RPZ triggers for this query
    bool wantsRPZ(true);
    RecursorPacketCache::OptPBData pbDataForCache;
    pdns::ProtoZero::RecMessage pbMessage;
    if (checkProtobufExport(luaconfsLocal)) {
      pbMessage.reserve(128, 128); // It's a bit of a guess...
      pbMessage.setResponse(comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype, comboWriter->d_mdp.d_qclass);
      pbMessage.setServerIdentity(SyncRes::s_serverID);

      // RRSets added below
    }
    checkOutgoingProtobufExport(luaconfsLocal); // to pick up changed configs
#ifdef HAVE_FSTRM
    checkFrameStreamExport(luaconfsLocal, luaconfsLocal->frameStreamExportConfig, t_frameStreamServersInfo);
    checkFrameStreamExport(luaconfsLocal, luaconfsLocal->nodFrameStreamExportConfig, t_nodFrameStreamServersInfo);
#endif

    DNSPacketWriter packetWriter(packet, comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype, comboWriter->d_mdp.d_qclass, comboWriter->d_mdp.d_header.opcode);

    packetWriter.getHeader()->aa = 0;
    packetWriter.getHeader()->ra = 1;
    packetWriter.getHeader()->qr = 1;
    packetWriter.getHeader()->tc = 0;
    packetWriter.getHeader()->id = comboWriter->d_mdp.d_header.id;
    packetWriter.getHeader()->rd = comboWriter->d_mdp.d_header.rd;
    packetWriter.getHeader()->cd = comboWriter->d_mdp.d_header.cd;

    /* This is the lowest TTL seen in the records of the response,
       so we can't cache it for longer than this value.
       If we have a TTL cap, this value can't be larger than the
       cap no matter what. */
    uint32_t minTTL = comboWriter->d_ttlCap;
    bool seenAuthSOA = false;

    resolver.d_eventTrace = std::move(comboWriter->d_eventTrace);
    resolver.setId(g_multiTasker->getTid());

    bool DNSSECOK = false;
    if (comboWriter->d_luaContext) {
      resolver.setLuaEngine(comboWriter->d_luaContext);
    }
    if (g_dnssecmode != DNSSECMode::Off) {
      resolver.setDoDNSSEC(true);

      // Does the requestor want DNSSEC records?
      if ((edo.d_extFlags & EDNSOpts::DNSSECOK) != 0) {
        DNSSECOK = true;
        t_Counters.at(rec::Counter::dnssecQueries)++;
      }
      if (comboWriter->d_mdp.d_header.cd) {
        /* Per rfc6840 section 5.9, "When processing a request with
           the Checking Disabled (CD) bit set, a resolver SHOULD attempt
           to return all response data, even data that has failed DNSSEC
           validation. */
        ++t_Counters.at(rec::Counter::dnssecCheckDisabledQueries);
      }
      if (comboWriter->d_mdp.d_header.ad) {
        /* Per rfc6840 section 5.7, "the AD bit in a query as a signal
           indicating that the requester understands and is interested in the
           value of the AD bit in the response.  This allows a requester to
           indicate that it understands the AD bit without also requesting
           DNSSEC data via the DO bit. */
        ++t_Counters.at(rec::Counter::dnssecAuthenticDataQueries);
      }
    }
    else {
      // Ignore the client-set CD flag
      packetWriter.getHeader()->cd = 0;
    }
    resolver.setDNSSECValidationRequested(g_dnssecmode == DNSSECMode::ValidateAll || g_dnssecmode == DNSSECMode::ValidateForLog || ((comboWriter->d_mdp.d_header.ad || DNSSECOK) && g_dnssecmode == DNSSECMode::Process));

    resolver.setInitialRequestId(comboWriter->d_uuid);
    resolver.setOutgoingProtobufServers(t_outgoingProtobufServers.servers);
#ifdef HAVE_FSTRM
    resolver.setFrameStreamServers(t_frameStreamServersInfo.servers);
#endif

    bool useMapped = true;
    // If proxy by table is active and had a match, we only want to use the mapped address if it also has a domain match
    // (if a domain suffix match table is present in the config)
    if (t_proxyMapping && comboWriter->d_source != comboWriter->d_mappedSource) {
      if (const auto* iter = t_proxyMapping->lookup(comboWriter->d_source)) {
        if (iter->second.suffixMatchNode) {
          if (!iter->second.suffixMatchNode->check(comboWriter->d_mdp.d_qname)) {
            // No match in domains, use original source
            useMapped = false;
          }
          else {
            ++iter->second.stats.suffixMatches;
          }
        }
        // No suffix match node defined, use mapped address
      }
      // lookup failing cannot happen as dc->d_source != dc->d_mappedSource
    }
    resolver.setQuerySource(useMapped ? comboWriter->d_mappedSource : comboWriter->d_source, g_useIncomingECS && !comboWriter->d_ednssubnet.source.empty() ? boost::optional<const EDNSSubnetOpts&>(comboWriter->d_ednssubnet) : boost::none);

    resolver.setQueryReceivedOverTCP(comboWriter->d_tcp);

    bool tracedQuery = false; // we could consider letting Lua know about this too
    bool shouldNotValidate = false;

    /* preresolve expects res (dq.rcode) to be set to RCode::NoError by default */
    int res = RCode::NoError;

    DNSFilterEngine::Policy appliedPolicy;
    RecursorLua4::DNSQuestion dnsQuestion(comboWriter->d_remote, comboWriter->d_local, comboWriter->d_source, comboWriter->d_destination, comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype, comboWriter->d_tcp, variableAnswer, wantsRPZ, comboWriter->d_logResponse, addPaddingToResponse, (g_useKernelTimestamp && comboWriter->d_kernelTimestamp.tv_sec != 0) ? comboWriter->d_kernelTimestamp : comboWriter->d_now);
    dnsQuestion.ednsFlags = &edo.d_extFlags;
    dnsQuestion.ednsOptions = &ednsOpts;
    dnsQuestion.tag = comboWriter->d_tag;
    dnsQuestion.discardedPolicies = &resolver.d_discardedPolicies;
    dnsQuestion.policyTags = &comboWriter->d_policyTags;
    dnsQuestion.appliedPolicy = &appliedPolicy;
    dnsQuestion.currentRecords = &ret;
    dnsQuestion.dh = &comboWriter->d_mdp.d_header;
    dnsQuestion.data = comboWriter->d_data;
    dnsQuestion.requestorId = comboWriter->d_requestorId;
    dnsQuestion.deviceId = comboWriter->d_deviceId;
    dnsQuestion.deviceName = comboWriter->d_deviceName;
    dnsQuestion.proxyProtocolValues = &comboWriter->d_proxyProtocolValues;
    dnsQuestion.extendedErrorCode = &comboWriter->d_extendedErrorCode;
    dnsQuestion.extendedErrorExtra = &comboWriter->d_extendedErrorExtra;
    dnsQuestion.meta = std::move(comboWriter->d_meta);
    dnsQuestion.fromAuthIP = &resolver.d_fromAuthIP;

    resolver.d_slog = resolver.d_slog->withValues("qname", Logging::Loggable(comboWriter->d_mdp.d_qname),
                                                  "qtype", Logging::Loggable(QType(comboWriter->d_mdp.d_qtype)),
                                                  "remote", Logging::Loggable(comboWriter->getRemote()),
                                                  "proto", Logging::Loggable(comboWriter->d_tcp ? "tcp" : "udp"),
                                                  "ecs", Logging::Loggable(comboWriter->d_ednssubnet.source.empty() ? "" : comboWriter->d_ednssubnet.source.toString()),
                                                  "mtid", Logging::Loggable(g_multiTasker->getTid()));
    RunningResolveGuard tcpGuard(comboWriter);

    if (ednsExtRCode != 0 || comboWriter->d_mdp.d_header.opcode == static_cast<unsigned>(Opcode::Notify)) {
      goto sendit; // NOLINT(cppcoreguidelines-avoid-goto)
    }

    if (comboWriter->d_mdp.d_qtype == QType::ANY && !comboWriter->d_tcp && g_anyToTcp) {
      packetWriter.getHeader()->tc = 1;
      res = 0;
      variableAnswer = true;
      goto sendit; // NOLINT(cppcoreguidelines-avoid-goto)
    }

    if (t_traceRegex && t_traceRegex->match(comboWriter->d_mdp.d_qname.toString())) {
      resolver.setLogMode(SyncRes::Store);
      tracedQuery = true;
    }

    if (!g_quiet || tracedQuery) {
      if (!g_slogStructured) {
        g_log << Logger::Warning << RecThreadInfo::id() << " [" << g_multiTasker->getTid() << "/" << g_multiTasker->numProcesses() << "] " << (comboWriter->d_tcp ? "TCP " : "") << "question for '" << comboWriter->d_mdp.d_qname << "|"
              << QType(comboWriter->d_mdp.d_qtype) << "' from " << comboWriter->getRemote();
        if (!comboWriter->d_ednssubnet.source.empty()) {
          g_log << " (ecs " << comboWriter->d_ednssubnet.source.toString() << ")";
        }
        g_log << endl;
      }
      else {
        resolver.d_slog->info(Logr::Info, "Question");
      }
    }

    if (!comboWriter->d_mdp.d_header.rd) {
      if (g_allowNoRD) {
        resolver.setCacheOnly();
      }
      else {
        ret.clear();
        res = RCode::Refused;
        goto haveAnswer; // NOLINT(cppcoreguidelines-avoid-goto)
      }
    }

    if (comboWriter->d_luaContext) {
      comboWriter->d_luaContext->prerpz(dnsQuestion, res, resolver.d_eventTrace);
    }

    // Check if the client has a policy attached to it
    if (wantsRPZ && !appliedPolicy.wasHit()) {

      if (luaconfsLocal->dfe.getClientPolicy(comboWriter->d_source, resolver.d_discardedPolicies, appliedPolicy)) {
        mergePolicyTags(comboWriter->d_policyTags, appliedPolicy.getTags());
      }
    }

    /* If we already have an answer generated from gettag_ffi, let's see if the filtering policies
       should be applied to it */
    if (comboWriter->d_rcode != boost::none) {

      bool policyOverride = false;
      /* Unless we already matched on the client IP, time to check the qname.
         We normally check it in beginResolve() but it will be bypassed since we already have an answer */
      if (wantsRPZ && appliedPolicy.policyOverridesGettag()) {
        if (appliedPolicy.d_type != DNSFilterEngine::PolicyType::None) {
          // Client IP already matched
        }
        else {
          // no match on the client IP, check the qname
          if (luaconfsLocal->dfe.getQueryPolicy(comboWriter->d_mdp.d_qname, resolver.d_discardedPolicies, appliedPolicy)) {
            // got a match
            mergePolicyTags(comboWriter->d_policyTags, appliedPolicy.getTags());
          }
        }

        if (appliedPolicy.wasHit()) {
          policyOverride = true;
        }
      }

      if (!policyOverride) {
        /* No RPZ or gettag overrides it anyway */
        ret = std::move(comboWriter->d_records);
        res = *comboWriter->d_rcode;
        if (res == RCode::NoError && comboWriter->d_followCNAMERecords) {
          res = followCNAMERecords(ret, QType(comboWriter->d_mdp.d_qtype), res);
        }
        goto haveAnswer; // NOLINT(cppcoreguidelines-avoid-goto)
      }
    }

    // if there is a RecursorLua active, and it 'took' the query in preResolve, we don't launch beginResolve
    if (!comboWriter->d_luaContext || !comboWriter->d_luaContext->preresolve(dnsQuestion, res, resolver.d_eventTrace)) {

      if (!g_dns64PrefixReverse.empty() && dnsQuestion.qtype == QType::PTR && dnsQuestion.qname.isPartOf(g_dns64PrefixReverse)) {
        res = getFakePTRRecords(dnsQuestion.qname, ret);
        goto haveAnswer; // NOLINT(cppcoreguidelines-avoid-goto)
      }

      resolver.setWantsRPZ(wantsRPZ);

      if (wantsRPZ && appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) {

        if (comboWriter->d_luaContext && comboWriter->d_luaContext->policyHitEventFilter(comboWriter->d_source, comboWriter->d_mdp.d_qname, QType(comboWriter->d_mdp.d_qtype), comboWriter->d_tcp, appliedPolicy, comboWriter->d_policyTags, resolver.d_discardedPolicies)) {
          /* reset to no match */
          appliedPolicy = DNSFilterEngine::Policy();
        }
        else {
          auto policyResult = handlePolicyHit(appliedPolicy, comboWriter, resolver, res, ret, packetWriter, tcpGuard);
          if (policyResult == PolicyResult::HaveAnswer) {
            if (g_dns64Prefix && dnsQuestion.qtype == QType::AAAA && dns64Candidate(comboWriter->d_mdp.d_qtype, res, ret)) {
              res = getFakeAAAARecords(dnsQuestion.qname, *g_dns64Prefix, ret);
              shouldNotValidate = true;
            }
            goto haveAnswer; // NOLINT(cppcoreguidelines-avoid-goto)
          }
          else if (policyResult == PolicyResult::Drop) {
            return;
          }
        }
      }

      // Query did not get handled for Client IP or QNAME Policy reasons, now actually go out to find an answer
      try {
        resolver.d_appliedPolicy = appliedPolicy;
        resolver.d_policyTags = std::move(comboWriter->d_policyTags);

        if (!comboWriter->d_routingTag.empty()) {
          resolver.d_routingTag = comboWriter->d_routingTag;
        }

        ret.clear(); // policy might have filled it with custom records but we decided not to use them
        res = resolver.beginResolve(comboWriter->d_mdp.d_qname, QType(comboWriter->d_mdp.d_qtype), comboWriter->d_mdp.d_qclass, ret);
        shouldNotValidate = resolver.wasOutOfBand();
      }
      catch (const ImmediateQueryDropException& e) {
        // XXX We need to export a protobuf message (and do a NOD lookup) if requested!
        t_Counters.at(rec::Counter::policyDrops)++;
        SLOG(g_log << Logger::Debug << "Dropping query because of a filtering policy " << makeLoginfo(comboWriter) << endl,
             resolver.d_slog->info(Logr::Debug, "Dropping query because of a filtering policy"));
        return;
      }
      catch (const ImmediateServFailException& e) {
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << comboWriter->getRemote() << " during resolve of '" << comboWriter->d_mdp.d_qname << "' because: " << e.reason << endl,
               resolver.d_slog->error(Logr::Notice, e.reason, "Sending SERVFAIL during resolve"));
        }
        res = RCode::ServFail;
      }
      catch (const pdns::validation::TooManySEC3IterationsException& e) {
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << comboWriter->getRemote() << " during resolve of '" << comboWriter->d_mdp.d_qname << "' because: " << e.what() << endl,
               resolver.d_slog->error(Logr::Notice, e.what(), "Sending SERVFAIL during resolve", "dnsseclimithit", Logging::Loggable(true)));
        }
        res = RCode::ServFail;
      }
      catch (const SendTruncatedAnswerException& e) {
        ret.clear();
        resolver.d_appliedPolicy.addSOAtoRPZResult(ret);
        res = RCode::NoError;
        packetWriter.getHeader()->tc = 1;
      }
      catch (const PolicyHitException& e) {
        res = -2;
      }
      dnsQuestion.validationState = resolver.getValidationState();
      appliedPolicy = resolver.d_appliedPolicy;
      comboWriter->d_policyTags = std::move(resolver.d_policyTags);

      if (appliedPolicy.d_type != DNSFilterEngine::PolicyType::None && appliedPolicy.d_zoneData && appliedPolicy.d_zoneData->d_extendedErrorCode) {
        comboWriter->d_extendedErrorCode = *appliedPolicy.d_zoneData->d_extendedErrorCode;
        comboWriter->d_extendedErrorExtra = appliedPolicy.d_zoneData->d_extendedErrorExtra;
      }

      // During lookup, an NSDNAME or NSIP trigger was hit in RPZ
      if (res == -2) { // XXX This block should be macro'd, it is repeated post-resolve.
        if (appliedPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction) {
          throw PDNSException("NoAction policy returned while a NSDNAME or NSIP trigger was hit");
        }
        auto policyResult = handlePolicyHit(appliedPolicy, comboWriter, resolver, res, ret, packetWriter, tcpGuard);
        if (policyResult == PolicyResult::HaveAnswer) {
          goto haveAnswer; // NOLINT(cppcoreguidelines-avoid-goto)
        }
        else if (policyResult == PolicyResult::Drop) {
          return;
        }
      }

      bool luaHookHandled = false;
      if (comboWriter->d_luaContext) {
        PolicyResult policyResult = PolicyResult::NoAction;
        if (SyncRes::answerIsNOData(comboWriter->d_mdp.d_qtype, res, ret)) {
          if (comboWriter->d_luaContext->nodata(dnsQuestion, res, resolver.d_eventTrace)) {
            luaHookHandled = true;
            shouldNotValidate = true;
            policyResult = handlePolicyHit(appliedPolicy, comboWriter, resolver, res, ret, packetWriter, tcpGuard);
          }
        }
        else if (res == RCode::NXDomain && comboWriter->d_luaContext->nxdomain(dnsQuestion, res, resolver.d_eventTrace)) {
          luaHookHandled = true;
          shouldNotValidate = true;
          policyResult = handlePolicyHit(appliedPolicy, comboWriter, resolver, res, ret, packetWriter, tcpGuard);
        }
        if (policyResult == PolicyResult::HaveAnswer) {
          goto haveAnswer; // NOLINT(cppcoreguidelines-avoid-goto)
        }
        else if (policyResult == PolicyResult::Drop) {
          return;
        }
      } // dc->d_luaContext

      if (!luaHookHandled && g_dns64Prefix && comboWriter->d_mdp.d_qtype == QType::AAAA && (shouldNotValidate || !resolver.isDNSSECValidationRequested() || !vStateIsBogus(dnsQuestion.validationState)) && dns64Candidate(comboWriter->d_mdp.d_qtype, res, ret)) {
        res = getFakeAAAARecords(dnsQuestion.qname, *g_dns64Prefix, ret);
        shouldNotValidate = true;
      }

      if (comboWriter->d_luaContext) {
        PolicyResult policyResult = PolicyResult::NoAction;
        if (comboWriter->d_luaContext->hasPostResolveFFIfunc()) {
          RecursorLua4::PostResolveFFIHandle handle(dnsQuestion);
          resolver.d_eventTrace.add(RecEventTrace::LuaPostResolveFFI);
          bool prResult = comboWriter->d_luaContext->postresolve_ffi(handle);
          resolver.d_eventTrace.add(RecEventTrace::LuaPostResolveFFI, prResult, false);
          if (prResult) {
            shouldNotValidate = true;
            policyResult = handlePolicyHit(appliedPolicy, comboWriter, resolver, res, ret, packetWriter, tcpGuard);
          }
        }
        else if (comboWriter->d_luaContext->postresolve(dnsQuestion, res, resolver.d_eventTrace)) {
          shouldNotValidate = true;
          policyResult = handlePolicyHit(appliedPolicy, comboWriter, resolver, res, ret, packetWriter, tcpGuard);
        }
        if (policyResult == PolicyResult::HaveAnswer) {
          goto haveAnswer; // NOLINT(cppcoreguidelines-avoid-goto)
        }
        else if (policyResult == PolicyResult::Drop) {
          return;
        }
      } // dc->d_luaContext
    }
    else if (comboWriter->d_luaContext) {
      // preresolve returned true
      shouldNotValidate = true;
      auto policyResult = handlePolicyHit(appliedPolicy, comboWriter, resolver, res, ret, packetWriter, tcpGuard);
      // haveAnswer case redundant
      if (policyResult == PolicyResult::Drop) {
        return;
      }
    }

  haveAnswer:;
    if (tracedQuery || res == -1 || res == RCode::ServFail || packetWriter.getHeader()->rcode == static_cast<unsigned>(RCode::ServFail)) {
      dumpTrace(resolver.getTrace(), resolver.d_fixednow);
    }

    if (res == -1) {
      packetWriter.getHeader()->rcode = RCode::ServFail;
      // no commit here, because no record
      ++t_Counters.at(rec::Counter::servFails);
    }
    else {
      packetWriter.getHeader()->rcode = res;

      // Does the validation mode or query demand validation?
      if (!shouldNotValidate && resolver.isDNSSECValidationRequested()) {
        try {
          auto state = resolver.getValidationState();

          string x_marker;
          std::shared_ptr<Logr::Logger> log;
          if (resolver.doLog() || vStateIsBogus(state)) {
            // Only create logging object if needed below, beware if you change the logging logic!
            log = resolver.d_slog->withValues("vstate", Logging::Loggable(state));
            if (resolver.getDNSSECLimitHit()) {
              log = log->withValues("dnsseclimithit", Logging::Loggable(true));
            }
            auto xdnssec = g_xdnssec.getLocal();
            if (xdnssec->check(comboWriter->d_mdp.d_qname)) {
              log = log->withValues("in-x-dnssec-names", Logging::Loggable(1));
              x_marker = " [in x-dnssec-names]";
            }
          }
          if (state == vState::Secure) {
            if (resolver.doLog()) {
              SLOG(g_log << Logger::Warning << "Answer to " << comboWriter->d_mdp.d_qname << "|" << QType(comboWriter->d_mdp.d_qtype) << x_marker << " for " << comboWriter->getRemote() << " validates correctly" << endl,
                   log->info(Logr::Info, "Validates Correctly"));
            }

            // Is the query source interested in the value of the ad-bit?
            if (comboWriter->d_mdp.d_header.ad || DNSSECOK) {
              packetWriter.getHeader()->ad = 1;
            }
          }
          else if (state == vState::Insecure) {
            if (resolver.doLog()) {
              SLOG(g_log << Logger::Warning << "Answer to " << comboWriter->d_mdp.d_qname << "|" << QType(comboWriter->d_mdp.d_qtype) << x_marker << " for " << comboWriter->getRemote() << " validates as Insecure" << endl,
                   log->info(Logr::Info, "Validates as Insecure"));
            }

            packetWriter.getHeader()->ad = 0;
          }
          else if (vStateIsBogus(state)) {
            if (t_bogusremotes) {
              t_bogusremotes->push_back(comboWriter->d_source);
            }
            if (t_bogusqueryring) {
              t_bogusqueryring->push_back({comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype});
            }
            if (g_dnssecLogBogus || resolver.doLog() || g_dnssecmode == DNSSECMode::ValidateForLog) {
              SLOG(g_log << Logger::Warning << "Answer to " << comboWriter->d_mdp.d_qname << "|" << QType(comboWriter->d_mdp.d_qtype) << x_marker << " for " << comboWriter->getRemote() << " validates as " << vStateToString(state) << endl,
                   log->info(Logr::Notice, "Validates as Bogus"));
            }

            // Does the query or validation mode sending out a SERVFAIL on validation errors?
            if (!packetWriter.getHeader()->cd && (g_dnssecmode == DNSSECMode::ValidateAll || comboWriter->d_mdp.d_header.ad || DNSSECOK)) {
              if (resolver.doLog()) {
                SLOG(g_log << Logger::Warning << "Sending out SERVFAIL for " << comboWriter->d_mdp.d_qname << "|" << QType(comboWriter->d_mdp.d_qtype) << " because recursor or query demands it for Bogus results" << endl,
                     log->info(Logr::Notice, "Sending out SERVFAIL because recursor or query demands it for Bogus results"));
              }

              packetWriter.getHeader()->rcode = RCode::ServFail;
              goto sendit; // NOLINT(cppcoreguidelines-avoid-goto)
            }
            else {
              if (resolver.doLog()) {
                SLOG(g_log << Logger::Warning << "Not sending out SERVFAIL for " << comboWriter->d_mdp.d_qname << "|" << QType(comboWriter->d_mdp.d_qtype) << x_marker << " Bogus validation since neither config nor query demands this" << endl,
                     log->info(Logr::Notice, "Sending out SERVFAIL because recursor or query demands it for Bogus results"));
              }
            }
          }
        }
        catch (const ImmediateServFailException& e) {
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << comboWriter->getRemote() << " during validation of '" << comboWriter->d_mdp.d_qname << "|" << QType(comboWriter->d_mdp.d_qtype) << "' because: " << e.reason << endl,
                 resolver.d_slog->error(Logr::Notice, e.reason, "Sending SERVFAIL during validation", "exception", Logging::Loggable("ImmediateServFailException")));
          }
          goto sendit; // NOLINT(cppcoreguidelines-avoid-goto)
        }
        catch (const pdns::validation::TooManySEC3IterationsException& e) {
          if (g_logCommonErrors || (g_dnssecLogBogus && resolver.getDNSSECLimitHit())) {
            SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << comboWriter->getRemote() << " during validation of '" << comboWriter->d_mdp.d_qname << "|" << QType(comboWriter->d_mdp.d_qtype) << "' because: " << e.what() << endl,
                 resolver.d_slog->error(Logr::Notice, e.what(), "Sending SERVFAIL during validation", "exception", Logging::Loggable("TooManySEC3IterationsException"), "dnsseclimithit", Logging::Loggable(resolver.getDNSSECLimitHit())));
          }
          goto sendit; // NOLINT(cppcoreguidelines-avoid-goto)
        }
      }

      if (!ret.empty()) {
        pdns::orderAndShuffle(ret, false);
        if (auto listToSort = luaconfsLocal->sortlist.getOrderCmp(comboWriter->d_source)) {
          stable_sort(ret.begin(), ret.end(), *listToSort);
          variableAnswer = true;
        }
      }

      bool needCommit = false;
      for (const auto& record : ret) {
        if (!DNSSECOK && (record.d_type == QType::NSEC3 || ((record.d_type == QType::RRSIG || record.d_type == QType::NSEC) && ((comboWriter->d_mdp.d_qtype != record.d_type && comboWriter->d_mdp.d_qtype != QType::ANY) || (record.d_place != DNSResourceRecord::ANSWER && record.d_place != DNSResourceRecord::ADDITIONAL))))) {
          continue;
        }

        if (!addRecordToPacket(packetWriter, record, minTTL, comboWriter->d_ttlCap, maxanswersize, seenAuthSOA)) {
          needCommit = false;
          break;
        }
        needCommit = true;

        bool udr = false;
#ifdef NOD_ENABLED
        if (g_udrEnabled) {
          udr = udrCheckUniqueDNSRecord(nodlogger, comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype, record);
          if (!hasUDR && udr) {
            hasUDR = true;
          }
        }
#endif /* NOD ENABLED */

        if (t_protobufServers.servers) {
          // Max size is 64k, but we're conservative here, as other fields are added after the answers have been added
          // If a single answer causes a too big protobuf message, it wil be dropped by queueData()
          // But note addRR has code to prevent that
          if (pbMessage.size() < std::numeric_limits<uint16_t>::max() / 2) {
            pbMessage.addRR(record, luaconfsLocal->protobufExportConfig.exportTypes, udr);
          }
        }
      }
      if (needCommit) {
        packetWriter.commit();
      }
#ifdef NOD_ENABLED
#ifdef HAVE_FSTRM
      if (hasUDR) {
        if (isEnabledForUDRs(t_nodFrameStreamServersInfo.servers)) {
          struct timespec timeSpec
          {
          };
          std::string str;
          if (g_useKernelTimestamp && comboWriter->d_kernelTimestamp.tv_sec != 0) {
            TIMEVAL_TO_TIMESPEC(&comboWriter->d_kernelTimestamp, &timeSpec); // NOLINT
          }
          else {
            TIMEVAL_TO_TIMESPEC(&comboWriter->d_now, &timeSpec); // NOLINT
          }
          DnstapMessage message(std::move(str), DnstapMessage::MessageType::resolver_response, SyncRes::s_serverID, &comboWriter->d_source, &comboWriter->d_destination, comboWriter->d_tcp ? DnstapMessage::ProtocolType::DoTCP : DnstapMessage::ProtocolType::DoUDP, reinterpret_cast<const char*>(&*packet.begin()), packet.size(), &timeSpec, nullptr, comboWriter->d_mdp.d_qname); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
          str = message.getBuffer();
          for (auto& logger : *(t_nodFrameStreamServersInfo.servers)) {
            if (logger->logUDRs()) {
              remoteLoggerQueueData(*logger, str);
            }
          }
        }
      }
#endif // HAVE_FSTRM
#endif // NOD_ENABLED
    }
  sendit:;

    if (g_useIncomingECS && comboWriter->d_ecsFound && !resolver.wasVariable() && !variableAnswer) {
      EDNSSubnetOpts ednsOptions;
      ednsOptions.source = comboWriter->d_ednssubnet.source;
      ComboAddress sourceAddr;
      sourceAddr.reset();
      sourceAddr.sin4.sin_family = ednsOptions.source.getNetwork().sin4.sin_family;
      ednsOptions.scope = Netmask(sourceAddr, 0);
      auto ecsPayload = makeEDNSSubnetOptsString(ednsOptions);

      // if we don't have enough space available let's just not set that scope of zero,
      // it will prevent some caching, mostly from dnsdist, but that's fine
      if (packetWriter.size() < maxanswersize && (maxanswersize - packetWriter.size()) >= (EDNSOptionCodeSize + EDNSOptionLengthSize + ecsPayload.size())) {

        maxanswersize -= EDNSOptionCodeSize + EDNSOptionLengthSize + ecsPayload.size();

        returnedEdnsOptions.emplace_back(EDNSOptionCode::ECS, std::move(ecsPayload));
      }
    }

    if (haveEDNS && addPaddingToResponse) {
      size_t currentSize = packetWriter.getSizeWithOpts(returnedEdnsOptions);
      /* we don't use maxawnswersize because it accounts for some EDNS options, but
         not all of them (for example ECS) */
      size_t maxSize = min(static_cast<uint16_t>(edo.d_packetsize >= 512 ? edo.d_packetsize : 512), g_udpTruncationThreshold);

      if (currentSize < (maxSize - 4)) {
        size_t remaining = maxSize - (currentSize + 4);
        /* from rfc8647, "4.1.  Recommended Strategy: Block-Length Padding":
           If a server receives a query that includes the EDNS(0) "Padding"
           option, it MUST pad the corresponding response (see Section 4 of
           RFC 7830) and SHOULD pad the corresponding response to a
           multiple of 468 octets (see below).
        */
        const size_t blockSize = 468;
        size_t modulo = (currentSize + 4) % blockSize;
        size_t padSize = 0;
        if (modulo > 0) {
          padSize = std::min(blockSize - modulo, remaining);
        }
        returnedEdnsOptions.emplace_back(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(padSize));
      }
    }

    if (haveEDNS) {
      auto state = resolver.getValidationState();
      if (comboWriter->d_extendedErrorCode || resolver.d_extendedError || (SyncRes::s_addExtendedResolutionDNSErrors && vStateIsBogus(state))) {
        EDNSExtendedError::code code = EDNSExtendedError::code::Other;
        std::string extra;

        if (comboWriter->d_extendedErrorCode) {
          code = static_cast<EDNSExtendedError::code>(*comboWriter->d_extendedErrorCode);
          extra = std::move(comboWriter->d_extendedErrorExtra);
        }
        else if (resolver.d_extendedError) {
          code = static_cast<EDNSExtendedError::code>(resolver.d_extendedError->infoCode);
          extra = std::move(resolver.d_extendedError->extraText);
        }
        else {
          switch (state) {
          case vState::BogusNoValidDNSKEY:
            code = EDNSExtendedError::code::DNSKEYMissing;
            break;
          case vState::BogusInvalidDenial:
            code = EDNSExtendedError::code::NSECMissing;
            break;
          case vState::BogusUnableToGetDSs:
            code = EDNSExtendedError::code::DNSSECBogus;
            break;
          case vState::BogusUnableToGetDNSKEYs:
            code = EDNSExtendedError::code::DNSKEYMissing;
            break;
          case vState::BogusSelfSignedDS:
            code = EDNSExtendedError::code::DNSSECBogus;
            break;
          case vState::BogusNoRRSIG:
            code = EDNSExtendedError::code::RRSIGsMissing;
            break;
          case vState::BogusNoValidRRSIG:
            code = EDNSExtendedError::code::DNSSECBogus;
            break;
          case vState::BogusMissingNegativeIndication:
            code = EDNSExtendedError::code::NSECMissing;
            break;
          case vState::BogusSignatureNotYetValid:
            code = EDNSExtendedError::code::SignatureNotYetValid;
            break;
          case vState::BogusSignatureExpired:
            code = EDNSExtendedError::code::SignatureExpired;
            break;
          case vState::BogusUnsupportedDNSKEYAlgo:
            code = EDNSExtendedError::code::UnsupportedDNSKEYAlgorithm;
            break;
          case vState::BogusUnsupportedDSDigestType:
            code = EDNSExtendedError::code::UnsupportedDSDigestType;
            break;
          case vState::BogusNoZoneKeyBitSet:
            code = EDNSExtendedError::code::NoZoneKeyBitSet;
            break;
          case vState::BogusRevokedDNSKEY:
          case vState::BogusInvalidDNSKEYProtocol:
            code = EDNSExtendedError::code::DNSSECBogus;
            break;
          default:
            throw std::runtime_error("Bogus validation state not handled: " + vStateToString(state));
          }
        }

        EDNSExtendedError eee;
        eee.infoCode = static_cast<uint16_t>(code);
        eee.extraText = std::move(extra);

        if (packetWriter.size() < maxanswersize && (maxanswersize - packetWriter.size()) >= (EDNSOptionCodeSize + EDNSOptionLengthSize + sizeof(eee.infoCode) + eee.extraText.size())) {
          returnedEdnsOptions.emplace_back(EDNSOptionCode::EXTENDEDERROR, makeEDNSExtendedErrorOptString(eee));
        }
      }

      /* we try to add the EDNS OPT RR even for truncated answers,
         as rfc6891 states:
         "The minimal response MUST be the DNS header, question section, and an
         OPT record.  This MUST also occur when a truncated response (using
         the DNS header's TC bit) is returned."
      */
      packetWriter.addOpt(512, ednsExtRCode, DNSSECOK ? EDNSOpts::DNSSECOK : 0, returnedEdnsOptions);
      packetWriter.commit();
    }

    t_Counters.at(rec::ResponseStats::responseStats).submitResponse(comboWriter->d_mdp.d_qtype, packet.size(), packetWriter.getHeader()->rcode);
    updateResponseStats(res, comboWriter->d_source, packet.size(), &comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype);
#ifdef NOD_ENABLED
    bool nod = false;
    if (g_nodEnabled) {
      if (nodCheckNewDomain(nodlogger, comboWriter->d_mdp.d_qname)) {
        nod = true;
#ifdef HAVE_FSTRM
        if (isEnabledForNODs(t_nodFrameStreamServersInfo.servers)) {
          struct timespec timeSpec
          {
          };
          std::string str;
          if (g_useKernelTimestamp && comboWriter->d_kernelTimestamp.tv_sec != 0) {
            TIMEVAL_TO_TIMESPEC(&comboWriter->d_kernelTimestamp, &timeSpec); // NOLINT
          }
          else {
            TIMEVAL_TO_TIMESPEC(&comboWriter->d_now, &timeSpec); // NOLINT
          }
          DnstapMessage message(std::move(str), DnstapMessage::MessageType::client_query, SyncRes::s_serverID, &comboWriter->d_source, &comboWriter->d_destination, comboWriter->d_tcp ? DnstapMessage::ProtocolType::DoTCP : DnstapMessage::ProtocolType::DoUDP, nullptr, 0, &timeSpec, nullptr, comboWriter->d_mdp.d_qname);
          str = message.getBuffer();

          for (auto& logger : *(t_nodFrameStreamServersInfo.servers)) {
            if (logger->logNODs()) {
              remoteLoggerQueueData(*logger, str);
            }
          }
        }
#endif // HAVE_FSTRM
      }
    }
#endif /* NOD_ENABLED */

    if (variableAnswer || resolver.wasVariable()) {
      t_Counters.at(rec::Counter::variableResponses)++;
    }

    if (t_protobufServers.servers && !(luaconfsLocal->protobufExportConfig.taggedOnly && appliedPolicy.getName().empty() && comboWriter->d_policyTags.empty())) {
      // Start constructing embedded DNSResponse object
      pbMessage.setResponseCode(packetWriter.getHeader()->rcode);
      if (!appliedPolicy.getName().empty()) {
        pbMessage.setAppliedPolicy(appliedPolicy.getName());
        pbMessage.setAppliedPolicyType(appliedPolicy.d_type);
        pbMessage.setAppliedPolicyTrigger(appliedPolicy.getTrigger());
        pbMessage.setAppliedPolicyHit(appliedPolicy.getHit());
        pbMessage.setAppliedPolicyKind(appliedPolicy.d_kind);
      }
      pbMessage.setInBytes(packet.size());
      pbMessage.setValidationState(resolver.getValidationState());
      // See if we want to store the policyTags into the PC
      addPolicyTagsToPBMessageIfNeeded(*comboWriter, pbMessage);

      // Take s snap of the current protobuf buffer state to store in the PC
      pbDataForCache = boost::make_optional(RecursorPacketCache::PBData{
        pbMessage.getMessageBuf(),
        pbMessage.getResponseBuf(),
        !appliedPolicy.getName().empty() || !comboWriter->d_policyTags.empty()});
#ifdef NOD_ENABLED
      // if (g_udrEnabled) ??
      pbMessage.clearUDR(pbDataForCache->d_response);
#endif
    }

    const bool intoPC = g_packetCache && !variableAnswer && !resolver.wasVariable();
    if (intoPC) {
      minTTL = capPacketCacheTTL(*packetWriter.getHeader(), minTTL, seenAuthSOA);
      g_packetCache->insertResponsePacket(comboWriter->d_tag, comboWriter->d_qhash, std::move(comboWriter->d_query), comboWriter->d_mdp.d_qname,
                                          comboWriter->d_mdp.d_qtype, comboWriter->d_mdp.d_qclass,
                                          string(reinterpret_cast<const char*>(&*packet.begin()), packet.size()), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                                          g_now.tv_sec,
                                          minTTL,
                                          dnsQuestion.validationState,
                                          std::move(pbDataForCache), comboWriter->d_tcp);
    }

    if (g_regressionTestMode) {
      t_Counters.updateSnap(g_regressionTestMode);
    }

    if (!comboWriter->d_tcp) {
      struct msghdr msgh
      {
      };
      struct iovec iov
      {
      };
      cmsgbuf_aligned cbuf{};
      fillMSGHdr(&msgh, &iov, &cbuf, 0, reinterpret_cast<char*>(&*packet.begin()), packet.size(), &comboWriter->d_remote); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      msgh.msg_control = nullptr;

      if (g_fromtosockets.count(comboWriter->d_socket) > 0) {
        addCMsgSrcAddr(&msgh, &cbuf, &comboWriter->d_local, 0);
      }
      int sendErr = sendOnNBSocket(comboWriter->d_socket, &msgh);
      if (sendErr != 0 && g_logCommonErrors) {
        SLOG(g_log << Logger::Warning << "Sending UDP reply to client " << comboWriter->getRemote() << " failed with: "
                   << stringerror(sendErr) << endl,
             g_slogudpin->error(Logr::Warning, sendErr, "Sending UDP reply to client failed"));
      }
    }
    else {
      bool hadError = sendResponseOverTCP(comboWriter, packet);
      finishTCPReply(comboWriter, hadError, true);
      tcpGuard.setHandled();
    }

    resolver.d_eventTrace.add(RecEventTrace::AnswerSent);

    // Now do the per query changing part ot the protobuf message
    if (t_protobufServers.servers && !(luaconfsLocal->protobufExportConfig.taggedOnly && appliedPolicy.getName().empty() && comboWriter->d_policyTags.empty())) {
      // Below are the fields that are not stored in the packet cache and will be appended here and on a cache hit
      if (g_useKernelTimestamp && comboWriter->d_kernelTimestamp.tv_sec != 0) {
        pbMessage.setQueryTime(comboWriter->d_kernelTimestamp.tv_sec, comboWriter->d_kernelTimestamp.tv_usec);
      }
      else {
        pbMessage.setQueryTime(comboWriter->d_now.tv_sec, comboWriter->d_now.tv_usec);
      }
      pbMessage.setMessageIdentity(comboWriter->d_uuid);
      pbMessage.setSocketProtocol(comboWriter->d_tcp ? pdns::ProtoZero::Message::TransportProtocol::TCP : pdns::ProtoZero::Message::TransportProtocol::UDP);

      if (!luaconfsLocal->protobufExportConfig.logMappedFrom) {
        pbMessage.setSocketFamily(comboWriter->d_source.sin4.sin_family);
        Netmask requestorNM(comboWriter->d_source, comboWriter->d_source.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
        ComboAddress requestor = requestorNM.getMaskedNetwork();
        pbMessage.setFrom(requestor);
        pbMessage.setFromPort(comboWriter->d_source.getPort());
      }
      else {
        pbMessage.setSocketFamily(comboWriter->d_mappedSource.sin4.sin_family);
        Netmask requestorNM(comboWriter->d_mappedSource, comboWriter->d_mappedSource.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
        ComboAddress requestor = requestorNM.getMaskedNetwork();
        pbMessage.setFrom(requestor);
        pbMessage.setFromPort(comboWriter->d_mappedSource.getPort());
      }

      pbMessage.setTo(comboWriter->d_destination);
      pbMessage.setId(comboWriter->d_mdp.d_header.id);

      pbMessage.setTime();
      pbMessage.setEDNSSubnet(comboWriter->d_ednssubnet.source, comboWriter->d_ednssubnet.source.isIPv4() ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
      pbMessage.setRequestorId(dnsQuestion.requestorId);
      pbMessage.setDeviceId(dnsQuestion.deviceId);
      pbMessage.setDeviceName(dnsQuestion.deviceName);
      pbMessage.setToPort(comboWriter->d_destination.getPort());
      pbMessage.addPolicyTags(comboWriter->d_gettagPolicyTags);
      pbMessage.setWorkerId(RecThreadInfo::id());
      pbMessage.setPacketCacheHit(false);
      pbMessage.setOutgoingQueries(resolver.d_outqueries);
      for (const auto& metaValue : dnsQuestion.meta) {
        pbMessage.setMeta(metaValue.first, metaValue.second.stringVal, metaValue.second.intVal);
      }
#ifdef NOD_ENABLED
      if (g_nodEnabled) {
        if (nod) {
          pbMessage.setNewlyObservedDomain(true);
          pbMessage.addPolicyTag(g_nod_pbtag);
        }
        if (hasUDR) {
          pbMessage.addPolicyTag(g_udr_pbtag);
        }
      }
#endif /* NOD_ENABLED */
      if (resolver.d_eventTrace.enabled() && (SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_pb) != 0) {
        pbMessage.addEvents(resolver.d_eventTrace);
      }
      if (comboWriter->d_logResponse) {
        protobufLogResponse(pbMessage);
      }
    }

    if (resolver.d_eventTrace.enabled() && (SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_log) != 0) {
      SLOG(g_log << Logger::Info << resolver.d_eventTrace.toString() << endl,
           resolver.d_slog->info(Logr::Info, resolver.d_eventTrace.toString())); // Maybe we want it to be more fancy?
    }

    // Originally this code used a mix of floats, doubles, uint64_t with different units.
    // Now it always uses an integral number of microseconds, except for averages, which use doubles
    uint64_t spentUsec = uSec(resolver.getNow() - comboWriter->d_now);
    if (!g_quiet) {
      if (!g_slogStructured) {
        g_log << Logger::Error << RecThreadInfo::id() << " [" << g_multiTasker->getTid() << "/" << g_multiTasker->numProcesses() << "] answer to " << (comboWriter->d_mdp.d_header.rd ? "" : "non-rd ") << "question '" << comboWriter->d_mdp.d_qname << "|" << DNSRecordContent::NumberToType(comboWriter->d_mdp.d_qtype);
        g_log << "': " << ntohs(packetWriter.getHeader()->ancount) << " answers, " << ntohs(packetWriter.getHeader()->arcount) << " additional, took " << resolver.d_outqueries << " packets, " << resolver.d_totUsec / 1000.0 << " netw ms, " << static_cast<double>(spentUsec) / 1000.0 << " tot ms, " << resolver.d_throttledqueries << " throttled, " << resolver.d_timeouts << " timeouts, " << resolver.d_tcpoutqueries << "/" << resolver.d_dotoutqueries << " tcp/dot connections, rcode=" << res;

        if (!shouldNotValidate && resolver.isDNSSECValidationRequested()) {
          g_log << ", dnssec=" << resolver.getValidationState();
        }
        g_log << " answer-is-variable=" << resolver.wasVariable() << ", into-packetcache=" << intoPC;
        g_log << " maxdepth=" << resolver.d_maxdepth;
        g_log << endl;
      }
      else {
        resolver.d_slog->info(Logr::Info, "Answer", "rd", Logging::Loggable(comboWriter->d_mdp.d_header.rd),
                              "answers", Logging::Loggable(ntohs(packetWriter.getHeader()->ancount)),
                              "additional", Logging::Loggable(ntohs(packetWriter.getHeader()->arcount)),
                              "outqueries", Logging::Loggable(resolver.d_outqueries),
                              "netms", Logging::Loggable(resolver.d_totUsec / 1000.0),
                              "totms", Logging::Loggable(static_cast<double>(spentUsec) / 1000.0),
                              "throttled", Logging::Loggable(resolver.d_throttledqueries),
                              "timeouts", Logging::Loggable(resolver.d_timeouts),
                              "tcpout", Logging::Loggable(resolver.d_tcpoutqueries),
                              "dotout", Logging::Loggable(resolver.d_dotoutqueries),
                              "rcode", Logging::Loggable(res),
                              "validationState", Logging::Loggable(resolver.getValidationState()),
                              "answer-is-variable", Logging::Loggable(resolver.wasVariable()),
                              "into-packetcache", Logging::Loggable(intoPC),
                              "maxdepth", Logging::Loggable(resolver.d_maxdepth));
      }
    }

    if (comboWriter->d_mdp.d_header.opcode == static_cast<unsigned>(Opcode::Query)) {
      if (resolver.d_outqueries != 0 || resolver.d_throttledqueries != 0 || resolver.d_authzonequeries != 0) {
        g_recCache->incCacheMisses();
      }
      else {
        g_recCache->incCacheHits();
      }
    }

    t_Counters.at(rec::Histogram::answers)(spentUsec);
    t_Counters.at(rec::Histogram::cumulativeAnswers)(spentUsec);

    auto newLat = static_cast<double>(spentUsec);
    newLat = min(newLat, g_networkTimeoutMsec * 1000.0); // outliers of several minutes exist..
    t_Counters.at(rec::DoubleWAvgCounter::avgLatencyUsec).addToRollingAvg(newLat, g_latencyStatSize);
    // no worries, we do this for packet cache hits elsewhere

    if (spentUsec >= resolver.d_totUsec) {
      uint64_t ourtime = spentUsec - resolver.d_totUsec;
      t_Counters.at(rec::Histogram::ourtime)(ourtime);
      newLat = static_cast<double>(ourtime); // usec
      t_Counters.at(rec::DoubleWAvgCounter::avgLatencyOursUsec).addToRollingAvg(newLat, g_latencyStatSize);
    }

#ifdef NOD_ENABLED
    if (nod) {
      sendNODLookup(nodlogger, comboWriter->d_mdp.d_qname);
    }
#endif /* NOD_ENABLED */

    //    cout<<dc->d_mdp.d_qname<<"\t"<<MT->getUsec()<<"\t"<<sr.d_outqueries<<endl;
  }
  catch (const PDNSException& ae) {
    SLOG(g_log << Logger::Error << "startDoResolve problem " << makeLoginfo(comboWriter) << ": " << ae.reason << endl,
         resolver.d_slog->error(Logr::Error, ae.reason, "startDoResolve problem", "exception", Logging::Loggable("PDNSException")));
  }
  catch (const MOADNSException& mde) {
    SLOG(g_log << Logger::Error << "DNS parser error " << makeLoginfo(comboWriter) << ": " << comboWriter->d_mdp.d_qname << ", " << mde.what() << endl,
         resolver.d_slog->error(Logr::Error, mde.what(), "DNS parser error"));
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "STL error " << makeLoginfo(comboWriter) << ": " << e.what(),
         resolver.d_slog->error(Logr::Error, e.what(), "Exception in resolver context", "exception", Logging::Loggable("std::exception")));

    // Luawrapper nests the exception from Lua, so we unnest it here
    try {
      std::rethrow_if_nested(e);
    }
    catch (const std::exception& ne) {
      SLOG(g_log << ". Extra info: " << ne.what(),
           resolver.d_slog->error(Logr::Error, ne.what(), "Nested exception in resolver context", Logging::Loggable("std::exception")));
    }
    catch (...) {
    }
    if (!g_slogStructured) {
      g_log << endl;
    }
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "Any other exception in a resolver context " << makeLoginfo(comboWriter) << endl,
         resolver.d_slog->info(Logr::Error, "Any other exception in a resolver context"));
  }

  runTaskOnce(g_logCommonErrors);

  static const size_t stackSizeThreshold = 9 * ::arg().asNum("stack-size") / 10;
  if (g_multiTasker->getMaxStackUsage() >= stackSizeThreshold) {
    SLOG(g_log << Logger::Error << "Reached mthread stack usage of 90%: " << g_multiTasker->getMaxStackUsage() << " " << makeLoginfo(comboWriter) << " after " << resolver.d_outqueries << " out queries, " << resolver.d_tcpoutqueries << " TCP out queries, " << resolver.d_dotoutqueries << " DoT out queries" << endl,
         resolver.d_slog->info(Logr::Error, "Reached mthread stack usage of 90%",
                               "stackUsage", Logging::Loggable(g_multiTasker->getMaxStackUsage()),
                               "outqueries", Logging::Loggable(resolver.d_outqueries),
                               "netms", Logging::Loggable(resolver.d_totUsec / 1000.0),
                               "throttled", Logging::Loggable(resolver.d_throttledqueries),
                               "timeouts", Logging::Loggable(resolver.d_timeouts),
                               "tcpout", Logging::Loggable(resolver.d_tcpoutqueries),
                               "dotout", Logging::Loggable(resolver.d_dotoutqueries),
                               "validationState", Logging::Loggable(resolver.getValidationState())));
  }
  t_Counters.at(rec::Counter::maxMThreadStackUsage) = max(g_multiTasker->getMaxStackUsage(), t_Counters.at(rec::Counter::maxMThreadStackUsage));
  t_Counters.updateSnap(g_regressionTestMode);
}

void getQNameAndSubnet(const std::string& question, DNSName* dnsname, uint16_t* qtype, uint16_t* qclass,
                       bool& foundECS, EDNSSubnetOpts* ednssubnet, EDNSOptionViewMap* options)
{
  const bool lookForECS = ednssubnet != nullptr;
  const dnsheader_aligned dnshead(question.data());
  const dnsheader* dhPointer = dnshead.get();
  size_t questionLen = question.length();
  unsigned int consumed = 0;
  *dnsname = DNSName(question.c_str(), static_cast<int>(questionLen), sizeof(dnsheader), false, qtype, qclass, &consumed);

  size_t pos = sizeof(dnsheader) + consumed + 4;
  const size_t headerSize = /* root */ 1 + sizeof(dnsrecordheader);
  const uint16_t arcount = ntohs(dhPointer->arcount);

  for (uint16_t arpos = 0; arpos < arcount && questionLen > (pos + headerSize) && (lookForECS && !foundECS); arpos++) {
    if (question.at(pos) != 0) {
      /* not an OPT, bye. */
      return;
    }

    pos += 1;
    const auto* drh = reinterpret_cast<const dnsrecordheader*>(&question.at(pos)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    pos += sizeof(dnsrecordheader);

    if (pos >= questionLen) {
      return;
    }

    /* OPT root label (1) followed by type (2) */
    if (lookForECS && ntohs(drh->d_type) == QType::OPT) {
      if (options == nullptr) {
        size_t ecsStartPosition = 0;
        size_t ecsLen = 0;
        /* we need to pass the record len */
        int res = getEDNSOption(reinterpret_cast<const char*>(&question.at(pos - sizeof(drh->d_clen))), questionLen - pos + sizeof(drh->d_clen), EDNSOptionCode::ECS, &ecsStartPosition, &ecsLen); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        if (res == 0 && ecsLen > 4) {
          EDNSSubnetOpts eso;
          if (getEDNSSubnetOptsFromString(&question.at(pos - sizeof(drh->d_clen) + ecsStartPosition + 4), ecsLen - 4, &eso)) {
            *ednssubnet = eso;
            foundECS = true;
          }
        }
      }
      else {
        /* we need to pass the record len */
        int res = getEDNSOptions(reinterpret_cast<const char*>(&question.at(pos - sizeof(drh->d_clen))), questionLen - pos + (sizeof(drh->d_clen)), *options); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        if (res == 0) {
          const auto& iter = options->find(EDNSOptionCode::ECS);
          if (iter != options->end() && !iter->second.values.empty() && iter->second.values.at(0).content != nullptr && iter->second.values.at(0).size > 0) {
            EDNSSubnetOpts eso;
            if (getEDNSSubnetOptsFromString(iter->second.values.at(0).content, iter->second.values.at(0).size, &eso)) {
              *ednssubnet = eso;
              foundECS = true;
            }
          }
        }
      }
    }

    pos += ntohs(drh->d_clen);
  }
}

bool checkForCacheHit(bool qnameParsed, unsigned int tag, const string& data,
                      DNSName& qname, uint16_t& qtype, uint16_t& qclass,
                      const struct timeval& now,
                      string& response, uint32_t& qhash,
                      RecursorPacketCache::OptPBData& pbData, bool tcp, const ComboAddress& source, const ComboAddress& mappedSource)
{
  if (!g_packetCache) {
    return false;
  }
  bool cacheHit = false;
  uint32_t age = 0;
  vState valState = vState::Indeterminate;

  if (qnameParsed) {
    cacheHit = g_packetCache->getResponsePacket(tag, data, qname, qtype, qclass, now.tv_sec, &response, &age, &valState, &qhash, &pbData, tcp);
  }
  else {
    cacheHit = g_packetCache->getResponsePacket(tag, data, qname, &qtype, &qclass, now.tv_sec, &response, &age, &valState, &qhash, &pbData, tcp);
  }

  if (cacheHit) {
    if (vStateIsBogus(valState)) {
      if (t_bogusremotes) {
        t_bogusremotes->push_back(source);
      }
      if (t_bogusqueryring) {
        t_bogusqueryring->push_back({qname, qtype});
      }
    }

    // This is only to get the proxyMapping suffixMatch stats right i the case of a PC hit
    if (t_proxyMapping && source != mappedSource) {
      if (const auto* found = t_proxyMapping->lookup(source)) {
        if (found->second.suffixMatchNode) {
          if (found->second.suffixMatchNode->check(qname)) {
            ++found->second.stats.suffixMatches;
          }
        }
      }
    }

    t_Counters.at(rec::Counter::packetCacheHits)++;
    t_Counters.at(rec::Counter::syncresqueries)++; // XXX
    if (response.length() >= sizeof(struct dnsheader)) {
      dnsheader_aligned dh_aligned(response.data());
      ageDNSPacket(response, age, dh_aligned);
      const auto* dhp = dh_aligned.get();
      updateResponseStats(dhp->rcode, source, response.length(), nullptr, 0);
      t_Counters.at(rec::ResponseStats::responseStats).submitResponse(qtype, response.length(), dhp->rcode);
    }

    // we assume 0 usec
    t_Counters.at(rec::DoubleWAvgCounter::avgLatencyUsec).addToRollingAvg(0.0, g_latencyStatSize);
    t_Counters.at(rec::DoubleWAvgCounter::avgLatencyOursUsec).addToRollingAvg(0.0, g_latencyStatSize);
#if 0
    // XXX changes behaviour compared to old code!
    t_Counters.at(rec::Counter::answers)(0);
    t_Counters.at(rec::Counter::ourtime)(0);
#endif
  }

  return cacheHit;
}

static void* pleaseWipeCaches(const DNSName& canon, bool subtree, uint16_t qtype)
{
  auto res = wipeCaches(canon, subtree, qtype);
  SLOG(g_log << Logger::Info << "Wiped caches for " << canon << ": " << res.record_count << " records; " << res.negative_record_count << " negative records; " << res.packet_count << " packets" << endl,
       g_slog->withName("runtime")->info(Logr::Info, "Wiped cache", "qname", Logging::Loggable(canon), "records", Logging::Loggable(res.record_count), "negrecords", Logging::Loggable(res.negative_record_count), "packets", Logging::Loggable(res.packet_count)));
  return nullptr;
}

void requestWipeCaches(const DNSName& canon)
{
  // send a message to the handler thread asking it
  // to wipe all of the caches
  ThreadMSG* tmsg = new ThreadMSG(); // NOLINT: pointer owner
  tmsg->func = [=] { return pleaseWipeCaches(canon, true, 0xffff); };
  tmsg->wantAnswer = false;
  if (write(RecThreadInfo::info(0).getPipes().writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) { // NOLINT: correct sizeof
    delete tmsg; // NOLINT: pointer owner

    unixDie("write to thread pipe returned wrong size or error");
  }
  // coverity[leaked_storage]
}

bool expectProxyProtocol(const ComboAddress& from, const ComboAddress& listenAddress)
{
  return g_proxyProtocolACL.match(from) && g_proxyProtocolExceptions.count(listenAddress) == 0;
}

// fromaddr: the address the query is coming from
// destaddr: the address the query was received on
// source: the address we assume the query is coming from, might be set by proxy protocol
// destination: the address we assume the query was sent to, might be set by proxy protocol
// mappedSource: the address we assume the query is coming from. Differs from source if table based mapping has been applied
static string* doProcessUDPQuestion(const std::string& question, const ComboAddress& fromaddr, const ComboAddress& destaddr, ComboAddress source, ComboAddress destination, const ComboAddress& mappedSource, struct timeval tval, int fileDesc, std::vector<ProxyProtocolValue>& proxyProtocolValues, RecEventTrace& eventTrace) // NOLINT(readability-function-cognitive-complexity): https://github.com/PowerDNS/pdns/issues/12791
{
  RecThreadInfo::self().incNumberOfDistributedQueries();
  gettimeofday(&g_now, nullptr);
  if (tval.tv_sec != 0) {
    struct timeval diff = g_now - tval;
    double delta = (static_cast<double>(diff.tv_sec) * 1000 + static_cast<double>(diff.tv_usec) / 1000.0);

    if (delta > 1000.0) {
      t_Counters.at(rec::Counter::tooOldDrops)++;
      return nullptr;
    }
  }

  ++t_Counters.at(rec::Counter::qcounter);

  if (fromaddr.sin4.sin_family == AF_INET6) {
    t_Counters.at(rec::Counter::ipv6qcounter)++;
  }

  string response;
  const dnsheader_aligned headerdata(question.data());
  const dnsheader* dnsheader = headerdata.get();
  unsigned int ctag = 0;
  uint32_t qhash = 0;
  bool needECS = false;
  std::unordered_set<std::string> policyTags;
  std::map<std::string, RecursorLua4::MetaValue> meta;
  LuaContext::LuaObject data;
  string requestorId;
  string deviceId;
  string deviceName;
  string routingTag;
  bool logQuery = false;
  bool logResponse = false;
  boost::uuids::uuid uniqueId{};
  auto luaconfsLocal = g_luaconfs.getLocal();
  const auto pbExport = checkProtobufExport(luaconfsLocal);
  const auto outgoingbExport = checkOutgoingProtobufExport(luaconfsLocal);
  if (pbExport || outgoingbExport) {
    if (pbExport) {
      needECS = true;
    }
    uniqueId = getUniqueID();
  }
  logQuery = t_protobufServers.servers && luaconfsLocal->protobufExportConfig.logQueries;
  logResponse = t_protobufServers.servers && luaconfsLocal->protobufExportConfig.logResponses;
#ifdef HAVE_FSTRM
  checkFrameStreamExport(luaconfsLocal, luaconfsLocal->frameStreamExportConfig, t_frameStreamServersInfo);
#endif
  EDNSSubnetOpts ednssubnet;
  bool ecsFound = false;
  bool ecsParsed = false;
  std::vector<DNSRecord> records;
  std::string extendedErrorExtra;
  boost::optional<int> rcode = boost::none;
  boost::optional<uint16_t> extendedErrorCode{boost::none};
  uint32_t ttlCap = std::numeric_limits<uint32_t>::max();
  bool variable = false;
  bool followCNAMEs = false;
  bool responsePaddingDisabled = false;
  DNSName qname;
  try {
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    bool qnameParsed = false;
#ifdef MALLOC_TRACE
    /*
    static uint64_t last=0;
    if(!last)
      g_mtracer->clearAllocators();
    cout<<g_mtracer->getAllocs()-last<<" "<<g_mtracer->getNumOut()<<" -- BEGIN TRACE"<<endl;
    last=g_mtracer->getAllocs();
    cout<<g_mtracer->topAllocatorsString()<<endl;
    g_mtracer->clearAllocators();
    */
#endif

    // We do not have a SyncRes specific Lua context at this point yet, so ok to use t_pdl
    if (needECS || (t_pdl && (t_pdl->hasGettagFunc() || t_pdl->hasGettagFFIFunc())) || dnsheader->opcode == static_cast<unsigned>(Opcode::Notify)) {
      try {
        EDNSOptionViewMap ednsOptions;

        ecsFound = false;

        getQNameAndSubnet(question, &qname, &qtype, &qclass,
                          ecsFound, &ednssubnet, g_gettagNeedsEDNSOptions ? &ednsOptions : nullptr);

        qnameParsed = true;
        ecsParsed = true;

        if (t_pdl) {
          try {
            if (t_pdl->hasGettagFFIFunc()) {
              RecursorLua4::FFIParams params(qname, qtype, destaddr, fromaddr, destination, source, ednssubnet.source, data, policyTags, records, ednsOptions, proxyProtocolValues, requestorId, deviceId, deviceName, routingTag, rcode, ttlCap, variable, false, logQuery, logResponse, followCNAMEs, extendedErrorCode, extendedErrorExtra, responsePaddingDisabled, meta);

              eventTrace.add(RecEventTrace::LuaGetTagFFI);
              ctag = t_pdl->gettag_ffi(params);
              eventTrace.add(RecEventTrace::LuaGetTagFFI, ctag, false);
            }
            else if (t_pdl->hasGettagFunc()) {
              eventTrace.add(RecEventTrace::LuaGetTag);
              ctag = t_pdl->gettag(source, ednssubnet.source, destination, qname, qtype, &policyTags, data, ednsOptions, false, requestorId, deviceId, deviceName, routingTag, proxyProtocolValues);
              eventTrace.add(RecEventTrace::LuaGetTag, ctag, false);
            }
          }
          catch (const std::exception& stdException) {
            s_rateLimitedLogger.log(g_slogudpin, "Error parsing a query packet for tag determination", stdException, "qname", Logging::Loggable(qname), "remote", Logging::Loggable(fromaddr));
          }
        }
      }
      catch (const std::exception& stdException) {
        s_rateLimitedLogger.log(g_slogudpin, "Error parsing a query packet for tag determination, setting tag=0", stdException);
      }
    }

    RecursorPacketCache::OptPBData pbData{boost::none};
    if (t_protobufServers.servers) {
      if (logQuery && !(luaconfsLocal->protobufExportConfig.taggedOnly && policyTags.empty())) {
        protobufLogQuery(luaconfsLocal, uniqueId, source, destination, mappedSource, ednssubnet.source, false, dnsheader->id, question.size(), qname, qtype, qclass, policyTags, requestorId, deviceId, deviceName, meta);
      }
    }

    if (ctag == 0 && !responsePaddingDisabled && g_paddingFrom.match(fromaddr)) {
      ctag = g_paddingTag;
    }

    if (dnsheader->opcode == static_cast<unsigned>(Opcode::Query)) {
      /* It might seem like a good idea to skip the packet cache lookup if we know that the answer is not cacheable,
         but it means that the hash would not be computed. If some script decides at a later time to mark back the answer
         as cacheable we would cache it with a wrong tag, so better safe than sorry. */
      eventTrace.add(RecEventTrace::PCacheCheck);
      bool cacheHit = checkForCacheHit(qnameParsed, ctag, question, qname, qtype, qclass, g_now, response, qhash, pbData, false, source, mappedSource);
      eventTrace.add(RecEventTrace::PCacheCheck, cacheHit, false);
      if (cacheHit) {
        if (!g_quiet) {
          SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " question answered from packet cache tag=" << ctag << " from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << endl,
               g_slogudpin->info(Logr::Notice, "Question answered from packet cache", "tag", Logging::Loggable(ctag),
                                 "qname", Logging::Loggable(qname), "qtype", Logging::Loggable(QType(qtype)),
                                 "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));
        }
        struct msghdr msgh
        {
        };
        struct iovec iov
        {
        };
        cmsgbuf_aligned cbuf{};
        fillMSGHdr(&msgh, &iov, &cbuf, 0, reinterpret_cast<char*>(response.data()), response.length(), const_cast<ComboAddress*>(&fromaddr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-type-const-cast)
        msgh.msg_control = nullptr;

        if (g_fromtosockets.count(fileDesc) != 0) {
          addCMsgSrcAddr(&msgh, &cbuf, &destaddr, 0);
        }
        int sendErr = sendOnNBSocket(fileDesc, &msgh);
        eventTrace.add(RecEventTrace::AnswerSent);

        if (t_protobufServers.servers && logResponse && (!luaconfsLocal->protobufExportConfig.taggedOnly || !pbData || pbData->d_tagged)) {
          protobufLogResponse(dnsheader, luaconfsLocal, pbData, tval, false, source, destination, mappedSource, ednssubnet, uniqueId, requestorId, deviceId, deviceName, meta, eventTrace, policyTags);
        }

        if (eventTrace.enabled() && (SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_log) != 0) {
          SLOG(g_log << Logger::Info << eventTrace.toString() << endl,
               g_slogudpin->info(Logr::Info, eventTrace.toString())); // Do we want more fancy logging here?
        }
        if (sendErr != 0 && g_logCommonErrors) {
          SLOG(g_log << Logger::Warning << "Sending UDP reply to client " << source.toStringWithPort()
                     << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << " failed with: "
                     << stringerror(sendErr) << endl,
               g_slogudpin->error(Logr::Error, sendErr, "Sending UDP reply to client failed", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));
        }
        struct timeval now
        {
        };
        Utility::gettimeofday(&now, nullptr);
        uint64_t spentUsec = uSec(now - tval);
        t_Counters.at(rec::Histogram::cumulativeAnswers)(spentUsec);
        t_Counters.updateSnap(g_regressionTestMode);
        return nullptr;
      }
    }
  }
  catch (const std::exception& e) {
    if (g_logCommonErrors) {
      SLOG(g_log << Logger::Error << "Error processing or aging answer packet: " << e.what() << endl,
           g_slogudpin->error(Logr::Error, e.what(), "Error processing or aging answer packet", "exception", Logging::Loggable("std::exception")));
    }
    return nullptr;
  }

  if (t_pdl) {
    bool ipf = t_pdl->ipfilter(source, destination, *dnsheader, eventTrace);
    if (ipf) {
      if (!g_quiet) {
        SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " [" << g_multiTasker->getTid() << "/" << g_multiTasker->numProcesses() << "] DROPPED question from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << " based on policy" << endl,
             g_slogudpin->info(Logr::Notice, "Dropped question based on policy", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));
      }
      t_Counters.at(rec::Counter::policyDrops)++;
      return nullptr;
    }
  }

  if (dnsheader->opcode == static_cast<unsigned>(Opcode::Notify)) {
    if (!isAllowNotifyForZone(qname)) {
      if (!g_quiet) {
        SLOG(g_log << Logger::Error << "[" << g_multiTasker->getTid() << "] dropping UDP NOTIFY from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << ", for " << qname.toLogString() << ", zone not matched by allow-notify-for" << endl,
             g_slogudpin->info(Logr::Notice, "Dropping UDP NOTIFY, zone not matched by allow-notify-for", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));
      }

      t_Counters.at(rec::Counter::zoneDisallowedNotify)++;
      return nullptr;
    }

    if (!g_quiet) {
      SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " got NOTIFY for " << qname.toLogString() << " from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << endl,
           g_slogudpin->info(Logr::Notice, "Got NOTIFY", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr), "qname", Logging::Loggable(qname)));
    }
    if (!notifyRPZTracker(qname)) {
      // It wasn't an RPZ
      requestWipeCaches(qname);
    }

    // the operation will now be treated as a Query, generating
    // a normal response, as the rest of the code does not
    // check dh->opcode, but we need to ensure that the response
    // to this request does not get put into the packet cache
    variable = true;
  }

  if (g_multiTasker->numProcesses() >= g_maxMThreads) {
    if (!g_quiet) {
      SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " [" << g_multiTasker->getTid() << "/" << g_multiTasker->numProcesses() << "] DROPPED question from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << ", over capacity" << endl,
           g_slogudpin->info(Logr::Notice, "Dropped question, over capacity", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));
    }
    t_Counters.at(rec::Counter::overCapacityDrops)++;
    return nullptr;
  }

  auto comboWriter = std::make_unique<DNSComboWriter>(question, g_now, std::move(policyTags), t_pdl, std::move(data), std::move(records));

  comboWriter->setSocket(fileDesc);
  comboWriter->d_tag = ctag;
  comboWriter->d_qhash = qhash;
  comboWriter->setRemote(fromaddr); // the address the query is coming from
  comboWriter->setSource(source); // the address we assume the query is coming from, might be set by proxy protocol
  comboWriter->setLocal(destaddr); // the address the query was received on
  comboWriter->setDestination(destination); // the address we assume the query is sent to, might be set by proxy protocol
  comboWriter->setMappedSource(mappedSource); // the address we assume the query is coming from. Differs from source if table-based mapping has been applied
  comboWriter->d_tcp = false;
  comboWriter->d_ecsFound = ecsFound;
  comboWriter->d_ecsParsed = ecsParsed;
  comboWriter->d_ednssubnet = ednssubnet;
  comboWriter->d_ttlCap = ttlCap;
  comboWriter->d_variable = variable;
  comboWriter->d_followCNAMERecords = followCNAMEs;
  comboWriter->d_rcode = rcode;
  comboWriter->d_logResponse = logResponse;
  if (t_protobufServers.servers || t_outgoingProtobufServers.servers) {
    comboWriter->d_uuid = uniqueId;
  }
  comboWriter->d_requestorId = std::move(requestorId);
  comboWriter->d_deviceId = std::move(deviceId);
  comboWriter->d_deviceName = std::move(deviceName);
  comboWriter->d_kernelTimestamp = tval;
  comboWriter->d_proxyProtocolValues = std::move(proxyProtocolValues);
  comboWriter->d_routingTag = std::move(routingTag);
  comboWriter->d_extendedErrorCode = extendedErrorCode;
  comboWriter->d_extendedErrorExtra = std::move(extendedErrorExtra);
  comboWriter->d_responsePaddingDisabled = responsePaddingDisabled;
  comboWriter->d_meta = std::move(meta);

  comboWriter->d_eventTrace = std::move(eventTrace);
  g_multiTasker->makeThread(startDoResolve, (void*)comboWriter.release()); // deletes dc

  return nullptr;
}

static void handleNewUDPQuestion(int fileDesc, FDMultiplexer::funcparam_t& /* var */) // NOLINT(readability-function-cognitive-complexity): https://github.com/PowerDNS/pdns/issues/12791
{
  static const size_t maxIncomingQuerySize = g_proxyProtocolACL.empty() ? 512 : (512 + g_proxyProtocolMaximumSize);
  static thread_local std::string data;
  ComboAddress fromaddr; // the address the query is coming from
  ComboAddress source; // the address we assume the query is coming from, might be set by proxy protocol
  ComboAddress destination; // the address we assume the query was sent to, might be set by proxy protocol
  struct msghdr msgh
  {
  };
  struct iovec iov
  {
  };
  cmsgbuf_aligned cbuf;
  bool firstQuery = true;
  std::vector<ProxyProtocolValue> proxyProtocolValues;
  RecEventTrace eventTrace;

  for (size_t queriesCounter = 0; queriesCounter < g_maxUDPQueriesPerRound; queriesCounter++) {
    bool proxyProto = false;
    proxyProtocolValues.clear();
    data.resize(maxIncomingQuerySize);
    fromaddr.sin6.sin6_family = AF_INET6; // this makes sure fromaddr is big enough
    fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), data.data(), data.size(), &fromaddr);

    if (ssize_t len = recvmsg(fileDesc, &msgh, 0); len >= 0) {
      eventTrace.clear();
      eventTrace.setEnabled(SyncRes::s_event_trace_enabled != 0);
      eventTrace.add(RecEventTrace::ReqRecv);

      firstQuery = false;

      if ((msgh.msg_flags & MSG_TRUNC) != 0) {
        t_Counters.at(rec::Counter::truncatedDrops)++;
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "Ignoring truncated query from " << fromaddr.toString() << endl,
               g_slogudpin->info(Logr::Error, "Ignoring truncated query", "remote", Logging::Loggable(fromaddr)));
        }
        return;
      }

      data.resize(static_cast<size_t>(len));

      ComboAddress destaddr; // the address the query was sent to to
      destaddr.reset(); // this makes sure we ignore this address if not explictly set below
      const auto* loc = rplookup(g_listenSocketsAddresses, fileDesc);
      if (HarvestDestinationAddress(&msgh, &destaddr)) {
        // but.. need to get port too
        if (loc != nullptr) {
          destaddr.sin4.sin_port = loc->sin4.sin_port;
        }
      }
      else {
        if (loc != nullptr) {
          destaddr = *loc;
        }
        else {
          destaddr.sin4.sin_family = fromaddr.sin4.sin_family;
          socklen_t slen = destaddr.getSocklen();
          getsockname(fileDesc, reinterpret_cast<sockaddr*>(&destaddr), &slen); // if this fails, we're ok with it  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        }
      }
      if (expectProxyProtocol(fromaddr, destaddr)) {
        bool tcp = false;
        ssize_t used = parseProxyHeader(data, proxyProto, source, destination, tcp, proxyProtocolValues);
        if (used <= 0) {
          ++t_Counters.at(rec::Counter::proxyProtocolInvalidCount);
          if (!g_quiet) {
            SLOG(g_log << Logger::Error << "Ignoring invalid proxy protocol (" << std::to_string(len) << ", " << std::to_string(used) << ") query from " << fromaddr.toStringWithPort() << endl,
                 g_slogudpin->info(Logr::Error, "Ignoring invalid proxy protocol query", "length", Logging::Loggable(len),
                                   "used", Logging::Loggable(used), "remote", Logging::Loggable(fromaddr)));
          }
          return;
        }
        if (static_cast<size_t>(used) > g_proxyProtocolMaximumSize) {
          if (g_quiet) {
            SLOG(g_log << Logger::Error << "Proxy protocol header in UDP packet from " << fromaddr.toStringWithPort() << " is larger than proxy-protocol-maximum-size (" << used << "), dropping" << endl,
                 g_slogudpin->info(Logr::Error, "Proxy protocol header in UDP packet  is larger than proxy-protocol-maximum-size",
                                   "used", Logging::Loggable(used), "remote", Logging::Loggable(fromaddr)));
          }
          ++t_Counters.at(rec::Counter::proxyProtocolInvalidCount);
          return;
        }

        data.erase(0, used);
      }
      else if (len > 512) {
        /* we only allow UDP packets larger than 512 for those with a proxy protocol header */
        t_Counters.at(rec::Counter::truncatedDrops)++;
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "Ignoring truncated query from " << fromaddr.toStringWithPort() << endl,
               g_slogudpin->info(Logr::Error, "Ignoring truncated query", "remote", Logging::Loggable(fromaddr)));
        }
        return;
      }

      if (data.size() < sizeof(dnsheader)) {
        t_Counters.at(rec::Counter::ignoredCount)++;
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "Ignoring too-short (" << std::to_string(data.size()) << ") query from " << fromaddr.toString() << endl,
               g_slogudpin->info(Logr::Error, "Ignoring too-short query", "length", Logging::Loggable(data.size()),
                                 "remote", Logging::Loggable(fromaddr)));
        }
        return;
      }

      if (!proxyProto) {
        source = fromaddr;
      }
      ComboAddress mappedSource = source;
      if (t_proxyMapping) {
        if (const auto* iter = t_proxyMapping->lookup(source)) {
          mappedSource = iter->second.address;
          ++iter->second.stats.netmaskMatches;
        }
      }
      if (t_remotes) {
        t_remotes->push_back(source);
      }

      if (t_allowFrom && !t_allowFrom->match(&mappedSource)) {
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "[" << g_multiTasker->getTid() << "] dropping UDP query from " << mappedSource.toString() << ", address not matched by allow-from" << endl,
               g_slogudpin->info(Logr::Error, "Dropping UDP query, address not matched by allow-from", "source", Logging::Loggable(mappedSource)));
        }

        t_Counters.at(rec::Counter::unauthorizedUDP)++;
        return;
      }

      BOOST_STATIC_ASSERT(offsetof(sockaddr_in, sin_port) == offsetof(sockaddr_in6, sin6_port));
      if (fromaddr.sin4.sin_port == 0) { // also works for IPv6
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "[" << g_multiTasker->getTid() << "] dropping UDP query from " << fromaddr.toStringWithPort() << ", can't deal with port 0" << endl,
               g_slogudpin->info(Logr::Error, "Dropping UDP query can't deal with port 0", "remote", Logging::Loggable(fromaddr)));
        }

        t_Counters.at(rec::Counter::clientParseError)++; // not quite the best place to put it, but needs to go somewhere
        return;
      }

      try {
        const dnsheader_aligned headerdata(data.data());
        const dnsheader* dnsheader = headerdata.get();

        if (dnsheader->qr) {
          t_Counters.at(rec::Counter::ignoredCount)++;
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Error << "Ignoring answer from " << fromaddr.toString() << " on server socket!" << endl,
                 g_slogudpin->info(Logr::Error, "Ignoring answer on server socket", "remote", Logging::Loggable(fromaddr)));
          }
        }
        else if (dnsheader->opcode != static_cast<unsigned>(Opcode::Query) && dnsheader->opcode != static_cast<unsigned>(Opcode::Notify)) {
          t_Counters.at(rec::Counter::ignoredCount)++;
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Error << "Ignoring unsupported opcode " << Opcode::to_s(dnsheader->opcode) << " from " << fromaddr.toString() << " on server socket!" << endl,
                 g_slogudpin->info(Logr::Error, "Ignoring unsupported opcode server socket", "remote", Logging::Loggable(fromaddr), "opcode", Logging::Loggable(Opcode::to_s(dnsheader->opcode))));
          }
        }
        else if (dnsheader->qdcount == 0U) {
          t_Counters.at(rec::Counter::emptyQueriesCount)++;
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Error << "Ignoring empty (qdcount == 0) query from " << fromaddr.toString() << " on server socket!" << endl,
                 g_slogudpin->info(Logr::Error, "Ignoring empty (qdcount == 0) query on server socket!", "remote", Logging::Loggable(fromaddr)));
          }
        }
        else {
          if (dnsheader->opcode == static_cast<unsigned>(Opcode::Notify)) {
            if (!t_allowNotifyFrom || !t_allowNotifyFrom->match(&mappedSource)) {
              if (!g_quiet) {
                SLOG(g_log << Logger::Error << "[" << g_multiTasker->getTid() << "] dropping UDP NOTIFY from " << mappedSource.toString() << ", address not matched by allow-notify-from" << endl,
                     g_slogudpin->info(Logr::Error, "Dropping UDP NOTIFY from address not matched by allow-notify-from",
                                       "source", Logging::Loggable(mappedSource)));
              }

              t_Counters.at(rec::Counter::sourceDisallowedNotify)++;
              return;
            }
          }

          struct timeval tval = {0, 0};
          HarvestTimestamp(&msgh, &tval);
          if (!proxyProto) {
            destination = destaddr;
          }

          if (RecThreadInfo::weDistributeQueries()) {
            std::string localdata = data;
            distributeAsyncFunction(data, [localdata = std::move(localdata), fromaddr, destaddr, source, destination, mappedSource, tval, fileDesc, proxyProtocolValues, eventTrace]() mutable {
              return doProcessUDPQuestion(localdata, fromaddr, destaddr, source, destination, mappedSource, tval, fileDesc, proxyProtocolValues, eventTrace);
            });
          }
          else {
            doProcessUDPQuestion(data, fromaddr, destaddr, source, destination, mappedSource, tval, fileDesc, proxyProtocolValues, eventTrace);
          }
        }
      }
      catch (const MOADNSException& mde) {
        t_Counters.at(rec::Counter::clientParseError)++;
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "Unable to parse packet from remote UDP client " << fromaddr.toString() << ": " << mde.what() << endl,
               g_slogudpin->error(Logr::Error, mde.what(), "Unable to parse packet from remote UDP client", "remote", Logging::Loggable(fromaddr), "exception", Logging::Loggable("MOADNSException")));
        }
      }
      catch (const std::runtime_error& e) {
        t_Counters.at(rec::Counter::clientParseError)++;
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "Unable to parse packet from remote UDP client " << fromaddr.toString() << ": " << e.what() << endl,
               g_slogudpin->error(Logr::Error, e.what(), "Unable to parse packet from remote UDP client", "remote", Logging::Loggable(fromaddr), "exception", Logging::Loggable("std::runtime_error")));
        }
      }
    }
    else {
      if (firstQuery && errno == EAGAIN) {
        t_Counters.at(rec::Counter::noPacketError)++;
      }

      break;
    }
  }
  t_Counters.updateSnap(g_regressionTestMode);
}

void makeUDPServerSockets(deferredAdd_t& deferredAdds, Logr::log_t log)
{
  int one = 1;
  vector<string> localAddresses;
  stringtok(localAddresses, ::arg()["local-address"], " ,");

  if (localAddresses.empty()) {
    throw PDNSException("No local address specified");
  }

  const uint16_t defaultLocalPort = ::arg().asNum("local-port");
  for (const auto& localAddress : localAddresses) {
    ComboAddress address{localAddress, defaultLocalPort};
    const int socketFd = socket(address.sin4.sin_family, SOCK_DGRAM, 0);
    if (socketFd < 0) {
      throw PDNSException("Making a UDP server socket for resolver: " + stringerror());
    }
    if (!setSocketTimestamps(socketFd)) {
      SLOG(g_log << Logger::Warning << "Unable to enable timestamp reporting for socket" << endl,
           log->info(Logr::Warning, "Unable to enable timestamp reporting for socket"));
    }
    if (IsAnyAddress(address)) {
      if (address.sin4.sin_family == AF_INET) {
        if (setsockopt(socketFd, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one)) == 0) { // linux supports this, so why not - might fail on other systems
          g_fromtosockets.insert(socketFd);
        }
      }
#ifdef IPV6_RECVPKTINFO
      if (address.sin4.sin_family == AF_INET6) {
        if (setsockopt(socketFd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) == 0) {
          g_fromtosockets.insert(socketFd);
        }
      }
#endif
      if (address.sin6.sin6_family == AF_INET6 && setsockopt(socketFd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0) {
        int err = errno;
        SLOG(g_log << Logger::Warning << "Failed to set IPv6 socket to IPv6 only, continuing anyhow: " << stringerror(err) << endl,
             log->error(Logr::Warning, err, "Failed to set IPv6 socket to IPv6 only, continuing anyhow"));
      }
    }
    if (::arg().mustDo("non-local-bind")) {
      Utility::setBindAny(AF_INET6, socketFd);
    }

    setCloseOnExec(socketFd);

    try {
      setSocketReceiveBuffer(socketFd, 250000);
    }
    catch (const std::exception& e) {
      SLOG(g_log << Logger::Error << e.what() << endl,
           log->error(Logr::Error, e.what(), "Exception while setting socket buffer size"));
    }

    if (g_reusePort) {
#if defined(SO_REUSEPORT_LB)
      try {
        SSetsockopt(socketFd, SOL_SOCKET, SO_REUSEPORT_LB, 1);
      }
      catch (const std::exception& e) {
        throw PDNSException(std::string("SO_REUSEPORT_LB: ") + e.what());
      }
#elif defined(SO_REUSEPORT)
      try {
        SSetsockopt(socketFd, SOL_SOCKET, SO_REUSEPORT, 1);
      }
      catch (const std::exception& e) {
        throw PDNSException(std::string("SO_REUSEPORT: ") + e.what());
      }
#endif
    }

    try {
      setSocketIgnorePMTU(socketFd, address.sin4.sin_family);
    }
    catch (const std::exception& e) {
      SLOG(g_log << Logger::Warning << "Failed to set IP_MTU_DISCOVER on UDP server socket: " << e.what() << endl,
           log->error(Logr::Warning, e.what(), "Failed to set IP_MTU_DISCOVER on UDP server socket"));
    }

    socklen_t socklen = address.getSocklen();
    if (::bind(socketFd, reinterpret_cast<struct sockaddr*>(&address), socklen) < 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      throw PDNSException("Resolver binding to server socket on " + address.toStringWithPort() + ": " + stringerror());
    }

    setNonBlocking(socketFd);

    deferredAdds.emplace_back(socketFd, handleNewUDPQuestion);
    g_listenSocketsAddresses[socketFd] = address; // this is written to only from the startup thread, not from the workers
    SLOG(g_log << Logger::Info << "Listening for UDP queries on " << address.toStringWithPort() << endl,
         log->info(Logr::Info, "Listening for queries", "proto", Logging::Loggable("UDP"), "address", Logging::Loggable(address)));
  }
}

static bool trySendingQueryToWorker(unsigned int target, ThreadMSG* tmsg)
{
  auto& targetInfo = RecThreadInfo::info(target);
  if (!targetInfo.isWorker()) {
    SLOG(g_log << Logger::Error << "distributeAsyncFunction() tried to assign a query to a non-worker thread" << endl,
         g_slog->withName("runtime")->info(Logr::Error, "distributeAsyncFunction() tried to assign a query to a non-worker thread"));
    _exit(1);
  }

  const auto& tps = targetInfo.getPipes();

  ssize_t written = write(tps.writeQueriesToThread, &tmsg, sizeof(tmsg)); // NOLINT: correct sizeof
  if (written > 0) {
    if (static_cast<size_t>(written) != sizeof(tmsg)) { // NOLINT: correct sizeof
      delete tmsg; // NOLINT: pointer ownership
      unixDie("write to thread pipe returned wrong size or error");
    }
  }
  else {
    int error = errno;
    if (error == EAGAIN || error == EWOULDBLOCK) {
      return false;
    }
    delete tmsg; // NOLINT: pointer ownership
    unixDie("write to thread pipe returned wrong size or error:" + std::to_string(error));
  }

  return true;
}

static unsigned int getWorkerLoad(size_t workerIdx)
{
  const auto* multiThreader = RecThreadInfo::info(RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + workerIdx).getMT();
  if (multiThreader != nullptr) {
    return multiThreader->numProcesses();
  }
  return 0;
}

static unsigned int selectWorker(unsigned int hash)
{
  assert(RecThreadInfo::numUDPWorkers() != 0); // NOLINT: assert implementation
  if (g_balancingFactor == 0) {
    return RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + (hash % RecThreadInfo::numUDPWorkers());
  }

  /* we start with one, representing the query we are currently handling */
  double currentLoad = 1;
  std::vector<unsigned int> load(RecThreadInfo::numUDPWorkers());
  for (size_t idx = 0; idx < RecThreadInfo::numUDPWorkers(); idx++) {
    load[idx] = getWorkerLoad(idx);
    currentLoad += load[idx];
  }

  double targetLoad = (currentLoad / RecThreadInfo::numUDPWorkers()) * g_balancingFactor;

  unsigned int worker = hash % RecThreadInfo::numUDPWorkers();
  /* at least one server has to be at or below the average load */
  if (load[worker] > targetLoad) {
    ++t_Counters.at(rec::Counter::rebalancedQueries);
    do {
      worker = (worker + 1) % RecThreadInfo::numUDPWorkers();
    } while (load[worker] > targetLoad);
  }

  return RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + worker;
}

// This function is only called by the distributor threads, when pdns-distributes-queries is set
void distributeAsyncFunction(const string& packet, const pipefunc_t& func)
{
  if (!RecThreadInfo::self().isDistributor()) {
    SLOG(g_log << Logger::Error << "distributeAsyncFunction() has been called by a worker (" << RecThreadInfo::id() << ")" << endl,
         g_slog->withName("runtime")->info(Logr::Error, "distributeAsyncFunction() has been called by a worker")); // tid will be added
    _exit(1);
  }

  bool hashOK = false;
  unsigned int hash = hashQuestion(reinterpret_cast<const uint8_t*>(packet.data()), packet.length(), g_disthashseed, hashOK); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  if (!hashOK) {
    // hashQuestion does detect invalid names, so we might as well punt here instead of in the worker thread
    t_Counters.at(rec::Counter::ignoredCount)++;
    throw MOADNSException("too-short (" + std::to_string(packet.length()) + ") or invalid name");
  }
  unsigned int target = selectWorker(hash);

  ThreadMSG* tmsg = new ThreadMSG(); // NOLINT: pointer ownership
  tmsg->func = func;
  tmsg->wantAnswer = false;

  if (!trySendingQueryToWorker(target, tmsg)) {
    /* if this function failed but did not raise an exception, it means that the pipe
       was full, let's try another one */
    unsigned int newTarget = 0;
    do {
      newTarget = RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + dns_random(RecThreadInfo::numUDPWorkers());
    } while (newTarget == target);

    if (!trySendingQueryToWorker(newTarget, tmsg)) {
      t_Counters.at(rec::Counter::queryPipeFullDrops)++;
      delete tmsg; // NOLINT: pointer ownership
    }
  }
  // coverity[leaked_storage]
}

// resend event to everybody chained onto it
static void doResends(MT_t::waiters_t::iterator& iter, const std::shared_ptr<PacketID>& resend, const PacketBuffer& content, const std::optional<bool>& ecsReceived)
{
  // We close the chain for new entries, since they won't be processed anyway
  iter->key->closed = true;

  if (iter->key->authReqChain.empty()) {
    return;
  }

  if (ecsReceived) {
    iter->key->ecsReceived = ecsReceived;
  }

  auto maxWeight = t_Counters.at(rec::Counter::maxChainWeight);
  auto weight = iter->key->authReqChain.size() * content.size();
  if (weight > maxWeight) {
    t_Counters.at(rec::Counter::maxChainWeight) = weight;
  }

  for (auto [fileDesc, qid] : iter->key->authReqChain) {
    auto packetID = std::make_shared<PacketID>(*resend);
    packetID->fd = fileDesc;
    packetID->id = qid;
    g_multiTasker->sendEvent(packetID, &content);
    t_Counters.at(rec::Counter::chainResends)++;
  }
}

void mthreadSleep(unsigned int jitterMsec)
{
  auto neverHappens = std::make_shared<PacketID>();
  neverHappens->id = dns_random_uint16();
  neverHappens->type = dns_random_uint16();
  neverHappens->remote = ComboAddress("100::"); // discard-only
  neverHappens->remote.setPort(dns_random_uint16());
  neverHappens->fd = -1;
  assert(g_multiTasker->waitEvent(neverHappens, nullptr, jitterMsec) != -1); // NOLINT
}

static bool checkIncomingECSSource(const PacketBuffer& packet, const Netmask& subnet)
{
  bool foundMatchingECS = false;

  // We sent out ECS, check if the response has the expected ECS info
  EDNSOptionViewMap ednsOptions;
  if (slowParseEDNSOptions(packet, ednsOptions)) {
    // check content
    auto option = ednsOptions.find(EDNSOptionCode::ECS);
    if (option != ednsOptions.end()) {
      // found an ECS option
      EDNSSubnetOpts ecs;
      for (const auto& value : option->second.values) {
        if (getEDNSSubnetOptsFromString(value.content, value.size, &ecs)) {
          if (ecs.source == subnet) {
            foundMatchingECS = true;
          }
        }
        break; // only look at first
      }
    }
  }
  return foundMatchingECS;
}

static void handleUDPServerResponse(int fileDesc, FDMultiplexer::funcparam_t& var)
{
  auto pid = boost::any_cast<std::shared_ptr<PacketID>>(var);
  PacketBuffer packet;
  packet.resize(g_outgoingEDNSBufsize);
  ComboAddress fromaddr;
  socklen_t addrlen = sizeof(fromaddr);

  ssize_t len = recvfrom(fileDesc, &packet.at(0), packet.size(), 0, reinterpret_cast<sockaddr*>(&fromaddr), &addrlen); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

  const ssize_t signed_sizeof_sdnsheader = sizeof(dnsheader);

  if (len < 0) {
    // len < 0: error on socket
    t_udpclientsocks->returnSocket(fileDesc);

    PacketBuffer empty;
    auto iter = g_multiTasker->getWaiters().find(pid);
    if (iter != g_multiTasker->getWaiters().end()) {
      doResends(iter, pid, empty, false);
    }
    g_multiTasker->sendEvent(pid, &empty); // this denotes error (does retry lookup using other NS)
    return;
  }

  if (len < signed_sizeof_sdnsheader) {
    // We have received a packet that cannot be a valid DNS packet, as it has no complete header
    // Drop it, but continue to wait for other packets
    t_Counters.at(rec::Counter::serverParseError)++;
    if (g_logCommonErrors) {
      SLOG(g_log << Logger::Error << "Unable to parse too short packet from remote UDP server " << fromaddr.toString() << ": packet smaller than DNS header" << endl,
           g_slogout->info(Logr::Error, "Unable to parse too short packet from remote UDP server", "from", Logging::Loggable(fromaddr)));
    }
    return;
  }

  // We have at least a full header
  packet.resize(len);
  dnsheader dnsheader{};
  memcpy(&dnsheader, &packet.at(0), sizeof(dnsheader));

  auto pident = std::make_shared<PacketID>();
  pident->remote = fromaddr;
  pident->id = dnsheader.id;
  pident->fd = fileDesc;

  if (!dnsheader.qr && g_logCommonErrors) {
    SLOG(g_log << Logger::Notice << "Not taking data from question on outgoing socket from " << fromaddr.toStringWithPort() << endl,
         g_slogout->info(Logr::Error, "Not taking data from question on outgoing socket", "from", Logging::Loggable(fromaddr)));
  }

  if (dnsheader.qdcount == 0U || // UPC, Nominum, very old BIND on FormErr, NSD
      dnsheader.qr == 0U) { // one weird server
    pident->domain.clear();
    pident->type = 0;
  }
  else {
    try {
      if (len > signed_sizeof_sdnsheader) {
        pident->domain = DNSName(reinterpret_cast<const char*>(packet.data()), static_cast<int>(len), static_cast<int>(sizeof(dnsheader)), false, &pident->type); // don't copy this from above - we need to do the actual read  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      }
      else {
        // len == sizeof(dnsheader), only header case
        // We will do a full scan search later to see if we can match this reply even without a domain
        pident->domain.clear();
        pident->type = 0;
      }
    }
    catch (std::exception& e) {
      // Parse error, continue waiting for other packets
      t_Counters.at(rec::Counter::serverParseError)++; // won't be fed to lwres.cc, so we have to increment
      SLOG(g_log << Logger::Warning << "Error in packet from remote nameserver " << fromaddr.toStringWithPort() << ": " << e.what() << endl,
           g_slogudpin->error(Logr::Warning, e.what(), "Error in packet from remote nameserver", "from", Logging::Loggable(fromaddr)));
      return;
    }
  }

  if (!pident->domain.empty()) {
    auto iter = g_multiTasker->getWaiters().find(pident);
    if (iter != g_multiTasker->getWaiters().end()) {
      iter->key->ecsReceived = iter->key->ecsSubnet && checkIncomingECSSource(packet, *iter->key->ecsSubnet);
      doResends(iter, pident, packet, iter->key->ecsReceived);
    }
  }

retryWithName:

  if (pident->domain.empty() || g_multiTasker->sendEvent(pident, &packet) == 0) {
    /* we did not find a match for this response, something is wrong */

    // we do a full scan for outstanding queries on unexpected answers. not too bad since we only accept them on the right port number, which is hard enough to guess
    for (const auto& d_waiter : g_multiTasker->getWaiters()) {
      if (pident->fd == d_waiter.key->fd && d_waiter.key->remote == pident->remote && d_waiter.key->type == pident->type && pident->domain == d_waiter.key->domain) {
        /* we are expecting an answer from that exact source, on that exact port (since we are using connected sockets), for that qname/qtype,
           but with a different message ID. That smells like a spoofing attempt. For now we will just increase the counter and will deal with
           that later. */
        d_waiter.key->nearMisses++;
      }

      // be a bit paranoid here since we're weakening our matching
      if (pident->domain.empty() && !d_waiter.key->domain.empty() && pident->type == 0 && d_waiter.key->type != 0 && pident->id == d_waiter.key->id && d_waiter.key->remote == pident->remote) {
        pident->domain = d_waiter.key->domain;
        pident->type = d_waiter.key->type;
        goto retryWithName; // note that this only passes on an error, lwres will still reject the packet NOLINT(cppcoreguidelines-avoid-goto)
      }
    }
    t_Counters.at(rec::Counter::unexpectedCount)++; // if we made it here, it really is an unexpected answer
    if (g_logCommonErrors) {
      SLOG(g_log << Logger::Warning << "Discarding unexpected packet from " << fromaddr.toStringWithPort() << ": " << (pident->domain.empty() ? "<empty>" : pident->domain.toString()) << ", " << pident->type << ", " << g_multiTasker->getWaiters().size() << " waiters" << endl,
           g_slogudpin->info(Logr::Warning, "Discarding unexpected packet", "from", Logging::Loggable(fromaddr),
                             "qname", Logging::Loggable(pident->domain),
                             "qtype", Logging::Loggable(QType(pident->type)),
                             "waiters", Logging::Loggable(g_multiTasker->getWaiters().size())));
    }
  }
  else if (fileDesc >= 0) {
    /* we either found a waiter (1) or encountered an issue (-1), it's up to us to clean the socket anyway */
    t_udpclientsocks->returnSocket(fileDesc);
  }
}
