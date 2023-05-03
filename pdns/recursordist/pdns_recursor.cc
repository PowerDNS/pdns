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

thread_local std::unique_ptr<MT_t> MT; // the big MTasker
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

typedef map<int, ComboAddress> listenSocketsAddresses_t; // is shared across all threads right now

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

LWResult::Result UDPClientSocks::getSocket(const ComboAddress& toaddr, int* fd)
{
  *fd = makeClientSocket(toaddr.sin4.sin_family);
  if (*fd < 0) { // temporary error - receive exception otherwise
    return LWResult::Result::OSLimitError;
  }

  if (connect(*fd, (struct sockaddr*)(&toaddr), toaddr.getSocklen()) < 0) {
    int err = errno;
    try {
      closesocket(*fd);
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
void UDPClientSocks::returnSocket(int fd)
{
  try {
    t_fdm->removeReadFD(fd);
  }
  catch (const FDMultiplexerException& e) {
    // we sometimes return a socket that has not yet been assigned to t_fdm
  }

  try {
    closesocket(fd);
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
    in_port_t port;

    if (tries == 1) { // last iteration: fall back to kernel 'random'
      port = 0;
    }
    else {
      do {
        port = g_minUdpSourcePort + dns_random(g_maxUdpSourcePort - g_minUdpSourcePort + 1);
      } while (g_avoidUdpSourcePorts.count(port) != 0);
    }

    sin = pdns::getQueryLocalAddress(family, port); // does htons for us
    if (::bind(ret, reinterpret_cast<struct sockaddr*>(&sin), sin.getSocklen()) >= 0) {
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

static void handleGenUDPQueryResponse(int fd, FDMultiplexer::funcparam_t& var)
{
  std::shared_ptr<PacketID> pident = boost::any_cast<std::shared_ptr<PacketID>>(var);
  PacketBuffer resp;
  resp.resize(512);
  ComboAddress fromaddr;
  socklen_t addrlen = sizeof(fromaddr);

  ssize_t ret = recvfrom(fd, resp.data(), resp.size(), 0, (sockaddr*)&fromaddr, &addrlen);
  if (fromaddr != pident->remote) {
    SLOG(g_log << Logger::Notice << "Response received from the wrong remote host (" << fromaddr.toStringWithPort() << " instead of " << pident->remote.toStringWithPort() << "), discarding" << endl,
         g_slog->withName("lua")->info(Logr::Notice, "Response received from the wrong remote host. discarding", "method", Logging::Loggable("GenUDPQueryResponse"), "fromaddr", Logging::Loggable(fromaddr), "expected", Logging::Loggable(pident->remote)));
  }

  t_fdm->removeReadFD(fd);
  if (ret >= 0) {
    resp.resize(ret);
    MT->sendEvent(pident, &resp);
  }
  else {
    PacketBuffer empty;
    MT->sendEvent(pident, &empty);
    //    cerr<<"Had some kind of error: "<<ret<<", "<<stringerror()<<endl;
  }
}

PacketBuffer GenUDPQueryResponse(const ComboAddress& dest, const string& query)
{
  Socket s(dest.sin4.sin_family, SOCK_DGRAM);
  s.setNonBlocking();
  ComboAddress local = pdns::getQueryLocalAddress(dest.sin4.sin_family, 0);

  s.bind(local);
  s.connect(dest);
  s.send(query);

  std::shared_ptr<PacketID> pident = std::make_shared<PacketID>();
  pident->fd = s.getHandle();
  pident->remote = dest;
  pident->type = 0;
  t_fdm->addReadFD(s.getHandle(), handleGenUDPQueryResponse, pident);

  PacketBuffer data;
  int ret = MT->waitEvent(pident, &data, g_networkTimeoutMsec);

  if (!ret || ret == -1) { // timeout
    t_fdm->removeReadFD(s.getHandle());
  }
  else if (data.empty()) { // error, EOF or other
    // we could special case this
    return data;
  }
  return data;
}

static void handleUDPServerResponse(int fd, FDMultiplexer::funcparam_t&);

thread_local std::unique_ptr<UDPClientSocks> t_udpclientsocks;

/* these two functions are used by LWRes */
LWResult::Result asendto(const char* data, size_t len, int /* flags */,
                         const ComboAddress& toaddr, uint16_t id, const DNSName& domain, uint16_t qtype, bool ecs, int* fd)
{

  auto pident = std::make_shared<PacketID>();
  pident->domain = domain;
  pident->remote = toaddr;
  pident->type = qtype;

  // We cannot merge ECS-enabled queries based on the ECS source only, as the scope
  // of the response might be narrower, so instead we do not chain ECS-enabled queries
  // at all.
  if (!ecs) {
    // See if there is an existing outstanding request we can chain on to, using partial equivalence
    // function looking for the same query (qname and qtype) to the same host, but with a different
    // message ID.
    auto chain = MT->d_waiters.equal_range(pident, PacketIDBirthdayCompare());

    for (; chain.first != chain.second; chain.first++) {
      // Line below detected an issue with the two ways of ordering PacketIDs (birthday and non-birthday)
      assert(chain.first->key->domain == pident->domain);
      // don't chain onto existing chained waiter or a chain already processed
      if (chain.first->key->fd > -1 && !chain.first->key->closed) {
        chain.first->key->chain.insert(id); // we can chain
        *fd = -1; // gets used in waitEvent / sendEvent later on
        return LWResult::Result::Success;
      }
    }
  }

  auto ret = t_udpclientsocks->getSocket(toaddr, fd);
  if (ret != LWResult::Result::Success) {
    return ret;
  }

  pident->fd = *fd;
  pident->id = id;

  t_fdm->addReadFD(*fd, handleUDPServerResponse, pident);
  ssize_t sent = send(*fd, data, len, 0);

  int tmp = errno;

  if (sent < 0) {
    t_udpclientsocks->returnSocket(*fd);
    errno = tmp; // this is for logging purposes only
    return LWResult::Result::PermanentError;
  }

  return LWResult::Result::Success;
}

LWResult::Result arecvfrom(PacketBuffer& packet, int /* flags */, const ComboAddress& fromaddr, size_t& len,
                           uint16_t id, const DNSName& domain, uint16_t qtype, int fd, const struct timeval& now)
{
  static const unsigned int nearMissLimit = ::arg().asNum("spoof-nearmiss-max");

  auto pident = std::make_shared<PacketID>();
  pident->fd = fd;
  pident->id = id;
  pident->domain = domain;
  pident->type = qtype;
  pident->remote = fromaddr;

  int ret = MT->waitEvent(pident, &packet, g_networkTimeoutMsec, &now);
  len = 0;

  /* -1 means error, 0 means timeout, 1 means a result from handleUDPServerResponse() which might still be an error */
  if (ret > 0) {
    /* handleUDPServerResponse() will close the socket for us no matter what */
    if (packet.empty()) { // means "error"
      return LWResult::Result::PermanentError;
    }

    len = packet.size();

    if (nearMissLimit > 0 && pident->nearMisses > nearMissLimit) {
      /* we have received more than nearMissLimit answers on the right IP and port, from the right source (we are using connected sockets),
         for the correct qname and qtype, but with an unexpected message ID. That looks like a spoofing attempt. */
      SLOG(g_log << Logger::Error << "Too many (" << pident->nearMisses << " > " << nearMissLimit << ") answers with a wrong message ID for '" << domain << "' from " << fromaddr.toString() << ", assuming spoof attempt." << endl,
           g_slogudpin->info(Logr::Error, "Too many answers with a wrong message ID, assuming spoofing attempt",
                             "nearmisses", Logging::Loggable(pident->nearMisses),
                             "nearmisslimit", Logging::Loggable(nearMissLimit),
                             "qname", Logging::Loggable(domain),
                             "from", Logging::Loggable(fromaddr)));
      t_Counters.at(rec::Counter::spoofCount)++;
      return LWResult::Result::Spoofed;
    }

    return LWResult::Result::Success;
  }
  else {
    /* getting there means error or timeout, it's up to us to close the socket */
    if (fd >= 0) {
      t_udpclientsocks->returnSocket(fd);
    }
  }

  return ret == 0 ? LWResult::Result::Timeout : LWResult::Result::PermanentError;
}

// the idea is, only do things that depend on the *response* here. Incoming accounting is on incoming.
static void updateResponseStats(int res, const ComboAddress& remote, unsigned int packetsize, const DNSName* query, uint16_t qtype)
{
  if (packetsize > 1000 && t_largeanswerremotes)
    t_largeanswerremotes->push_back(remote);
  switch (res) {
  case RCode::ServFail:
    if (t_servfailremotes) {
      t_servfailremotes->push_back(remote);
      if (query && t_servfailqueryring) // packet cache
        t_servfailqueryring->push_back({*query, qtype});
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

static string makeLoginfo(const std::unique_ptr<DNSComboWriter>& dc)
try {
  return "(" + dc->d_mdp.d_qname.toLogString() + "/" + DNSRecordContent::NumberToType(dc->d_mdp.d_qtype) + " from " + (dc->getRemote()) + ")";
}
catch (...) {
  return "Exception making error message for exception";
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
static void handleRPZCustom(const DNSRecord& spoofed, const QType& qtype, SyncRes& sr, int& res, vector<DNSRecord>& ret)
{
  if (spoofed.d_type == QType::CNAME) {
    bool oldWantsRPZ = sr.getWantsRPZ();
    sr.setWantsRPZ(false);
    vector<DNSRecord> ans;
    res = sr.beginResolve(DNSName(spoofed.getContent()->getZoneRepresentation()), qtype, QClass::IN, ans);
    for (const auto& rec : ans) {
      if (rec.d_place == DNSResourceRecord::ANSWER) {
        ret.push_back(rec);
      }
    }
    // Reset the RPZ state of the SyncRes
    sr.setWantsRPZ(oldWantsRPZ);
  }
}

static bool addRecordToPacket(DNSPacketWriter& pw, const DNSRecord& rec, uint32_t& minTTL, uint32_t ttlCap, const uint16_t maxAnswerSize, bool& seenAuthSOA)
{
  pw.startRecord(rec.d_name, rec.d_type, (rec.d_ttl > ttlCap ? ttlCap : rec.d_ttl), rec.d_class, rec.d_place);

  if (rec.d_type == QType::SOA && rec.d_place == DNSResourceRecord::AUTHORITY) {
    seenAuthSOA = true;
  }

  if (rec.d_type != QType::OPT) // their TTL ain't real
    minTTL = min(minTTL, rec.d_ttl);

  rec.getContent()->toPacket(pw);
  if (pw.size() > static_cast<size_t>(maxAnswerSize)) {
    pw.rollback();
    if (rec.d_place != DNSResourceRecord::ADDITIONAL) {
      pw.getHeader()->tc = 1;
      pw.truncate();
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
  RunningResolveGuard(std::unique_ptr<DNSComboWriter>& dc) :
    d_dc(dc)
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
  std::unique_ptr<DNSComboWriter>& d_dc;
  bool d_handled{false};
};

enum class PolicyResult : uint8_t
{
  NoAction,
  HaveAnswer,
  Drop
};

static PolicyResult handlePolicyHit(const DNSFilterEngine::Policy& appliedPolicy, const std::unique_ptr<DNSComboWriter>& dc, SyncRes& sr, int& res, vector<DNSRecord>& ret, DNSPacketWriter& pw, RunningResolveGuard& tcpGuard)
{
  /* don't account truncate actions for TCP queries, since they are not applied */
  if (appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::Truncate || !dc->d_tcp) {
    ++t_Counters.at(rec::PolicyHistogram::policy).at(appliedPolicy.d_kind);
    ++t_Counters.at(rec::PolicyNameHits::policyName).counts[appliedPolicy.getName()];
  }

  if (sr.doLog() && appliedPolicy.d_type != DNSFilterEngine::PolicyType::None) {
    SLOG(g_log << Logger::Warning << dc->d_mdp.d_qname << "|" << QType(dc->d_mdp.d_qtype) << appliedPolicy.getLogString() << endl,
         appliedPolicy.info(Logr::Warning, sr.d_slog));
  }

  if (appliedPolicy.d_zoneData && appliedPolicy.d_zoneData->d_extendedErrorCode) {
    dc->d_extendedErrorCode = *appliedPolicy.d_zoneData->d_extendedErrorCode;
    dc->d_extendedErrorExtra = appliedPolicy.d_zoneData->d_extendedErrorExtra;
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
    res = RCode::NXDomain;
    return PolicyResult::HaveAnswer;

  case DNSFilterEngine::PolicyKind::NODATA:
    ret.clear();
    res = RCode::NoError;
    return PolicyResult::HaveAnswer;

  case DNSFilterEngine::PolicyKind::Truncate:
    if (!dc->d_tcp) {
      ret.clear();
      res = RCode::NoError;
      pw.getHeader()->tc = 1;
      return PolicyResult::HaveAnswer;
    }
    return PolicyResult::NoAction;

  case DNSFilterEngine::PolicyKind::Custom:
    res = RCode::NoError;
    {
      auto spoofed = appliedPolicy.getCustomRecords(dc->d_mdp.d_qname, dc->d_mdp.d_qtype);
      for (auto& dr : spoofed) {
        ret.push_back(dr);
        try {
          handleRPZCustom(dr, QType(dc->d_mdp.d_qtype), sr, res, ret);
        }
        catch (const ImmediateServFailException& e) {
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << dc->getRemote() << " during resolve of the custom filter policy '" << appliedPolicy.getName() << "' while resolving '" << dc->d_mdp.d_qname << "' because: " << e.reason << endl,
                 sr.d_slog->error(Logr::Notice, e.reason, "Sending SERVFAIL during resolve of the custom filter policy",
                                  "policyName", Logging::Loggable(appliedPolicy.getName()), "exception", Logging::Loggable("ImmediateServFailException")));
          }
          res = RCode::ServFail;
          break;
        }
        catch (const PolicyHitException& e) {
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << dc->getRemote() << " during resolve of the custom filter policy '" << appliedPolicy.getName() << "' while resolving '" << dc->d_mdp.d_qname << "' because another RPZ policy was hit" << endl,
                 sr.d_slog->info(Logr::Notice, "Sending SERVFAIL during resolve of the custom filter policy because another RPZ policy was hit",
                                 "policyName", Logging::Loggable(appliedPolicy.getName()), "exception", Logging::Loggable("PolicyHitException")));
          }
          res = RCode::ServFail;
          break;
        }
      }

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
  if (!g_nodDomainWL.check(dname)) {
    // Now check the NODDB (note this is probabilistic so can have FNs/FPs)
    if (t_nodDBp && t_nodDBp->isNewDomain(dname)) {
      if (g_nodLog) {
        // This should probably log to a dedicated log file
        SLOG(g_log << Logger::Notice << "Newly observed domain nod=" << dname << endl,
             nodlogger->info(Logr::Notice, "New domain observed"));
      }
      ret = true;
    }
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
  if (record.d_place == DNSResourceRecord::ANSWER || record.d_place == DNSResourceRecord::ADDITIONAL) {
    // Create a string that represent a triplet of (qname, qtype and RR[type, name, content])
    std::stringstream ss;
    ss << dname.toDNSStringLC() << ":" << qtype << ":" << qtype << ":" << record.d_type << ":" << record.d_name.toDNSStringLC() << ":" << record.getContent()->getZoneRepresentation();
    if (t_udrDBp && t_udrDBp->isUniqueResponse(ss.str())) {
      if (g_udrLog) {
        // This should also probably log to a dedicated file.
        SLOG(g_log << Logger::Notice << "Unique response observed: qname=" << dname << " qtype=" << QType(qtype) << " rrtype=" << QType(record.d_type) << " rrname=" << record.d_name << " rrcontent=" << record.getContent()->getZoneRepresentation() << endl,
             nodlogger->info(Logr::Debug, "New response observed",
                             "qtype", Logging::Loggable(QType(qtype)),
                             "rrtype", Logging::Loggable(QType(record.d_type)),
                             "rrname", Logging::Loggable(record.d_name),
                             "rrcontent", Logging::Loggable(record.getContent()->getZoneRepresentation())););
      }
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
  for (const DNSRecord& rr : ret) {
    if (rr.d_type == QType::CNAME) {
      auto rec = getRR<CNAMERecordContent>(rr);
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

  for (DNSRecord& rr : resolved) {
    if (rr.d_place == DNSResourceRecord::ANSWER) {
      ret.push_back(std::move(rr));
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
              [&seenCNAMEs](DNSRecord& rr) {
                if (rr.d_type == QType::CNAME) {
                  auto target = getRR<CNAMERecordContent>(rr);
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
  for (DNSRecord& rr : ret) {
    if (rr.d_type == QType::A && rr.d_place == DNSResourceRecord::ANSWER) {
      if (auto rec = getRR<ARecordContent>(rr)) {
        ComboAddress ipv4(rec->getCA());
        memcpy(&prefix.sin6.sin6_addr.s6_addr[12], &ipv4.sin4.sin_addr.s_addr, sizeof(ipv4.sin4.sin_addr.s_addr));
        rr.setContent(std::make_shared<AAAARecordContent>(prefix));
        rr.d_type = QType::AAAA;
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
                [](DNSRecord& rr) {
                  return (rr.d_type == QType::SOA && rr.d_place == DNSResourceRecord::AUTHORITY);
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
  for (int n = 0; n < 4; ++n) {
    newquery += std::to_string(stoll(parts[n * 2], 0, 16) + 16 * stoll(parts[n * 2 + 1], 0, 16));
    newquery.append(1, '.');
  }
  newquery += "in-addr.arpa.";

  DNSRecord rr;
  rr.d_name = qname;
  rr.d_type = QType::CNAME;
  rr.setContent(std::make_shared<CNAMERecordContent>(newquery));
  ret.push_back(rr);

  auto log = g_slog->withName("dns64")->withValues("method", Logging::Loggable("getPTR"));
  int rcode = directResolve(DNSName(newquery), QType::PTR, QClass::IN, ret, t_pdl, log);

  t_Counters.at(rec::Counter::dns64prefixanswers)++;
  return rcode;
}

static bool answerIsNOData(uint16_t requestedType, int rcode, const std::vector<DNSRecord>& records)
{
  if (rcode != RCode::NoError) {
    return false;
  }
  for (const auto& rec : records) {
    if (rec.d_place != DNSResourceRecord::ANSWER) {
      /* no records in the answer section */
      return true;
    }
    if (rec.d_type == requestedType) {
      /* we have a record, of the right type, in the right section */
      return false;
    }
  }
  return true;
}

// RFC 6147 section 5.1 all rcodes except NXDomain should be candidate for dns64
// for NoError, check if it is NoData
static bool dns64Candidate(uint16_t requestedType, int rcode, const std::vector<DNSRecord>& records)
{
  if (rcode == RCode::NoError) {
    return answerIsNOData(requestedType, rcode, records);
  }
  return rcode != RCode::NXDomain;
}

bool isAllowNotifyForZone(DNSName qname)
{
  if (t_allowNotifyFor->empty()) {
    return false;
  }

  notifyset_t::const_iterator ret;
  do {
    ret = t_allowNotifyFor->find(qname);
    if (ret != t_allowNotifyFor->end())
      return true;
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
  auto filep = std::unique_ptr<FILE, decltype(&fclose)>(fdopen(traceFd, "a"), &fclose);
  if (!filep) {
    int err = errno;
    SLOG(g_log << Logger::Error << "Could not write to trace file: " << stringerror(err) << endl,
         g_slog->withName("trace")->error(Logr::Error, err, "Could not write to trace file"));
    close(traceFd);
    return;
  }
  std::array<char, 64> timebuf;
  isoDateTimeMillis(timev, timebuf.data(), timebuf.size());
  fprintf(filep.get(), " us === START OF TRACE %s ===\n", timebuf.data());
  fprintf(filep.get(), "%s", trace.c_str());
  isoDateTimeMillis(now, timebuf.data(), timebuf.size());
  fprintf(filep.get(), "=== END OF TRACE %s ===\n", timebuf.data());
  if (ferror(filep.get())) {
    int err = errno;
    SLOG(g_log << Logger::Error << "Problems writing to trace file: " << stringerror(err) << endl,
         g_slog->withName("trace")->error(Logr::Error, err, "Problems writing to trace file"));
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

void startDoResolve(void* p)
{
  auto dc = std::unique_ptr<DNSComboWriter>(reinterpret_cast<DNSComboWriter*>(p));
  SyncRes sr(dc->d_now);
  try {
    if (t_queryring)
      t_queryring->push_back({dc->d_mdp.d_qname, dc->d_mdp.d_qtype});

    uint16_t maxanswersize = dc->d_tcp ? 65535 : min(static_cast<uint16_t>(512), g_udpTruncationThreshold);
    EDNSOpts edo;
    std::vector<pair<uint16_t, string>> ednsOpts;
    bool variableAnswer = dc->d_variable;
    bool haveEDNS = false;
    bool paddingAllowed = false;
    bool addPaddingToResponse = false;
#ifdef NOD_ENABLED
    bool hasUDR = false;
    std::shared_ptr<Logr::Logger> nodlogger{nullptr};
    if (g_udrEnabled || g_nodEnabled) {
      nodlogger = g_slog->withName("nod")->v(1)->withValues("qname", Logging::Loggable(dc->d_mdp.d_qname));
    }
#endif /* NOD_ENABLED */
    DNSPacketWriter::optvect_t returnedEdnsOptions; // Here we stuff all the options for the return packet
    uint8_t ednsExtRCode = 0;
    if (getEDNSOpts(dc->d_mdp, &edo)) {
      haveEDNS = true;
      if (edo.d_version != 0) {
        ednsExtRCode = ERCode::BADVERS;
      }

      if (!dc->d_tcp) {
        /* rfc6891 6.2.3:
           "Values lower than 512 MUST be treated as equal to 512."
        */
        maxanswersize = min(static_cast<uint16_t>(edo.d_packetsize >= 512 ? edo.d_packetsize : 512), g_udpTruncationThreshold);
      }
      ednsOpts = edo.d_options;
      maxanswersize -= 11; // EDNS header size

      if (!dc->d_responsePaddingDisabled && g_paddingFrom.match(dc->d_remote)) {
        paddingAllowed = true;
        if (g_paddingMode == PaddingMode::Always) {
          addPaddingToResponse = true;
        }
      }

      for (const auto& o : edo.d_options) {
        if (o.first == EDNSOptionCode::ECS && g_useIncomingECS && !dc->d_ecsParsed) {
          dc->d_ecsFound = getEDNSSubnetOptsFromString(o.second, &dc->d_ednssubnet);
        }
        else if (o.first == EDNSOptionCode::NSID) {
          const static string mode_server_id = ::arg()["server-id"];
          if (mode_server_id != "disabled" && !mode_server_id.empty() && maxanswersize > (EDNSOptionCodeSize + EDNSOptionLengthSize + mode_server_id.size())) {
            returnedEdnsOptions.emplace_back(EDNSOptionCode::NSID, mode_server_id);
            variableAnswer = true; // Can't packetcache an answer with NSID
            maxanswersize -= EDNSOptionCodeSize + EDNSOptionLengthSize + mode_server_id.size();
          }
        }
        else if (paddingAllowed && !addPaddingToResponse && g_paddingMode == PaddingMode::PaddedQueries && o.first == EDNSOptionCode::PADDING) {
          addPaddingToResponse = true;
        }
      }
    }

    /* the lookup will be done _before_ knowing whether the query actually
       has a padding option, so we need to use the separate tag even when the
       query does not have padding, as long as it is from an allowed source */
    if (paddingAllowed && dc->d_tag == 0) {
      dc->d_tag = g_paddingTag;
    }

    /* perhaps there was no EDNS or no ECS but by now we looked */
    dc->d_ecsParsed = true;
    vector<DNSRecord> ret;
    vector<uint8_t> packet;

    auto luaconfsLocal = g_luaconfs.getLocal();
    // Used to tell syncres later on if we should apply NSDNAME and NSIP RPZ triggers for this query
    bool wantsRPZ(true);
    RecursorPacketCache::OptPBData pbDataForCache;
    pdns::ProtoZero::RecMessage pbMessage;
    if (checkProtobufExport(luaconfsLocal)) {
      pbMessage.reserve(128, 128); // It's a bit of a guess...
      pbMessage.setResponse(dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_mdp.d_qclass);
      pbMessage.setServerIdentity(SyncRes::s_serverID);

      // RRSets added below
    }
    checkOutgoingProtobufExport(luaconfsLocal); // to pick up changed configs
#ifdef HAVE_FSTRM
    checkFrameStreamExport(luaconfsLocal, luaconfsLocal->frameStreamExportConfig, t_frameStreamServersInfo);
    checkFrameStreamExport(luaconfsLocal, luaconfsLocal->nodFrameStreamExportConfig, t_nodFrameStreamServersInfo);
#endif

    DNSPacketWriter pw(packet, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_mdp.d_qclass, dc->d_mdp.d_header.opcode);

    pw.getHeader()->aa = 0;
    pw.getHeader()->ra = 1;
    pw.getHeader()->qr = 1;
    pw.getHeader()->tc = 0;
    pw.getHeader()->id = dc->d_mdp.d_header.id;
    pw.getHeader()->rd = dc->d_mdp.d_header.rd;
    pw.getHeader()->cd = dc->d_mdp.d_header.cd;

    /* This is the lowest TTL seen in the records of the response,
       so we can't cache it for longer than this value.
       If we have a TTL cap, this value can't be larger than the
       cap no matter what. */
    uint32_t minTTL = dc->d_ttlCap;
    bool seenAuthSOA = false;

    sr.d_eventTrace = std::move(dc->d_eventTrace);
    sr.setId(MT->getTid());

    bool DNSSECOK = false;
    if (dc->d_luaContext) {
      sr.setLuaEngine(dc->d_luaContext);
    }
    if (g_dnssecmode != DNSSECMode::Off) {
      sr.setDoDNSSEC(true);

      // Does the requestor want DNSSEC records?
      if (edo.d_extFlags & EDNSOpts::DNSSECOK) {
        DNSSECOK = true;
        t_Counters.at(rec::Counter::dnssecQueries)++;
      }
      if (dc->d_mdp.d_header.cd) {
        /* Per rfc6840 section 5.9, "When processing a request with
           the Checking Disabled (CD) bit set, a resolver SHOULD attempt
           to return all response data, even data that has failed DNSSEC
           validation. */
        ++t_Counters.at(rec::Counter::dnssecCheckDisabledQueries);
      }
      if (dc->d_mdp.d_header.ad) {
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
      pw.getHeader()->cd = 0;
    }
    sr.setDNSSECValidationRequested(g_dnssecmode == DNSSECMode::ValidateAll || g_dnssecmode == DNSSECMode::ValidateForLog || ((dc->d_mdp.d_header.ad || DNSSECOK) && g_dnssecmode == DNSSECMode::Process));

    sr.setInitialRequestId(dc->d_uuid);
    sr.setOutgoingProtobufServers(t_outgoingProtobufServers.servers);
#ifdef HAVE_FSTRM
    sr.setFrameStreamServers(t_frameStreamServersInfo.servers);
#endif

    bool useMapped = true;
    // If proxy by table is active and had a match, we only want to use the mapped address if it also has a domain match
    // (if a domain suffix match table is present in the config)
    if (t_proxyMapping && dc->d_source != dc->d_mappedSource) {
      if (auto it = t_proxyMapping->lookup(dc->d_source)) {
        if (it->second.suffixMatchNode) {
          if (!it->second.suffixMatchNode->check(dc->d_mdp.d_qname)) {
            // No match in domains, use original source
            useMapped = false;
          }
          else {
            ++it->second.stats.suffixMatches;
          }
        }
        // No suffix match node defined, use mapped address
      }
      // lookup failing cannot happen as dc->d_source != dc->d_mappedSource
    }
    sr.setQuerySource(useMapped ? dc->d_mappedSource : dc->d_source, g_useIncomingECS && !dc->d_ednssubnet.source.empty() ? boost::optional<const EDNSSubnetOpts&>(dc->d_ednssubnet) : boost::none);

    sr.setQueryReceivedOverTCP(dc->d_tcp);

    bool tracedQuery = false; // we could consider letting Lua know about this too
    bool shouldNotValidate = false;

    /* preresolve expects res (dq.rcode) to be set to RCode::NoError by default */
    int res = RCode::NoError;

    DNSFilterEngine::Policy appliedPolicy;
    RecursorLua4::DNSQuestion dq(dc->d_source, dc->d_destination, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_tcp, variableAnswer, wantsRPZ, dc->d_logResponse, addPaddingToResponse, (g_useKernelTimestamp && dc->d_kernelTimestamp.tv_sec != 0) ? dc->d_kernelTimestamp : dc->d_now);
    dq.ednsFlags = &edo.d_extFlags;
    dq.ednsOptions = &ednsOpts;
    dq.tag = dc->d_tag;
    dq.discardedPolicies = &sr.d_discardedPolicies;
    dq.policyTags = &dc->d_policyTags;
    dq.appliedPolicy = &appliedPolicy;
    dq.currentRecords = &ret;
    dq.dh = &dc->d_mdp.d_header;
    dq.data = dc->d_data;
    dq.requestorId = dc->d_requestorId;
    dq.deviceId = dc->d_deviceId;
    dq.deviceName = dc->d_deviceName;
    dq.proxyProtocolValues = &dc->d_proxyProtocolValues;
    dq.extendedErrorCode = &dc->d_extendedErrorCode;
    dq.extendedErrorExtra = &dc->d_extendedErrorExtra;
    dq.meta = std::move(dc->d_meta);
    dq.fromAuthIP = &sr.d_fromAuthIP;

    sr.d_slog = sr.d_slog->withValues("qname", Logging::Loggable(dc->d_mdp.d_qname),
                                      "qtype", Logging::Loggable(QType(dc->d_mdp.d_qtype)),
                                      "remote", Logging::Loggable(dc->getRemote()),
                                      "proto", Logging::Loggable(dc->d_tcp ? "tcp" : "udp"),
                                      "ecs", Logging::Loggable(dc->d_ednssubnet.source.empty() ? "" : dc->d_ednssubnet.source.toString()),
                                      "mtid", Logging::Loggable(MT->getTid()));
    RunningResolveGuard tcpGuard(dc);

    if (ednsExtRCode != 0 || dc->d_mdp.d_header.opcode == Opcode::Notify) {
      goto sendit;
    }

    if (dc->d_mdp.d_qtype == QType::ANY && !dc->d_tcp && g_anyToTcp) {
      pw.getHeader()->tc = 1;
      res = 0;
      variableAnswer = true;
      goto sendit;
    }

    if (t_traceRegex && t_traceRegex->match(dc->d_mdp.d_qname.toString())) {
      sr.setLogMode(SyncRes::Store);
      tracedQuery = true;
    }

    if (!g_quiet || tracedQuery) {
      if (!g_slogStructured) {
        g_log << Logger::Warning << RecThreadInfo::id() << " [" << MT->getTid() << "/" << MT->numProcesses() << "] " << (dc->d_tcp ? "TCP " : "") << "question for '" << dc->d_mdp.d_qname << "|"
              << QType(dc->d_mdp.d_qtype) << "' from " << dc->getRemote();
        if (!dc->d_ednssubnet.source.empty()) {
          g_log << " (ecs " << dc->d_ednssubnet.source.toString() << ")";
        }
        g_log << endl;
      }
      else {
        sr.d_slog->info(Logr::Info, "Question");
      }
    }

    if (!dc->d_mdp.d_header.rd) {
      sr.setCacheOnly();
    }

    if (dc->d_luaContext) {
      dc->d_luaContext->prerpz(dq, res, sr.d_eventTrace);
    }

    // Check if the client has a policy attached to it
    if (wantsRPZ && !appliedPolicy.wasHit()) {

      if (luaconfsLocal->dfe.getClientPolicy(dc->d_source, sr.d_discardedPolicies, appliedPolicy)) {
        mergePolicyTags(dc->d_policyTags, appliedPolicy.getTags());
      }
    }

    /* If we already have an answer generated from gettag_ffi, let's see if the filtering policies
       should be applied to it */
    if (dc->d_rcode != boost::none) {

      bool policyOverride = false;
      /* Unless we already matched on the client IP, time to check the qname.
         We normally check it in beginResolve() but it will be bypassed since we already have an answer */
      if (wantsRPZ && appliedPolicy.policyOverridesGettag()) {
        if (appliedPolicy.d_type != DNSFilterEngine::PolicyType::None) {
          // Client IP already matched
        }
        else {
          // no match on the client IP, check the qname
          if (luaconfsLocal->dfe.getQueryPolicy(dc->d_mdp.d_qname, sr.d_discardedPolicies, appliedPolicy)) {
            // got a match
            mergePolicyTags(dc->d_policyTags, appliedPolicy.getTags());
          }
        }

        if (appliedPolicy.wasHit()) {
          policyOverride = true;
        }
      }

      if (!policyOverride) {
        /* No RPZ or gettag overrides it anyway */
        ret = std::move(dc->d_records);
        res = *dc->d_rcode;
        if (res == RCode::NoError && dc->d_followCNAMERecords) {
          res = followCNAMERecords(ret, QType(dc->d_mdp.d_qtype), res);
        }
        goto haveAnswer;
      }
    }

    // if there is a RecursorLua active, and it 'took' the query in preResolve, we don't launch beginResolve
    if (!dc->d_luaContext || !dc->d_luaContext->preresolve(dq, res, sr.d_eventTrace)) {

      if (!g_dns64PrefixReverse.empty() && dq.qtype == QType::PTR && dq.qname.isPartOf(g_dns64PrefixReverse)) {
        res = getFakePTRRecords(dq.qname, ret);
        goto haveAnswer;
      }

      sr.setWantsRPZ(wantsRPZ);

      if (wantsRPZ && appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) {

        if (dc->d_luaContext && dc->d_luaContext->policyHitEventFilter(dc->d_source, dc->d_mdp.d_qname, QType(dc->d_mdp.d_qtype), dc->d_tcp, appliedPolicy, dc->d_policyTags, sr.d_discardedPolicies)) {
          /* reset to no match */
          appliedPolicy = DNSFilterEngine::Policy();
        }
        else {
          auto policyResult = handlePolicyHit(appliedPolicy, dc, sr, res, ret, pw, tcpGuard);
          if (policyResult == PolicyResult::HaveAnswer) {
            if (g_dns64Prefix && dq.qtype == QType::AAAA && dns64Candidate(dc->d_mdp.d_qtype, res, ret)) {
              res = getFakeAAAARecords(dq.qname, *g_dns64Prefix, ret);
              shouldNotValidate = true;
            }
            goto haveAnswer;
          }
          else if (policyResult == PolicyResult::Drop) {
            return;
          }
        }
      }

      // Query did not get handled for Client IP or QNAME Policy reasons, now actually go out to find an answer
      try {
        sr.d_appliedPolicy = appliedPolicy;
        sr.d_policyTags = std::move(dc->d_policyTags);

        if (!dc->d_routingTag.empty()) {
          sr.d_routingTag = dc->d_routingTag;
        }

        ret.clear(); // policy might have filled it with custom records but we decided not to use them
        res = sr.beginResolve(dc->d_mdp.d_qname, QType(dc->d_mdp.d_qtype), dc->d_mdp.d_qclass, ret);
        shouldNotValidate = sr.wasOutOfBand();
      }
      catch (const ImmediateQueryDropException& e) {
        // XXX We need to export a protobuf message (and do a NOD lookup) if requested!
        t_Counters.at(rec::Counter::policyDrops)++;
        SLOG(g_log << Logger::Debug << "Dropping query because of a filtering policy " << makeLoginfo(dc) << endl,
             sr.d_slog->info(Logr::Debug, "Dropping query because of a filtering policy"));
        return;
      }
      catch (const ImmediateServFailException& e) {
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << dc->getRemote() << " during resolve of '" << dc->d_mdp.d_qname << "' because: " << e.reason << endl,
               sr.d_slog->error(Logr::Notice, e.reason, "Sending SERVFAIL during resolve"));
        }
        res = RCode::ServFail;
      }
      catch (const SendTruncatedAnswerException& e) {
        ret.clear();
        res = RCode::NoError;
        pw.getHeader()->tc = 1;
      }
      catch (const PolicyHitException& e) {
        res = -2;
      }
      dq.validationState = sr.getValidationState();
      appliedPolicy = sr.d_appliedPolicy;
      dc->d_policyTags = std::move(sr.d_policyTags);

      if (appliedPolicy.d_type != DNSFilterEngine::PolicyType::None && appliedPolicy.d_zoneData && appliedPolicy.d_zoneData->d_extendedErrorCode) {
        dc->d_extendedErrorCode = *appliedPolicy.d_zoneData->d_extendedErrorCode;
        dc->d_extendedErrorExtra = appliedPolicy.d_zoneData->d_extendedErrorExtra;
      }

      // During lookup, an NSDNAME or NSIP trigger was hit in RPZ
      if (res == -2) { // XXX This block should be macro'd, it is repeated post-resolve.
        if (appliedPolicy.d_kind == DNSFilterEngine::PolicyKind::NoAction) {
          throw PDNSException("NoAction policy returned while a NSDNAME or NSIP trigger was hit");
        }
        auto policyResult = handlePolicyHit(appliedPolicy, dc, sr, res, ret, pw, tcpGuard);
        if (policyResult == PolicyResult::HaveAnswer) {
          goto haveAnswer;
        }
        else if (policyResult == PolicyResult::Drop) {
          return;
        }
      }

      bool luaHookHandled = false;
      if (dc->d_luaContext) {
        PolicyResult policyResult = PolicyResult::NoAction;
        if (answerIsNOData(dc->d_mdp.d_qtype, res, ret)) {
          if (dc->d_luaContext->nodata(dq, res, sr.d_eventTrace)) {
            luaHookHandled = true;
            shouldNotValidate = true;
            policyResult = handlePolicyHit(appliedPolicy, dc, sr, res, ret, pw, tcpGuard);
          }
        }
        else if (res == RCode::NXDomain && dc->d_luaContext->nxdomain(dq, res, sr.d_eventTrace)) {
          luaHookHandled = true;
          shouldNotValidate = true;
          policyResult = handlePolicyHit(appliedPolicy, dc, sr, res, ret, pw, tcpGuard);
        }
        if (policyResult == PolicyResult::HaveAnswer) {
          goto haveAnswer;
        }
        else if (policyResult == PolicyResult::Drop) {
          return;
        }
      } // dc->d_luaContext

      if (!luaHookHandled && g_dns64Prefix && dc->d_mdp.d_qtype == QType::AAAA && (shouldNotValidate || !sr.isDNSSECValidationRequested() || !vStateIsBogus(dq.validationState)) && dns64Candidate(dc->d_mdp.d_qtype, res, ret)) {
        res = getFakeAAAARecords(dq.qname, *g_dns64Prefix, ret);
        shouldNotValidate = true;
      }

      if (dc->d_luaContext) {
        PolicyResult policyResult = PolicyResult::NoAction;
        if (dc->d_luaContext->d_postresolve_ffi) {
          RecursorLua4::PostResolveFFIHandle handle(dq);
          sr.d_eventTrace.add(RecEventTrace::LuaPostResolveFFI);
          bool pr = dc->d_luaContext->postresolve_ffi(handle);
          sr.d_eventTrace.add(RecEventTrace::LuaPostResolveFFI, pr, false);
          if (pr) {
            shouldNotValidate = true;
            policyResult = handlePolicyHit(appliedPolicy, dc, sr, res, ret, pw, tcpGuard);
          }
        }
        else if (dc->d_luaContext->postresolve(dq, res, sr.d_eventTrace)) {
          shouldNotValidate = true;
          policyResult = handlePolicyHit(appliedPolicy, dc, sr, res, ret, pw, tcpGuard);
        }
        if (policyResult == PolicyResult::HaveAnswer) {
          goto haveAnswer;
        }
        else if (policyResult == PolicyResult::Drop) {
          return;
        }
      } // dc->d_luaContext
    }
    else if (dc->d_luaContext) {
      // preresolve returned true
      shouldNotValidate = true;
      auto policyResult = handlePolicyHit(appliedPolicy, dc, sr, res, ret, pw, tcpGuard);
      // haveAnswer case redundant
      if (policyResult == PolicyResult::Drop) {
        return;
      }
    }

  haveAnswer:;
    if (tracedQuery || res == -1 || res == RCode::ServFail || pw.getHeader()->rcode == RCode::ServFail) {
      dumpTrace(sr.getTrace(), sr.d_fixednow);
    }

    if (res == -1) {
      pw.getHeader()->rcode = RCode::ServFail;
      // no commit here, because no record
      ++t_Counters.at(rec::Counter::servFails);
    }
    else {
      pw.getHeader()->rcode = res;

      // Does the validation mode or query demand validation?
      if (!shouldNotValidate && sr.isDNSSECValidationRequested()) {
        try {
          auto state = sr.getValidationState();

          string x_marker;
          std::shared_ptr<Logr::Logger> log;
          if (sr.doLog() || vStateIsBogus(state)) {
            // Only create logging object if needed below, beware if you change the logging logic!
            log = sr.d_slog->withValues("vstate", Logging::Loggable(state));
            auto xdnssec = g_xdnssec.getLocal();
            if (xdnssec->check(dc->d_mdp.d_qname)) {
              log = log->withValues("in-x-dnssec-names", Logging::Loggable(1));
              x_marker = " [in x-dnssec-names]";
            }
          }
          if (state == vState::Secure) {
            if (sr.doLog()) {
              SLOG(g_log << Logger::Warning << "Answer to " << dc->d_mdp.d_qname << "|" << QType(dc->d_mdp.d_qtype) << x_marker << " for " << dc->getRemote() << " validates correctly" << endl,
                   log->info(Logr::Info, "Validates Correctly"));
            }

            // Is the query source interested in the value of the ad-bit?
            if (dc->d_mdp.d_header.ad || DNSSECOK)
              pw.getHeader()->ad = 1;
          }
          else if (state == vState::Insecure) {
            if (sr.doLog()) {
              SLOG(g_log << Logger::Warning << "Answer to " << dc->d_mdp.d_qname << "|" << QType(dc->d_mdp.d_qtype) << x_marker << " for " << dc->getRemote() << " validates as Insecure" << endl,
                   log->info(Logr::Info, "Validates as Insecure"));
            }

            pw.getHeader()->ad = 0;
          }
          else if (vStateIsBogus(state)) {
            if (t_bogusremotes)
              t_bogusremotes->push_back(dc->d_source);
            if (t_bogusqueryring)
              t_bogusqueryring->push_back({dc->d_mdp.d_qname, dc->d_mdp.d_qtype});
            if (g_dnssecLogBogus || sr.doLog() || g_dnssecmode == DNSSECMode::ValidateForLog) {
              SLOG(g_log << Logger::Warning << "Answer to " << dc->d_mdp.d_qname << "|" << QType(dc->d_mdp.d_qtype) << x_marker << " for " << dc->getRemote() << " validates as " << vStateToString(state) << endl,
                   log->info(Logr::Notice, "Validates as Bogus"));
            }

            // Does the query or validation mode sending out a SERVFAIL on validation errors?
            if (!pw.getHeader()->cd && (g_dnssecmode == DNSSECMode::ValidateAll || dc->d_mdp.d_header.ad || DNSSECOK)) {
              if (sr.doLog()) {
                SLOG(g_log << Logger::Warning << "Sending out SERVFAIL for " << dc->d_mdp.d_qname << "|" << QType(dc->d_mdp.d_qtype) << " because recursor or query demands it for Bogus results" << endl,
                     log->info(Logr::Notice, "Sending out SERVFAIL because recursor or query demands it for Bogus results"));
              }

              pw.getHeader()->rcode = RCode::ServFail;
              goto sendit;
            }
            else {
              if (sr.doLog()) {
                SLOG(g_log << Logger::Warning << "Not sending out SERVFAIL for " << dc->d_mdp.d_qname << "|" << QType(dc->d_mdp.d_qtype) << x_marker << " Bogus validation since neither config nor query demands this" << endl,
                     log->info(Logr::Notice, "Sending out SERVFAIL because recursor or query demands it for Bogus results"));
              }
            }
          }
        }
        catch (const ImmediateServFailException& e) {
          if (g_logCommonErrors)
            SLOG(g_log << Logger::Notice << "Sending SERVFAIL to " << dc->getRemote() << " during validation of '" << dc->d_mdp.d_qname << "|" << QType(dc->d_mdp.d_qtype) << "' because: " << e.reason << endl,
                 sr.d_slog->error(Logr::Notice, e.reason, "Sending SERVFAIL during validation", "exception", Logging::Loggable("ImmediateServFailException")));
          goto sendit;
        }
      }

      if (ret.size()) {
        pdns::orderAndShuffle(ret, false);
        if (auto sl = luaconfsLocal->sortlist.getOrderCmp(dc->d_source)) {
          stable_sort(ret.begin(), ret.end(), *sl);
          variableAnswer = true;
        }
      }

      bool needCommit = false;
      for (auto i = ret.cbegin(); i != ret.cend(); ++i) {
        if (!DNSSECOK && (i->d_type == QType::NSEC3 || ((i->d_type == QType::RRSIG || i->d_type == QType::NSEC) && ((dc->d_mdp.d_qtype != i->d_type && dc->d_mdp.d_qtype != QType::ANY) || (i->d_place != DNSResourceRecord::ANSWER && i->d_place != DNSResourceRecord::ADDITIONAL))))) {
          continue;
        }

        if (!addRecordToPacket(pw, *i, minTTL, dc->d_ttlCap, maxanswersize, seenAuthSOA)) {
          needCommit = false;
          break;
        }
        needCommit = true;

        bool udr = false;
#ifdef NOD_ENABLED
        if (g_udrEnabled) {
          udr = udrCheckUniqueDNSRecord(nodlogger, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, *i);
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
            pbMessage.addRR(*i, luaconfsLocal->protobufExportConfig.exportTypes, udr);
          }
        }
      }
      if (needCommit) {
        pw.commit();
      }
#ifdef NOD_ENABLED
#ifdef HAVE_FSTRM
      if (hasUDR) {
        if (isEnabledForUDRs(t_nodFrameStreamServersInfo.servers)) {
          struct timespec ts;
          std::string str;
          if (g_useKernelTimestamp && dc->d_kernelTimestamp.tv_sec) {
            TIMEVAL_TO_TIMESPEC(&(dc->d_kernelTimestamp), &ts);
          }
          else {
            TIMEVAL_TO_TIMESPEC(&(dc->d_now), &ts);
          }
          DnstapMessage message(str, DnstapMessage::MessageType::resolver_response, SyncRes::s_serverID, &dc->d_source, &dc->d_destination, dc->d_tcp ? DnstapMessage::ProtocolType::DoTCP : DnstapMessage::ProtocolType::DoUDP, reinterpret_cast<const char*>(&*packet.begin()), packet.size(), &ts, nullptr, dc->d_mdp.d_qname);

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

    if (g_useIncomingECS && dc->d_ecsFound && !sr.wasVariable() && !variableAnswer) {
      EDNSSubnetOpts eo;
      eo.source = dc->d_ednssubnet.source;
      ComboAddress sa;
      sa.reset();
      sa.sin4.sin_family = eo.source.getNetwork().sin4.sin_family;
      eo.scope = Netmask(sa, 0);
      auto ecsPayload = makeEDNSSubnetOptsString(eo);

      // if we don't have enough space available let's just not set that scope of zero,
      // it will prevent some caching, mostly from dnsdist, but that's fine
      if (pw.size() < maxanswersize && (maxanswersize - pw.size()) >= (EDNSOptionCodeSize + EDNSOptionLengthSize + ecsPayload.size())) {

        maxanswersize -= EDNSOptionCodeSize + EDNSOptionLengthSize + ecsPayload.size();

        returnedEdnsOptions.emplace_back(EDNSOptionCode::ECS, std::move(ecsPayload));
      }
    }

    if (haveEDNS && addPaddingToResponse) {
      size_t currentSize = pw.getSizeWithOpts(returnedEdnsOptions);
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
      auto state = sr.getValidationState();
      if (dc->d_extendedErrorCode || sr.d_extendedError || (SyncRes::s_addExtendedResolutionDNSErrors && vStateIsBogus(state))) {
        EDNSExtendedError::code code;
        std::string extra;

        if (dc->d_extendedErrorCode) {
          code = static_cast<EDNSExtendedError::code>(*dc->d_extendedErrorCode);
          extra = std::move(dc->d_extendedErrorExtra);
        }
        else if (sr.d_extendedError) {
          code = static_cast<EDNSExtendedError::code>(sr.d_extendedError->infoCode);
          extra = std::move(sr.d_extendedError->extraText);
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
            code = EDNSExtendedError::code::DNSSECBogus;
            break;
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

        if (pw.size() < maxanswersize && (maxanswersize - pw.size()) >= (EDNSOptionCodeSize + EDNSOptionLengthSize + sizeof(eee.infoCode) + eee.extraText.size())) {
          returnedEdnsOptions.emplace_back(EDNSOptionCode::EXTENDEDERROR, makeEDNSExtendedErrorOptString(eee));
        }
      }

      /* we try to add the EDNS OPT RR even for truncated answers,
         as rfc6891 states:
         "The minimal response MUST be the DNS header, question section, and an
         OPT record.  This MUST also occur when a truncated response (using
         the DNS header's TC bit) is returned."
      */
      pw.addOpt(512, ednsExtRCode, DNSSECOK ? EDNSOpts::DNSSECOK : 0, returnedEdnsOptions);
      pw.commit();
    }

    t_Counters.at(rec::ResponseStats::responseStats).submitResponse(dc->d_mdp.d_qtype, packet.size(), pw.getHeader()->rcode);
    updateResponseStats(res, dc->d_source, packet.size(), &dc->d_mdp.d_qname, dc->d_mdp.d_qtype);
#ifdef NOD_ENABLED
    bool nod = false;
    if (g_nodEnabled) {
      if (nodCheckNewDomain(nodlogger, dc->d_mdp.d_qname)) {
        nod = true;
#ifdef HAVE_FSTRM
        if (isEnabledForNODs(t_nodFrameStreamServersInfo.servers)) {
          struct timespec ts;
          std::string str;
          if (g_useKernelTimestamp && dc->d_kernelTimestamp.tv_sec) {
            TIMEVAL_TO_TIMESPEC(&(dc->d_kernelTimestamp), &ts);
          }
          else {
            TIMEVAL_TO_TIMESPEC(&(dc->d_now), &ts);
          }
          DnstapMessage message(str, DnstapMessage::MessageType::client_query, SyncRes::s_serverID, &dc->d_source, &dc->d_destination, dc->d_tcp ? DnstapMessage::ProtocolType::DoTCP : DnstapMessage::ProtocolType::DoUDP, nullptr, 0, &ts, nullptr, dc->d_mdp.d_qname);

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

    if (variableAnswer || sr.wasVariable()) {
      t_Counters.at(rec::Counter::variableResponses)++;
    }

    if (t_protobufServers.servers && !(luaconfsLocal->protobufExportConfig.taggedOnly && appliedPolicy.getName().empty() && dc->d_policyTags.empty())) {
      // Start constructing embedded DNSResponse object
      pbMessage.setResponseCode(pw.getHeader()->rcode);
      if (!appliedPolicy.getName().empty()) {
        pbMessage.setAppliedPolicy(appliedPolicy.getName());
        pbMessage.setAppliedPolicyType(appliedPolicy.d_type);
        pbMessage.setAppliedPolicyTrigger(appliedPolicy.d_trigger);
        pbMessage.setAppliedPolicyHit(appliedPolicy.d_hit);
        pbMessage.setAppliedPolicyKind(appliedPolicy.d_kind);
      }
      pbMessage.addPolicyTags(dc->d_policyTags);
      pbMessage.setInBytes(packet.size());
      pbMessage.setValidationState(sr.getValidationState());

      // Take s snap of the current protobuf buffer state to store in the PC
      pbDataForCache = boost::make_optional(RecursorPacketCache::PBData{
        pbMessage.getMessageBuf(),
        pbMessage.getResponseBuf(),
        !appliedPolicy.getName().empty() || !dc->d_policyTags.empty()});
#ifdef NOD_ENABLED
      // if (g_udrEnabled) ??
      pbMessage.clearUDR(pbDataForCache->d_response);
#endif
    }

    if (g_packetCache && !variableAnswer && !sr.wasVariable()) {
      minTTL = capPacketCacheTTL(*pw.getHeader(), minTTL, seenAuthSOA);
      g_packetCache->insertResponsePacket(dc->d_tag, dc->d_qhash, std::move(dc->d_query), dc->d_mdp.d_qname,
                                          dc->d_mdp.d_qtype, dc->d_mdp.d_qclass,
                                          string((const char*)&*packet.begin(), packet.size()),
                                          g_now.tv_sec,
                                          minTTL,
                                          dq.validationState,
                                          std::move(pbDataForCache), dc->d_tcp);
    }

    if (g_regressionTestMode) {
      t_Counters.updateSnap(g_regressionTestMode);
    }

    if (!dc->d_tcp) {
      struct msghdr msgh;
      struct iovec iov;
      cmsgbuf_aligned cbuf;
      fillMSGHdr(&msgh, &iov, &cbuf, 0, (char*)&*packet.begin(), packet.size(), &dc->d_remote);
      msgh.msg_control = NULL;

      if (g_fromtosockets.count(dc->d_socket)) {
        addCMsgSrcAddr(&msgh, &cbuf, &dc->d_local, 0);
      }
      int sendErr = sendOnNBSocket(dc->d_socket, &msgh);
      if (sendErr && g_logCommonErrors) {
        SLOG(g_log << Logger::Warning << "Sending UDP reply to client " << dc->getRemote() << " failed with: "
                   << strerror(sendErr) << endl,
             g_slogudpin->error(Logr::Warning, sendErr, "Sending UDP reply to client failed"));
      }
    }
    else {
      bool hadError = sendResponseOverTCP(dc, packet);
      finishTCPReply(dc, hadError, true);
      tcpGuard.setHandled();
    }

    sr.d_eventTrace.add(RecEventTrace::AnswerSent);

    // Now do the per query changing part ot the protobuf message
    if (t_protobufServers.servers && !(luaconfsLocal->protobufExportConfig.taggedOnly && appliedPolicy.getName().empty() && dc->d_policyTags.empty())) {
      // Below are the fields that are not stored in the packet cache and will be appended here and on a cache hit
      if (g_useKernelTimestamp && dc->d_kernelTimestamp.tv_sec) {
        pbMessage.setQueryTime(dc->d_kernelTimestamp.tv_sec, dc->d_kernelTimestamp.tv_usec);
      }
      else {
        pbMessage.setQueryTime(dc->d_now.tv_sec, dc->d_now.tv_usec);
      }
      pbMessage.setMessageIdentity(dc->d_uuid);
      pbMessage.setSocketProtocol(dc->d_tcp ? pdns::ProtoZero::Message::TransportProtocol::TCP : pdns::ProtoZero::Message::TransportProtocol::UDP);

      if (!luaconfsLocal->protobufExportConfig.logMappedFrom) {
        pbMessage.setSocketFamily(dc->d_source.sin4.sin_family);
        Netmask requestorNM(dc->d_source, dc->d_source.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
        ComboAddress requestor = requestorNM.getMaskedNetwork();
        pbMessage.setFrom(requestor);
        pbMessage.setFromPort(dc->d_source.getPort());
      }
      else {
        pbMessage.setSocketFamily(dc->d_mappedSource.sin4.sin_family);
        Netmask requestorNM(dc->d_mappedSource, dc->d_mappedSource.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
        ComboAddress requestor = requestorNM.getMaskedNetwork();
        pbMessage.setFrom(requestor);
        pbMessage.setFromPort(dc->d_mappedSource.getPort());
      }

      pbMessage.setTo(dc->d_destination);
      pbMessage.setId(dc->d_mdp.d_header.id);

      pbMessage.setTime();
      pbMessage.setEDNSSubnet(dc->d_ednssubnet.source, dc->d_ednssubnet.source.isIPv4() ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
      pbMessage.setRequestorId(dq.requestorId);
      pbMessage.setDeviceId(dq.deviceId);
      pbMessage.setDeviceName(dq.deviceName);
      pbMessage.setToPort(dc->d_destination.getPort());

      for (const auto& m : dq.meta) {
        pbMessage.setMeta(m.first, m.second.stringVal, m.second.intVal);
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
      if (sr.d_eventTrace.enabled() && SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_pb) {
        pbMessage.addEvents(sr.d_eventTrace);
      }
      if (dc->d_logResponse) {
        protobufLogResponse(pbMessage);
      }
    }

    if (sr.d_eventTrace.enabled() && SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_log) {
      SLOG(g_log << Logger::Info << sr.d_eventTrace.toString() << endl,
           sr.d_slog->info(Logr::Info, sr.d_eventTrace.toString())); // Maybe we want it to be more fancy?
    }

    // Originally this code used a mix of floats, doubles, uint64_t with different units.
    // Now it always uses an integral number of microseconds, except for averages, which use doubles
    uint64_t spentUsec = uSec(sr.getNow() - dc->d_now);
    if (!g_quiet) {
      if (!g_slogStructured) {
        g_log << Logger::Error << RecThreadInfo::id() << " [" << MT->getTid() << "/" << MT->numProcesses() << "] answer to " << (dc->d_mdp.d_header.rd ? "" : "non-rd ") << "question '" << dc->d_mdp.d_qname << "|" << DNSRecordContent::NumberToType(dc->d_mdp.d_qtype);
        g_log << "': " << ntohs(pw.getHeader()->ancount) << " answers, " << ntohs(pw.getHeader()->arcount) << " additional, took " << sr.d_outqueries << " packets, " << sr.d_totUsec / 1000.0 << " netw ms, " << spentUsec / 1000.0 << " tot ms, " << sr.d_throttledqueries << " throttled, " << sr.d_timeouts << " timeouts, " << sr.d_tcpoutqueries << "/" << sr.d_dotoutqueries << " tcp/dot connections, rcode=" << res;

        if (!shouldNotValidate && sr.isDNSSECValidationRequested()) {
          g_log << ", dnssec=" << sr.getValidationState();
        }
        g_log << endl;
      }
      else {
        sr.d_slog->info(Logr::Info, "Answer", "rd", Logging::Loggable(dc->d_mdp.d_header.rd),
                        "answers", Logging::Loggable(ntohs(pw.getHeader()->ancount)),
                        "additional", Logging::Loggable(ntohs(pw.getHeader()->arcount)),
                        "outqueries", Logging::Loggable(sr.d_outqueries),
                        "netms", Logging::Loggable(sr.d_totUsec / 1000.0),
                        "totms", Logging::Loggable(spentUsec / 1000.0),
                        "throttled", Logging::Loggable(sr.d_throttledqueries),
                        "timeouts", Logging::Loggable(sr.d_timeouts),
                        "tcpout", Logging::Loggable(sr.d_tcpoutqueries),
                        "dotout", Logging::Loggable(sr.d_dotoutqueries),
                        "rcode", Logging::Loggable(res),
                        "validationState", Logging::Loggable(sr.getValidationState()));
      }
    }

    if (dc->d_mdp.d_header.opcode == Opcode::Query) {
      if (sr.d_outqueries || sr.d_authzonequeries) {
        g_recCache->cacheMisses++;
      }
      else {
        g_recCache->cacheHits++;
      }
    }

    t_Counters.at(rec::Histogram::answers)(spentUsec);
    t_Counters.at(rec::Histogram::cumulativeAnswers)(spentUsec);

    double newLat = spentUsec;
    newLat = min(newLat, g_networkTimeoutMsec * 1000.0); // outliers of several minutes exist..
    t_Counters.at(rec::DoubleWAvgCounter::avgLatencyUsec).addToRollingAvg(newLat, g_latencyStatSize);
    // no worries, we do this for packet cache hits elsewhere

    if (spentUsec >= sr.d_totUsec) {
      uint64_t ourtime = spentUsec - sr.d_totUsec;
      t_Counters.at(rec::Histogram::ourtime)(ourtime);
      newLat = ourtime; // usec
      t_Counters.at(rec::DoubleWAvgCounter::avgLatencyOursUsec).addToRollingAvg(newLat, g_latencyStatSize);
    }

#ifdef NOD_ENABLED
    if (nod) {
      sendNODLookup(nodlogger, dc->d_mdp.d_qname);
    }
#endif /* NOD_ENABLED */

    //    cout<<dc->d_mdp.d_qname<<"\t"<<MT->getUsec()<<"\t"<<sr.d_outqueries<<endl;
  }
  catch (const PDNSException& ae) {
    SLOG(g_log << Logger::Error << "startDoResolve problem " << makeLoginfo(dc) << ": " << ae.reason << endl,
         sr.d_slog->error(Logr::Error, ae.reason, "startDoResolve problem", "exception", Logging::Loggable("PDNSException")));
  }
  catch (const MOADNSException& mde) {
    SLOG(g_log << Logger::Error << "DNS parser error " << makeLoginfo(dc) << ": " << dc->d_mdp.d_qname << ", " << mde.what() << endl,
         sr.d_slog->error(Logr::Error, mde.what(), "DNS parser error"));
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "STL error " << makeLoginfo(dc) << ": " << e.what(),
         sr.d_slog->error(Logr::Error, e.what(), "Exception in resolver context ", "exception", Logging::Loggable("std::exception")));

    // Luawrapper nests the exception from Lua, so we unnest it here
    try {
      std::rethrow_if_nested(e);
    }
    catch (const std::exception& ne) {
      SLOG(g_log << ". Extra info: " << ne.what(),
           sr.d_slog->error(Logr::Error, ne.what(), "Nested exception in resolver context", Logging::Loggable("std::exception")));
    }
    catch (...) {
    }
    if (!g_slogStructured) {
      g_log << endl;
    }
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "Any other exception in a resolver context " << makeLoginfo(dc) << endl,
         sr.d_slog->info(Logr::Error, "Any other exception in a resolver context"));
  }

  runTaskOnce(g_logCommonErrors);

  static const size_t stackSizeThreshold = 9 * ::arg().asNum("stack-size") / 10;
  if (MT->getMaxStackUsage() >= stackSizeThreshold) {
    SLOG(g_log << Logger::Error << "Reached mthread stack usage of 90%: " << MT->getMaxStackUsage() << " " << makeLoginfo(dc) << " after " << sr.d_outqueries << " out queries, " << sr.d_tcpoutqueries << " TCP out queries, " << sr.d_dotoutqueries << " DoT out queries" << endl,
         sr.d_slog->info(Logr::Error, "Reached mthread stack usage of 90%",
                         "stackUsage", Logging::Loggable(MT->getMaxStackUsage()),
                         "outqueries", Logging::Loggable(sr.d_outqueries),
                         "netms", Logging::Loggable(sr.d_totUsec / 1000.0),
                         "throttled", Logging::Loggable(sr.d_throttledqueries),
                         "timeouts", Logging::Loggable(sr.d_timeouts),
                         "tcpout", Logging::Loggable(sr.d_tcpoutqueries),
                         "dotout", Logging::Loggable(sr.d_dotoutqueries),
                         "validationState", Logging::Loggable(sr.getValidationState())));
  }
  t_Counters.at(rec::Counter::maxMThreadStackUsage) = max(MT->getMaxStackUsage(), t_Counters.at(rec::Counter::maxMThreadStackUsage));
  t_Counters.updateSnap(g_regressionTestMode);
}

void getQNameAndSubnet(const std::string& question, DNSName* dnsname, uint16_t* qtype, uint16_t* qclass,
                       bool& foundECS, EDNSSubnetOpts* ednssubnet, EDNSOptionViewMap* options)
{
  const bool lookForECS = ednssubnet != nullptr;
  const dnsheader_aligned dnshead(question.data());
  const dnsheader* dh = dnshead.get();
  size_t questionLen = question.length();
  unsigned int consumed = 0;
  *dnsname = DNSName(question.c_str(), questionLen, sizeof(dnsheader), false, qtype, qclass, &consumed);

  size_t pos = sizeof(dnsheader) + consumed + 4;
  const size_t headerSize = /* root */ 1 + sizeof(dnsrecordheader);
  const uint16_t arcount = ntohs(dh->arcount);

  for (uint16_t arpos = 0; arpos < arcount && questionLen > (pos + headerSize) && (lookForECS && !foundECS); arpos++) {
    if (question.at(pos) != 0) {
      /* not an OPT, bye. */
      return;
    }

    pos += 1;
    const dnsrecordheader* drh = reinterpret_cast<const dnsrecordheader*>(&question.at(pos));
    pos += sizeof(dnsrecordheader);

    if (pos >= questionLen) {
      return;
    }

    /* OPT root label (1) followed by type (2) */
    if (lookForECS && ntohs(drh->d_type) == QType::OPT) {
      if (!options) {
        size_t ecsStartPosition = 0;
        size_t ecsLen = 0;
        /* we need to pass the record len */
        int res = getEDNSOption(reinterpret_cast<const char*>(&question.at(pos - sizeof(drh->d_clen))), questionLen - pos + sizeof(drh->d_clen), EDNSOptionCode::ECS, &ecsStartPosition, &ecsLen);
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
        int res = getEDNSOptions(reinterpret_cast<const char*>(&question.at(pos - sizeof(drh->d_clen))), questionLen - pos + (sizeof(drh->d_clen)), *options);
        if (res == 0) {
          const auto& it = options->find(EDNSOptionCode::ECS);
          if (it != options->end() && !it->second.values.empty() && it->second.values.at(0).content != nullptr && it->second.values.at(0).size > 0) {
            EDNSSubnetOpts eso;
            if (getEDNSSubnetOptsFromString(it->second.values.at(0).content, it->second.values.at(0).size, &eso)) {
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
  uint32_t age;
  vState valState;

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
  ThreadMSG* tmsg = new ThreadMSG();
  tmsg->func = [=] { return pleaseWipeCaches(canon, true, 0xffff); };
  tmsg->wantAnswer = false;
  if (write(RecThreadInfo::info(0).pipes.writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) {
    delete tmsg;

    unixDie("write to thread pipe returned wrong size or error");
  }
  // coverity[leaked_storage]
}

bool expectProxyProtocol(const ComboAddress& from)
{
  return g_proxyProtocolACL.match(from);
}

// fromaddr: the address the query is coming from
// destaddr: the address the query was received on
// source: the address we assume the query is coming from, might be set by proxy protocol
// destination: the address we assume the query was sent to, might be set by proxy protocol
// mappedSource: the address we assume the query is coming from. Differs from source if table based mapping has been applied
static string* doProcessUDPQuestion(const std::string& question, const ComboAddress& fromaddr, const ComboAddress& destaddr, ComboAddress source, ComboAddress destination, const ComboAddress& mappedSource, struct timeval tv, int fd, std::vector<ProxyProtocolValue>& proxyProtocolValues, RecEventTrace& eventTrace)
{
  ++(RecThreadInfo::self().numberOfDistributedQueries);
  gettimeofday(&g_now, nullptr);
  if (tv.tv_sec) {
    struct timeval diff = g_now - tv;
    double delta = (diff.tv_sec * 1000 + diff.tv_usec / 1000.0);

    if (delta > 1000.0) {
      t_Counters.at(rec::Counter::tooOldDrops)++;
      return nullptr;
    }
  }

  ++t_Counters.at(rec::Counter::qcounter);

  if (fromaddr.sin4.sin_family == AF_INET6)
    t_Counters.at(rec::Counter::ipv6qcounter)++;

  string response;
  const dnsheader_aligned headerdata(question.data());
  const dnsheader* dh = headerdata.get();
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
  boost::uuids::uuid uniqueId;
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
    if (needECS || (t_pdl && (t_pdl->d_gettag || t_pdl->d_gettag_ffi)) || dh->opcode == Opcode::Notify) {
      try {
        EDNSOptionViewMap ednsOptions;

        ecsFound = false;

        getQNameAndSubnet(question, &qname, &qtype, &qclass,
                          ecsFound, &ednssubnet, g_gettagNeedsEDNSOptions ? &ednsOptions : nullptr);

        qnameParsed = true;
        ecsParsed = true;

        if (t_pdl) {
          try {
            if (t_pdl->d_gettag_ffi) {
              RecursorLua4::FFIParams params(qname, qtype, destination, source, ednssubnet.source, data, policyTags, records, ednsOptions, proxyProtocolValues, requestorId, deviceId, deviceName, routingTag, rcode, ttlCap, variable, false, logQuery, logResponse, followCNAMEs, extendedErrorCode, extendedErrorExtra, responsePaddingDisabled, meta);

              eventTrace.add(RecEventTrace::LuaGetTagFFI);
              ctag = t_pdl->gettag_ffi(params);
              eventTrace.add(RecEventTrace::LuaGetTagFFI, ctag, false);
            }
            else if (t_pdl->d_gettag) {
              eventTrace.add(RecEventTrace::LuaGetTag);
              ctag = t_pdl->gettag(source, ednssubnet.source, destination, qname, qtype, &policyTags, data, ednsOptions, false, requestorId, deviceId, deviceName, routingTag, proxyProtocolValues);
              eventTrace.add(RecEventTrace::LuaGetTag, ctag, false);
            }
          }
          catch (const std::exception& e) {
            if (g_logCommonErrors) {
              SLOG(g_log << Logger::Warning << "Error parsing a query packet qname='" << qname << "' for tag determination, setting tag=0: " << e.what() << endl,
                   g_slogudpin->error(Logr::Warning, e.what(), "Error parsing a query packet for tag determination, setting tag=0", "qname", Logging::Loggable(qname), "remote", Logging::Loggable(fromaddr), "exception", Logging::Loggable("std;:exception")));
            }
          }
        }
      }
      catch (const std::exception& e) {
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Warning << "Error parsing a query packet for tag determination, setting tag=0: " << e.what() << endl,
               g_slogudpin->error(Logr::Warning, e.what(), "Error parsing a query packet for tag determination, setting tag=0", "remote", Logging::Loggable(fromaddr), "exception", Logging::Loggable("std;:exception")));
        }
      }
    }

    RecursorPacketCache::OptPBData pbData{boost::none};
    if (t_protobufServers.servers) {
      if (logQuery && !(luaconfsLocal->protobufExportConfig.taggedOnly && policyTags.empty())) {
        protobufLogQuery(luaconfsLocal, uniqueId, source, destination, mappedSource, ednssubnet.source, false, dh->id, question.size(), qname, qtype, qclass, policyTags, requestorId, deviceId, deviceName, meta);
      }
    }

    if (ctag == 0 && !responsePaddingDisabled && g_paddingFrom.match(fromaddr)) {
      ctag = g_paddingTag;
    }

    if (dh->opcode == Opcode::Query) {
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
        struct msghdr msgh;
        struct iovec iov;
        cmsgbuf_aligned cbuf;
        fillMSGHdr(&msgh, &iov, &cbuf, 0, (char*)response.c_str(), response.length(), const_cast<ComboAddress*>(&fromaddr));
        msgh.msg_control = NULL;

        if (g_fromtosockets.count(fd)) {
          addCMsgSrcAddr(&msgh, &cbuf, &destaddr, 0);
        }
        int sendErr = sendOnNBSocket(fd, &msgh);
        eventTrace.add(RecEventTrace::AnswerSent);

        if (t_protobufServers.servers && logResponse && !(luaconfsLocal->protobufExportConfig.taggedOnly && pbData && !pbData->d_tagged)) {
          protobufLogResponse(dh, luaconfsLocal, pbData, tv, false, source, destination, mappedSource, ednssubnet, uniqueId, requestorId, deviceId, deviceName, meta, eventTrace);
        }

        if (eventTrace.enabled() && SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_log) {
          SLOG(g_log << Logger::Info << eventTrace.toString() << endl,
               g_slogudpin->info(Logr::Info, eventTrace.toString())); // Do we want more fancy logging here?
        }
        if (sendErr && g_logCommonErrors) {
          SLOG(g_log << Logger::Warning << "Sending UDP reply to client " << source.toStringWithPort()
                     << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << " failed with: "
                     << strerror(sendErr) << endl,
               g_slogudpin->error(Logr::Error, sendErr, "Sending UDP reply to client failed", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));
        }
        struct timeval now;
        Utility::gettimeofday(&now, nullptr);
        uint64_t spentUsec = uSec(now - tv);
        t_Counters.at(rec::Histogram::cumulativeAnswers)(spentUsec);
        t_Counters.updateSnap(g_regressionTestMode);
        return 0;
      }
    }
  }
  catch (const std::exception& e) {
    if (g_logCommonErrors) {
      SLOG(g_log << Logger::Error << "Error processing or aging answer packet: " << e.what() << endl,
           g_slogudpin->error(Logr::Error, e.what(), "Error processing or aging answer packet", "exception", Logging::Loggable("std::exception")));
    }
    return 0;
  }

  if (t_pdl) {
    bool ipf = t_pdl->ipfilter(source, destination, *dh, eventTrace);
    if (ipf) {
      if (!g_quiet) {
        SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " [" << MT->getTid() << "/" << MT->numProcesses() << "] DROPPED question from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << " based on policy" << endl,
             g_slogudpin->info(Logr::Notice, "Dropped question based on policy", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));
      }
      t_Counters.at(rec::Counter::policyDrops)++;
      return 0;
    }
  }

  if (dh->opcode == Opcode::Notify) {
    if (!isAllowNotifyForZone(qname)) {
      if (!g_quiet) {
        SLOG(g_log << Logger::Error << "[" << MT->getTid() << "] dropping UDP NOTIFY from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << ", for " << qname.toLogString() << ", zone not matched by allow-notify-for" << endl,
             g_slogudpin->info(Logr::Notice, "Dropping UDP NOTIFY, zone not matched by allow-notify-for", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));
      }

      t_Counters.at(rec::Counter::zoneDisallowedNotify)++;
      return 0;
    }

    if (!g_quiet) {
      SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " got NOTIFY for " << qname.toLogString() << " from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << endl,
           g_slogudpin->info(Logr::Notice, "Got NOTIFY", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr), "qname", Logging::Loggable(qname)));
    }

    requestWipeCaches(qname);

    // the operation will now be treated as a Query, generating
    // a normal response, as the rest of the code does not
    // check dh->opcode, but we need to ensure that the response
    // to this request does not get put into the packet cache
    variable = true;
  }

  if (MT->numProcesses() > g_maxMThreads) {
    if (!g_quiet)
      SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " [" << MT->getTid() << "/" << MT->numProcesses() << "] DROPPED question from " << source.toStringWithPort() << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << ", over capacity" << endl,
           g_slogudpin->info(Logr::Notice, "Dropped question, over capacity", "source", Logging::Loggable(source), "remote", Logging::Loggable(fromaddr)));

    t_Counters.at(rec::Counter::overCapacityDrops)++;
    return 0;
  }

  auto dc = std::make_unique<DNSComboWriter>(question, g_now, std::move(policyTags), t_pdl, std::move(data), std::move(records));

  dc->setSocket(fd);
  dc->d_tag = ctag;
  dc->d_qhash = qhash;
  dc->setRemote(fromaddr); // the address the query is coming from
  dc->setSource(source); // the address we assume the query is coming from, might be set by proxy protocol
  dc->setLocal(destaddr); // the address the query was received on
  dc->setDestination(destination); // the address we assume the query is sent to, might be set by proxy protocol
  dc->setMappedSource(mappedSource); // the address we assume the query is coming from. Differs from source if table-based mapping has been applied
  dc->d_tcp = false;
  dc->d_ecsFound = ecsFound;
  dc->d_ecsParsed = ecsParsed;
  dc->d_ednssubnet = ednssubnet;
  dc->d_ttlCap = ttlCap;
  dc->d_variable = variable;
  dc->d_followCNAMERecords = followCNAMEs;
  dc->d_rcode = rcode;
  dc->d_logResponse = logResponse;
  if (t_protobufServers.servers || t_outgoingProtobufServers.servers) {
    dc->d_uuid = std::move(uniqueId);
  }
  dc->d_requestorId = requestorId;
  dc->d_deviceId = deviceId;
  dc->d_deviceName = deviceName;
  dc->d_kernelTimestamp = tv;
  dc->d_proxyProtocolValues = std::move(proxyProtocolValues);
  dc->d_routingTag = std::move(routingTag);
  dc->d_extendedErrorCode = extendedErrorCode;
  dc->d_extendedErrorExtra = std::move(extendedErrorExtra);
  dc->d_responsePaddingDisabled = responsePaddingDisabled;
  dc->d_meta = std::move(meta);

  dc->d_eventTrace = std::move(eventTrace);
  MT->makeThread(startDoResolve, (void*)dc.release()); // deletes dc

  return 0;
}

static void handleNewUDPQuestion(int fd, FDMultiplexer::funcparam_t& /* var */)
{
  ssize_t len;
  static const size_t maxIncomingQuerySize = g_proxyProtocolACL.empty() ? 512 : (512 + g_proxyProtocolMaximumSize);
  static thread_local std::string data;
  ComboAddress fromaddr; // the address the query is coming from
  ComboAddress source; // the address we assume the query is coming from, might be set by proxy protocol
  ComboAddress destination; // the address we assume the query was sent to, might be set by proxy protocol
  struct msghdr msgh;
  struct iovec iov;
  cmsgbuf_aligned cbuf;
  bool firstQuery = true;
  std::vector<ProxyProtocolValue> proxyProtocolValues;
  RecEventTrace eventTrace;

  for (size_t queriesCounter = 0; queriesCounter < g_maxUDPQueriesPerRound; queriesCounter++) {
    bool proxyProto = false;
    proxyProtocolValues.clear();
    data.resize(maxIncomingQuerySize);
    fromaddr.sin6.sin6_family = AF_INET6; // this makes sure fromaddr is big enough
    fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), &data[0], data.size(), &fromaddr);

    if ((len = recvmsg(fd, &msgh, 0)) >= 0) {
      eventTrace.clear();
      eventTrace.setEnabled(SyncRes::s_event_trace_enabled);
      eventTrace.add(RecEventTrace::ReqRecv);

      firstQuery = false;

      if (msgh.msg_flags & MSG_TRUNC) {
        t_Counters.at(rec::Counter::truncatedDrops)++;
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "Ignoring truncated query from " << fromaddr.toString() << endl,
               g_slogudpin->info(Logr::Error, "Ignoring truncated query", "remote", Logging::Loggable(fromaddr)));
        }
        return;
      }

      data.resize(static_cast<size_t>(len));

      if (expectProxyProtocol(fromaddr)) {
        bool tcp;
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
        else if (static_cast<size_t>(used) > g_proxyProtocolMaximumSize) {
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
        if (auto it = t_proxyMapping->lookup(source)) {
          mappedSource = it->second.address;
          ++it->second.stats.netmaskMatches;
        }
      }
      if (t_remotes) {
        t_remotes->push_back(fromaddr);
      }

      if (t_allowFrom && !t_allowFrom->match(&mappedSource)) {
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "[" << MT->getTid() << "] dropping UDP query from " << mappedSource.toString() << ", address not matched by allow-from" << endl,
               g_slogudpin->info(Logr::Error, "Dropping UDP query, address not matched by allow-from", "source", Logging::Loggable(mappedSource)));
        }

        t_Counters.at(rec::Counter::unauthorizedUDP)++;
        return;
      }

      BOOST_STATIC_ASSERT(offsetof(sockaddr_in, sin_port) == offsetof(sockaddr_in6, sin6_port));
      if (!fromaddr.sin4.sin_port) { // also works for IPv6
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "[" << MT->getTid() << "] dropping UDP query from " << fromaddr.toStringWithPort() << ", can't deal with port 0" << endl,
               g_slogudpin->info(Logr::Error, "Dropping UDP query can't deal with port 0", "remote", Logging::Loggable(fromaddr)));
        }

        t_Counters.at(rec::Counter::clientParseError)++; // not quite the best place to put it, but needs to go somewhere
        return;
      }

      try {
        const dnsheader_aligned headerdata(data.data());
        const dnsheader* dh = headerdata.get();

        if (dh->qr) {
          t_Counters.at(rec::Counter::ignoredCount)++;
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Error << "Ignoring answer from " << fromaddr.toString() << " on server socket!" << endl,
                 g_slogudpin->info(Logr::Error, "Ignoring answer on server socket", "remote", Logging::Loggable(fromaddr)));
          }
        }
        else if (dh->opcode != Opcode::Query && dh->opcode != Opcode::Notify) {
          t_Counters.at(rec::Counter::ignoredCount)++;
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Error << "Ignoring unsupported opcode " << Opcode::to_s(dh->opcode) << " from " << fromaddr.toString() << " on server socket!" << endl,
                 g_slogudpin->info(Logr::Error, "Ignoring unsupported opcode server socket", "remote", Logging::Loggable(fromaddr), "opcode", Logging::Loggable(Opcode::to_s(dh->opcode))));
          }
        }
        else if (dh->qdcount == 0) {
          t_Counters.at(rec::Counter::emptyQueriesCount)++;
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Error << "Ignoring empty (qdcount == 0) query from " << fromaddr.toString() << " on server socket!" << endl,
                 g_slogudpin->info(Logr::Error, "Ignoring empty (qdcount == 0) query on server socket!", "remote", Logging::Loggable(fromaddr)));
          }
        }
        else {
          if (dh->opcode == Opcode::Notify) {
            if (!t_allowNotifyFrom || !t_allowNotifyFrom->match(&mappedSource)) {
              if (!g_quiet) {
                SLOG(g_log << Logger::Error << "[" << MT->getTid() << "] dropping UDP NOTIFY from " << mappedSource.toString() << ", address not matched by allow-notify-from" << endl,
                     g_slogudpin->info(Logr::Error, "Dropping UDP NOTIFY from address not matched by allow-notify-from",
                                       "source", Logging::Loggable(mappedSource)));
              }

              t_Counters.at(rec::Counter::sourceDisallowedNotify)++;
              return;
            }
          }

          struct timeval tv = {0, 0};
          HarvestTimestamp(&msgh, &tv);
          ComboAddress dest; // the address the query was sent to to
          dest.reset(); // this makes sure we ignore this address if not returned by recvmsg above
          auto loc = rplookup(g_listenSocketsAddresses, fd);
          if (HarvestDestinationAddress(&msgh, &dest)) {
            // but.. need to get port too
            if (loc) {
              dest.sin4.sin_port = loc->sin4.sin_port;
            }
          }
          else {
            if (loc) {
              dest = *loc;
            }
            else {
              dest.sin4.sin_family = fromaddr.sin4.sin_family;
              socklen_t slen = dest.getSocklen();
              getsockname(fd, (sockaddr*)&dest, &slen); // if this fails, we're ok with it
            }
          }
          if (!proxyProto) {
            destination = dest;
          }

          if (RecThreadInfo::weDistributeQueries()) {
            std::string localdata = data;
            distributeAsyncFunction(data, [localdata, fromaddr, dest, source, destination, mappedSource, tv, fd, proxyProtocolValues, eventTrace]() mutable {
              return doProcessUDPQuestion(localdata, fromaddr, dest, source, destination, mappedSource, tv, fd, proxyProtocolValues, eventTrace);
            });
          }
          else {
            doProcessUDPQuestion(data, fromaddr, dest, source, destination, mappedSource, tv, fd, proxyProtocolValues, eventTrace);
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
      // cerr<<t_id<<" had error: "<<stringerror()<<endl;
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
        if (!setsockopt(socketFd, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one))) { // linux supports this, so why not - might fail on other systems
          g_fromtosockets.insert(socketFd);
        }
      }
#ifdef IPV6_RECVPKTINFO
      if (address.sin4.sin_family == AF_INET6) {
        if (!setsockopt(socketFd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one))) {
          g_fromtosockets.insert(socketFd);
        }
      }
#endif
      if (address.sin6.sin6_family == AF_INET6 && setsockopt(socketFd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0) {
        int err = errno;
        SLOG(g_log << Logger::Error << "Failed to set IPv6 socket to IPv6 only, continuing anyhow: " << strerror(err) << endl,
             log->error(Logr::Error, "Failed to set IPv6 socket to IPv6 only, continuing anyhow"));
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
    if (::bind(socketFd, (struct sockaddr*)&address, socklen) < 0) {
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

  const auto& tps = targetInfo.pipes;

  ssize_t written = write(tps.writeQueriesToThread, &tmsg, sizeof(tmsg));
  if (written > 0) {
    if (static_cast<size_t>(written) != sizeof(tmsg)) {
      delete tmsg;
      unixDie("write to thread pipe returned wrong size or error");
    }
  }
  else {
    int error = errno;
    if (error == EAGAIN || error == EWOULDBLOCK) {
      return false;
    }
    else {
      delete tmsg;
      unixDie("write to thread pipe returned wrong size or error:" + std::to_string(error));
    }
  }

  return true;
}

static unsigned int getWorkerLoad(size_t workerIdx)
{
  const auto mt = RecThreadInfo::info(RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + workerIdx).mt;
  if (mt != nullptr) {
    return mt->numProcesses();
  }
  return 0;
}

static unsigned int selectWorker(unsigned int hash)
{
  assert(RecThreadInfo::numWorkers() != 0);
  if (g_balancingFactor == 0) {
    return RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + (hash % RecThreadInfo::numWorkers());
  }

  /* we start with one, representing the query we are currently handling */
  double currentLoad = 1;
  std::vector<unsigned int> load(RecThreadInfo::numWorkers());
  for (size_t idx = 0; idx < RecThreadInfo::numWorkers(); idx++) {
    load[idx] = getWorkerLoad(idx);
    currentLoad += load[idx];
  }

  double targetLoad = (currentLoad / RecThreadInfo::numWorkers()) * g_balancingFactor;

  unsigned int worker = hash % RecThreadInfo::numWorkers();
  /* at least one server has to be at or below the average load */
  if (load[worker] > targetLoad) {
    ++t_Counters.at(rec::Counter::rebalancedQueries);
    do {
      worker = (worker + 1) % RecThreadInfo::numWorkers();
    } while (load[worker] > targetLoad);
  }

  return RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + worker;
}

// This function is only called by the distributor threads, when pdns-distributes-queries is set
void distributeAsyncFunction(const string& packet, const pipefunc_t& func)
{
  if (!RecThreadInfo::self().isDistributor()) {
    SLOG(g_log << Logger::Error << "distributeAsyncFunction() has been called by a worker (" << RecThreadInfo::id() << ")" << endl,
         g_slog->info(Logr::Error, "distributeAsyncFunction() has been called by a worker")); // tid will be added
    _exit(1);
  }

  bool ok;
  unsigned int hash = hashQuestion(reinterpret_cast<const uint8_t*>(packet.data()), packet.length(), g_disthashseed, ok);
  if (!ok) {
    // hashQuestion does detect invalid names, so we might as well punt here instead of in the worker thread
    t_Counters.at(rec::Counter::ignoredCount)++;
    throw MOADNSException("too-short (" + std::to_string(packet.length()) + ") or invalid name");
  }
  unsigned int target = selectWorker(hash);

  ThreadMSG* tmsg = new ThreadMSG();
  tmsg->func = func;
  tmsg->wantAnswer = false;

  if (!trySendingQueryToWorker(target, tmsg)) {
    /* if this function failed but did not raise an exception, it means that the pipe
       was full, let's try another one */
    unsigned int newTarget = 0;
    do {
      newTarget = RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + dns_random(RecThreadInfo::numWorkers());
    } while (newTarget == target);

    if (!trySendingQueryToWorker(newTarget, tmsg)) {
      t_Counters.at(rec::Counter::queryPipeFullDrops)++;
      delete tmsg;
    }
  }
  // coverity[leaked_storage]
}

// resend event to everybody chained onto it
static void doResends(MT_t::waiters_t::iterator& iter, const std::shared_ptr<PacketID>& resend, const PacketBuffer& content)
{
  // We close the chain for new entries, since they won't be processed anyway
  iter->key->closed = true;

  if (iter->key->chain.empty())
    return;
  for (PacketID::chain_t::iterator i = iter->key->chain.begin(); i != iter->key->chain.end(); ++i) {
    auto r = std::make_shared<PacketID>(*resend);
    r->fd = -1;
    r->id = *i;
    MT->sendEvent(r, &content);
    t_Counters.at(rec::Counter::chainResends)++;
  }
}

static void handleUDPServerResponse(int fd, FDMultiplexer::funcparam_t& var)
{
  std::shared_ptr<PacketID> pid = boost::any_cast<std::shared_ptr<PacketID>>(var);
  PacketBuffer packet;
  packet.resize(g_outgoingEDNSBufsize);
  ComboAddress fromaddr;
  socklen_t addrlen = sizeof(fromaddr);

  ssize_t len = recvfrom(fd, &packet.at(0), packet.size(), 0, reinterpret_cast<sockaddr*>(&fromaddr), &addrlen);

  const ssize_t signed_sizeof_sdnsheader = sizeof(dnsheader);

  if (len < 0) {
    // len < 0: error on socket
    t_udpclientsocks->returnSocket(fd);

    PacketBuffer empty;
    MT_t::waiters_t::iterator iter = MT->d_waiters.find(pid);
    if (iter != MT->d_waiters.end()) {
      doResends(iter, pid, empty);
    }
    MT->sendEvent(pid, &empty); // this denotes error (does retry lookup using other NS)
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
  dnsheader dh;
  memcpy(&dh, &packet.at(0), sizeof(dh));

  auto pident = std::make_shared<PacketID>();
  pident->remote = fromaddr;
  pident->id = dh.id;
  pident->fd = fd;

  if (!dh.qr && g_logCommonErrors) {
    SLOG(g_log << Logger::Notice << "Not taking data from question on outgoing socket from " << fromaddr.toStringWithPort() << endl,
         g_slogout->info(Logr::Error, "Not taking data from question on outgoing socket", "from", Logging::Loggable(fromaddr)));
  }

  if (!dh.qdcount || // UPC, Nominum, very old BIND on FormErr, NSD
      !dh.qr) { // one weird server
    pident->domain.clear();
    pident->type = 0;
  }
  else {
    try {
      if (len > signed_sizeof_sdnsheader) {
        pident->domain = DNSName(reinterpret_cast<const char*>(packet.data()), len, static_cast<int>(sizeof(dnsheader)), false, &pident->type); // don't copy this from above - we need to do the actual read
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
    MT_t::waiters_t::iterator iter = MT->d_waiters.find(pident);
    if (iter != MT->d_waiters.end()) {
      doResends(iter, pident, packet);
    }
  }

retryWithName:

  if (pident->domain.empty() || MT->sendEvent(pident, &packet) == 0) {
    /* we did not find a match for this response, something is wrong */

    // we do a full scan for outstanding queries on unexpected answers. not too bad since we only accept them on the right port number, which is hard enough to guess
    for (MT_t::waiters_t::iterator mthread = MT->d_waiters.begin(); mthread != MT->d_waiters.end(); ++mthread) {
      if (pident->fd == mthread->key->fd && mthread->key->remote == pident->remote && mthread->key->type == pident->type && pident->domain == mthread->key->domain) {
        /* we are expecting an answer from that exact source, on that exact port (since we are using connected sockets), for that qname/qtype,
           but with a different message ID. That smells like a spoofing attempt. For now we will just increase the counter and will deal with
           that later. */
        mthread->key->nearMisses++;
      }

      // be a bit paranoid here since we're weakening our matching
      if (pident->domain.empty() && !mthread->key->domain.empty() && !pident->type && mthread->key->type && pident->id == mthread->key->id && mthread->key->remote == pident->remote) {
        // cerr<<"Empty response, rest matches though, sending to a waiter"<<endl;
        pident->domain = mthread->key->domain;
        pident->type = mthread->key->type;
        goto retryWithName; // note that this only passes on an error, lwres will still reject the packet
      }
    }
    t_Counters.at(rec::Counter::unexpectedCount)++; // if we made it here, it really is an unexpected answer
    if (g_logCommonErrors) {
      SLOG(g_log << Logger::Warning << "Discarding unexpected packet from " << fromaddr.toStringWithPort() << ": " << (pident->domain.empty() ? "<empty>" : pident->domain.toString()) << ", " << pident->type << ", " << MT->d_waiters.size() << " waiters" << endl,
           g_slogudpin->info(Logr::Warning, "Discarding unexpected packet", "from", Logging::Loggable(fromaddr),
                             "qname", Logging::Loggable(pident->domain),
                             "qtype", Logging::Loggable(QType(pident->type)),
                             "waiters", Logging::Loggable(MT->d_waiters.size())));
    }
  }
  else if (fd >= 0) {
    /* we either found a waiter (1) or encountered an issue (-1), it's up to us to clean the socket anyway */
    t_udpclientsocks->returnSocket(fd);
  }
}
