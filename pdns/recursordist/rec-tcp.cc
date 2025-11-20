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
#include "logger.hh"
#include "mplexer.hh"
#include "uuid-utils.hh"

// OLD PRE 5.0.0 situation:
//
// When pdns-distributes-queries is false with reuseport true (the default since 4.9.0), TCP queries
// are read and handled by worker threads. If the kernel balancing is OK for TCP sockets (observed
// to be good on Debian bullseye, but not good on e.g. MacOS), the TCP handling is no extra burden.
// In the case of MacOS all incoming TCP queries are handled by a single worker, while incoming UDP
// queries do get distributed round-robin over the worker threads.  Do note the TCP queries might
// need to wait until the g_maxUDPQueriesPerRound is reached.
//
// In the case of pdns-distributes-queries true and reuseport false the queries were read and
// initially processed by the distributor thread(s).
//
// Initial processing consist of parsing, calling gettag and checking if we have a packet cache
// hit. If that does not produce a hit, the query is passed to an mthread in the same way as with
// UDP queries, but do note that the mthread processing is serviced by the distributor thread. The
// final answer will be sent by the same distributor thread that originally picked up the query.
//
// Changing this, and having incoming TCP queries handled by worker threads is somewhat more complex
// than UDP, as the socket must remain available in the distributor thread (for reading more
// queries), but the TCP socket must also be passed to a worker thread so it can write its
// answer. The in-flight bookkeeping also has to be aware of how a query is handled to do the
// accounting properly. I am not sure if changing the current setup is worth all this trouble,
// especially since the default is now to not use pdns-distributes-queries, which works well in many
// cases.
//
// NEW SITUATION SINCE 5.0.0:
//
// The drawback mentioned in https://github.com/PowerDNS/pdns/issues/8394 are not longer true, so an
// alternative approach would be to introduce dedicated TCP worker thread(s).
//
// This approach was implemented in https://github.com/PowerDNS/pdns/pull/13195. The distributor and
// worker thread(s) now no longer process TCP queries.

size_t g_tcpMaxQueriesPerConn;
unsigned int g_maxTCPClients;
unsigned int g_maxTCPPerClient;
int g_tcpTimeout;
bool g_anyToTcp;

uint16_t TCPConnection::s_maxInFlight;

using tcpClientCounts_t = map<ComboAddress, uint32_t, ComboAddress::addressOnlyLessThan>;
static thread_local std::unique_ptr<tcpClientCounts_t> t_tcpClientCounts = std::make_unique<tcpClientCounts_t>();

static void handleRunningTCPQuestion(int fileDesc, FDMultiplexer::funcparam_t& var);

#if 0
#define TCPLOG(tcpsock, x)                                 \
  do {                                                     \
    cerr << []() { timeval t; gettimeofday(&t, nullptr); return t.tv_sec % 10  + t.tv_usec/1000000.0; }() << " FD " << (tcpsock) << ' ' << x; \
  } while (0)
#else
// We do not define this as empty since that produces a duplicate case label warning from clang-tidy
#define TCPLOG(pid, x) /* NOLINT(cppcoreguidelines-macro-usage) */ \
  while (false) {                                                  \
    cerr << x; /* NOLINT(bugprone-macro-parentheses) */            \
  }
#endif

std::atomic<uint32_t> TCPConnection::s_currentConnections;

TCPConnection::TCPConnection(int fileDesc, const ComboAddress& addr) :
  data(2, 0), d_remote(addr), d_fd(fileDesc)
{
  ++s_currentConnections;
  (*t_tcpClientCounts)[d_remote]++;
}

TCPConnection::~TCPConnection()
{
  try {
    if (closesocket(d_fd) < 0) {
      g_slogtcpin->info(Logr::Error, "Error closing socket for TCPConnection");
    }
  }
  catch (const PDNSException& e) {
    g_slogtcpin->error(Logr::Error, e.reason, "Error closing TCPConnection socket", "exception", Logging::Loggable("PDNSException"));
  }

  if (t_tcpClientCounts && t_tcpClientCounts->count(d_remote) != 0 && (*t_tcpClientCounts)[d_remote]-- == 0) {
    t_tcpClientCounts->erase(d_remote);
  }
  --s_currentConnections;
}

static void terminateTCPConnection(int fileDesc)
{
  try {
    t_fdm->removeReadFD(fileDesc);
  }
  catch (const FDMultiplexerException& fde) {
  }
}

static void sendErrorOverTCP(std::unique_ptr<DNSComboWriter>& comboWriter, int rcode)
{
  std::vector<uint8_t> packet;
  if (comboWriter->d_mdp.d_header.qdcount == 0U) {
    /* header-only */
    packet.resize(sizeof(dnsheader));
  }
  else {
    DNSPacketWriter packetWriter(packet, comboWriter->d_mdp.d_qname, comboWriter->d_mdp.d_qtype, comboWriter->d_mdp.d_qclass);
    if (comboWriter->d_mdp.hasEDNS()) {
      /* we try to add the EDNS OPT RR even for truncated answers,
         as rfc6891 states:
         "The minimal response MUST be the DNS header, question section, and an
         OPT record.  This MUST also occur when a truncated response (using
         the DNS header's TC bit) is returned."
      */
      packetWriter.addOpt(512, 0, 0);
      packetWriter.commit();
    }
  }

  auto& header = reinterpret_cast<dnsheader&>(packet.at(0)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) safe cast
  header.aa = 0;
  header.ra = 1;
  header.qr = 1;
  header.tc = 0;
  header.id = comboWriter->d_mdp.d_header.id;
  header.rd = comboWriter->d_mdp.d_header.rd;
  header.cd = comboWriter->d_mdp.d_header.cd;
  header.rcode = rcode;

  sendResponseOverTCP(comboWriter, packet);
}

void finishTCPReply(std::unique_ptr<DNSComboWriter>& comboWriter, bool hadError, bool updateInFlight)
{
  // update tcp connection status, closing if needed and doing the fd multiplexer accounting
  if (updateInFlight && comboWriter->d_tcpConnection->d_requestsInFlight > 0) {
    comboWriter->d_tcpConnection->d_requestsInFlight--;
  }

  // In the code below, we try to remove the fd from the set, but
  // we don't know if another mthread already did the remove, so we can get a
  // "Tried to remove unlisted fd" exception.  Not that an inflight < limit test
  // will not work since we do not know if the other mthread got an error or not.
  if (hadError) {
    terminateTCPConnection(comboWriter->d_socket);
    comboWriter->d_socket = -1;
    return;
  }
  comboWriter->d_tcpConnection->queriesCount++;
  if ((g_tcpMaxQueriesPerConn > 0 && comboWriter->d_tcpConnection->queriesCount >= g_tcpMaxQueriesPerConn) || (comboWriter->d_tcpConnection->isDropOnIdle() && comboWriter->d_tcpConnection->d_requestsInFlight == 0)) {
    try {
      t_fdm->removeReadFD(comboWriter->d_socket);
    }
    catch (FDMultiplexerException&) {
    }
    comboWriter->d_socket = -1;
    return;
  }

  Utility::gettimeofday(&g_now, nullptr); // needs to be updated
  struct timeval ttd = g_now;

  // If we cross from max to max-1 in flight requests, the fd was not listened to, add it back
  if (updateInFlight && comboWriter->d_tcpConnection->d_requestsInFlight == TCPConnection::s_maxInFlight - 1) {
    // A read error might have happened. If we add the fd back, it will most likely error again.
    // This is not a big issue, the next handleTCPClientReadable() will see another read error
    // and take action.
    ttd.tv_sec += g_tcpTimeout;
    t_fdm->addReadFD(comboWriter->d_socket, handleRunningTCPQuestion, comboWriter->d_tcpConnection, &ttd);
    return;
  }
  // fd might have been removed by read error code, or a read timeout, so expect an exception
  try {
    t_fdm->setReadTTD(comboWriter->d_socket, ttd, g_tcpTimeout);
  }
  catch (const FDMultiplexerException&) {
    // but if the FD was removed because of a timeout while we were sending a response,
    // we need to re-arm it. If it was an error it will error again.
    ttd.tv_sec += g_tcpTimeout;
    t_fdm->addReadFD(comboWriter->d_socket, handleRunningTCPQuestion, comboWriter->d_tcpConnection, &ttd);
  }
}

/*
 * A helper class that by default closes the incoming TCP connection on destruct
 * If you want to keep the connection alive, call keep() on the guard object
 */
class RunningTCPQuestionGuard
{
public:
  RunningTCPQuestionGuard(const RunningTCPQuestionGuard&) = default;
  RunningTCPQuestionGuard(RunningTCPQuestionGuard&&) = delete;
  RunningTCPQuestionGuard& operator=(const RunningTCPQuestionGuard&) = default;
  RunningTCPQuestionGuard& operator=(RunningTCPQuestionGuard&&) = delete;
  RunningTCPQuestionGuard(int fileDesc) :
    d_fd(fileDesc) {}
  ~RunningTCPQuestionGuard()
  {
    if (d_fd != -1) {
      terminateTCPConnection(d_fd);
      d_fd = -1;
    }
  }
  void keep()
  {
    d_fd = -1;
  }
  bool handleTCPReadResult(int /* fd */, ssize_t bytes)
  {
    if (bytes == 0) {
      /* EOF */
      return false;
    }
    if (bytes < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        return false;
      }
    }
    keep();
    return true;
  }

private:
  int d_fd{-1};
};

static void handleNotify(std::unique_ptr<DNSComboWriter>& comboWriter, const DNSName& qname)
{
  if (!t_allowNotifyFrom || !t_allowNotifyFrom->match(comboWriter->d_mappedSource)) {
    if (!g_quiet) {
      g_slogtcpin->info(Logr::Error, "Dropping TCP NOTIFY, address not matched by allow-notify-from", "source", Logging::Loggable(comboWriter->d_mappedSource));
    }

    t_Counters.at(rec::Counter::sourceDisallowedNotify)++;
    return;
  }

  if (!isAllowNotifyForZone(qname)) {
    if (!g_quiet) {
      g_slogtcpin->info(Logr::Error, "Dropping TCP NOTIFY,  zone not matched by allow-notify-for", "source", Logging::Loggable(comboWriter->d_mappedSource), "zone", Logging::Loggable(qname));
    }

    t_Counters.at(rec::Counter::zoneDisallowedNotify)++;
    return;
  }
}

static void doProtobufLogQuery(bool logQuery, LocalStateHolder<LuaConfigItems>& luaconfsLocal, const std::unique_ptr<DNSComboWriter>& comboWriter, const DNSName& qname, QType qtype, QClass qclass, const dnsheader* dnsheader, const shared_ptr<TCPConnection>& conn, const boost::optional<uint32_t>& ednsVersion)
{
  try {
    if (logQuery && !(luaconfsLocal->protobufExportConfig.taggedOnly && comboWriter->d_policyTags.empty())) {
      protobufLogQuery(luaconfsLocal, comboWriter->d_uuid, comboWriter->d_source, comboWriter->d_destination, comboWriter->d_mappedSource, comboWriter->d_ednssubnet.getSource(), true, conn->qlen, qname, qtype, qclass, comboWriter->d_policyTags, comboWriter->d_requestorId, comboWriter->d_deviceId, comboWriter->d_deviceName, comboWriter->d_meta, ednsVersion, *dnsheader, comboWriter->d_otTrace.trace_id);
    }
  }
  catch (const std::exception& e) {
    if (g_logCommonErrors) {
      g_slogtcpin->error(Logr::Warning, e.what(), "Error parsing a TCP query packet for edns subnet", "exception", Logging::Loggable("std::exception"), "remote", Logging::Loggable(conn->d_remote));
    }
  }
}

static void doProcessTCPQuestion(std::unique_ptr<DNSComboWriter>& comboWriter, shared_ptr<TCPConnection>& conn, RunningTCPQuestionGuard& tcpGuard, int fileDesc) // NOLINT(readability-function-cognitive-complexity) will fix one day
{
  RecThreadInfo::self().incNumberOfDistributedQueries();
  struct timeval start{};
  Utility::gettimeofday(&start, nullptr);

  DNSName qname;
  uint16_t qtype = 0;
  uint16_t qclass = 0;
  bool needEDNSParse = false;
  string requestorId;
  string deviceId;
  string deviceName;
  bool logQuery = false;
  bool qnameParsed = false;
  boost::optional<uint32_t> ednsVersion;

  comboWriter->d_eventTrace.setEnabled(SyncRes::s_event_trace_enabled != 0);
  if (comboWriter->d_eventTrace.enabled() && !matchOTConditions(t_OTConditions, comboWriter->d_mappedSource) && SyncRes::eventTraceEnabledOnly(SyncRes::event_trace_to_ot)) {
    comboWriter->d_eventTrace.setEnabled(false);
  }

  // eventTrace uses monotonic time, while OpenTelemetry uses absolute time. setEnabled()
  // established the reference point, get an absolute TS as close as possible to the
  // eventTrace start of trace time.
  auto traceTS = pdns::trace::timestamp();
  comboWriter->d_eventTrace.add(RecEventTrace::ReqRecv);
  if (SyncRes::eventTraceEnabled(SyncRes::event_trace_to_ot)) {
    comboWriter->d_otTrace.clear();
    comboWriter->d_otTrace.start_time_unix_nano = traceTS;
  }
  auto newParent = comboWriter->d_eventTrace.add(RecEventTrace::ProcessTCP);
  auto oldParent = comboWriter->d_eventTrace.setParent(newParent);
  RecEventTrace::EventScope traceScope(oldParent, comboWriter->d_eventTrace);

  auto luaconfsLocal = g_luaconfs.getLocal();
  if (checkProtobufExport(luaconfsLocal)) {
    needEDNSParse = true;
  }
  logQuery = t_protobufServers.servers && luaconfsLocal->protobufExportConfig.logQueries;
  comboWriter->d_logResponse = t_protobufServers.servers && luaconfsLocal->protobufExportConfig.logResponses;

  if (needEDNSParse || (t_pdl && (t_pdl->hasGettagFFIFunc() || t_pdl->hasGettagFunc())) || comboWriter->d_mdp.d_header.opcode == static_cast<unsigned>(Opcode::Notify)) {

    try {
      auto parseMatch = comboWriter->d_eventTrace.add(RecEventTrace::PacketParse);
      EDNSOptionViewMap ednsOptions;
      comboWriter->d_ecsParsed = true;
      comboWriter->d_ecsFound = false;
      getQNameAndSubnet(conn->data, &qname, &qtype, &qclass,
                        comboWriter->d_ecsFound, &comboWriter->d_ednssubnet,
                        (g_gettagNeedsEDNSOptions || SyncRes::eventTraceEnabled(SyncRes::event_trace_to_ot)) ? &ednsOptions : nullptr, ednsVersion);
      comboWriter->d_eventTrace.add(RecEventTrace::PacketParse, 0, false, parseMatch);
      qnameParsed = true;

      if (SyncRes::eventTraceEnabled(SyncRes::event_trace_to_ot)) {
        bool ednsFound = pdns::trace::extractOTraceIDs(ednsOptions, EDNSOptionCode::OTTRACEIDS, comboWriter->d_otTrace);
        if (SyncRes::eventTraceEnabledOnly(SyncRes::event_trace_to_ot) && !matchOTConditions(comboWriter->d_eventTrace, t_OTConditions, comboWriter->d_mappedSource, qname, qtype, ntohs(comboWriter->d_mdp.d_header.id), ednsFound)) {
          comboWriter->d_eventTrace.setEnabled(false);
        }
      }
      if (t_pdl) {
        try {
          if (t_pdl->hasGettagFFIFunc()) {
            RecursorLua4::FFIParams params(qname, qtype, comboWriter->d_local, comboWriter->d_remote, comboWriter->d_destination, comboWriter->d_source, comboWriter->d_ednssubnet.getSource(), comboWriter->d_data, comboWriter->d_gettagPolicyTags, comboWriter->d_records, ednsOptions, comboWriter->d_proxyProtocolValues, requestorId, deviceId, deviceName, comboWriter->d_routingTag, comboWriter->d_rcode, comboWriter->d_ttlCap, comboWriter->d_variable, true, logQuery, comboWriter->d_logResponse, comboWriter->d_followCNAMERecords, comboWriter->d_extendedErrorCode, comboWriter->d_extendedErrorExtra, comboWriter->d_responsePaddingDisabled, comboWriter->d_meta);
            auto match = comboWriter->d_eventTrace.add(RecEventTrace::LuaGetTagFFI);
            comboWriter->d_tag = t_pdl->gettag_ffi(params);
            comboWriter->d_eventTrace.add(RecEventTrace::LuaGetTagFFI, comboWriter->d_tag, false, match);
          }
          else if (t_pdl->hasGettagFunc()) {
            auto match = comboWriter->d_eventTrace.add(RecEventTrace::LuaGetTag);
            comboWriter->d_tag = t_pdl->gettag(comboWriter->d_source, comboWriter->d_ednssubnet.getSource(), comboWriter->d_destination, qname, qtype, &comboWriter->d_gettagPolicyTags, comboWriter->d_data, ednsOptions, true, requestorId, deviceId, deviceName, comboWriter->d_routingTag, comboWriter->d_proxyProtocolValues);
            comboWriter->d_eventTrace.add(RecEventTrace::LuaGetTag, comboWriter->d_tag, false, match);
          }
          // Copy d_gettagPolicyTags to d_policyTags, so other Lua hooks see them and can add their
          // own. Before storing into the packetcache, the tags in d_gettagPolicyTags will be
          // cleared by addPolicyTagsToPBMessageIfNeeded() so they do *not* end up in the PC. When an
          // Protobuf message is constructed, one part comes from the PC (including the tags
          // set by non-gettag hooks), and the tags in d_gettagPolicyTags will be added by the code
          // constructing the PB message.
          comboWriter->d_policyTags = comboWriter->d_gettagPolicyTags;
        }
        catch (const MOADNSException& moadnsexception) {
          if (g_logCommonErrors) {
            g_slogtcpin->error(moadnsexception.what(), "Error parsing a query packet for tag determination", "qname", Logging::Loggable(qname), "exception", Logging::Loggable("MOADNSException"));
          }
        }
        catch (const std::exception& stdException) {
          g_rateLimitedLogger.log(g_slogtcpin, "Error parsing a query packet for tag determination", stdException, "qname", Logging::Loggable(qname), "remote", Logging::Loggable(conn->d_remote));
        }
      }
    }
    catch (const std::exception& stdException) {
      g_rateLimitedLogger.log(g_slogudpin, "Error parsing a query packet for tag determination, setting tag=0", stdException, "remote", Logging::Loggable(conn->d_remote));
    }
  }

  if (comboWriter->d_tag == 0 && !comboWriter->d_responsePaddingDisabled && g_paddingFrom.match(comboWriter->d_remote)) {
    comboWriter->d_tag = g_paddingTag;
  }

  const dnsheader_aligned headerdata(conn->data.data());
  const struct dnsheader* dnsheader = headerdata.get();

  if (t_protobufServers.servers || t_outgoingProtobufServers.servers) {
    comboWriter->d_requestorId = std::move(requestorId);
    comboWriter->d_deviceId = std::move(deviceId);
    comboWriter->d_deviceName = std::move(deviceName);
    comboWriter->d_uuid = getUniqueID();
  }

  if (t_protobufServers.servers) {
    doProtobufLogQuery(logQuery, luaconfsLocal, comboWriter, qname, qtype, qclass, dnsheader, conn, ednsVersion);
  }

  if (t_pdl) {
    bool ipf = t_pdl->ipfilter(comboWriter->d_source, comboWriter->d_destination, *dnsheader, comboWriter->d_eventTrace);
    if (ipf) {
      if (!g_quiet) {
        g_slogtcpin->info(Logr::Info, "Dropped TCP question based on policy", "remote", Logging::Loggable(conn->d_remote), "source", Logging::Loggable(comboWriter->d_source));
      }
      t_Counters.at(rec::Counter::policyDrops)++;
      return;
    }
  }

  if (comboWriter->d_mdp.d_header.qr) {
    t_Counters.at(rec::Counter::ignoredCount)++;
    if (g_logCommonErrors) {
      g_slogtcpin->info(Logr::Error, "Ignoring answer from TCP client on server socket", "remote", Logging::Loggable(comboWriter->getRemote()));
    }
    return;
  }
  if (comboWriter->d_mdp.d_header.opcode != static_cast<unsigned>(Opcode::Query) && comboWriter->d_mdp.d_header.opcode != static_cast<unsigned>(Opcode::Notify)) {
    t_Counters.at(rec::Counter::ignoredCount)++;
    if (g_logCommonErrors) {
      g_slogtcpin->info(Logr::Error, "Ignoring unsupported opcode from TCP client", "remote", Logging::Loggable(comboWriter->getRemote()), "opcode", Logging::Loggable(Opcode::to_s(comboWriter->d_mdp.d_header.opcode)));
    }
    sendErrorOverTCP(comboWriter, RCode::NotImp);
    tcpGuard.keep();
    return;
  }
  if (dnsheader->qdcount == 0U) {
    t_Counters.at(rec::Counter::emptyQueriesCount)++;
    if (g_logCommonErrors) {
      g_slogtcpin->info(Logr::Error, "Ignoring empty (qdcount == 0) query on server socket", "remote", Logging::Loggable(comboWriter->getRemote()));
    }
    sendErrorOverTCP(comboWriter, RCode::NotImp);
    tcpGuard.keep();
    return;
  }
  {
    // We have read a proper query
    ++t_Counters.at(rec::Counter::qcounter);
    ++t_Counters.at(rec::Counter::tcpqcounter);
    if (comboWriter->d_source.sin4.sin_family == AF_INET6) {
      ++t_Counters.at(rec::Counter::ipv6qcounter);
    }

    if (comboWriter->d_mdp.d_header.opcode == static_cast<unsigned>(Opcode::Notify)) {
      handleNotify(comboWriter, qname);
    }

    string response;
    RecursorPacketCache::OptPBData pbData{boost::none};

    if (comboWriter->d_mdp.d_header.opcode == static_cast<unsigned>(Opcode::Query)) {
      /* It might seem like a good idea to skip the packet cache lookup if we know that the answer is not cacheable,
         but it means that the hash would not be computed. If some script decides at a later time to mark back the answer
         as cacheable we would cache it with a wrong tag, so better safe than sorry. */
      auto match = comboWriter->d_eventTrace.add(RecEventTrace::PCacheCheck);
      bool cacheHit = checkForCacheHit(qnameParsed, comboWriter->d_tag, conn->data, qname, qtype, qclass, g_now, response, comboWriter->d_qhash, pbData, true, comboWriter->d_source, comboWriter->d_mappedSource);
      comboWriter->d_eventTrace.add(RecEventTrace::PCacheCheck, cacheHit, false, match);

      if (cacheHit) {
        if (!g_quiet) {
          g_slogtcpin->info(Logr::Notice, "TCP question answered from packet cache", "tag", Logging::Loggable(comboWriter->d_tag),
                            "qname", Logging::Loggable(qname), "qtype", Logging::Loggable(QType(qtype)),
                            "source", Logging::Loggable(comboWriter->d_source), "remote", Logging::Loggable(comboWriter->d_remote));
        }

        auto answerMatch = comboWriter->d_eventTrace.add(RecEventTrace::AnswerSent);
        bool hadError = sendResponseOverTCP(comboWriter, response);
        finishTCPReply(comboWriter, hadError, false);
        struct timeval now{};
        Utility::gettimeofday(&now, nullptr);
        uint64_t spentUsec = uSec(now - start);
        t_Counters.at(rec::Histogram::cumulativeAnswers)(spentUsec);
        comboWriter->d_eventTrace.add(RecEventTrace::AnswerSent, 0, false, answerMatch);
        traceScope.close(0);

        if (t_protobufServers.servers && comboWriter->d_logResponse && (!luaconfsLocal->protobufExportConfig.taggedOnly || (pbData && pbData->d_tagged))) {
          struct timeval tval{
            0, 0};
          protobufLogResponse(qname, qtype, dnsheader, luaconfsLocal, pbData, tval, true, comboWriter->d_source, comboWriter->d_destination, comboWriter->d_mappedSource, comboWriter->d_ednssubnet, comboWriter->d_uuid, comboWriter->d_requestorId, comboWriter->d_deviceId, comboWriter->d_deviceName, comboWriter->d_meta, comboWriter->d_eventTrace, comboWriter->d_otTrace, comboWriter->d_policyTags);
        }

        if (comboWriter->d_eventTrace.enabled() && SyncRes::eventTraceEnabled(SyncRes::event_trace_to_log)) {
          g_slogtcpin->info(Logr::Info, comboWriter->d_eventTrace.toString()); // More fancy?
        }
        tcpGuard.keep();
        t_Counters.updateSnap(g_regressionTestMode);
        return;
      } // cache hit
    } // query opcode

    if (comboWriter->d_mdp.d_header.opcode == static_cast<unsigned>(Opcode::Notify)) {
      if (!g_quiet) {
        g_slogtcpin->info(Logr::Notice, "Got NOTIFY", "qname", Logging::Loggable(qname), "source", Logging::Loggable(comboWriter->d_source), "remote", Logging::Loggable(comboWriter->d_remote));
      }

      requestWipeCaches(qname);

      // the operation will now be treated as a Query, generating
      // a normal response, as the rest of the code does not
      // check dh->opcode, but we need to ensure that the response
      // to this request does not get put into the packet cache
      comboWriter->d_variable = true;
    }

    // setup for startDoResolve() in an mthread
    ++conn->d_requestsInFlight;
    if (conn->d_requestsInFlight >= TCPConnection::s_maxInFlight) {
      t_fdm->removeReadFD(fileDesc); // should no longer awake ourselves when there is data to read
    }
    else {
      Utility::gettimeofday(&g_now, nullptr); // needed?
      struct timeval ttd = g_now;
      t_fdm->setReadTTD(fileDesc, ttd, g_tcpTimeout);
    }
    tcpGuard.keep();
    traceScope.close(0);
    g_multiTasker->makeThread(startDoResolve, comboWriter.release()); // deletes dc
  } // good query
}

static void handleRunningTCPQuestion(int fileDesc, FDMultiplexer::funcparam_t& var) // NOLINT(readability-function-cognitive-complexity)
{
  auto conn = boost::any_cast<shared_ptr<TCPConnection>>(var);

  RunningTCPQuestionGuard tcpGuard{fileDesc};

  if (conn->state == TCPConnection::PROXYPROTOCOLHEADER) {
    ssize_t bytes = recv(conn->getFD(), &conn->data.at(conn->proxyProtocolGot), conn->proxyProtocolNeed, 0);
    if (bytes <= 0) {
      tcpGuard.handleTCPReadResult(fileDesc, bytes);
      return;
    }

    conn->proxyProtocolGot += bytes;
    conn->data.resize(conn->proxyProtocolGot);
    ssize_t remaining = isProxyHeaderComplete(conn->data);
    if (remaining == 0) {
      if (g_logCommonErrors) {
        g_slogtcpin->info(Logr::Error, "Unable to consume proxy protocol header in packet from TCP client", "remote", Logging::Loggable(conn->d_remote));
      }
      ++t_Counters.at(rec::Counter::proxyProtocolInvalidCount);
      return;
    }
    if (remaining < 0) {
      conn->proxyProtocolNeed = -remaining;
      conn->data.resize(conn->proxyProtocolGot + conn->proxyProtocolNeed);
      tcpGuard.keep();
      return;
    }
    {
      /* proxy header received */
      /* we ignore the TCP field for now, but we could properly set whether
         the connection was received over UDP or TCP if needed */
      bool tcp = false;
      bool proxy = false;
      size_t used = parseProxyHeader(conn->data, proxy, conn->d_source, conn->d_destination, tcp, conn->proxyProtocolValues);
      if (used <= 0) {
        if (g_logCommonErrors) {
          g_slogtcpin->info(Logr::Error, "Unable to parse proxy protocol header in packet from TCP client", "remote", Logging::Loggable(conn->d_remote));
        }
        ++t_Counters.at(rec::Counter::proxyProtocolInvalidCount);
        return;
      }
      if (static_cast<size_t>(used) > g_proxyProtocolMaximumSize) {
        if (g_logCommonErrors) {
          g_slogtcpin->info(Logr::Error, "Proxy protocol header in packet from TCP client is larger than proxy-protocol-maximum-size", "remote", Logging::Loggable(conn->d_remote), "size", Logging::Loggable(used));
        }
        ++t_Counters.at(rec::Counter::proxyProtocolInvalidCount);
        return;
      }

      /* Now that we have retrieved the address of the client, as advertised by the proxy
         via the proxy protocol header, check that it is allowed by our ACL */
      /* note that if the proxy header used a 'LOCAL' command, the original source and destination are untouched so everything should be fine */
      conn->d_mappedSource = conn->d_source;
      if (t_proxyMapping) {
        if (const auto* iter = t_proxyMapping->lookup(conn->d_source)) {
          conn->d_mappedSource = iter->second.address;
          ++iter->second.stats.netmaskMatches;
        }
      }
      if (t_remotes) {
        t_remotes->push_back(conn->d_source);
      }
      if (t_allowFrom && !t_allowFrom->match(&conn->d_mappedSource)) {
        if (!g_quiet) {
          g_slogtcpin->info(Logr::Error, "Dropping TCP query, address not matched by allow-from", "remote", Logging::Loggable(conn->d_remote));
        }

        ++t_Counters.at(rec::Counter::unauthorizedTCP);
        return;
      }

      conn->data.resize(2);
      conn->state = TCPConnection::BYTE0;
    }
  }

  if (conn->state == TCPConnection::BYTE0) {
    ssize_t bytes = recv(conn->getFD(), conn->data.data(), 2, 0);
    if (bytes == 1) {
      conn->state = TCPConnection::BYTE1;
    }
    if (bytes == 2) {
      conn->qlen = (((unsigned char)conn->data[0]) << 8) + (unsigned char)conn->data[1];
      conn->data.resize(conn->qlen);
      conn->bytesread = 0;
      conn->state = TCPConnection::GETQUESTION;
    }
    if (bytes <= 0) {
      tcpGuard.handleTCPReadResult(fileDesc, bytes);
      return;
    }
  }

  if (conn->state == TCPConnection::BYTE1) {
    ssize_t bytes = recv(conn->getFD(), &conn->data[1], 1, 0);
    if (bytes == 1) {
      conn->state = TCPConnection::GETQUESTION;
      conn->qlen = (((unsigned char)conn->data[0]) << 8) + (unsigned char)conn->data[1];
      conn->data.resize(conn->qlen);
      conn->bytesread = 0;
    }
    if (bytes <= 0) {
      if (!tcpGuard.handleTCPReadResult(fileDesc, bytes)) {
        if (g_logCommonErrors) {
          g_slogtcpin->info(Logr::Error, "TCP client disconnected after first byte", "remote", Logging::Loggable(conn->d_remote));
        }
      }
      return;
    }
  }

  if (conn->state == TCPConnection::GETQUESTION) {
    ssize_t bytes = recv(conn->getFD(), &conn->data[conn->bytesread], conn->qlen - conn->bytesread, 0);
    if (bytes <= 0) {
      if (!tcpGuard.handleTCPReadResult(fileDesc, bytes)) {
        if (g_logCommonErrors) {
          g_slogtcpin->info(Logr::Error, "TCP client disconnected while reading question body", "remote", Logging::Loggable(conn->d_remote));
        }
      }
      return;
    }
    if (bytes > std::numeric_limits<std::uint16_t>::max()) {
      if (g_logCommonErrors) {
        g_slogtcpin->info(Logr::Error, "TCP client sent an invalid question size while reading question body", "remote", Logging::Loggable(conn->d_remote));
      }
      return;
    }
    conn->bytesread += (uint16_t)bytes;
    if (conn->bytesread == conn->qlen) {
      conn->state = TCPConnection::BYTE0;
      std::unique_ptr<DNSComboWriter> comboWriter;
      try {
        comboWriter = std::make_unique<DNSComboWriter>(conn->data, g_now, t_pdl);
      }
      catch (const MOADNSException& mde) {
        t_Counters.at(rec::Counter::clientParseError)++;
        if (g_logCommonErrors) {
          g_slogtcpin->info(Logr::Error, "Unable to parse packet from TCP client", "remte", Logging::Loggable(conn->d_remote));
        }
        return;
      }

      comboWriter->d_tcpConnection = conn; // carry the torch
      comboWriter->setSocket(conn->getFD()); // this is the only time a copy is made of the actual fd
      comboWriter->d_tcp = true;
      comboWriter->setRemote(conn->d_remote); // the address from which the query was received
      comboWriter->setSource(conn->d_source); // the address we assume the query is coming from, might be set by proxy protocol
      ComboAddress dest;
      dest.reset();
      dest.sin4.sin_family = conn->d_remote.sin4.sin_family;
      socklen_t len = dest.getSocklen();
      getsockname(conn->getFD(), reinterpret_cast<sockaddr*>(&dest), &len); // if this fails, we're ok with it NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      comboWriter->setLocal(dest); // the address we received the query on
      comboWriter->setDestination(conn->d_destination); // the address we assume the query is received on, might be set by proxy protocol
      comboWriter->setMappedSource(conn->d_mappedSource); // the address we assume the query is coming from after table based mapping
      /* we can't move this if we want to be able to access the values in
         all queries sent over this connection */
      comboWriter->d_proxyProtocolValues = conn->proxyProtocolValues;

      doProcessTCPQuestion(comboWriter, conn, tcpGuard, fileDesc);
    } // reading query
  }
  // more to come
  tcpGuard.keep();
}

//! Handle new incoming TCP connection
void handleNewTCPQuestion(int fileDesc, [[maybe_unused]] FDMultiplexer::funcparam_t& var)
{
  ComboAddress addr;
  socklen_t addrlen = sizeof(addr);
  int newsock = accept(fileDesc, reinterpret_cast<struct sockaddr*>(&addr), &addrlen); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  if (newsock < 0) {
    return;
  }
  auto closeSock = [newsock](rec::Counter cnt, const string& msg) {
    try {
      closesocket(newsock);
      t_Counters.at(cnt)++;
      // We want this bump to percolate up without too much delay
      t_Counters.updateSnap(false);
    }
    catch (const PDNSException& e) {
      g_slogtcpin->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("PDNSException"));
    }
  };

  if (TCPConnection::getCurrentConnections() >= g_maxTCPClients) {
    closeSock(rec::Counter::tcpOverflow, "Error closing TCP socket after an overflow drop");
    return;
  }
  if (g_multiTasker->numProcesses() >= g_maxMThreads) {
    closeSock(rec::Counter::overCapacityDrops, "Error closing TCP socket after an over capacity drop");
    return;
  }

  ComboAddress destaddr;
  socklen_t len = sizeof(destaddr);
  getsockname(newsock, reinterpret_cast<sockaddr*>(&destaddr), &len); // if this fails, we're ok with it NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  bool fromProxyProtocolSource = expectProxyProtocol(addr, destaddr);
  if (!fromProxyProtocolSource && t_remotes) {
    t_remotes->push_back(addr);
  }
  ComboAddress mappedSource = addr;
  if (!fromProxyProtocolSource && t_proxyMapping) {
    if (const auto* iter = t_proxyMapping->lookup(addr)) {
      mappedSource = iter->second.address;
      ++iter->second.stats.netmaskMatches;
    }
  }
  if (!fromProxyProtocolSource && t_allowFrom && !t_allowFrom->match(&mappedSource)) {
    if (!g_quiet) {
      g_slogtcpin->info(Logr::Error, "dropping TCP query address neither matched by allow-from nor proxy-protocol-from", "source", Logging::Loggable(mappedSource));
    }
    closeSock(rec::Counter::unauthorizedTCP, "Error closing TCP socket after an ACL drop");
    return;
  }

  if (g_maxTCPPerClient > 0 && t_tcpClientCounts->count(addr) > 0 && (*t_tcpClientCounts)[addr] >= g_maxTCPPerClient) {
    closeSock(rec::Counter::tcpClientOverflow, "Error closing TCP socket after a client overflow drop");
    return;
  }

  setNonBlocking(newsock);
  setTCPNoDelay(newsock);
  std::shared_ptr<TCPConnection> tcpConn = std::make_shared<TCPConnection>(newsock, addr);
  tcpConn->d_source = addr;
  tcpConn->d_destination = destaddr;
  tcpConn->d_mappedSource = mappedSource;

  if (fromProxyProtocolSource) {
    tcpConn->proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
    tcpConn->data.resize(tcpConn->proxyProtocolNeed);
    tcpConn->state = TCPConnection::PROXYPROTOCOLHEADER;
  }
  else {
    tcpConn->state = TCPConnection::BYTE0;
  }

  timeval ttd{};
  Utility::gettimeofday(&ttd, nullptr);
  ttd.tv_sec += g_tcpTimeout;

  t_fdm->addReadFD(tcpConn->getFD(), handleRunningTCPQuestion, tcpConn, &ttd);
}

static void TCPIOHandlerIO(int fileDesc, FDMultiplexer::funcparam_t& var);

static void TCPIOHandlerStateChange(IOState oldstate, IOState newstate, std::shared_ptr<PacketID>& pid)
{
  TCPLOG(pid->tcpsock, "State transition " << int(oldstate) << "->" << int(newstate) << endl);

  pid->lowState = newstate;

  // handle state transitions
  switch (oldstate) {
  case IOState::NeedRead:

    switch (newstate) {
    case IOState::NeedWrite:
      TCPLOG(pid->tcpsock, "NeedRead -> NeedWrite: flip FD" << endl);
      t_fdm->alterFDToWrite(pid->tcpsock, TCPIOHandlerIO, pid);
      break;
    case IOState::NeedRead:
      break;
    case IOState::Done:
      TCPLOG(pid->tcpsock, "Done -> removeReadFD" << endl);
      t_fdm->removeReadFD(pid->tcpsock);
      break;
    case IOState::Async:
      throw std::runtime_error("TLS async mode not supported");
      break;
    }
    break;

  case IOState::NeedWrite:

    switch (newstate) {
    case IOState::NeedRead:
      TCPLOG(pid->tcpsock, "NeedWrite -> NeedRead: flip FD" << endl);
      t_fdm->alterFDToRead(pid->tcpsock, TCPIOHandlerIO, pid);
      break;
    case IOState::NeedWrite:
      break;
    case IOState::Done:
      TCPLOG(pid->tcpsock, "Done -> removeWriteFD" << endl);
      t_fdm->removeWriteFD(pid->tcpsock);
      break;
    case IOState::Async:
      throw std::runtime_error("TLS async mode not supported");
      break;
    }
    break;

  case IOState::Done:
    switch (newstate) {
    case IOState::NeedRead:
      TCPLOG(pid->tcpsock, "NeedRead: addReadFD" << endl);
      t_fdm->addReadFD(pid->tcpsock, TCPIOHandlerIO, pid);
      break;
    case IOState::NeedWrite:
      TCPLOG(pid->tcpsock, "NeedWrite: addWriteFD" << endl);
      t_fdm->addWriteFD(pid->tcpsock, TCPIOHandlerIO, pid);
      break;
    case IOState::Done:
      break;
    case IOState::Async:
      throw std::runtime_error("TLS async mode not supported");
      break;
    }
    break;

  case IOState::Async:
    throw std::runtime_error("TLS async mode not supported");
    break;
  }
}

static void TCPIOHandlerIO(int fileDesc, FDMultiplexer::funcparam_t& var)
{
  auto pid = boost::any_cast<std::shared_ptr<PacketID>>(var);
  assert(pid->tcphandler); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay): def off assert triggers it
  assert(fileDesc == pid->tcphandler->getDescriptor()); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay) idem
  IOState newstate = IOState::Done;

  TCPLOG(pid->tcpsock, "TCPIOHandlerIO: lowState " << int(pid->lowState) << endl);

  // In the code below, we want to update the state of the fd before calling sendEvent
  // a sendEvent might close the fd, and some poll multiplexers do not like to manipulate a closed fd

  switch (pid->highState) {
  case TCPAction::DoingRead:
    TCPLOG(pid->tcpsock, "highState: Reading" << endl);
    // In arecvtcp, the buffer was resized already so inWanted bytes will fit
    // try reading
    try {
      newstate = pid->tcphandler->tryRead(pid->inMSG, pid->inPos, pid->inWanted);
      switch (newstate) {
      case IOState::Done:
      case IOState::NeedRead:
        TCPLOG(pid->tcpsock, "tryRead: Done or NeedRead " << int(newstate) << ' ' << pid->inPos << '/' << pid->inWanted << endl);
        TCPLOG(pid->tcpsock, "TCPIOHandlerIO " << pid->inWanted << ' ' << pid->inIncompleteOkay << endl);
        if (pid->inPos == pid->inWanted || (pid->inIncompleteOkay && pid->inPos > 0)) {
          pid->inMSG.resize(pid->inPos); // old content (if there) + new bytes read, only relevant for the inIncompleteOkay case
          newstate = IOState::Done;
          TCPIOHandlerStateChange(pid->lowState, newstate, pid);
          g_multiTasker->sendEvent(pid, &pid->inMSG);
          return;
        }
        break;
      case IOState::NeedWrite:
        break;
      case IOState::Async:
        throw std::runtime_error("TLS async mode not supported");
        break;
      }
    }
    catch (const std::exception& e) {
      newstate = IOState::Done;
      TCPLOG(pid->tcpsock, "read exception..." << e.what() << endl);
      PacketBuffer empty;
      TCPIOHandlerStateChange(pid->lowState, newstate, pid);
      g_multiTasker->sendEvent(pid, &empty); // this conveys error status
      return;
    }
    break;

  case TCPAction::DoingWrite:
    TCPLOG(pid->tcpsock, "highState: Writing" << endl);
    try {
      TCPLOG(pid->tcpsock, "tryWrite: " << pid->outPos << '/' << pid->outMSG.size() << ' ' << " -> ");
      newstate = pid->tcphandler->tryWrite(pid->outMSG, pid->outPos, pid->outMSG.size());
      TCPLOG(pid->tcpsock, pid->outPos << '/' << pid->outMSG.size() << endl);
      switch (newstate) {
      case IOState::Done: {
        TCPLOG(pid->tcpsock, "tryWrite: Done" << endl);
        TCPIOHandlerStateChange(pid->lowState, newstate, pid);
        g_multiTasker->sendEvent(pid, &pid->outMSG); // send back what we sent to convey everything is ok
        return;
      }
      case IOState::NeedRead:
        TCPLOG(pid->tcpsock, "tryWrite: NeedRead" << endl);
        break;
      case IOState::NeedWrite:
        TCPLOG(pid->tcpsock, "tryWrite: NeedWrite" << endl);
        break;
      case IOState::Async:
        throw std::runtime_error("TLS async mode not supported");
        break;
      }
    }
    catch (const std::exception& e) {
      newstate = IOState::Done;
      TCPLOG(pid->tcpsock, "write exception..." << e.what() << endl);
      PacketBuffer sent;
      TCPIOHandlerStateChange(pid->lowState, newstate, pid);
      g_multiTasker->sendEvent(pid, &sent); // we convey error status by sending empty string
      return;
    }
    break;
  }

  // Cases that did not end up doing a sendEvent
  TCPIOHandlerStateChange(pid->lowState, newstate, pid);
}

void checkFastOpenSysctl([[maybe_unused]] bool active, [[maybe_unused]] Logr::log_t log)
{
#ifdef __linux__
  string line;
  if (readFileIfThere("/proc/sys/net/ipv4/tcp_fastopen", &line)) {
    int flag = std::stoi(line);
    if (active && !(flag & 1)) {
      log->info(Logr::Error, "tcp-fast-open-connect enabled but net.ipv4.tcp_fastopen does not allow it");
    }
    if (!active && !(flag & 2)) {
      log->info(Logr::Error, "tcp-fast-open enabled but net.ipv4.tcp_fastopen does not allow it");
    }
  }
  else {
    log->info(Logr::Notice, "Cannot determine if kernel settings allow fast-open");
  }
#else
  log->info(Logr::Notice, "Cannot determine if kernel settings allow fast-open");
#endif
}

void checkTFOconnect(Logr::log_t log)
{
  try {
    Socket socket(AF_INET, SOCK_STREAM);
    socket.setNonBlocking();
    socket.setFastOpenConnect();
  }
  catch (const NetworkError& e) {
    log->error(Logr::Error, e.what(), "tcp-fast-open-connect enabled but returned error");
  }
}

LWResult::Result asendtcp(const PacketBuffer& data, shared_ptr<TCPIOHandler>& handler)
{
  TCPLOG(handler->getDescriptor(), "asendtcp called " << data.size() << endl);

  auto pident = std::make_shared<PacketID>();
  pident->tcphandler = handler;
  pident->tcpsock = handler->getDescriptor();
  pident->outMSG = data;
  pident->highState = TCPAction::DoingWrite;

  IOState state = IOState::Done;
  try {
    TCPLOG(pident->tcpsock, "Initial tryWrite: " << pident->outPos << '/' << pident->outMSG.size() << ' ' << " -> ");
    state = handler->tryWrite(pident->outMSG, pident->outPos, pident->outMSG.size());
    TCPLOG(pident->tcpsock, pident->outPos << '/' << pident->outMSG.size() << endl);

    if (state == IOState::Done) {
      TCPLOG(pident->tcpsock, "asendtcp success A" << endl);
      return LWResult::Result::Success;
    }
  }
  catch (const std::exception& e) {
    TCPLOG(pident->tcpsock, "tryWrite() exception..." << e.what() << endl);
    return LWResult::Result::PermanentError;
  }

  // Will set pident->lowState
  TCPIOHandlerStateChange(IOState::Done, state, pident);

  PacketBuffer packet;
  int ret = g_multiTasker->waitEvent(pident, &packet, g_networkTimeoutMsec);
  TCPLOG(pident->tcpsock, "asendtcp waitEvent returned " << ret << ' ' << packet.size() << '/' << data.size() << ' ');
  if (ret == 0) {
    TCPLOG(pident->tcpsock, "timeout" << endl);
    TCPIOHandlerStateChange(pident->lowState, IOState::Done, pident);
    return LWResult::Result::Timeout;
  }
  if (ret == -1) { // error
    TCPLOG(pident->tcpsock, "PermanentError" << endl);
    TCPIOHandlerStateChange(pident->lowState, IOState::Done, pident);
    return LWResult::Result::PermanentError;
  }
  if (packet.size() != data.size()) { // main loop tells us what it sent out, or empty in case of an error
    // fd housekeeping done by TCPIOHandlerIO
    TCPLOG(pident->tcpsock, "PermanentError size mismatch " << endl);
    return LWResult::Result::PermanentError;
  }

  TCPLOG(pident->tcpsock, "asendtcp success" << endl);
  return LWResult::Result::Success;
}

LWResult::Result arecvtcp(PacketBuffer& data, const size_t len, shared_ptr<TCPIOHandler>& handler, const bool incompleteOkay)
{
  TCPLOG(handler->getDescriptor(), "arecvtcp called " << len << ' ' << data.size() << endl);
  data.resize(len);

  // We might have data already available from the TLS layer, try to get that into the buffer
  size_t pos = 0;
  IOState state = IOState::Done;
  try {
    TCPLOG(handler->getDescriptor(), "calling tryRead() " << len << endl);
    state = handler->tryRead(data, pos, len);
    TCPLOG(handler->getDescriptor(), "arecvtcp tryRead() returned " << int(state) << ' ' << pos << '/' << len << endl);
    switch (state) {
    case IOState::Done:
    case IOState::NeedRead:
      if (pos == len || (incompleteOkay && pos > 0)) {
        data.resize(pos);
        TCPLOG(handler->getDescriptor(), "arecvtcp success A" << endl);
        return LWResult::Result::Success;
      }
      break;
    case IOState::NeedWrite:
      break;
    case IOState::Async:
      throw std::runtime_error("TLS async mode not supported");
      break;
    }
  }
  catch (const std::exception& e) {
    TCPLOG(handler->getDescriptor(), "tryRead() exception..." << e.what() << endl);
    return LWResult::Result::PermanentError;
  }

  auto pident = std::make_shared<PacketID>();
  pident->tcphandler = handler;
  pident->tcpsock = handler->getDescriptor();
  // We might have a partial result
  pident->inMSG = std::move(data);
  pident->inPos = pos;
  pident->inWanted = len;
  pident->inIncompleteOkay = incompleteOkay;
  pident->highState = TCPAction::DoingRead;

  data.clear();

  // Will set pident->lowState
  TCPIOHandlerStateChange(IOState::Done, state, pident);

  int ret = g_multiTasker->waitEvent(pident, &data, authWaitTimeMSec(g_multiTasker));
  TCPLOG(pident->tcpsock, "arecvtcp " << ret << ' ' << data.size() << ' ');
  if (ret == 0) {
    TCPLOG(pident->tcpsock, "timeout" << endl);
    TCPIOHandlerStateChange(pident->lowState, IOState::Done, pident);
    return LWResult::Result::Timeout;
  }
  if (ret == -1) {
    TCPLOG(pident->tcpsock, "PermanentError" << endl);
    TCPIOHandlerStateChange(pident->lowState, IOState::Done, pident);
    return LWResult::Result::PermanentError;
  }
  if (data.empty()) { // error, EOF or other
    // fd housekeeping done by TCPIOHandlerIO
    TCPLOG(pident->tcpsock, "EOF" << endl);
    return LWResult::Result::PermanentError;
  }

  TCPLOG(pident->tcpsock, "arecvtcp success" << endl);
  return LWResult::Result::Success;
}

// The two last arguments to makeTCPServerSockets are used for logging purposes only
unsigned int makeTCPServerSockets(deferredAdd_t& deferredAdds, std::set<int>& tcpSockets, Logr::log_t log, bool doLog, unsigned int instances)
{
  vector<string> localAddresses;
  vector<string> logVec;
  stringtok(localAddresses, ::arg()["local-address"], " ,");

  if (localAddresses.empty()) {
    throw PDNSException("No local address specified");
  }

#ifdef TCP_DEFER_ACCEPT
  auto first = true;
#endif
  const uint16_t defaultLocalPort = ::arg().asNum("local-port");
  const vector<string> defaultVector = {"127.0.0.1", "::1"};
  const auto configIsDefault = localAddresses == defaultVector;

  for (const auto& localAddress : localAddresses) {
    ComboAddress address{localAddress, defaultLocalPort};
    auto socketFd = FDWrapper(socket(address.sin6.sin6_family, SOCK_STREAM, 0));
    if (socketFd < 0) {
      throw PDNSException("Making a TCP server socket for resolver: " + stringerror());
    }
    setCloseOnExec(socketFd);

    int tmp = 1;
    if (setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof tmp) < 0) {
      int err = errno;
      log->error(Logr::Critical, err, "Setsockopt failed for TCP listening socket");
      _exit(1);
    }
    if (address.sin6.sin6_family == AF_INET6 && setsockopt(socketFd, IPPROTO_IPV6, IPV6_V6ONLY, &tmp, sizeof(tmp)) < 0) {
      int err = errno;
      log->error(Logr::Warning, err, "Failed to set IPv6 socket to IPv6 only, continuing anyhow");
    }

#ifdef TCP_DEFER_ACCEPT
    if (setsockopt(socketFd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &tmp, sizeof tmp) >= 0) {
      if (first) {
        log->info(Logr::Info, "Enabled TCP data-ready filter for (slight) DoS protection");
      }
    }
#endif

    if (::arg().mustDo("non-local-bind")) {
      Utility::setBindAny(AF_INET, socketFd);
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

    if (SyncRes::s_tcp_fast_open > 0) {
      checkFastOpenSysctl(false, log);
#ifdef TCP_FASTOPEN
      if (setsockopt(socketFd, IPPROTO_TCP, TCP_FASTOPEN, &SyncRes::s_tcp_fast_open, sizeof SyncRes::s_tcp_fast_open) < 0) {
        int err = errno;
        log->error(Logr::Error, err, "Failed to enable TCP Fast Open for listening socket");
      }
#else
      log->info(Logr::Warning, "TCP Fast Open configured but not supported for listening socket");
#endif
    }

    socklen_t socklen = address.sin4.sin_family == AF_INET ? sizeof(address.sin4) : sizeof(address.sin6);
    if (::bind(socketFd, reinterpret_cast<struct sockaddr*>(&address), socklen) < 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      int err = errno;
      if (!configIsDefault || address != ComboAddress{"::1", defaultLocalPort}) {
        throw PDNSException("Binding TCP server socket for " + address.toStringWithPort() + ": " + stringerror(err));
      }
      log->info(Logr::Warning, "Cannot listen on this address, skipping", "proto", Logging::Loggable("TCP"), "address", Logging::Loggable(address), "error", Logging::Loggable(stringerror(err)));
      continue;
    }

    setNonBlocking(socketFd);
    try {
      setSocketSendBuffer(socketFd, 65000);
    }
    catch (const std::exception& e) {
      log->error(Logr::Error, e.what(), "Exception while setting socket send buffer");
    }

    listen(socketFd, 128);
    deferredAdds.emplace_back(socketFd, handleNewTCPQuestion);
    tcpSockets.insert(socketFd);
    logVec.emplace_back(address.toStringWithPort());

    // we don't need to update g_listenSocketsAddresses since it doesn't work for TCP/IP:
    //  - fd is not that which we know here, but returned from accept()

#ifdef TCP_DEFER_ACCEPT
    first = false;
#endif
    socketFd.release(); // to avoid auto-close by FDWrapper
  }
  if (doLog) {
    log->info(Logr::Info, "Listening for queries", "protocol", Logging::Loggable("TCP"), "addresses", Logging::IterLoggable(logVec.cbegin(), logVec.cend()), "socketInstances", Logging::Loggable(instances), "reuseport", Logging::Loggable(g_reusePort));
  }
  return localAddresses.size();
}
