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

size_t g_tcpMaxQueriesPerConn;
unsigned int g_maxTCPPerClient;
int g_tcpTimeout;
bool g_anyToTcp;

uint16_t TCPConnection::s_maxInFlight;

thread_local std::unique_ptr<tcpClientCounts_t> t_tcpClientCounts;

static void handleRunningTCPQuestion(int fd, FDMultiplexer::funcparam_t& var);

#if 0
#define TCPLOG(tcpsock, x)                                 \
  do {                                                     \
    cerr << []() { timeval t; gettimeofday(&t, nullptr); return t.tv_sec % 10  + t.tv_usec/1000000.0; }() << " FD " << (tcpsock) << ' ' << x; \
  } while (0)
#else
#define TCPLOG(pid, x)
#endif

std::atomic<uint32_t> TCPConnection::s_currentConnections;

TCPConnection::TCPConnection(int fd, const ComboAddress& addr) :
  data(2, 0), d_remote(addr), d_fd(fd)
{
  ++s_currentConnections;
  (*t_tcpClientCounts)[d_remote]++;
}

TCPConnection::~TCPConnection()
{
  try {
    if (closesocket(d_fd) < 0)
      SLOG(g_log << Logger::Error << "Error closing socket for TCPConnection" << endl,
           g_slogtcpin->info(Logr::Error, "Error closing socket for TCPConnection"));
  }
  catch (const PDNSException& e) {
    SLOG(g_log << Logger::Error << "Error closing TCPConnection socket: " << e.reason << endl,
         g_slogtcpin->error(Logr::Error, e.reason, "Error closing TCPConnection socket", "exception", Logging::Loggable("PDNSException")));
  }

  if (t_tcpClientCounts->count(d_remote) && !(*t_tcpClientCounts)[d_remote]--)
    t_tcpClientCounts->erase(d_remote);
  --s_currentConnections;
}

static void terminateTCPConnection(int fd)
{
  try {
    t_fdm->removeReadFD(fd);
  }
  catch (const FDMultiplexerException& fde) {
  }
}

static void sendErrorOverTCP(std::unique_ptr<DNSComboWriter>& dc, int rcode)
{
  std::vector<uint8_t> packet;
  if (dc->d_mdp.d_header.qdcount == 0) {
    /* header-only */
    packet.resize(sizeof(dnsheader));
  }
  else {
    DNSPacketWriter pw(packet, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_mdp.d_qclass);
    if (dc->d_mdp.hasEDNS()) {
      /* we try to add the EDNS OPT RR even for truncated answers,
         as rfc6891 states:
         "The minimal response MUST be the DNS header, question section, and an
         OPT record.  This MUST also occur when a truncated response (using
         the DNS header's TC bit) is returned."
      */
      pw.addOpt(512, 0, 0);
      pw.commit();
    }
  }

  dnsheader& header = reinterpret_cast<dnsheader&>(packet.at(0));
  header.aa = 0;
  header.ra = 1;
  header.qr = 1;
  header.tc = 0;
  header.id = dc->d_mdp.d_header.id;
  header.rd = dc->d_mdp.d_header.rd;
  header.cd = dc->d_mdp.d_header.cd;
  header.rcode = rcode;

  sendResponseOverTCP(dc, packet);
}

void finishTCPReply(std::unique_ptr<DNSComboWriter>& dc, bool hadError, bool updateInFlight)
{
  // update tcp connection status, closing if needed and doing the fd multiplexer accounting
  if (updateInFlight && dc->d_tcpConnection->d_requestsInFlight > 0) {
    dc->d_tcpConnection->d_requestsInFlight--;
  }

  // In the code below, we try to remove the fd from the set, but
  // we don't know if another mthread already did the remove, so we can get a
  // "Tried to remove unlisted fd" exception.  Not that an inflight < limit test
  // will not work since we do not know if the other mthread got an error or not.
  if (hadError) {
    terminateTCPConnection(dc->d_socket);
    dc->d_socket = -1;
    return;
  }
  dc->d_tcpConnection->queriesCount++;
  if ((g_tcpMaxQueriesPerConn && dc->d_tcpConnection->queriesCount >= g_tcpMaxQueriesPerConn) || (dc->d_tcpConnection->isDropOnIdle() && dc->d_tcpConnection->d_requestsInFlight == 0)) {
    try {
      t_fdm->removeReadFD(dc->d_socket);
    }
    catch (FDMultiplexerException&) {
    }
    dc->d_socket = -1;
    return;
  }

  Utility::gettimeofday(&g_now, nullptr); // needs to be updated
  struct timeval ttd = g_now;

  // If we cross from max to max-1 in flight requests, the fd was not listened to, add it back
  if (updateInFlight && dc->d_tcpConnection->d_requestsInFlight == TCPConnection::s_maxInFlight - 1) {
    // A read error might have happened. If we add the fd back, it will most likely error again.
    // This is not a big issue, the next handleTCPClientReadable() will see another read error
    // and take action.
    ttd.tv_sec += g_tcpTimeout;
    t_fdm->addReadFD(dc->d_socket, handleRunningTCPQuestion, dc->d_tcpConnection, &ttd);
    return;
  }
  // fd might have been removed by read error code, or a read timeout, so expect an exception
  try {
    t_fdm->setReadTTD(dc->d_socket, ttd, g_tcpTimeout);
  }
  catch (const FDMultiplexerException&) {
    // but if the FD was removed because of a timeout while we were sending a response,
    // we need to re-arm it. If it was an error it will error again.
    ttd.tv_sec += g_tcpTimeout;
    t_fdm->addReadFD(dc->d_socket, handleRunningTCPQuestion, dc->d_tcpConnection, &ttd);
  }
}

/*
 * A helper class that by default closes the incoming TCP connection on destruct
 * If you want to keep the connection alive, call keep() on the guard object
 */
class RunningTCPQuestionGuard
{
public:
  RunningTCPQuestionGuard(int fd)
  {
    d_fd = fd;
  }
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
    else if (bytes < 0) {
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

static void handleRunningTCPQuestion(int fd, FDMultiplexer::funcparam_t& var)
{
  shared_ptr<TCPConnection> conn = boost::any_cast<shared_ptr<TCPConnection>>(var);

  RunningTCPQuestionGuard tcpGuard{fd};

  if (conn->state == TCPConnection::PROXYPROTOCOLHEADER) {
    ssize_t bytes = recv(conn->getFD(), &conn->data.at(conn->proxyProtocolGot), conn->proxyProtocolNeed, 0);
    if (bytes <= 0) {
      tcpGuard.handleTCPReadResult(fd, bytes);
      return;
    }

    conn->proxyProtocolGot += bytes;
    conn->data.resize(conn->proxyProtocolGot);
    ssize_t remaining = isProxyHeaderComplete(conn->data);
    if (remaining == 0) {
      if (g_logCommonErrors) {
        SLOG(g_log << Logger::Error << "Unable to consume proxy protocol header in packet from TCP client " << conn->d_remote.toStringWithPort() << endl,
             g_slogtcpin->info(Logr::Error, "Unable to consume proxy protocol header in packet from TCP client", "remote", Logging::Loggable(conn->d_remote)));
      }
      ++t_Counters.at(rec::Counter::proxyProtocolInvalidCount);
      return;
    }
    else if (remaining < 0) {
      conn->proxyProtocolNeed = -remaining;
      conn->data.resize(conn->proxyProtocolGot + conn->proxyProtocolNeed);
      tcpGuard.keep();
      return;
    }
    else {
      /* proxy header received */
      /* we ignore the TCP field for now, but we could properly set whether
         the connection was received over UDP or TCP if needed */
      bool tcp;
      bool proxy = false;
      size_t used = parseProxyHeader(conn->data, proxy, conn->d_source, conn->d_destination, tcp, conn->proxyProtocolValues);
      if (used <= 0) {
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "Unable to parse proxy protocol header in packet from TCP client " << conn->d_remote.toStringWithPort() << endl,
               g_slogtcpin->info(Logr::Error, "Unable to parse proxy protocol header in packet from TCP client", "remote", Logging::Loggable(conn->d_remote)));
        }
        ++t_Counters.at(rec::Counter::proxyProtocolInvalidCount);
        return;
      }
      else if (static_cast<size_t>(used) > g_proxyProtocolMaximumSize) {
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "Proxy protocol header in packet from TCP client " << conn->d_remote.toStringWithPort() << " is larger than proxy-protocol-maximum-size (" << used << "), dropping" << endl,
               g_slogtcpin->info(Logr::Error, "Proxy protocol header in packet from TCP client is larger than proxy-protocol-maximum-size", "remote", Logging::Loggable(conn->d_remote), "size", Logging::Loggable(used)));
        }
        ++t_Counters.at(rec::Counter::proxyProtocolInvalidCount);
        return;
      }

      /* Now that we have retrieved the address of the client, as advertised by the proxy
         via the proxy protocol header, check that it is allowed by our ACL */
      /* note that if the proxy header used a 'LOCAL' command, the original source and destination are untouched so everything should be fine */
      conn->d_mappedSource = conn->d_source;
      if (t_proxyMapping) {
        if (auto it = t_proxyMapping->lookup(conn->d_source)) {
          conn->d_mappedSource = it->second.address;
          ++it->second.stats.netmaskMatches;
        }
      }
      if (t_allowFrom && !t_allowFrom->match(&conn->d_mappedSource)) {
        if (!g_quiet) {
          SLOG(g_log << Logger::Error << "[" << MT->getTid() << "] dropping TCP query from " << conn->d_mappedSource.toString() << ", address not matched by allow-from" << endl,
               g_slogtcpin->info(Logr::Error, "Dropping TCP query, address not matched by allow-from", "remote", Logging::Loggable(conn->d_remote)));
        }

        ++t_Counters.at(rec::Counter::unauthorizedTCP);
        return;
      }

      conn->data.resize(2);
      conn->state = TCPConnection::BYTE0;
    }
  }

  if (conn->state == TCPConnection::BYTE0) {
    ssize_t bytes = recv(conn->getFD(), &conn->data[0], 2, 0);
    if (bytes == 1)
      conn->state = TCPConnection::BYTE1;
    if (bytes == 2) {
      conn->qlen = (((unsigned char)conn->data[0]) << 8) + (unsigned char)conn->data[1];
      conn->data.resize(conn->qlen);
      conn->bytesread = 0;
      conn->state = TCPConnection::GETQUESTION;
    }
    if (bytes <= 0) {
      tcpGuard.handleTCPReadResult(fd, bytes);
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
      if (!tcpGuard.handleTCPReadResult(fd, bytes)) {
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "TCP client " << conn->d_remote.toStringWithPort() << " disconnected after first byte" << endl,
               g_slogtcpin->info(Logr::Error, "TCP client disconnected after first byte", "remote", Logging::Loggable(conn->d_remote)));
        }
      }
      return;
    }
  }

  if (conn->state == TCPConnection::GETQUESTION) {
    ssize_t bytes = recv(conn->getFD(), &conn->data[conn->bytesread], conn->qlen - conn->bytesread, 0);
    if (bytes <= 0) {
      if (!tcpGuard.handleTCPReadResult(fd, bytes)) {
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "TCP client " << conn->d_remote.toStringWithPort() << " disconnected while reading question body" << endl,
               g_slogtcpin->info(Logr::Error, "TCP client disconnected while reading question body", "remote", Logging::Loggable(conn->d_remote)));
        }
      }
      return;
    }
    else if (bytes > std::numeric_limits<std::uint16_t>::max()) {
      if (g_logCommonErrors) {
        SLOG(g_log << Logger::Error << "TCP client " << conn->d_remote.toStringWithPort() << " sent an invalid question size while reading question body" << endl,
             g_slogtcpin->info(Logr::Error, "TCP client sent an invalid question size while reading question body", "remote", Logging::Loggable(conn->d_remote)));
      }
      return;
    }
    conn->bytesread += (uint16_t)bytes;
    if (conn->bytesread == conn->qlen) {
      conn->state = TCPConnection::BYTE0;
      std::unique_ptr<DNSComboWriter> dc;
      try {
        dc = std::make_unique<DNSComboWriter>(conn->data, g_now, t_pdl);
      }
      catch (const MOADNSException& mde) {
        t_Counters.at(rec::Counter::clientParseError)++;
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "Unable to parse packet from TCP client " << conn->d_remote.toStringWithPort() << endl,
               g_slogtcpin->info(Logr::Error, "Unable to parse packet from TCP client", "remte", Logging::Loggable(conn->d_remote)));
        }
        return;
      }

      dc->d_tcpConnection = conn; // carry the torch
      dc->setSocket(conn->getFD()); // this is the only time a copy is made of the actual fd
      dc->d_tcp = true;
      dc->setRemote(conn->d_remote); // the address the query was received from
      dc->setSource(conn->d_source); // the address we assume the query is coming from, might be set by proxy protocol
      ComboAddress dest;
      dest.reset();
      dest.sin4.sin_family = conn->d_remote.sin4.sin_family;
      socklen_t len = dest.getSocklen();
      getsockname(conn->getFD(), (sockaddr*)&dest, &len); // if this fails, we're ok with it
      dc->setLocal(dest); // the address we received the query on
      dc->setDestination(conn->d_destination); // the address we assume the query is received on, might be set by proxy protocol
      dc->setMappedSource(conn->d_mappedSource); // the address we assume the query is coming from after table based mapping
      /* we can't move this if we want to be able to access the values in
         all queries sent over this connection */
      dc->d_proxyProtocolValues = conn->proxyProtocolValues;

      struct timeval start;
      Utility::gettimeofday(&start, nullptr);

      DNSName qname;
      uint16_t qtype = 0;
      uint16_t qclass = 0;
      bool needECS = false;
      string requestorId;
      string deviceId;
      string deviceName;
      bool logQuery = false;
      bool qnameParsed = false;

      dc->d_eventTrace.setEnabled(SyncRes::s_event_trace_enabled);
      dc->d_eventTrace.add(RecEventTrace::ReqRecv);
      auto luaconfsLocal = g_luaconfs.getLocal();
      if (checkProtobufExport(luaconfsLocal)) {
        needECS = true;
      }
      logQuery = t_protobufServers.servers && luaconfsLocal->protobufExportConfig.logQueries;
      dc->d_logResponse = t_protobufServers.servers && luaconfsLocal->protobufExportConfig.logResponses;

      if (needECS || (t_pdl && (t_pdl->d_gettag_ffi || t_pdl->d_gettag)) || dc->d_mdp.d_header.opcode == Opcode::Notify) {

        try {
          EDNSOptionViewMap ednsOptions;
          dc->d_ecsParsed = true;
          dc->d_ecsFound = false;
          getQNameAndSubnet(conn->data, &qname, &qtype, &qclass,
                            dc->d_ecsFound, &dc->d_ednssubnet, g_gettagNeedsEDNSOptions ? &ednsOptions : nullptr);
          qnameParsed = true;

          if (t_pdl) {
            try {
              if (t_pdl->d_gettag_ffi) {
                RecursorLua4::FFIParams params(qname, qtype, dc->d_destination, dc->d_source, dc->d_ednssubnet.source, dc->d_data, dc->d_policyTags, dc->d_records, ednsOptions, dc->d_proxyProtocolValues, requestorId, deviceId, deviceName, dc->d_routingTag, dc->d_rcode, dc->d_ttlCap, dc->d_variable, true, logQuery, dc->d_logResponse, dc->d_followCNAMERecords, dc->d_extendedErrorCode, dc->d_extendedErrorExtra, dc->d_responsePaddingDisabled, dc->d_meta);
                dc->d_eventTrace.add(RecEventTrace::LuaGetTagFFI);
                dc->d_tag = t_pdl->gettag_ffi(params);
                dc->d_eventTrace.add(RecEventTrace::LuaGetTagFFI, dc->d_tag, false);
              }
              else if (t_pdl->d_gettag) {
                dc->d_eventTrace.add(RecEventTrace::LuaGetTag);
                dc->d_tag = t_pdl->gettag(dc->d_source, dc->d_ednssubnet.source, dc->d_destination, qname, qtype, &dc->d_policyTags, dc->d_data, ednsOptions, true, requestorId, deviceId, deviceName, dc->d_routingTag, dc->d_proxyProtocolValues);
                dc->d_eventTrace.add(RecEventTrace::LuaGetTag, dc->d_tag, false);
              }
            }
            catch (const std::exception& e) {
              if (g_logCommonErrors) {
                SLOG(g_log << Logger::Warning << "Error parsing a query packet qname='" << qname << "' for tag determination, setting tag=0: " << e.what() << endl,
                     g_slogtcpin->info(Logr::Warning, "Error parsing a query packet for tag determination, setting tag=0", "remote", Logging::Loggable(conn->d_remote), "qname", Logging::Loggable(qname)));
              }
            }
          }
        }
        catch (const std::exception& e) {
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Warning << "Error parsing a query packet for tag determination, setting tag=0: " << e.what() << endl,
                 g_slogtcpin->error(Logr::Warning, e.what(), "Error parsing a query packet for tag determination, setting tag=0", "exception", Logging::Loggable("std::exception"), "remote", Logging::Loggable(conn->d_remote)));
          }
        }
      }

      if (dc->d_tag == 0 && !dc->d_responsePaddingDisabled && g_paddingFrom.match(dc->d_remote)) {
        dc->d_tag = g_paddingTag;
      }

      const dnsheader_aligned headerdata(conn->data.data());
      const struct dnsheader* dh = headerdata.get();

      if (t_protobufServers.servers || t_outgoingProtobufServers.servers) {
        dc->d_requestorId = requestorId;
        dc->d_deviceId = deviceId;
        dc->d_deviceName = deviceName;
        dc->d_uuid = getUniqueID();
      }

      if (t_protobufServers.servers) {
        try {

          if (logQuery && !(luaconfsLocal->protobufExportConfig.taggedOnly && dc->d_policyTags.empty())) {
            protobufLogQuery(luaconfsLocal, dc->d_uuid, dc->d_source, dc->d_destination, dc->d_mappedSource, dc->d_ednssubnet.source, true, dh->id, conn->qlen, qname, qtype, qclass, dc->d_policyTags, dc->d_requestorId, dc->d_deviceId, dc->d_deviceName, dc->d_meta);
          }
        }
        catch (const std::exception& e) {
          if (g_logCommonErrors) {
            SLOG(g_log << Logger::Warning << "Error parsing a TCP query packet for edns subnet: " << e.what() << endl,
                 g_slogtcpin->error(Logr::Warning, e.what(), "Error parsing a TCP query packet for edns subnet", "exception", Logging::Loggable("std::exception"), "remote", Logging::Loggable(conn->d_remote)));
          }
        }
      }

      if (t_pdl) {
        bool ipf = t_pdl->ipfilter(dc->d_source, dc->d_destination, *dh, dc->d_eventTrace);
        if (ipf) {
          if (!g_quiet) {
            SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " [" << MT->getTid() << "/" << MT->numProcesses() << "] DROPPED TCP question from " << dc->d_source.toStringWithPort() << (dc->d_source != dc->d_remote ? " (via " + dc->d_remote.toStringWithPort() + ")" : "") << " based on policy" << endl,
                 g_slogtcpin->info(Logr::Info, "Dropped TCP question based on policy", "remote", Logging::Loggable(conn->d_remote), "source", Logging::Loggable(dc->d_source)));
          }
          t_Counters.at(rec::Counter::policyDrops)++;
          return;
        }
      }

      if (dc->d_mdp.d_header.qr) {
        t_Counters.at(rec::Counter::ignoredCount)++;
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "Ignoring answer from TCP client " << dc->getRemote() << " on server socket!" << endl,
               g_slogtcpin->info(Logr::Error, "Ignoring answer from TCP client on server socket", "remote", Logging::Loggable(dc->getRemote())));
        }
        return;
      }
      if (dc->d_mdp.d_header.opcode != Opcode::Query && dc->d_mdp.d_header.opcode != Opcode::Notify) {
        t_Counters.at(rec::Counter::ignoredCount)++;
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "Ignoring unsupported opcode " << Opcode::to_s(dc->d_mdp.d_header.opcode) << " from TCP client " << dc->getRemote() << " on server socket!" << endl,
               g_slogtcpin->info(Logr::Error, "Ignoring unsupported opcode from TCP client", "remote", Logging::Loggable(dc->getRemote()), "opcode", Logging::Loggable(Opcode::to_s(dc->d_mdp.d_header.opcode))));
        }
        sendErrorOverTCP(dc, RCode::NotImp);
        tcpGuard.keep();
        return;
      }
      else if (dh->qdcount == 0) {
        t_Counters.at(rec::Counter::emptyQueriesCount)++;
        if (g_logCommonErrors) {
          SLOG(g_log << Logger::Error << "Ignoring empty (qdcount == 0) query from " << dc->getRemote() << " on server socket!" << endl,
               g_slogtcpin->info(Logr::Error, "Ignoring empty (qdcount == 0) query on server socket", "remote", Logging::Loggable(dc->getRemote())));
        }
        sendErrorOverTCP(dc, RCode::NotImp);
        tcpGuard.keep();
        return;
      }
      else {
        // We have read a proper query
        //++t_Counters.at(rec::Counter::qcounter);
        ++t_Counters.at(rec::Counter::qcounter);
        ++t_Counters.at(rec::Counter::tcpqcounter);

        if (dc->d_mdp.d_header.opcode == Opcode::Notify) {
          if (!t_allowNotifyFrom || !t_allowNotifyFrom->match(dc->d_mappedSource)) {
            if (!g_quiet) {
              SLOG(g_log << Logger::Error << "[" << MT->getTid() << "] dropping TCP NOTIFY from " << dc->d_mappedSource.toString() << ", address not matched by allow-notify-from" << endl,
                   g_slogtcpin->info(Logr::Error, "Dropping TCP NOTIFY, address not matched by allow-notify-from", "source", Logging::Loggable(dc->d_mappedSource)));
            }

            t_Counters.at(rec::Counter::sourceDisallowedNotify)++;
            return;
          }

          if (!isAllowNotifyForZone(qname)) {
            if (!g_quiet) {
              SLOG(g_log << Logger::Error << "[" << MT->getTid() << "] dropping TCP NOTIFY from " << dc->d_mappedSource.toString() << ", for " << qname.toLogString() << ", zone not matched by allow-notify-for" << endl,
                   g_slogtcpin->info(Logr::Error, "Dropping TCP NOTIFY,  zone not matched by allow-notify-for", "source", Logging::Loggable(dc->d_mappedSource), "zone", Logging::Loggable(qname)));
            }

            t_Counters.at(rec::Counter::zoneDisallowedNotify)++;
            return;
          }
        }

        string response;
        RecursorPacketCache::OptPBData pbData{boost::none};

        if (dc->d_mdp.d_header.opcode == Opcode::Query) {
          /* It might seem like a good idea to skip the packet cache lookup if we know that the answer is not cacheable,
             but it means that the hash would not be computed. If some script decides at a later time to mark back the answer
             as cacheable we would cache it with a wrong tag, so better safe than sorry. */
          dc->d_eventTrace.add(RecEventTrace::PCacheCheck);
          bool cacheHit = checkForCacheHit(qnameParsed, dc->d_tag, conn->data, qname, qtype, qclass, g_now, response, dc->d_qhash, pbData, true, dc->d_source, dc->d_mappedSource);
          dc->d_eventTrace.add(RecEventTrace::PCacheCheck, cacheHit, false);

          if (cacheHit) {
            if (!g_quiet) {
              SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " TCP question answered from packet cache tag=" << dc->d_tag << " from " << dc->d_source.toStringWithPort() << (dc->d_source != dc->d_remote ? " (via " + dc->d_remote.toStringWithPort() + ")" : "") << endl,
                   g_slogtcpin->info(Logr::Notice, "TCP question answered from packet cache", "tag", Logging::Loggable(dc->d_tag),
                                     "qname", Logging::Loggable(qname), "qtype", Logging::Loggable(QType(qtype)),
                                     "source", Logging::Loggable(dc->d_source), "remote", Logging::Loggable(dc->d_remote)));
            }

            bool hadError = sendResponseOverTCP(dc, response);
            finishTCPReply(dc, hadError, false);
            struct timeval now;
            Utility::gettimeofday(&now, nullptr);
            uint64_t spentUsec = uSec(now - start);
            t_Counters.at(rec::Histogram::cumulativeAnswers)(spentUsec);
            dc->d_eventTrace.add(RecEventTrace::AnswerSent);

            if (t_protobufServers.servers && dc->d_logResponse && !(luaconfsLocal->protobufExportConfig.taggedOnly && pbData && !pbData->d_tagged)) {
              struct timeval tv
              {
                0, 0
              };
              protobufLogResponse(dh, luaconfsLocal, pbData, tv, true, dc->d_source, dc->d_destination, dc->d_mappedSource, dc->d_ednssubnet, dc->d_uuid, dc->d_requestorId, dc->d_deviceId, dc->d_deviceName, dc->d_meta, dc->d_eventTrace);
            }

            if (dc->d_eventTrace.enabled() && SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_log) {
              SLOG(g_log << Logger::Info << dc->d_eventTrace.toString() << endl,
                   g_slogtcpin->info(Logr::Info, dc->d_eventTrace.toString())); // More fancy?
            }
            tcpGuard.keep();
            t_Counters.updateSnap(g_regressionTestMode);
            return;
          } // cache hit
        } // query opcode

        if (dc->d_mdp.d_header.opcode == Opcode::Notify) {
          if (!g_quiet) {
            SLOG(g_log << Logger::Notice << RecThreadInfo::id() << " got NOTIFY for " << qname.toLogString() << " from " << dc->d_source.toStringWithPort() << (dc->d_source != dc->d_remote ? " (via " + dc->d_remote.toStringWithPort() + ")" : "") << endl,
                 g_slogtcpin->info(Logr::Notice, "Got NOTIFY", "qname", Logging::Loggable(qname), "source", Logging::Loggable(dc->d_source), "remote", Logging::Loggable(dc->d_remote)));
          }

          requestWipeCaches(qname);

          // the operation will now be treated as a Query, generating
          // a normal response, as the rest of the code does not
          // check dh->opcode, but we need to ensure that the response
          // to this request does not get put into the packet cache
          dc->d_variable = true;
        }

        // setup for startDoResolve() in an mthread
        ++conn->d_requestsInFlight;
        if (conn->d_requestsInFlight >= TCPConnection::s_maxInFlight) {
          t_fdm->removeReadFD(fd); // should no longer awake ourselves when there is data to read
        }
        else {
          Utility::gettimeofday(&g_now, nullptr); // needed?
          struct timeval ttd = g_now;
          t_fdm->setReadTTD(fd, ttd, g_tcpTimeout);
        }
        tcpGuard.keep();
        MT->makeThread(startDoResolve, dc.release()); // deletes dc
      } // good query
    } // read full query
  } // reading query

  // more to come
  tcpGuard.keep();
}

//! Handle new incoming TCP connection
void handleNewTCPQuestion(int fd, FDMultiplexer::funcparam_t&)
{
  ComboAddress addr;
  socklen_t addrlen = sizeof(addr);
  int newsock = accept(fd, (struct sockaddr*)&addr, &addrlen);
  if (newsock >= 0) {
    if (MT->numProcesses() > g_maxMThreads) {
      t_Counters.at(rec::Counter::overCapacityDrops)++;
      try {
        closesocket(newsock);
      }
      catch (const PDNSException& e) {
        SLOG(g_log << Logger::Error << "Error closing TCP socket after an over capacity drop: " << e.reason << endl,
             g_slogtcpin->error(Logr::Error, e.reason, "Error closing TCP socket after an over capacity drop", "exception", Logging::Loggable("PDNSException")));
      }
      return;
    }

    if (t_remotes) {
      t_remotes->push_back(addr);
    }

    bool fromProxyProtocolSource = expectProxyProtocol(addr);
    ComboAddress mappedSource = addr;
    if (!fromProxyProtocolSource && t_proxyMapping) {
      if (auto it = t_proxyMapping->lookup(addr)) {
        mappedSource = it->second.address;
        ++it->second.stats.netmaskMatches;
      }
    }
    if (!fromProxyProtocolSource && t_allowFrom && !t_allowFrom->match(&mappedSource)) {
      if (!g_quiet)
        SLOG(g_log << Logger::Error << "[" << MT->getTid() << "] dropping TCP query from " << mappedSource.toString() << ", address neither matched by allow-from nor proxy-protocol-from" << endl,
             g_slogtcpin->info(Logr::Error, "dropping TCP query address neither matched by allow-from nor proxy-protocol-from", "source", Logging::Loggable(mappedSource)));

      t_Counters.at(rec::Counter::unauthorizedTCP)++;
      try {
        closesocket(newsock);
      }
      catch (const PDNSException& e) {
        SLOG(g_log << Logger::Error << "Error closing TCP socket after an ACL drop: " << e.reason << endl,
             g_slogtcpin->error(Logr::Error, e.reason, "Error closing TCP socket after an ACL drop", "exception", Logging::Loggable("PDNSException")));
      }
      return;
    }

    if (g_maxTCPPerClient && t_tcpClientCounts->count(addr) && (*t_tcpClientCounts)[addr] >= g_maxTCPPerClient) {
      t_Counters.at(rec::Counter::tcpClientOverflow)++;
      try {
        closesocket(newsock); // don't call TCPConnection::closeAndCleanup here - did not enter it in the counts yet!
      }
      catch (const PDNSException& e) {
        SLOG(g_log << Logger::Error << "Error closing TCP socket after an overflow drop: " << e.reason << endl,
             g_slogtcpin->error(Logr::Error, e.reason, "Error closing TCP socket after an overflow drop", "exception", Logging::Loggable("PDNSException")));
      }
      return;
    }

    setNonBlocking(newsock);
    setTCPNoDelay(newsock);
    std::shared_ptr<TCPConnection> tc = std::make_shared<TCPConnection>(newsock, addr);
    tc->d_source = addr;
    tc->d_destination.reset();
    tc->d_destination.sin4.sin_family = addr.sin4.sin_family;
    socklen_t len = tc->d_destination.getSocklen();
    getsockname(tc->getFD(), reinterpret_cast<sockaddr*>(&tc->d_destination), &len); // if this fails, we're ok with it
    tc->d_mappedSource = mappedSource;

    if (fromProxyProtocolSource) {
      tc->proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
      tc->data.resize(tc->proxyProtocolNeed);
      tc->state = TCPConnection::PROXYPROTOCOLHEADER;
    }
    else {
      tc->state = TCPConnection::BYTE0;
    }

    struct timeval ttd;
    Utility::gettimeofday(&ttd, nullptr);
    ttd.tv_sec += g_tcpTimeout;

    t_fdm->addReadFD(tc->getFD(), handleRunningTCPQuestion, tc, &ttd);
  }
}

static void TCPIOHandlerIO(int fd, FDMultiplexer::funcparam_t& var);

static void TCPIOHandlerStateChange(IOState oldstate, IOState newstate, std::shared_ptr<PacketID>& pid)
{
  TCPLOG(pid->tcpsock, "State transation " << int(oldstate) << "->" << int(newstate) << endl);

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

static void TCPIOHandlerIO(int fd, FDMultiplexer::funcparam_t& var)
{
  std::shared_ptr<PacketID> pid = boost::any_cast<std::shared_ptr<PacketID>>(var);
  assert(pid->tcphandler);
  assert(fd == pid->tcphandler->getDescriptor());
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
          MT->sendEvent(pid, &pid->inMSG);
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
      MT->sendEvent(pid, &empty); // this conveys error status
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
        MT->sendEvent(pid, &pid->outMSG); // send back what we sent to convey everything is ok
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
      MT->sendEvent(pid, &sent); // we convey error status by sending empty string
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
      SLOG(g_log << Logger::Error << "tcp-fast-open-connect enabled but net.ipv4.tcp_fastopen does not allow it" << endl,
           log->info(Logr::Error, "tcp-fast-open-connect enabled but net.ipv4.tcp_fastopen does not allow it"));
    }
    if (!active && !(flag & 2)) {
      SLOG(g_log << Logger::Error << "tcp-fast-open enabled but net.ipv4.tcp_fastopen does not allow it" << endl,
           log->info(Logr::Error, "tcp-fast-open enabled but net.ipv4.tcp_fastopen does not allow it"));
    }
  }
  else {
    SLOG(g_log << Logger::Notice << "Cannot determine if kernel settings allow fast-open" << endl,
         log->info(Logr::Notice, "Cannot determine if kernel settings allow fast-open"));
  }
#else
  SLOG(g_log << Logger::Notice << "Cannot determine if kernel settings allow fast-open" << endl,
       log->info(Logr::Notice, "Cannot determine if kernel settings allow fast-open"));
#endif
}

void checkTFOconnect(Logr::log_t log)
{
  try {
    Socket s(AF_INET, SOCK_STREAM);
    s.setNonBlocking();
    s.setFastOpenConnect();
  }
  catch (const NetworkError& e) {
    SLOG(g_log << Logger::Error << "tcp-fast-open-connect enabled but returned error: " << e.what() << endl,
         log->error(Logr::Error, e.what(), "tcp-fast-open-connect enabled but returned error"));
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

  IOState state;
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
  int ret = MT->waitEvent(pident, &packet, g_networkTimeoutMsec);
  TCPLOG(pident->tcpsock, "asendtcp waitEvent returned " << ret << ' ' << packet.size() << '/' << data.size() << ' ');
  if (ret == 0) {
    TCPLOG(pident->tcpsock, "timeout" << endl);
    TCPIOHandlerStateChange(pident->lowState, IOState::Done, pident);
    return LWResult::Result::Timeout;
  }
  else if (ret == -1) { // error
    TCPLOG(pident->tcpsock, "PermanentError" << endl);
    TCPIOHandlerStateChange(pident->lowState, IOState::Done, pident);
    return LWResult::Result::PermanentError;
  }
  else if (packet.size() != data.size()) { // main loop tells us what it sent out, or empty in case of an error
    // fd housekeeping done by TCPIOHandlerIO
    TCPLOG(pident->tcpsock, "PermanentError size mismatch" << endl);
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
  IOState state;
  try {
    TCPLOG(handler->getDescriptor(), "calling tryRead() " << len << endl);
    state = handler->tryRead(data, pos, len);
    TCPLOG(handler->getDescriptor(), "arcvtcp tryRead() returned " << int(state) << ' ' << pos << '/' << len << endl);
    switch (state) {
    case IOState::Done:
    case IOState::NeedRead:
      if (pos == len || (incompleteOkay && pos > 0)) {
        data.resize(pos);
        TCPLOG(handler->getDescriptor(), "acecvtcp success A" << endl);
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

  int ret = MT->waitEvent(pident, &data, g_networkTimeoutMsec);
  TCPLOG(pident->tcpsock, "arecvtcp " << ret << ' ' << data.size() << ' ');
  if (ret == 0) {
    TCPLOG(pident->tcpsock, "timeout" << endl);
    TCPIOHandlerStateChange(pident->lowState, IOState::Done, pident);
    return LWResult::Result::Timeout;
  }
  else if (ret == -1) {
    TCPLOG(pident->tcpsock, "PermanentError" << endl);
    TCPIOHandlerStateChange(pident->lowState, IOState::Done, pident);
    return LWResult::Result::PermanentError;
  }
  else if (data.empty()) { // error, EOF or other
    // fd housekeeping done by TCPIOHandlerIO
    TCPLOG(pident->tcpsock, "EOF" << endl);
    return LWResult::Result::PermanentError;
  }

  TCPLOG(pident->tcpsock, "arecvtcp success" << endl);
  return LWResult::Result::Success;
}

void makeTCPServerSockets(deferredAdd_t& deferredAdds, std::set<int>& tcpSockets, Logr::log_t log)
{
  vector<string> localAddresses;
  stringtok(localAddresses, ::arg()["local-address"], " ,");

  if (localAddresses.empty()) {
    throw PDNSException("No local address specified");
  }

#ifdef TCP_DEFER_ACCEPT
  auto first = true;
#endif
  const uint16_t defaultLocalPort = ::arg().asNum("local-port");
  for (const auto& localAddress : localAddresses) {
    ComboAddress address{localAddress, defaultLocalPort};
    const int socketFd = socket(address.sin6.sin6_family, SOCK_STREAM, 0);
    if (socketFd < 0) {
      throw PDNSException("Making a TCP server socket for resolver: " + stringerror());
    }

    setCloseOnExec(socketFd);

    int tmp = 1;
    if (setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof tmp) < 0) {
      int err = errno;
      SLOG(g_log << Logger::Error << "Setsockopt failed for TCP listening socket" << endl,
           log->error(Logr::Critical, err, "Setsockopt failed for TCP listening socket"));
      exit(1);
    }
    if (address.sin6.sin6_family == AF_INET6 && setsockopt(socketFd, IPPROTO_IPV6, IPV6_V6ONLY, &tmp, sizeof(tmp)) < 0) {
      int err = errno;
      SLOG(g_log << Logger::Error << "Failed to set IPv6 socket to IPv6 only, continuing anyhow: " << strerror(err) << endl,
           log->error(Logr::Error, err, "Failed to set IPv6 socket to IPv6 only, continuing anyhow"));
    }

#ifdef TCP_DEFER_ACCEPT
    if (setsockopt(socketFd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &tmp, sizeof tmp) >= 0) {
      if (first) {
        SLOG(g_log << Logger::Info << "Enabled TCP data-ready filter for (slight) DoS protection" << endl,
             log->info(Logr::Info, "Enabled TCP data-ready filter for (slight) DoS protection"));
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
        SLOG(g_log << Logger::Error << "Failed to enable TCP Fast Open for listening socket: " << strerror(err) << endl,
             log->error(Logr::Error, err, "Failed to enable TCP Fast Open for listening socket"));
      }
#else
      SLOG(g_log << Logger::Warning << "TCP Fast Open configured but not supported for listening socket" << endl,
           log->info(Logr::Warning, "TCP Fast Open configured but not supported for listening socket"));
#endif
    }

    socklen_t socklen = address.sin4.sin_family == AF_INET ? sizeof(address.sin4) : sizeof(address.sin6);
    if (::bind(socketFd, (struct sockaddr*)&address, socklen) < 0) {
      throw PDNSException("Binding TCP server socket for " + address.toStringWithPort() + ": " + stringerror());
    }

    setNonBlocking(socketFd);
    try {
      setSocketSendBuffer(socketFd, 65000);
    }
    catch (const std::exception& e) {
      SLOG(g_log << Logger::Error << e.what() << endl,
           log->error(Logr::Error, e.what(), "Exception while setting socket send buffer"));
    }

    listen(socketFd, 128);
    deferredAdds.emplace_back(socketFd, handleNewTCPQuestion);
    tcpSockets.insert(socketFd);

    // we don't need to update g_listenSocketsAddresses since it doesn't work for TCP/IP:
    //  - fd is not that which we know here, but returned from accept()
    SLOG(g_log << Logger::Info << "Listening for TCP queries on " << address.toStringWithPort() << endl,
         log->info(Logr::Info, "Listening for queries", "protocol", Logging::Loggable("TCP"), "address", Logging::Loggable(address)));

#ifdef TCP_DEFER_ACCEPT
    first = false;
#endif
  }
}
