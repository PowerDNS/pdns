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
#pragma once

#include <unistd.h>
#include "iputils.hh"
#include "dnsdist.hh"

struct ConnectionInfo
{
  ConnectionInfo(ClientState* cs_) :
    cs(cs_), fd(-1)
  {
  }
  ConnectionInfo(ClientState* cs_, const ComboAddress remote_) :
    remote(remote_), cs(cs_), fd(-1)
  {
  }
  ConnectionInfo(ConnectionInfo&& rhs) :
    remote(rhs.remote), cs(rhs.cs), fd(rhs.fd)
  {
    rhs.cs = nullptr;
    rhs.fd = -1;
  }

  ConnectionInfo(const ConnectionInfo& rhs) = delete;
  ConnectionInfo& operator=(const ConnectionInfo& rhs) = delete;

  ConnectionInfo& operator=(ConnectionInfo&& rhs)
  {
    remote = rhs.remote;
    cs = rhs.cs;
    rhs.cs = nullptr;
    fd = rhs.fd;
    rhs.fd = -1;
    return *this;
  }

  ~ConnectionInfo()
  {
    if (fd != -1) {
      close(fd);
      fd = -1;
    }

    if (cs) {
      --cs->tcpCurrentConnections;
    }
  }

  ComboAddress remote;
  ClientState* cs{nullptr};
  int fd{-1};
};

struct InternalQuery
{
  InternalQuery()
  {
  }

  InternalQuery(PacketBuffer&& buffer, IDState&& state) :
    d_idstate(std::move(state)), d_buffer(std::move(buffer))
  {
  }

  InternalQuery(InternalQuery&& rhs) :
    d_idstate(std::move(rhs.d_idstate)), d_buffer(std::move(rhs.d_buffer)), d_proxyProtocolPayload(std::move(rhs.d_proxyProtocolPayload)), d_xfrMasterSerial(rhs.d_xfrMasterSerial), d_xfrSerialCount(rhs.d_xfrSerialCount), d_downstreamFailures(rhs.d_downstreamFailures), d_xfrMasterSerialCount(rhs.d_xfrMasterSerialCount), d_proxyProtocolPayloadAdded(rhs.d_proxyProtocolPayloadAdded)
  {
  }
  InternalQuery& operator=(InternalQuery&& rhs)
  {
    d_idstate = std::move(rhs.d_idstate);
    d_buffer = std::move(rhs.d_buffer);
    d_proxyProtocolPayload = std::move(rhs.d_proxyProtocolPayload);
    d_xfrMasterSerial = rhs.d_xfrMasterSerial;
    d_xfrSerialCount = rhs.d_xfrSerialCount;
    d_downstreamFailures = rhs.d_downstreamFailures;
    d_xfrMasterSerialCount = rhs.d_xfrMasterSerialCount;
    d_proxyProtocolPayloadAdded = rhs.d_proxyProtocolPayloadAdded;
    return *this;
  }

  InternalQuery(const InternalQuery& rhs) = delete;
  InternalQuery& operator=(const InternalQuery& rhs) = delete;

  bool isXFR() const
  {
    return d_idstate.qtype == QType::AXFR || d_idstate.qtype == QType::IXFR;
  }

  IDState d_idstate;
  PacketBuffer d_buffer;
  std::string d_proxyProtocolPayload;
  uint32_t d_xfrMasterSerial{0};
  uint32_t d_xfrSerialCount{0};
  uint32_t d_downstreamFailures{0};
  uint8_t d_xfrMasterSerialCount{0};
  bool d_xfrStarted{false};
  bool d_proxyProtocolPayloadAdded{false};
};

using TCPQuery = InternalQuery;

class TCPConnectionToBackend;

struct TCPResponse : public TCPQuery
{
  TCPResponse()
  {
    /* let's make Coverity happy */
    memset(&d_cleartextDH, 0, sizeof(d_cleartextDH));
  }

  TCPResponse(PacketBuffer&& buffer, IDState&& state, std::shared_ptr<TCPConnectionToBackend> conn) :
    TCPQuery(std::move(buffer), std::move(state)), d_connection(conn)
  {
    memset(&d_cleartextDH, 0, sizeof(d_cleartextDH));
  }

  std::shared_ptr<TCPConnectionToBackend> d_connection{nullptr};
  dnsheader d_cleartextDH;
  bool d_selfGenerated{false};
};

class TCPQuerySender
{
public:
  virtual ~TCPQuerySender()
  {
  }

  virtual bool active() const = 0;
  virtual const ClientState* getClientState() const = 0;
  virtual void handleResponse(const struct timeval& now, TCPResponse&& response) = 0;
  virtual void handleXFRResponse(const struct timeval& now, TCPResponse&& response) = 0;
  virtual void notifyIOError(IDState&& query, const struct timeval& now) = 0;

  /* whether the connection should be automatically released to the pool after handleResponse()
     has been called */
  bool releaseConnection() const
  {
    return d_releaseConnection;
  }

protected:
  bool d_releaseConnection{true};
};

struct CrossProtocolQuery
{
  CrossProtocolQuery()
  {
  }

  CrossProtocolQuery(CrossProtocolQuery&& rhs) = delete;
  virtual ~CrossProtocolQuery()
  {
  }

  virtual std::shared_ptr<TCPQuerySender> getTCPQuerySender() = 0;

  InternalQuery query;
  std::shared_ptr<DownstreamState> downstream{nullptr};
  size_t proxyProtocolPayloadSize{0};
  bool isXFR{false};
};

class TCPClientCollection
{
public:
  TCPClientCollection(size_t maxThreads);

  int getThread()
  {
    if (d_numthreads == 0) {
      throw std::runtime_error("No TCP worker thread yet");
    }

    uint64_t pos = d_pos++;
    ++d_queued;
    return d_tcpclientthreads.at(pos % d_numthreads).d_newConnectionPipe.getHandle();
  }

  bool passConnectionToThread(std::unique_ptr<ConnectionInfo>&& conn)
  {
    if (d_numthreads == 0) {
      throw std::runtime_error("No TCP worker thread yet");
    }

    uint64_t pos = d_pos++;
    auto pipe = d_tcpclientthreads.at(pos % d_numthreads).d_newConnectionPipe.getHandle();
    auto tmp = conn.release();

    if (write(pipe, &tmp, sizeof(tmp)) != sizeof(tmp)) {
      ++g_stats.tcpQueryPipeFull;
      delete tmp;
      tmp = nullptr;
      return false;
    }
    ++d_queued;
    return true;
  }

  bool passCrossProtocolQueryToThread(std::unique_ptr<CrossProtocolQuery>&& cpq)
  {
    if (d_numthreads == 0) {
      throw std::runtime_error("No TCP worker thread yet");
    }

    uint64_t pos = d_pos++;
    auto pipe = d_tcpclientthreads.at(pos % d_numthreads).d_crossProtocolQueriesPipe.getHandle();
    auto tmp = cpq.release();

    if (write(pipe, &tmp, sizeof(tmp)) != sizeof(tmp)) {
      ++g_stats.tcpCrossProtocolQueryPipeFull;
      delete tmp;
      tmp = nullptr;
      return false;
    }

    return true;
  }

  bool hasReachedMaxThreads() const
  {
    return d_numthreads >= d_maxthreads;
  }

  uint64_t getThreadsCount() const
  {
    return d_numthreads;
  }

  uint64_t getQueuedCount() const
  {
    return d_queued;
  }

  void decrementQueuedCount()
  {
    --d_queued;
  }

private:
  void addTCPClientThread();

  struct TCPWorkerThread
  {
    TCPWorkerThread()
    {
    }

    TCPWorkerThread(int newConnPipe, int crossProtocolQueriesPipe, int crossProtocolResponsesPipe) :
      d_newConnectionPipe(newConnPipe), d_crossProtocolQueriesPipe(crossProtocolQueriesPipe), d_crossProtocolResponsesPipe(crossProtocolResponsesPipe)
    {
    }

    TCPWorkerThread(TCPWorkerThread&& rhs) = default;
    TCPWorkerThread& operator=(TCPWorkerThread&& rhs) = default;
    TCPWorkerThread(const TCPWorkerThread& rhs) = delete;
    TCPWorkerThread& operator=(const TCPWorkerThread&) = delete;

    FDWrapper d_newConnectionPipe;
    FDWrapper d_crossProtocolQueriesPipe;
    FDWrapper d_crossProtocolResponsesPipe;
  };

  std::vector<TCPWorkerThread> d_tcpclientthreads;
  stat_t d_numthreads{0};
  stat_t d_pos{0};
  stat_t d_queued{0};
  const uint64_t d_maxthreads{0};
};

extern std::unique_ptr<TCPClientCollection> g_tcpclientthreads;
