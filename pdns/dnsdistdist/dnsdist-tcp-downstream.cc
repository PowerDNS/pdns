
#include "dnsdist-session-cache.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-tcp-upstream.hh"

#include "dnsparser.hh"

thread_local DownstreamTCPConnectionsManager t_downstreamTCPConnectionsManager;

ConnectionToBackend::~ConnectionToBackend()
{
  if (d_ds && d_handler) {
    --d_ds->tcpCurrentConnections;
    struct timeval now;
    gettimeofday(&now, nullptr);

    if (d_handler->isTLS()) {
      if (d_handler->hasTLSSessionBeenResumed()) {
        ++d_ds->tlsResumptions;
      }
      try {
        auto sessions = d_handler->getTLSSessions();
        if (!sessions.empty()) {
          g_sessionCache.putSessions(d_ds->getID(), now.tv_sec, std::move(sessions));
        }
      }
      catch (const std::exception& e) {
        vinfolog("Unable to get a TLS session: %s", e.what());
      }
    }
    auto diff = now - d_connectionStartTime;
    // cerr<<"connection to backend terminated after "<<d_queries<<" queries, "<<diff.tv_sec<<" seconds"<<endl;
    d_ds->updateTCPMetrics(d_queries, diff.tv_sec * 1000 + diff.tv_usec / 1000);
  }
}

bool ConnectionToBackend::reconnect()
{
  std::unique_ptr<TLSSession> tlsSession{nullptr};
  if (d_handler) {
    DEBUGLOG("closing socket "<<d_handler->getDescriptor());
    if (d_handler->isTLS()) {
      if (d_handler->hasTLSSessionBeenResumed()) {
        ++d_ds->tlsResumptions;
      }
      try {
        auto sessions = d_handler->getTLSSessions();
        if (!sessions.empty()) {
          tlsSession = std::move(sessions.back());
          sessions.pop_back();
          if (!sessions.empty()) {
            g_sessionCache.putSessions(d_ds->getID(), time(nullptr), std::move(sessions));
          }
        }
      }
      catch (const std::exception& e) {
        vinfolog("Unable to get a TLS session to resume: %s", e.what());
      }
    }
    d_handler->close();
    d_ioState.reset();
    d_handler.reset();
    --d_ds->tcpCurrentConnections;
  }

  d_fresh = true;
  d_highestStreamID = 0;
  d_proxyProtocolPayloadSent = false;

  do {
    vinfolog("TCP connecting to downstream %s (%d)", d_ds->getNameWithAddr(), d_downstreamFailures);
    DEBUGLOG("Opening TCP connection to backend "<<d_ds->getNameWithAddr());
    ++d_ds->tcpNewConnections;
    try {
      auto socket = std::make_unique<Socket>(d_ds->remote.sin4.sin_family, SOCK_STREAM, 0);
      DEBUGLOG("result of socket() is "<<socket->getHandle());

      if (!IsAnyAddress(d_ds->sourceAddr)) {
        SSetsockopt(socket->getHandle(), SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef IP_BIND_ADDRESS_NO_PORT
        if (d_ds->ipBindAddrNoPort) {
          SSetsockopt(socket->getHandle(), SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
        }
#endif
#ifdef SO_BINDTODEVICE
        if (!d_ds->sourceItfName.empty()) {
          int res = setsockopt(socket->getHandle(), SOL_SOCKET, SO_BINDTODEVICE, d_ds->sourceItfName.c_str(), d_ds->sourceItfName.length());
          if (res != 0) {
            vinfolog("Error setting up the interface on backend TCP socket '%s': %s", d_ds->getNameWithAddr(), stringerror());
          }
        }
#endif
        socket->bind(d_ds->sourceAddr, false);
      }
      socket->setNonBlocking();

      gettimeofday(&d_connectionStartTime, nullptr);
      auto handler = std::make_unique<TCPIOHandler>(d_ds->d_tlsSubjectName, socket->releaseHandle(), timeval{0,0}, d_ds->d_tlsCtx, d_connectionStartTime.tv_sec);
      if (!tlsSession && d_ds->d_tlsCtx) {
        tlsSession = g_sessionCache.getSession(d_ds->getID(), d_connectionStartTime.tv_sec);
      }
      if (tlsSession) {
        handler->setTLSSession(tlsSession);
      }
      handler->tryConnect(d_ds->tcpFastOpen && isFastOpenEnabled(), d_ds->remote);
      d_queries = 0;

      d_handler = std::move(handler);
      d_ds->incCurrentConnectionsCount();
      return true;
    }
    catch (const std::runtime_error& e) {
      vinfolog("Connection to downstream server %s failed: %s", d_ds->getName(), e.what());
      d_downstreamFailures++;
      if (d_downstreamFailures >= d_ds->d_retries) {
        throw;
      }
    }
  }
  while (d_downstreamFailures < d_ds->d_retries);

  return false;
}

TCPConnectionToBackend::~TCPConnectionToBackend()
{
  if (d_ds && !d_pendingResponses.empty()) {
    d_ds->outstanding -= d_pendingResponses.size();
  }
}

void TCPConnectionToBackend::release()
{
  d_ds->outstanding -= d_pendingResponses.size();

  d_pendingResponses.clear();
  d_pendingQueries.clear();

  if (d_ioState) {
    d_ioState.reset();
  }
}

static void editPayloadID(PacketBuffer& payload, uint16_t newId, size_t proxyProtocolPayloadSize, bool sizePrepended)
{
  /* we cannot do a direct cast as the alignment might be off (the size of the payload might have been prepended, which is bad enough,
     but we might also have a proxy protocol payload */
  size_t startOfHeaderOffset = (sizePrepended ? sizeof(uint16_t) : 0) + proxyProtocolPayloadSize;
  if (payload.size() < startOfHeaderOffset + sizeof(dnsheader)) {
    throw std::runtime_error("Invalid buffer for outgoing TCP query (size " + std::to_string(payload.size()));
  }
  uint16_t id = htons(newId);
  memcpy(&payload.at(startOfHeaderOffset), &id, sizeof(id));
}

enum class QueryState : uint8_t {
  hasSizePrepended,
  noSize
};

enum class ConnectionState : uint8_t {
  needProxy,
  proxySent
};

static void prepareQueryForSending(TCPQuery& query, uint16_t id, QueryState queryState, ConnectionState connectionState)
{
  if (connectionState == ConnectionState::needProxy) {
    if (query.d_proxyProtocolPayload.size() > 0 && !query.d_proxyProtocolPayloadAdded) {
      query.d_buffer.insert(query.d_buffer.begin(), query.d_proxyProtocolPayload.begin(), query.d_proxyProtocolPayload.end());
      query.d_proxyProtocolPayloadAdded = true;
    }
  }
  else if (connectionState == ConnectionState::proxySent) {
    if (query.d_proxyProtocolPayloadAdded) {
      if (query.d_buffer.size() < query.d_proxyProtocolPayload.size()) {
        throw std::runtime_error("Trying to remove a proxy protocol payload of size " + std::to_string(query.d_proxyProtocolPayload.size()) + " from a buffer of size " + std::to_string(query.d_buffer.size()));
      }
      query.d_buffer.erase(query.d_buffer.begin(), query.d_buffer.begin() + query.d_proxyProtocolPayload.size());
      query.d_proxyProtocolPayloadAdded = false;
    }
  }

  editPayloadID(query.d_buffer, id, query.d_proxyProtocolPayloadAdded ? query.d_proxyProtocolPayload.size() : 0, true);
}

IOState TCPConnectionToBackend::queueNextQuery(std::shared_ptr<TCPConnectionToBackend>& conn)
{
  conn->d_currentQuery = std::move(conn->d_pendingQueries.front());

  uint16_t id = conn->d_highestStreamID;
  prepareQueryForSending(conn->d_currentQuery.d_query, id, QueryState::hasSizePrepended, conn->needProxyProtocolPayload() ? ConnectionState::needProxy : ConnectionState::proxySent);

  conn->d_pendingQueries.pop_front();
  conn->d_state = State::sendingQueryToBackend;
  conn->d_currentPos = 0;

  return IOState::NeedWrite;
}

IOState TCPConnectionToBackend::sendQuery(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now)
{
  DEBUGLOG("sending query to backend "<<conn->getDS()->getName()<<" over FD "<<conn->d_handler->getDescriptor());

  IOState state = conn->d_handler->tryWrite(conn->d_currentQuery.d_query.d_buffer, conn->d_currentPos, conn->d_currentQuery.d_query.d_buffer.size());

  if (state != IOState::Done) {
    return state;
  }

  DEBUGLOG("query sent to backend");
  /* request sent ! */
  if (conn->d_currentQuery.d_query.d_proxyProtocolPayloadAdded) {
    conn->d_proxyProtocolPayloadSent = true;
  }
  ++conn->d_queries;
  conn->d_currentPos = 0;

  DEBUGLOG("adding a pending response for ID "<<conn->d_highestStreamID<<" and QNAME "<<conn->d_currentQuery.d_query.d_idstate.qname);
  auto res = conn->d_pendingResponses.insert({conn->d_highestStreamID, std::move(conn->d_currentQuery)});
  /* if there was already a pending response with that ID, we messed up and we don't expect more
     than one response */
  if (res.second) {
    ++conn->d_ds->outstanding;
  }
  ++conn->d_highestStreamID;
  conn->d_currentQuery.d_sender.reset();
  conn->d_currentQuery.d_query.d_buffer.clear();

  return state;
}

void TCPConnectionToBackend::handleIO(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now)
{
  if (conn->d_handler == nullptr) {
    throw std::runtime_error("No downstream socket in " + std::string(__PRETTY_FUNCTION__) + "!");
  }

  bool connectionDied = false;
  IOState iostate = IOState::Done;
  IOStateGuard ioGuard(conn->d_ioState);
  bool reconnected = false;

  do {
    reconnected = false;

    try {
      if (conn->d_state == State::sendingQueryToBackend) {
        iostate = sendQuery(conn, now);

        while (iostate == IOState::Done && !conn->d_pendingQueries.empty()) {
          queueNextQuery(conn);
          iostate = sendQuery(conn, now);
        }

        if (iostate == IOState::Done && conn->d_pendingQueries.empty()) {
          conn->d_state = State::waitingForResponseFromBackend;
          conn->d_currentPos = 0;
          conn->d_responseBuffer.resize(sizeof(uint16_t));
          iostate = IOState::NeedRead;
        }
      }

      if (conn->d_state == State::waitingForResponseFromBackend ||
          conn->d_state == State::readingResponseSizeFromBackend) {
        DEBUGLOG("reading response size from backend");
        // then we need to allocate a new buffer (new because we might need to re-send the query if the
        // backend dies on us)
        // We also might need to read and send to the client more than one response in case of XFR (yeah!)
        conn->d_responseBuffer.resize(sizeof(uint16_t));
        iostate = conn->d_handler->tryRead(conn->d_responseBuffer, conn->d_currentPos, sizeof(uint16_t));
        if (iostate == IOState::Done) {
          DEBUGLOG("got response size from backend");
          conn->d_state = State::readingResponseFromBackend;
          conn->d_responseSize = conn->d_responseBuffer.at(0) * 256 + conn->d_responseBuffer.at(1);
          conn->d_responseBuffer.reserve(conn->d_responseSize + /* we will need to prepend the size later */ 2);
          conn->d_responseBuffer.resize(conn->d_responseSize);
          conn->d_currentPos = 0;
          conn->d_lastDataReceivedTime = now;
        }
        else if (conn->d_state == State::waitingForResponseFromBackend && conn->d_currentPos > 0) {
          conn->d_state = State::readingResponseSizeFromBackend;
        }
      }

      if (conn->d_state == State::readingResponseFromBackend) {
        DEBUGLOG("reading response from backend");
        iostate = conn->d_handler->tryRead(conn->d_responseBuffer, conn->d_currentPos, conn->d_responseSize);
        if (iostate == IOState::Done) {
          DEBUGLOG("got response from backend");
          try {
            conn->d_lastDataReceivedTime = now;
            iostate = conn->handleResponse(conn, now);
          }
          catch (const std::exception& e) {
            vinfolog("Got an exception while handling TCP response from %s (client is %s): %s", conn->d_ds ? conn->d_ds->getName() : "unknown", conn->d_currentQuery.d_query.d_idstate.origRemote.toStringWithPort(), e.what());
            ioGuard.release();
            conn->release();
            return;
          }
        }
      }

      if (conn->d_state != State::idle &&
          conn->d_state != State::sendingQueryToBackend &&
          conn->d_state != State::waitingForResponseFromBackend &&
          conn->d_state != State::readingResponseSizeFromBackend &&
          conn->d_state != State::readingResponseFromBackend) {
        vinfolog("Unexpected state %d in TCPConnectionToBackend::handleIO", static_cast<int>(conn->d_state));
      }
    }
    catch (const std::exception& e) {
      /* most likely an EOF because the other end closed the connection,
         but it might also be a real IO error or something else.
         Let's just drop the connection
      */
      vinfolog("Got an exception while handling (%s backend) TCP query from %s: %s", (conn->d_state == State::sendingQueryToBackend ? "writing to" : "reading from"), conn->d_currentQuery.d_query.d_idstate.origRemote.toStringWithPort(), e.what());

      if (conn->d_state == State::sendingQueryToBackend) {
        ++conn->d_ds->tcpDiedSendingQuery;
      }
      else if (conn->d_state != State::idle) {
        ++conn->d_ds->tcpDiedReadingResponse;
      }

      /* don't increase this counter when reusing connections */
      if (conn->d_fresh) {
        ++conn->d_downstreamFailures;
      }

      /* remove this FD from the IO multiplexer */
      iostate = IOState::Done;
      connectionDied = true;
    }

    if (connectionDied) {

      DEBUGLOG("connection died, number of failures is "<<conn->d_downstreamFailures<<", retries is "<<conn->d_ds->d_retries);

      if (conn->d_downstreamFailures < conn->d_ds->d_retries) {

        conn->d_ioState.reset();
        ioGuard.release();

        try {
          if (conn->reconnect()) {
            conn->d_ioState = make_unique<IOStateHandler>(*conn->d_mplexer, conn->d_handler->getDescriptor());

            /* we need to resend the queries that were in flight, if any */
            if (conn->d_state == State::sendingQueryToBackend) {
              /* we need to edit this query so it has the correct ID */
              auto query = std::move(conn->d_currentQuery);
              uint16_t id = conn->d_highestStreamID;
              prepareQueryForSending(query.d_query, id, QueryState::hasSizePrepended, ConnectionState::needProxy);
              conn->d_currentQuery = std::move(query);
            }

            for (auto& pending : conn->d_pendingResponses) {
              --conn->d_ds->outstanding;

              if (pending.second.d_query.isXFR() && pending.second.d_query.d_xfrStarted) {
                /* this one can't be restarted, sorry */
                DEBUGLOG("A XFR for which a response has already been sent cannot be restarted");
                try {
                  pending.second.d_sender->notifyIOError(std::move(pending.second.d_query.d_idstate), now);
                }
                catch (const std::exception& e) {
                  vinfolog("Got an exception while notifying: %s", e.what());
                }
                catch (...) {
                  vinfolog("Got exception while notifying");
                }
              }
              else {
                conn->d_pendingQueries.push_back(std::move(pending.second));
              }
            }
            conn->d_pendingResponses.clear();
            conn->d_currentPos = 0;

            if (conn->d_state == State::sendingQueryToBackend) {
              iostate = IOState::NeedWrite;
              // resume sending query
            }
            else {
              if (conn->d_pendingQueries.empty()) {
                throw std::runtime_error("TCP connection to a backend in state " + std::to_string((int)conn->d_state) + " with no pending queries");
              }

              iostate = queueNextQuery(conn);
            }

            reconnected = true;
            connectionDied = false;
          }
        }
        catch (const std::exception& e) {
          // reconnect might throw on failure, let's ignore that, we just need to know
          // it failed
        }
      }

      if (!reconnected) {
        /* reconnect failed, we give up */
        DEBUGLOG("reconnect failed, we give up");
        ++conn->d_ds->tcpGaveUp;
        conn->notifyAllQueriesFailed(now, FailureReason::gaveUp);
      }
    }

    if (conn->d_ioState) {
      if (iostate == IOState::Done) {
        conn->d_ioState->update(iostate, handleIOCallback, conn);
      }
      else {
        boost::optional<struct timeval> ttd{boost::none};
        if (iostate == IOState::NeedRead) {
          ttd = conn->getBackendReadTTD(now);
        }
        else if (conn->isFresh() && conn->d_queries == 0) {
          /* first write just after the non-blocking connect */
          ttd = conn->getBackendConnectTTD(now);
        }
        else {
          ttd = conn->getBackendWriteTTD(now);
        }

        conn->d_ioState->update(iostate, handleIOCallback, conn, ttd);
      }
    }
  }
  while (reconnected);

  ioGuard.release();
}

void TCPConnectionToBackend::handleIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<TCPConnectionToBackend>>(param);
  if (fd != conn->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->getHandle()));
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  handleIO(conn, now);
}

void TCPConnectionToBackend::queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query)
{
  if (!d_ioState) {
    d_ioState = make_unique<IOStateHandler>(*d_mplexer, d_handler->getDescriptor());
  }

  // if we are not already sending a query or in the middle of reading a response (so idle),
  // start sending the query
  if (d_state == State::idle || d_state == State::waitingForResponseFromBackend) {
    DEBUGLOG("Sending new query to backend right away, with ID "<<d_highestStreamID);
    d_state = State::sendingQueryToBackend;
    d_currentPos = 0;

    uint16_t id = d_highestStreamID;

    d_currentQuery = PendingRequest({sender, std::move(query)});
    prepareQueryForSending(d_currentQuery.d_query, id, QueryState::hasSizePrepended, needProxyProtocolPayload() ? ConnectionState::needProxy : ConnectionState::proxySent);

    struct timeval now;
    gettimeofday(&now, 0);

    auto shared = std::dynamic_pointer_cast<TCPConnectionToBackend>(shared_from_this());
    handleIO(shared, now);
  }
  else {
    DEBUGLOG("Adding new query to the queue because we are in state "<<(int)d_state);
    // store query in the list of queries to send
    d_pendingQueries.push_back(PendingRequest({sender, std::move(query)}));
  }
}

void TCPConnectionToBackend::handleTimeout(const struct timeval& now, bool write)
{
  /* in some cases we could retry, here, reconnecting and sending our pending responses again */
  if (write) {
    if (isFresh() && d_queries == 0) {
      ++d_ds->tcpConnectTimeouts;
      vinfolog("Timeout while connecting to TCP backend %s", d_ds->getName());
    }
    else {
      ++d_ds->tcpWriteTimeouts;
      vinfolog("Timeout while writing to TCP backend %s", d_ds->getName());
    }
  }
  else {
    ++d_ds->tcpReadTimeouts;
    vinfolog("Timeout while reading from TCP backend %s", d_ds->getName());
  }

  try {
    notifyAllQueriesFailed(now, FailureReason::timeout);
  }
  catch (const std::exception& e) {
    vinfolog("Got an exception while notifying a timeout: %s", e.what());
  }
  catch (...) {
    vinfolog("Got exception while notifying a timeout");
  }

  release();
}

void TCPConnectionToBackend::notifyAllQueriesFailed(const struct timeval& now, FailureReason reason)
{
  d_connectionDied = true;

  /* we might be terminated while notifying a query sender */
  d_ds->outstanding -= d_pendingResponses.size();
  auto pendingQueries = std::move(d_pendingQueries);
  auto pendingResponses = std::move(d_pendingResponses);

  auto increaseCounters = [reason](std::shared_ptr<TCPQuerySender>& sender) {
    if (reason == FailureReason::timeout) {
      const ClientState* cs = sender->getClientState();
      if (cs) {
        ++cs->tcpDownstreamTimeouts;
      }
    }
    else if (reason == FailureReason::gaveUp) {
      const ClientState* cs = sender->getClientState();
      if (cs) {
        ++cs->tcpGaveUp;
      }
    }
  };

  try {
    if (d_state == State::sendingQueryToBackend) {
      auto sender = d_currentQuery.d_sender;
      if (sender->active()) {
        increaseCounters(sender);
        sender->notifyIOError(std::move(d_currentQuery.d_query.d_idstate), now);
      }
    }

    for (auto& query : pendingQueries) {
      auto sender = query.d_sender;
      if (sender->active()) {
        increaseCounters(sender);
        sender->notifyIOError(std::move(query.d_query.d_idstate), now);
      }
    }

    for (auto& response : pendingResponses) {
      auto sender = response.second.d_sender;
      if (sender->active()) {
        increaseCounters(sender);
        sender->notifyIOError(std::move(response.second.d_query.d_idstate), now);
      }
    }
  }
  catch (const std::exception& e) {
    vinfolog("Got an exception while notifying: %s", e.what());
  }
  catch (...) {
    vinfolog("Got exception while notifying");
  }

  release();
}

static uint32_t getSerialFromRawSOAContent(const std::vector<uint8_t>& raw)
{
  /* minimal size for a SOA record, as defined by rfc1035:
     MNAME (root): 1
     RNAME (root): 1
     SERIAL: 4
     REFRESH: 4
     RETRY: 4
     EXPIRE: 4
     MINIMUM: 4
     = 22 bytes
  */
  if (raw.size() < 22) {
    throw std::runtime_error("Invalid content of size " + std::to_string(raw.size()) + " for a SOA record");
  }
  /* As rfc1025 states that "all domain names in the RDATA section of these RRs may be compressed",
     and we don't want to parse these names, start at the end */
  uint32_t serial = 0;
  memcpy(&serial, &raw.at(raw.size() - 20), sizeof(serial));
  return ntohl(serial);
}

IOState TCPConnectionToBackend::handleResponse(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now)
{
  d_downstreamFailures = 0;

  uint16_t queryId = 0;
  try {
    queryId = getQueryIdFromResponse();
  }
  catch (const std::exception& e) {
    DEBUGLOG("Unable to get query ID");
    notifyAllQueriesFailed(now, FailureReason::unexpectedQueryID);
    throw;
  }

  auto it = d_pendingResponses.find(queryId);
  if (it == d_pendingResponses.end()) {
    DEBUGLOG("could not find any corresponding query for ID "<<queryId<<". This is likely a duplicated ID over the same TCP connection, giving up!");
    notifyAllQueriesFailed(now, FailureReason::unexpectedQueryID);
    return IOState::Done;
  }

  editPayloadID(d_responseBuffer, ntohs(it->second.d_query.d_idstate.origID), 0, false);

  auto sender = it->second.d_sender;

  if (sender->active() && it->second.d_query.isXFR()) {
    DEBUGLOG("XFR!");
    bool done = false;
    TCPResponse response;
    response.d_buffer = std::move(d_responseBuffer);
    response.d_connection = conn;
    /* we don't move the whole IDS because we will need for the responses to come */
    response.d_idstate.qtype = it->second.d_query.d_idstate.qtype;
    response.d_idstate.qname = it->second.d_query.d_idstate.qname;
    DEBUGLOG("passing XFRresponse to client connection for "<<response.d_idstate.qname);

    it->second.d_query.d_xfrStarted = true;
    done = isXFRFinished(response, it->second.d_query);

    if (done) {
      d_pendingResponses.erase(it);
      --conn->d_ds->outstanding;
      /* marking as idle for now, so we can accept new queries if our queues are empty */
      if (d_pendingQueries.empty() && d_pendingResponses.empty()) {
        t_downstreamTCPConnectionsManager.moveToIdle(conn);
        d_state = State::idle;
      }
    }

    sender->handleXFRResponse(now, std::move(response));
    if (done) {
      t_downstreamTCPConnectionsManager.moveToIdle(conn);
      d_state = State::idle;
      return IOState::Done;
    }

    d_state = State::waitingForResponseFromBackend;
    d_currentPos = 0;
    d_responseBuffer.resize(sizeof(uint16_t));
    // get ready to read the next packet, if any
    return IOState::NeedRead;
  }

  --conn->d_ds->outstanding;
  auto ids = std::move(it->second.d_query.d_idstate);
  d_pendingResponses.erase(it);
  /* marking as idle for now, so we can accept new queries if our queues are empty */
  if (d_pendingQueries.empty() && d_pendingResponses.empty()) {
    t_downstreamTCPConnectionsManager.moveToIdle(conn);
    d_state = State::idle;
  }

  auto shared = conn;
  if (sender->active()) {
    DEBUGLOG("passing response to client connection for "<<ids.qname);
    // make sure that we still exist after calling handleResponse()
    sender->handleResponse(now, TCPResponse(std::move(d_responseBuffer), std::move(ids), conn));
  }

  if (!d_pendingQueries.empty()) {
    DEBUGLOG("still have some queries to send");
    return queueNextQuery(shared);
  }
  else if (!d_pendingResponses.empty()) {
    DEBUGLOG("still have some responses to read");
    d_state = State::waitingForResponseFromBackend;
    d_currentPos = 0;
    d_responseBuffer.resize(sizeof(uint16_t));
    return IOState::NeedRead;
  }
  else {
    DEBUGLOG("nothing to do, waiting for a new query");
    t_downstreamTCPConnectionsManager.moveToIdle(conn);
    d_state = State::idle;
    return IOState::Done;
  }
}

uint16_t TCPConnectionToBackend::getQueryIdFromResponse() const
{
  if (d_responseBuffer.size() < sizeof(dnsheader)) {
    throw std::runtime_error("Unable to get query ID in a too small (" + std::to_string(d_responseBuffer.size()) + ") response from " + d_ds->getNameWithAddr());
  }

  uint16_t id;
  memcpy(&id, &d_responseBuffer.at(0), sizeof(id));
  return ntohs(id);
}

void TCPConnectionToBackend::setProxyProtocolValuesSent(std::unique_ptr<std::vector<ProxyProtocolValue>>&& proxyProtocolValuesSent)
{
  /* if we already have some values, we have already verified they match */
  if (!d_proxyProtocolValuesSent) {
    d_proxyProtocolValuesSent = std::move(proxyProtocolValuesSent);
  }
}

bool TCPConnectionToBackend::matchesTLVs(const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs) const
{
  if (tlvs == nullptr) {
    if (d_proxyProtocolValuesSent == nullptr) {
      return true;
    }
    else {
      return false;
    }
  }

  if (d_proxyProtocolValuesSent == nullptr) {
    return false;
  }

  return *tlvs == *d_proxyProtocolValuesSent;
}

bool TCPConnectionToBackend::isXFRFinished(const TCPResponse& response, TCPQuery& query)
{
  bool done = false;
  try {
    MOADNSParser parser(true, reinterpret_cast<const char*>(response.d_buffer.data()), response.d_buffer.size());
    if (parser.d_header.rcode != 0U) {
      done = true;
    }
    else {
      for (const auto& record : parser.d_answers) {
        if (record.first.d_class != QClass::IN || record.first.d_type != QType::SOA) {
          continue;
        }

        auto unknownContent = getRR<UnknownRecordContent>(record.first);
        if (!unknownContent) {
          continue;
        }
        auto raw = unknownContent->getRawContent();
        auto serial = getSerialFromRawSOAContent(raw);
        ++query.d_xfrSerialCount;
        if (query.d_xfrMasterSerial == 0) {
          // store the first SOA in our client's connection metadata
          ++query.d_xfrMasterSerialCount;
          query.d_xfrMasterSerial = serial;
        }
        else if (query.d_xfrMasterSerial == serial) {
          ++query.d_xfrMasterSerialCount;
          // figure out if it's end when receiving master's SOA again
          if (query.d_xfrSerialCount == 2) {
            // if there are only two SOA records marks a finished AXFR
            done = true;
          }
          if (query.d_xfrMasterSerialCount == 3) {
            // receiving master's SOA 3 times marks a finished IXFR
            done = true;
          }
        }
      }
    }
  }
  catch (const MOADNSException& e) {
    DEBUGLOG("Exception when parsing TCPResponse to DNS: " << e.what());
    /* ponder what to do here, shall we close the connection? */
  }
  return done;
}
