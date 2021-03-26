
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-tcp-upstream.hh"

const uint16_t TCPConnectionToBackend::s_xfrID = 0;

void TCPConnectionToBackend::assignToClientConnection(std::shared_ptr<IncomingTCPConnectionState>& clientConn, bool isXFR)
{
  if (d_usedForXFR == true) {
    throw std::runtime_error("Trying to send a query over a backend connection used for XFR");
  }

  if (isXFR) {
    d_usedForXFR = true;
  }

  if (!d_clientConn) {
    d_clientConn = clientConn;
    d_ioState = make_unique<IOStateHandler>(clientConn->getIOMPlexer(), d_handler->getDescriptor());
  }
  else if (d_clientConn != clientConn) {
    throw std::runtime_error("Assigning a query from a different client to an existing backend connection with pending queries");
  }
}

void TCPConnectionToBackend::release()
{
  if (!d_usedForXFR) {
    d_ds->outstanding -= d_pendingResponses.size();
  }

  d_pendingResponses.clear();
  d_pendingQueries.clear();

  d_clientConn.reset();
  if (d_ioState) {
    d_ioState.reset();
  }
}

IOState TCPConnectionToBackend::queueNextQuery(std::shared_ptr<TCPConnectionToBackend>& conn)
{
  conn->d_currentQuery = std::move(conn->d_pendingQueries.front());
  conn->d_pendingQueries.pop_front();
  conn->d_state = State::sendingQueryToBackend;
  conn->d_currentPos = 0;

  return IOState::NeedWrite;
}

IOState TCPConnectionToBackend::sendQuery(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now)
{
  DEBUGLOG("sending query to backend "<<conn->getDS()->getName()<<" over FD "<<conn->d_handler->getDescriptor());

  IOState state = conn->d_handler->tryWrite(conn->d_currentQuery.d_buffer, conn->d_currentPos, conn->d_currentQuery.d_buffer.size());

  if (state != IOState::Done) {
    return state;
  }

  DEBUGLOG("query sent to backend");
  /* request sent ! */
  if (conn->d_currentQuery.d_proxyProtocolPayloadAdded) {
    conn->d_proxyProtocolPayloadSent = true;
  }
  conn->incQueries();
  conn->d_currentPos = 0;

  DEBUGLOG("adding a pending response for ID "<<conn->d_currentQuery.d_idstate.origID<<" and QNAME "<<conn->d_currentQuery.d_idstate.qname);
  conn->d_pendingResponses[conn->d_currentQuery.d_idstate.origID] = std::move(conn->d_currentQuery);
  conn->d_currentQuery.d_buffer.clear();

  if (!conn->d_usedForXFR) {
    ++conn->d_ds->outstanding;
  }

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
            vinfolog("Got an exception while handling TCP response from %s (client is %s): %s", conn->d_ds ? conn->d_ds->getName() : "unknown", conn->d_currentQuery.d_idstate.origRemote.toStringWithPort(), e.what());
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
      vinfolog("Got an exception while handling (%s backend) TCP query from %s: %s", (conn->d_state == State::sendingQueryToBackend ? "writing to" : "reading from"), conn->d_currentQuery.d_idstate.origRemote.toStringWithPort(), e.what());
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

      DEBUGLOG("connection died, number of failures is "<<conn->d_downstreamFailures<<", retries is "<<conn->d_ds->retries);

      if ((!conn->d_usedForXFR || conn->d_queries == 0) && conn->d_downstreamFailures < conn->d_ds->retries) {

        conn->d_ioState.reset();
        ioGuard.release();

        try {
          if (conn->reconnect()) {
            conn->d_ioState = make_unique<IOStateHandler>(conn->d_clientConn->getIOMPlexer(), conn->d_handler->getDescriptor());

            /* we need to resend the queries that were in flight, if any */
            for (auto& pending : conn->d_pendingResponses) {
              conn->d_pendingQueries.push_back(std::move(pending.second));
              if (!conn->d_usedForXFR) {
                --conn->d_ds->outstanding;
              }
            }
            conn->d_pendingResponses.clear();
            conn->d_currentPos = 0;

            if (conn->d_state == State::doingHandshake ||
                conn->d_state == State::sendingQueryToBackend) {
              iostate = IOState::NeedWrite;
              // resume sending query
            }
            else {
              if (conn->d_pendingQueries.empty()) {
                throw std::runtime_error("TCP connection to a backend in state " + std::to_string((int)conn->d_state) + " with no pending queries");
              }

              iostate = queueNextQuery(conn);
            }

            if (conn->needProxyProtocolPayload() && !conn->d_currentQuery.d_proxyProtocolPayloadAdded && !conn->d_currentQuery.d_proxyProtocolPayload.empty()) {
              conn->d_currentQuery.d_buffer.insert(conn->d_currentQuery.d_buffer.begin(), conn->d_currentQuery.d_proxyProtocolPayload.begin(), conn->d_currentQuery.d_proxyProtocolPayload.end());
              conn->d_currentQuery.d_proxyProtocolPayloadAdded = true;
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
  gettimeofday(&now, 0);
  handleIO(conn, now);
}

void TCPConnectionToBackend::queueQuery(TCPQuery&& query, std::shared_ptr<TCPConnectionToBackend>& sharedSelf)
{
  if (d_ioState == nullptr) {
    throw std::runtime_error("Trying to queue a query to a TCP connection that has no incoming client connection assigned");
  }

  // if we are not already sending a query or in the middle of reading a response (so idle or doingHandshake),
  // start sending the query
  if (d_state == State::idle || d_state == State::waitingForResponseFromBackend) {
    DEBUGLOG("Sending new query to backend right away");
    d_state = State::sendingQueryToBackend;
    d_currentPos = 0;
    d_currentQuery = std::move(query);
    if (needProxyProtocolPayload() && !d_currentQuery.d_proxyProtocolPayloadAdded && !d_currentQuery.d_proxyProtocolPayload.empty()) {
      d_currentQuery.d_buffer.insert(d_currentQuery.d_buffer.begin(), d_currentQuery.d_proxyProtocolPayload.begin(), d_currentQuery.d_proxyProtocolPayload.end());
      d_currentQuery.d_proxyProtocolPayloadAdded = true;
    }

    struct timeval now;
    gettimeofday(&now, 0);

    handleIO(sharedSelf, now);
  }
  else {
    DEBUGLOG("Adding new query to the queue because we are in state "<<(int)d_state);
    // store query in the list of queries to send
    d_pendingQueries.push_back(std::move(query));
  }
}

bool TCPConnectionToBackend::reconnect()
{
  if (d_handler) {
    DEBUGLOG("closing socket "<<d_handler->getDescriptor());
    d_handler->close();
    d_ioState.reset();
    --d_ds->tcpCurrentConnections;
  }

  d_fresh = true;
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
      auto handler = std::make_unique<TCPIOHandler>("", socket->releaseHandle(), 0, d_ds->d_tlsCtx, time(nullptr));
      handler->tryConnect(d_ds->tcpFastOpen && isFastOpenEnabled(), d_ds->remote);
      d_queries = 0;

      d_handler = std::move(handler);
      ++d_ds->tcpCurrentConnections;
      if (d_ds->tcpCurrentConnections > d_ds->tcpMaxConcurrentConnections) {
        d_ds->tcpMaxConcurrentConnections = d_ds->tcpCurrentConnections;
      }
      return true;
    }
    catch (const std::runtime_error& e) {
      vinfolog("Connection to downstream server %s failed: %s", d_ds->getName(), e.what());
      d_downstreamFailures++;
      if (d_downstreamFailures >= d_ds->retries) {
        throw;
      }
    }
  }
  while (d_downstreamFailures < d_ds->retries);

  return false;
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

  auto& clientConn = d_clientConn;
  if (!clientConn->active()) {
    // a client timeout occurred, or something like that */
    d_clientConn.reset();
    return;
  }

  if (reason == FailureReason::timeout) {
    ++clientConn->d_ci.cs->tcpDownstreamTimeouts;
  }
  else if (reason == FailureReason::gaveUp) {
    ++clientConn->d_ci.cs->tcpGaveUp;
  }

  try {
    if (d_state == State::sendingQueryToBackend) {
      clientConn->notifyIOError(clientConn, std::move(d_currentQuery.d_idstate), now);
    }

    for (auto& query : d_pendingQueries) {
      clientConn->notifyIOError(clientConn, std::move(query.d_idstate), now);
    }

    for (auto& response : d_pendingResponses) {
      clientConn->notifyIOError(clientConn, std::move(response.second.d_idstate), now);
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

IOState TCPConnectionToBackend::handleResponse(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now)
{
  d_downstreamFailures = 0;

  auto& clientConn = d_clientConn;
  if (!clientConn || !clientConn->active()) {
    // a client timeout occurred, or something like that */
    d_connectionDied = true;

    release();

    return IOState::Done;
  }

  if (d_usedForXFR) {
    DEBUGLOG("XFR!");
    TCPResponse response;
    response.d_buffer = std::move(d_responseBuffer);
    response.d_connection = conn;
    clientConn->handleXFRResponse(clientConn, now, std::move(response));
    d_state = State::waitingForResponseFromBackend;
    d_currentPos = 0;
    d_responseBuffer.resize(sizeof(uint16_t));
    // get ready to read the next packet, if any
    return IOState::NeedRead;
  }

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

  if (!conn->d_usedForXFR) {
    --conn->d_ds->outstanding;
  }

  auto ids = std::move(it->second.d_idstate);
  d_pendingResponses.erase(it);
  DEBUGLOG("passing response to client connection for "<<ids.qname);
  /* marking as idle for now, so we can accept new queries if our queues are empty */
  if (d_pendingQueries.empty() && d_pendingResponses.empty()) {
    d_state = State::idle;
  }
  clientConn->handleResponse(clientConn, now, TCPResponse(std::move(d_responseBuffer), std::move(ids), conn));

  if (!d_pendingQueries.empty()) {
    DEBUGLOG("still have some queries to send");
    d_state = State::sendingQueryToBackend;
    d_currentQuery = std::move(d_pendingQueries.front());
    d_currentPos = 0;
    d_pendingQueries.pop_front();
    return IOState::NeedWrite;
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
    d_state = State::idle;
    d_clientConn.reset();
    return IOState::Done;
  }
}

uint16_t TCPConnectionToBackend::getQueryIdFromResponse()
{
  if (d_responseBuffer.size() < sizeof(dnsheader)) {
    throw std::runtime_error("Unable to get query ID in a too small (" + std::to_string(d_responseBuffer.size()) + ") response from " + d_ds->getNameWithAddr());
  }

  dnsheader dh;
  memcpy(&dh, &d_responseBuffer.at(0), sizeof(dh));
  return ntohs(dh.id);
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
