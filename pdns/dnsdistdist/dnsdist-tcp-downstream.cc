
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-tcp-upstream.hh"

const uint16_t TCPConnectionToBackend::s_xfrID = 0;

void TCPConnectionToBackend::assignToClientConnection(std::shared_ptr<IncomingTCPConnectionState>& clientConn, bool isXFR)
{
  // DEBUG: cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  if (isXFR) {
    d_usedForXFR = true;
  }

  d_clientConn = clientConn;
  d_ioState = make_unique<IOStateHandler>(clientConn->getIOMPlexer(), d_socket->getHandle());
}

IOState TCPConnectionToBackend::sendNextQuery(std::shared_ptr<TCPConnectionToBackend>& conn)
{
  conn->d_currentQuery = std::move(conn->d_pendingQueries.front());
  conn->d_pendingQueries.pop_front();
  conn->d_state = State::sendingQueryToBackend;
  return IOState::NeedWrite;
}

void TCPConnectionToBackend::handleIO(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now)
{
  // DEBUG: cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  if (conn->d_socket == nullptr) {
    throw std::runtime_error("No downstream socket in " + std::string(__PRETTY_FUNCTION__) + "!");
  }

  bool connectionDied = false;
  IOState iostate = IOState::Done;
  IOStateGuard ioGuard(conn->d_ioState);
  int fd = conn->d_socket->getHandle();

  try {
    if (conn->d_state == State::sendingQueryToBackend) {
      // DEBUG: cerr<<"sending query to backend over FD "<<fd<<endl;
      int socketFlags = 0;
#ifdef MSG_FASTOPEN
      if (conn->isFastOpenEnabled()) {
        socketFlags |= MSG_FASTOPEN;
      }
#endif /* MSG_FASTOPEN */

      size_t sent = sendMsgWithOptions(fd, reinterpret_cast<const char *>(&conn->d_currentQuery.d_buffer.at(conn->d_currentPos)), conn->d_currentQuery.d_buffer.size() - conn->d_currentPos, &conn->d_ds->remote, &conn->d_ds->sourceAddr, conn->d_ds->sourceItf, socketFlags);
      if (sent == conn->d_currentQuery.d_buffer.size()) {
        // DEBUG: cerr<<"query sent to backend"<<endl;
        /* request sent ! */
        conn->incQueries();
        conn->d_currentPos = 0;
        //conn->d_currentQuery.d_querySentTime = now;
        // DEBUG: cerr<<"adding a pending response for ID "<<conn->d_currentQuery.d_idstate.origID<<" and QNAME "<<conn->d_currentQuery.d_idstate.qname<<endl;
        // DEBUG: cerr<<"IDS has "<<(conn->d_currentQuery.d_idstate.qTag?"tags":"no tags")<<endl;
        conn->d_pendingResponses[conn->d_currentQuery.d_idstate.origID] = std::move(conn->d_currentQuery);
        conn->d_currentQuery.d_buffer.clear();
#if 0
        if (!conn->d_usedForXFR) {
          /* don't bother with the outstanding count for XFR queries */
          ++conn->d_ds->outstanding;
          ++conn->d_outstanding;
        }
#endif

        if (conn->d_pendingQueries.empty()) {
          conn->d_state = State::readingResponseSizeFromBackend;
          conn->d_currentPos = 0;
          conn->d_responseBuffer.resize(sizeof(uint16_t));
          iostate = IOState::NeedRead;
        }
        else {
          iostate = sendNextQuery(conn);
        }
      }
      else {
        conn->d_currentPos += sent;
        iostate = IOState::NeedWrite;
        /* disable fast open on partial write */
        conn->disableFastOpen();
      }
    }

    if (conn->d_state == State::readingResponseSizeFromBackend) {
      // DEBUG: cerr<<"reading response size from backend"<<endl;
      // then we need to allocate a new buffer (new because we might need to re-send the query if the
      // backend dies on us)
      // We also might need to read and send to the client more than one response in case of XFR (yeah!)
      // should very likely be a TCPIOHandler d_downstreamHandler
      conn->d_responseBuffer.resize(sizeof(uint16_t));
      iostate = tryRead(fd, conn->d_responseBuffer, conn->d_currentPos, sizeof(uint16_t) - conn->d_currentPos);
      if (iostate == IOState::Done) {
        // DEBUG: cerr<<"got response size from backend"<<endl;
        conn->d_state = State::readingResponseFromBackend;
        conn->d_responseSize = conn->d_responseBuffer.at(0) * 256 + conn->d_responseBuffer.at(1);
        conn->d_responseBuffer.reserve(conn->d_responseSize + /* we will need to prepend the size later */ 2);
        conn->d_responseBuffer.resize(conn->d_responseSize);
        conn->d_currentPos = 0;
      }
    }

    if (conn->d_state == State::readingResponseFromBackend) {
      // DEBUG: cerr<<"reading response from backend"<<endl;
      iostate = tryRead(fd, conn->d_responseBuffer, conn->d_currentPos, conn->d_responseSize - conn->d_currentPos);
      if (iostate == IOState::Done) {
        // DEBUG: cerr<<"got response from backend"<<endl;
        //conn->d_responseReadTime = now;
        try {
          iostate = conn->handleResponse(now);
        }
        catch (const std::exception& e) {
          vinfolog("Got an exception while handling TCP response from %s (client is %s): %s", conn->d_ds ? conn->d_ds->getName() : "unknown", conn->d_currentQuery.d_idstate.origRemote.toStringWithPort(), e.what());
        }
        //return;
      }
    }

    if (conn->d_state != State::idle &&
        conn->d_state != State::sendingQueryToBackend &&
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
    vinfolog("Got an exception while handling (%s backend) TCP query from %s: %s", (conn->d_ioState->getState() == IOState::NeedRead ? "reading from" : "writing to"), conn->d_currentQuery.d_idstate.origRemote.toStringWithPort(), e.what());
    if (conn->d_state == State::sendingQueryToBackend) {
      ++conn->d_ds->tcpDiedSendingQuery;
    }
    else {
      ++conn->d_ds->tcpDiedReadingResponse;
    }

    /* don't increase this counter when reusing connections */
    if (conn->d_fresh) {
      ++conn->d_downstreamFailures;
    }

#if 0
    if (conn->d_outstanding) {
      conn->d_outstanding = false;

      if (conn->d_ds != nullptr) {
        --conn->d_ds->outstanding;
      }
    }
#endif
    /* remove this FD from the IO multiplexer */
    iostate = IOState::Done;
    connectionDied = true;
  }

  if (connectionDied) {
    bool reconnected = false;
    // DEBUG: cerr<<"connection died, number of failures is "<<conn->d_downstreamFailures<<", retries is "<<conn->d_ds->retries<<endl;

    if ((!conn->d_usedForXFR || conn->d_queries == 0) && conn->d_downstreamFailures < conn->d_ds->retries) {
      // DEBUG: cerr<<"reconnecting"<<endl;
      conn->d_ioState->reset();
      ioGuard.release();

      if (conn->reconnect()) {
        // DEBUG: cerr<<"reconnected"<<endl;

        conn->d_ioState = make_unique<IOStateHandler>(conn->d_clientConn->getIOMPlexer(), conn->d_socket->getHandle());
        // DEBUG: cerr<<"new state"<<endl;

        for (auto& pending : conn->d_pendingResponses) {
          conn->d_pendingQueries.push_back(std::move(pending.second));
        }
        conn->d_pendingResponses.clear();
        conn->d_currentPos = 0;

        if (conn->d_state == State::doingHandshake ||
            conn->d_state == State::sendingQueryToBackend) {
          iostate = IOState::NeedWrite;
          // resume sending query
        }
        else {
          // DEBUG: cerr<<"sending next query"<<endl;
          iostate = sendNextQuery(conn);
          // DEBUG: cerr<<"after call to sendNextQuery"<<endl;
        }

        if (!conn->d_proxyProtocolPayloadAdded && !conn->d_proxyProtocolPayload.empty()) {
          conn->d_currentQuery.d_buffer.insert(conn->d_currentQuery.d_buffer.begin(), conn->d_proxyProtocolPayload.begin(), conn->d_proxyProtocolPayload.end());
          conn->d_proxyProtocolPayloadAdded = true;
        }

        reconnected = true;
      }
    }

    if (!reconnected) {
      /* reconnect failed, we give up */
      conn->d_connectionDied = true;
      conn->notifyAllQueriesFailed(now);
    }
  }

  if (iostate == IOState::Done) {
    // DEBUG: cerr<<"in "<<__PRETTY_FUNCTION__<<", done"<<endl;
    conn->d_ioState->update(iostate, handleIOCallback, conn);
  }
  else {
    // DEBUG: cerr<<"in "<<__PRETTY_FUNCTION__<<", updating to "<<(int)iostate<<endl;
    conn->d_ioState->update(iostate, handleIOCallback, conn, iostate == IOState::NeedRead ? conn->getBackendReadTTD(now) : conn->getBackendWriteTTD(now));
  }
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
  // DEBUG: cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  // DEBUG: cerr<<"IDS has "<<(query.d_idstate.qTag?"tags":"no tags")<<endl;
  if (d_ioState == nullptr) {
    throw std::runtime_error("Trying to queue a query to a TCP connection that has no incoming client connection assigned");
  }

  // if we are not already sending a query or in the middle of reading a response (so idle or doingHandshake),
  // start sending the query
  if (d_state == State::idle || d_state == State::waitingForResponseFromBackend) {
    d_state = State::sendingQueryToBackend;
    d_currentQuery = std::move(query);
    // DEBUG: cerr<<"need write"<<endl;

    struct timeval now;
    gettimeofday(&now, 0);

    d_ioState->update(IOState::NeedWrite, handleIOCallback, sharedSelf, getBackendWriteTTD(now));
  }
  else {
    // store query in the list of queries to send
    d_pendingQueries.push_back(std::move(query));
  }
  // DEBUG: cerr<<"out of "<<__PRETTY_FUNCTION__<<endl;
}

bool TCPConnectionToBackend::reconnect()
{
  std::unique_ptr<Socket> result;

  if (d_socket) {
    // DEBUG: cerr<<"closing socket "<<d_socket->getHandle()<<endl;
    shutdown(d_socket->getHandle(), SHUT_RDWR);
    d_socket.reset();
    d_ioState.reset();
    --d_ds->tcpCurrentConnections;
  }

  do {
    vinfolog("TCP connecting to downstream %s (%d)", d_ds->getNameWithAddr(), d_downstreamFailures);
    try {
      result = std::unique_ptr<Socket>(new Socket(d_ds->remote.sin4.sin_family, SOCK_STREAM, 0));
      // DEBUG: cerr<<"result of connect is "<<result->getHandle()<<endl;
      if (!IsAnyAddress(d_ds->sourceAddr)) {
        SSetsockopt(result->getHandle(), SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef IP_BIND_ADDRESS_NO_PORT
        if (d_ds->ipBindAddrNoPort) {
          SSetsockopt(result->getHandle(), SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
        }
#endif
#ifdef SO_BINDTODEVICE
        if (!d_ds->sourceItfName.empty()) {
          int res = setsockopt(result->getHandle(), SOL_SOCKET, SO_BINDTODEVICE, d_ds->sourceItfName.c_str(), d_ds->sourceItfName.length());
          if (res != 0) {
            vinfolog("Error setting up the interface on backend TCP socket '%s': %s", d_ds->getNameWithAddr(), stringerror());
          }
        }
#endif
        result->bind(d_ds->sourceAddr, false);
      }
      result->setNonBlocking();
#ifdef MSG_FASTOPEN
      if (!d_ds->tcpFastOpen || !isFastOpenEnabled()) {
        SConnectWithTimeout(result->getHandle(), d_ds->remote, /* no timeout, we will handle it ourselves */ 0);
      }
#else
      SConnectWithTimeout(result->getHandle(), d_ds->remote, /* no timeout, we will handle it ourselves */ 0);
#endif /* MSG_FASTOPEN */

      d_socket = std::move(result);
      // DEBUG: cerr<<"connected new socket "<<d_socket->getHandle()<<endl;
      ++d_ds->tcpCurrentConnections;
      return true;
    }
    catch(const std::runtime_error& e) {
      vinfolog("Connection to downstream server %s failed: %s", d_ds->getName(), e.what());
      d_downstreamFailures++;
      if (d_downstreamFailures > d_ds->retries) {
        throw;
      }
    }
  }
  while (d_downstreamFailures <= d_ds->retries);

  return false;
}

void TCPConnectionToBackend::handleTimeout(const struct timeval& now, bool write)
{
  if (write) {
    ++d_ds->tcpWriteTimeouts;
  }
  else {
    ++d_ds->tcpReadTimeouts;
  }

  if (d_ioState) {
    d_ioState->reset();
  }

  notifyAllQueriesFailed(now, true);
}

void TCPConnectionToBackend::notifyAllQueriesFailed(const struct timeval& now, bool timeout)
{
  d_connectionDied = true;
  //auto clientConn = d_clientConn.lock();
  //if (!clientConn) {
  //  d_clientConn.reset();
  //  return;
  //}
  auto& clientConn = d_clientConn;
  if (!clientConn->active()) {
    // a client timeout occured, or something like that */
    d_connectionDied = true;
    d_clientConn.reset();
    return;
  }

  if (timeout) {
    ++clientConn->d_ci.cs->tcpDownstreamTimeouts;
  }

  if (d_state == State::doingHandshake || d_state == State::sendingQueryToBackend) {
    clientConn->notifyIOError(clientConn, std::move(d_currentQuery.d_idstate), now);
  }

  for (auto& query : d_pendingQueries) {
    clientConn->notifyIOError(clientConn, std::move(query.d_idstate), now);
  }

  for (auto& response : d_pendingResponses) {
    clientConn->notifyIOError(clientConn, std::move(response.second.d_idstate), now);
  }

  d_pendingQueries.clear();
  d_pendingResponses.clear();

  d_clientConn.reset();
}

IOState TCPConnectionToBackend::handleResponse(const struct timeval& now)
{
  // DEBUG: cerr<<"in "<<__PRETTY_FUNCTION__<<endl;
  //auto clientConn = d_clientConn.lock();
  //if (!clientConn) {
  //d_clientConn.reset();
  //  d_connectionDied = true;
  //  // DEBUG: cerr<<"connection to client died, bye bye"<<endl;
  //  return IOState::Done;
  //}

  auto& clientConn = d_clientConn;
  if (!clientConn->active()) {
    // DEBUG: cerr<<"client is not active"<<endl;
    // a client timeout occured, or something like that */
    d_connectionDied = true;
    d_clientConn.reset();
    return IOState::Done;
  }

  if (d_usedForXFR) {
    // DEBUG: cerr<<"XFR!"<<endl;
    TCPResponse response;
    response.d_buffer = std::move(d_responseBuffer);
    response.d_ds = d_ds;
    clientConn->handleXFRResponse(clientConn, now, std::move(response));
    d_state = State::readingResponseSizeFromBackend;
    d_currentPos = 0;
    d_responseBuffer.resize(sizeof(uint16_t));
    return IOState::NeedRead;
    // get ready to read the next packet, if any
  }
  else {
    // DEBUG: cerr<<"not XFR, phew"<<endl;
    uint16_t queryId = 0;
    try {
      queryId = getQueryIdFromResponse();
    }
    catch (const std::exception& e) {
      notifyAllQueriesFailed(now);
      throw;
    }

    auto it = d_pendingResponses.find(queryId);
    if (it == d_pendingResponses.end()) {
      // DEBUG: cerr<<"could not found any corresponding query for ID "<<queryId<<endl;
      notifyAllQueriesFailed(now);
      return IOState::Done;
    }
    auto ids = std::move(it->second.d_idstate);
    // DEBUG: cerr<<"IDS has "<<(ids.qTag?" TAGS ": "NO TAGS")<<endl;
    // DEBUG: cerr<<"passing response to client connection for "<<ids.qname<<endl;
    clientConn->handleResponse(clientConn, now, TCPResponse(std::move(d_responseBuffer), std::move(ids), d_ds));
    d_pendingResponses.erase(it);

    if (!d_pendingQueries.empty()) {
      // DEBUG: cerr<<"still have some queries to send"<<endl;
      d_state = State::sendingQueryToBackend;
      d_currentQuery = std::move(d_pendingQueries.front());
      d_pendingQueries.pop_front();
      return IOState::NeedWrite;
    }
    else if (!d_pendingResponses.empty()) {
      // DEBUG: cerr<<"still have some responses to read"<<endl;
      d_state = State::readingResponseSizeFromBackend;
      d_currentPos = 0;
      d_responseBuffer.resize(sizeof(uint16_t));
      return IOState::NeedRead;
    }
    else {
      // DEBUG: cerr<<"nothing to do, phewwwww"<<endl;
      d_state = State::idle;
      d_clientConn.reset();
      return IOState::Done;
    }
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

void TCPConnectionToBackend::setProxyProtocolPayload(std::string&& payload)
{
  d_proxyProtocolPayload = std::move(payload);
}

void TCPConnectionToBackend::setProxyProtocolPayloadAdded(bool added)
{
  d_proxyProtocolPayloadAdded = added;
}
