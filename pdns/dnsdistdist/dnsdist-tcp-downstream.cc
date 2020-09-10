
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
    d_ioState = make_unique<IOStateHandler>(clientConn->getIOMPlexer(), d_socket->getHandle());
  }
  else if (d_clientConn != clientConn) {
    throw std::runtime_error("Assigning a query from a different client to an existing backend connection with pending queries");
  }
}

IOState TCPConnectionToBackend::sendNextQuery(std::shared_ptr<TCPConnectionToBackend>& conn)
{
  conn->d_currentQuery = std::move(conn->d_pendingQueries.front());
  conn->d_pendingQueries.pop_front();
  conn->d_state = State::sendingQueryToBackend;
  conn->d_currentPos = 0;

  return IOState::NeedWrite;
}

/* Tries to read exactly toRead bytes into the buffer, starting at position pos.
   Updates pos everytime a successful read occurs,
   throws an std::runtime_error in case of IO error,
   return Done when toRead bytes have been read, needRead or needWrite if the IO operation
   would block.
*/
// XXX could probably be implemented as a TCPIOHandler
static IOState tryRead(int fd, std::vector<uint8_t>& buffer, size_t& pos, size_t toRead)
{
  if (buffer.size() < (pos + toRead)) {
    throw std::out_of_range("Calling tryRead() with a too small buffer (" + std::to_string(buffer.size()) + ") for a read of " + std::to_string(toRead) + " bytes starting at " + std::to_string(pos));
  }

  size_t got = 0;
  do {
    ssize_t res = ::read(fd, reinterpret_cast<char*>(&buffer.at(pos)), toRead - got);
    if (res == 0) {
      throw runtime_error("EOF while reading message");
    }
    if (res < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN) {
        return IOState::NeedRead;
      }
      else {
        throw std::runtime_error(std::string("Error while reading message: ") + stringerror());
      }
    }

    pos += static_cast<size_t>(res);
    got += static_cast<size_t>(res);
  }
  while (got < toRead);

  return IOState::Done;
}

void TCPConnectionToBackend::handleIO(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now)
{
  if (conn->d_socket == nullptr) {
    throw std::runtime_error("No downstream socket in " + std::string(__PRETTY_FUNCTION__) + "!");
  }

  bool connectionDied = false;
  IOState iostate = IOState::Done;
  IOStateGuard ioGuard(conn->d_ioState);
  int fd = conn->d_socket->getHandle();

  try {
    if (conn->d_state == State::sendingQueryToBackend) {
      DEBUGLOG("sending query to backend "<<conn->getDS()->getName()<<" over FD "<<fd);
      int socketFlags = 0;
#ifdef MSG_FASTOPEN
      if (conn->isFastOpenEnabled()) {
        socketFlags |= MSG_FASTOPEN;
      }
#endif /* MSG_FASTOPEN */

      size_t sent = sendMsgWithOptions(fd, reinterpret_cast<const char *>(&conn->d_currentQuery.d_buffer.at(conn->d_currentPos)), conn->d_currentQuery.d_buffer.size() - conn->d_currentPos, &conn->d_ds->remote, &conn->d_ds->sourceAddr, conn->d_ds->sourceItf, socketFlags);
      if (sent == conn->d_currentQuery.d_buffer.size()) {
        DEBUGLOG("query sent to backend");
        /* request sent ! */
        conn->incQueries();
        conn->d_currentPos = 0;

        DEBUGLOG("adding a pending response for ID "<<conn->d_currentQuery.d_idstate.origID<<" and QNAME "<<conn->d_currentQuery.d_idstate.qname);
        conn->d_pendingResponses[conn->d_currentQuery.d_idstate.origID] = std::move(conn->d_currentQuery);
        conn->d_currentQuery.d_buffer.clear();

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
      DEBUGLOG("reading response size from backend");
      // then we need to allocate a new buffer (new because we might need to re-send the query if the
      // backend dies on us)
      // We also might need to read and send to the client more than one response in case of XFR (yeah!)
      // should very likely be a TCPIOHandler
      conn->d_responseBuffer.resize(sizeof(uint16_t));
      iostate = tryRead(fd, conn->d_responseBuffer, conn->d_currentPos, sizeof(uint16_t) - conn->d_currentPos);
      if (iostate == IOState::Done) {
        DEBUGLOG("got response size from backend");
        conn->d_state = State::readingResponseFromBackend;
        conn->d_responseSize = conn->d_responseBuffer.at(0) * 256 + conn->d_responseBuffer.at(1);
        conn->d_responseBuffer.reserve(conn->d_responseSize + /* we will need to prepend the size later */ 2);
        conn->d_responseBuffer.resize(conn->d_responseSize);
        conn->d_currentPos = 0;
      }
    }

    if (conn->d_state == State::readingResponseFromBackend) {
      DEBUGLOG("reading response from backend");
      iostate = tryRead(fd, conn->d_responseBuffer, conn->d_currentPos, conn->d_responseSize - conn->d_currentPos);
      if (iostate == IOState::Done) {
        DEBUGLOG("got response from backend");
        try {
          iostate = conn->handleResponse(conn, now);
        }
        catch (const std::exception& e) {
          vinfolog("Got an exception while handling TCP response from %s (client is %s): %s", conn->d_ds ? conn->d_ds->getName() : "unknown", conn->d_currentQuery.d_idstate.origRemote.toStringWithPort(), e.what());
        }
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

    /* remove this FD from the IO multiplexer */
    iostate = IOState::Done;
    connectionDied = true;
  }

  if (connectionDied) {
    bool reconnected = false;
    DEBUGLOG("connection died, number of failures is "<<conn->d_downstreamFailures<<", retries is "<<conn->d_ds->retries);

    if ((!conn->d_usedForXFR || conn->d_queries == 0) && conn->d_downstreamFailures < conn->d_ds->retries) {

      conn->d_ioState->reset();
      ioGuard.release();

      if (conn->reconnect()) {
        conn->d_ioState = make_unique<IOStateHandler>(conn->d_clientConn->getIOMPlexer(), conn->d_socket->getHandle());

        /* we need to resend the queries that were in flight, if any */
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
          iostate = sendNextQuery(conn);
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
      DEBUGLOG("reconnect failed, we give up");
      conn->notifyAllQueriesFailed(now);
    }
  }

  if (iostate == IOState::Done) {
    conn->d_ioState->update(iostate, handleIOCallback, conn);
  }
  else {
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
  if (d_ioState == nullptr) {
    throw std::runtime_error("Trying to queue a query to a TCP connection that has no incoming client connection assigned");
  }

  // if we are not already sending a query or in the middle of reading a response (so idle or doingHandshake),
  // start sending the query
  if (d_state == State::idle || d_state == State::waitingForResponseFromBackend) {

    d_state = State::sendingQueryToBackend;
    d_currentPos = 0;
    d_currentQuery = std::move(query);
    if (!d_proxyProtocolPayloadAdded && !d_proxyProtocolPayload.empty()) {
      d_currentQuery.d_buffer.insert(d_currentQuery.d_buffer.begin(), d_proxyProtocolPayload.begin(), d_proxyProtocolPayload.end());
      d_proxyProtocolPayloadAdded = true;
    }

    struct timeval now;
    gettimeofday(&now, 0);

    d_ioState->update(IOState::NeedWrite, handleIOCallback, sharedSelf, getBackendWriteTTD(now));
  }
  else {
    // store query in the list of queries to send
    d_pendingQueries.push_back(std::move(query));
  }
}

bool TCPConnectionToBackend::reconnect()
{
  std::unique_ptr<Socket> result;

  if (d_socket) {
    DEBUGLOG("closing socket "<<d_socket->getHandle());
    shutdown(d_socket->getHandle(), SHUT_RDWR);
    d_socket.reset();
    d_ioState.reset();
    --d_ds->tcpCurrentConnections;
  }

  do {
    vinfolog("TCP connecting to downstream %s (%d)", d_ds->getNameWithAddr(), d_downstreamFailures);
    DEBUGLOG("Opening TCP connection to backend "<<d_ds->getNameWithAddr());
    try {
      result = std::unique_ptr<Socket>(new Socket(d_ds->remote.sin4.sin_family, SOCK_STREAM, 0));
      DEBUGLOG("result of connect is "<<result->getHandle());

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

  auto& clientConn = d_clientConn;
  if (!clientConn->active()) {
    // a client timeout occured, or something like that */
    d_clientConn.reset();
    return;
  }

  if (timeout) {
    ++clientConn->d_ci.cs->tcpDownstreamTimeouts;
  }

  if (d_state == State::sendingQueryToBackend) {
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

IOState TCPConnectionToBackend::handleResponse(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now)
{
  d_downstreamFailures = 0;

  auto& clientConn = d_clientConn;
  if (!clientConn->active()) {
    // a client timeout occured, or something like that */
    d_connectionDied = true;
    d_clientConn.reset();
    return IOState::Done;
  }

  if (d_usedForXFR) {
    DEBUGLOG("XFR!");
    TCPResponse response;
    response.d_buffer = std::move(d_responseBuffer);
    response.d_connection = conn;
    clientConn->handleXFRResponse(clientConn, now, std::move(response));
    d_state = State::readingResponseSizeFromBackend;
    d_currentPos = 0;
    d_responseBuffer.resize(sizeof(uint16_t));
    // get ready to read the next packet, if any
    return IOState::NeedRead;
  }
  else {
    uint16_t queryId = 0;
    try {
      queryId = getQueryIdFromResponse();
    }
    catch (const std::exception& e) {
      DEBUGLOG("Unable to get query ID");
      notifyAllQueriesFailed(now);
      throw;
    }

    auto it = d_pendingResponses.find(queryId);
    if (it == d_pendingResponses.end()) {
      DEBUGLOG("could not found any corresponding query for ID "<<queryId);
      notifyAllQueriesFailed(now);
      return IOState::Done;
    }

    auto ids = std::move(it->second.d_idstate);
    d_pendingResponses.erase(it);
    DEBUGLOG("passing response to client connection for "<<ids.qname);
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
      d_state = State::readingResponseSizeFromBackend;
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
