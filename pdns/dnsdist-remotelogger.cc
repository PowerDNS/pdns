
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-remotelogger.hh"
#include "dnsparser.hh"

#include <boost/uuid/uuid_io.hpp>

#ifdef HAVE_PROTOBUF
#include "dnsmessage.pb.h"
#endif

bool RemoteLogger::reconnect()
{
  if (d_socket >= 0) {
    close(d_socket);
  }
  try {
    //cerr<<"Connecting to " << d_remote.toStringWithPort()<<endl;
    d_socket = SSocket(d_remote.sin4.sin_family, SOCK_STREAM, 0);
    SConnect(d_socket, d_remote);
    setNonBlocking(d_socket);
  }
  catch(const std::exception& e) {
    infolog("Error connecting to remote logger (%s): %s", d_remote.toStringWithPort(), e.what());
    return false;
  }
  return true;
}

bool RemoteLogger::sendData(const char* buffer, size_t bufferSize)
{
  size_t pos = 0;
  while(pos < bufferSize) {
    //cerr<<"Sending "<< bufferSize-pos <<" to " << d_remote.toStringWithPort()<<endl;
    ssize_t written = write(d_socket, buffer + pos, bufferSize - pos);
    if (written == -1) {
      int res = errno;
      //cerr<<"errno is "<<errno<<endl;
      if (res == EWOULDBLOCK || res == EAGAIN) {
        return false;
      }
      else if (res != EINTR) {
        reconnect();
        return false;
      }
    }
    else if (written == 0) {
      reconnect();
      return false;
    }
    else {
      pos += (size_t) written;
    }
  }

  return true;
}

void RemoteLogger::worker()
{
  while(true) {
    std::string data;
    {
      std::unique_lock<std::mutex> lock(d_writeMutex);
      d_queueCond.wait(lock, [this]{return !d_writeQueue.empty();});
      data = d_writeQueue.front();
      d_writeQueue.pop();
    }

    try {
      uint32_t len = htonl(data.length());
      writen2WithTimeout(d_socket, &len, sizeof(len), (int) d_timeout);
      writen2WithTimeout(d_socket, data.c_str(), data.length(), (int) d_timeout);
    }
    catch(const std::runtime_error& e) {
      vinfolog("Error sending data to remote logger (%s): %s", d_remote.toStringWithPort(), e.what());

      while (!reconnect()) {
        sleep(d_reconnectWaitTime);
      }
    }
  }
}

void RemoteLogger::queueData(const std::string& data)
{
  {
    std::unique_lock<std::mutex> lock(d_writeMutex);
    if (d_writeQueue.size() >= d_maxQueuedEntries) {
      d_writeQueue.pop();
    }
    d_writeQueue.push(data);
  }
  d_queueCond.notify_one();
}

RemoteLogger::RemoteLogger(const ComboAddress& remote, uint16_t timeout, uint64_t maxQueuedEntries, uint8_t reconnectWaitTime): d_remote(remote), d_maxQueuedEntries(maxQueuedEntries), d_timeout(timeout), d_reconnectWaitTime(reconnectWaitTime), d_thread(&RemoteLogger::worker, this)
{
#ifdef HAVE_PROTOBUF
  reconnect();
#else
  throw new std::runtime_error("Remote logging requires protobuf support, which is not enabled.");
#endif /* HAVE_PROTOBUF */
}

RemoteLogger::~RemoteLogger()
{
  if (d_socket >= 0)
    close(d_socket);
}

void RemoteLogger::logQuery(const DNSQuestion& dq)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage message;
  message.set_type(PBDNSMessage_Type_DNSQueryType);
  message.set_messageid(boost::uuids::to_string(dq.uniqueId));
  message.set_socketfamily(dq.remote->sin4.sin_family == AF_INET ? PBDNSMessage_SocketFamily_INET : PBDNSMessage_SocketFamily_INET6);
  message.set_socketprotocol(dq.tcp ? PBDNSMessage_SocketProtocol_TCP : PBDNSMessage_SocketProtocol_UDP);
  if (dq.local->sin4.sin_family == AF_INET) {
    message.set_to(&dq.local->sin4.sin_addr.s_addr, sizeof(dq.local->sin4.sin_addr.s_addr));
  }
  else if (dq.local->sin4.sin_family == AF_INET6) {
    message.set_to(&dq.local->sin6.sin6_addr.s6_addr, sizeof(dq.local->sin6.sin6_addr.s6_addr));
  }
  if (dq.remote->sin4.sin_family == AF_INET) {
    message.set_from(&dq.remote->sin4.sin_addr.s_addr, sizeof(dq.remote->sin4.sin_addr.s_addr));
  }
  else if (dq.remote->sin4.sin_family == AF_INET6) {
    message.set_from(&dq.remote->sin6.sin6_addr.s6_addr, sizeof(dq.remote->sin6.sin6_addr.s6_addr));
  }
  message.set_inbytes(dq.len);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  message.set_timesec(ts.tv_sec);
  message.set_timeusec(ts.tv_nsec / 1000);
  message.set_id(ntohs(dq.dh->id));

  PBDNSMessage_DNSQuestion question;
  question.set_qname(dq.qname->toString());
  question.set_qtype(dq.qtype);
  question.set_qclass(dq.qclass);
  message.set_allocated_question(&question);

  //cerr <<message.DebugString()<<endl;
  std::string str;
  message.SerializeToString(&str);
  queueData(str);
  message.release_question();
#endif /* HAVE_PROTOBUF */
}

#ifdef HAVE_PROTOBUF
static void addRRs(const char* packet, const size_t len, PBDNSMessage_DNSResponse& response)
{
  if (len < sizeof(struct dnsheader))
    return;

  const struct dnsheader* dh = (const struct dnsheader*) packet;

  if (ntohs(dh->ancount) == 0)
    return;

  if (ntohs(dh->qdcount) == 0)
    return;

  vector<uint8_t> content(len - sizeof(dnsheader));
  copy(packet + sizeof(dnsheader), packet + len, content.begin());
  PacketReader pr(content);

  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t rrtype;
  uint16_t rrclass;
  string blob;
  struct dnsrecordheader ah;

  rrname = pr.getName();
  rrtype = pr.get16BitInt();
  rrclass = pr.get16BitInt();

  /* consume remaining qd if any */
  if (qdcount > 1) {
    for(idx = 1; idx < qdcount; idx++) {
      rrname = pr.getName();
      rrtype = pr.get16BitInt();
      rrclass = pr.get16BitInt();
      (void) rrtype;
      (void) rrclass;
    }
  }

  /* parse AN */
  for (idx = 0; idx < ancount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pr.xfrBlob(blob);
    if (ah.d_type == QType::A || ah.d_type == QType::AAAA) {
      PBDNSMessage_DNSResponse_DNSRR* rr = response.add_rrs();
      if (rr) {
        rr->set_name(rrname.toString());
        rr->set_type(ah.d_type);
        rr->set_class_(ah.d_class);
        rr->set_ttl(ah.d_ttl);
        rr->set_rdata(blob.c_str(), blob.length());
      }
    }
  }
}
#endif /* HAVE_PROTOBUF */

void RemoteLogger::logResponse(const DNSQuestion& dr)
{
#ifdef HAVE_PROTOBUF
  PBDNSMessage message;
  message.set_type(PBDNSMessage_Type_DNSResponseType);
  message.set_messageid(boost::uuids::to_string(dr.uniqueId));
  message.set_socketfamily(dr.remote->sin4.sin_family == AF_INET ? PBDNSMessage_SocketFamily_INET : PBDNSMessage_SocketFamily_INET6);
  message.set_socketprotocol(dr.tcp ? PBDNSMessage_SocketProtocol_TCP : PBDNSMessage_SocketProtocol_UDP);
  if (dr.local->sin4.sin_family == AF_INET) {
    message.set_from(&dr.local->sin4.sin_addr.s_addr, sizeof(dr.local->sin4.sin_addr.s_addr));
  }
  else if (dr.local->sin4.sin_family == AF_INET6) {
    message.set_from(&dr.local->sin6.sin6_addr.s6_addr, sizeof(dr.local->sin6.sin6_addr.s6_addr));
  }
  if (dr.remote->sin4.sin_family == AF_INET) {
    message.set_to(&dr.remote->sin4.sin_addr.s_addr, sizeof(dr.remote->sin4.sin_addr.s_addr));
  }
  else if (dr.remote->sin4.sin_family == AF_INET6) {
    message.set_to(&dr.remote->sin6.sin6_addr.s6_addr, sizeof(dr.remote->sin6.sin6_addr.s6_addr));
  }
  message.set_inbytes(dr.len);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  message.set_timesec(ts.tv_sec);
  message.set_timeusec(ts.tv_nsec / 1000);
  message.set_id(ntohs(dr.dh->id));

  PBDNSMessage_DNSResponse response;
  response.set_rcode(dr.dh->rcode);

  message.set_allocated_response(&response);

  addRRs((const char*) dr.dh, dr.len, response);

  //cerr <<message.DebugString()<<endl;
  std::string str;
  message.SerializeToString(&str);
  queueData(str);
  message.release_response();
#endif /* HAVE_PROTOBUF */
}
