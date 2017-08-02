#include "gettime.hh"
#include "protobuf-dnstap.hh"
#include "dnsparser.hh"
#include "config.h"
#ifdef PDNS_CONFIG_ARGS
#include "logger.hh"
#define WE_ARE_RECURSOR
#else
#include "dolog.hh"
#endif

#define MAXHOSTNAMELEN 256

DnstapProtoBufMessage::DnstapProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type)
{
  setType(type);
}

void DnstapProtoBufMessage::addRRsFromPacket(const char* packet, const size_t len, bool includeCNAME)
{
#ifdef HAVE_PROTOBUF
  if (len < sizeof(struct dnsheader))
    return;

  dnstap::Message* message = proto_message.mutable_message();
  message->set_response_message(packet, len);
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::serialize(std::string& data) const
{
#ifdef HAVE_PROTOBUF
  proto_message.SerializeToString(&data);
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setBytes(size_t bytes)
{
  // Noop as dnstap.proto doesn't have an attr for query size
}

void DnstapProtoBufMessage::setEDNSSubnet(const Netmask& subnet, uint8_t mask)
{
  // No support for EDNS subnet
}

void DnstapProtoBufMessage::setQueryTime(time_t sec, uint32_t usec)
{
#ifdef HAVE_PROTOBUF
  dnstap::Message* message = proto_message.mutable_message();
  message->set_query_time_sec(sec);
  message->set_query_time_nsec(usec);
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setResponseTime(time_t sec, uint32_t usec)
{
#ifdef HAVE_PROTOBUF
  dnstap::Message* message = proto_message.mutable_message();
  message->set_response_time_sec(sec);
  message->set_response_time_nsec(usec);
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setQuestion(const char* packet, const size_t len)
{
#ifdef HAVE_PROTOBUF
  dnstap::Message* message = proto_message.mutable_message();
  message->set_query_message(packet, len);
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setQuestion(const DNSName& qname, uint16_t qtype, uint16_t qclass)
{
#ifdef HAVE_PROTOBUF
  std::string msg = "qname: " + qname.toString() + "; qtype: " +  std::to_string(qtype) + "; qclass: " + std::to_string(qclass);
  proto_message.set_extra(msg);
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setRequestor(const ComboAddress& requestor)
{
#ifdef HAVE_PROTOBUF
  dnstap::Message* message = proto_message.mutable_message();
  if (requestor.sin4.sin_family == AF_INET) {
    message->set_query_address(&requestor.sin4.sin_addr.s_addr, sizeof(requestor.sin4.sin_addr.s_addr));
    message->set_query_port(ntohs(requestor.sin4.sin_port));
  }
  else if (requestor.sin4.sin_family == AF_INET6) {
    message->set_query_address(&requestor.sin6.sin6_addr.s6_addr, sizeof(requestor.sin6.sin6_addr.s6_addr));
    // There is no ipv6 port, it's stored in ipv4
    message->set_query_port(ntohs(requestor.sin4.sin_port));
  }
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setRequestor(const std::string& requestor)
{
#ifdef HAVE_PROTOBUF
  dnstap::Message* message = proto_message.mutable_message();
  message->set_query_address(requestor);
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setResponder(const ComboAddress& responder)
{
#ifdef HAVE_PROTOBUF
  dnstap::Message* message = proto_message.mutable_message();
  if (responder.sin4.sin_family == AF_INET) {
    message->set_response_address(&responder.sin4.sin_addr.s_addr, sizeof(responder.sin4.sin_addr.s_addr));
    message->set_response_port(ntohs(responder.sin4.sin_port));
  }
  else if (responder.sin4.sin_family == AF_INET6) {
    message->set_response_address(&responder.sin6.sin6_addr.s6_addr, sizeof(responder.sin6.sin6_addr.s6_addr));
    // There is no ipv6 port, it's stored in ipv4
    message->set_response_port(ntohs(responder.sin4.sin_port));
  }
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setResponder(const std::string& responder)
{
#ifdef HAVE_PROTOBUF
  dnstap::Message* message = proto_message.mutable_message();
  message->set_response_address(responder);
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setResponseCode(uint8_t rcode)
{
  // There is no specific response code field to set for dnstap
  // messages. However, it can be found in the response_message.
}

void DnstapProtoBufMessage::setTime(time_t sec, uint32_t usec)
{
#ifdef HAVE_PROTOBUF
  const dnstap::Message message = proto_message.message();
  if (message.type() == dnstap::Message_Type_FORWARDER_QUERY) {
    setQueryTime(sec, usec);
  } else if (message.type() == dnstap::Message_Type_FORWARDER_RESPONSE) {
    setResponseTime(sec, usec);
  } else {
    warnlog("TODO");
  }
#endif /* HAVE_PROTOBUF */
}

void DnstapProtoBufMessage::setType(DNSProtoBufMessage::DNSProtoBufMessageType type)
{
#ifdef HAVE_PROTOBUF
  // Required. Only possible value.
  proto_message.set_type(dnstap::Dnstap_Type_MESSAGE);

  dnstap::Message* message = proto_message.mutable_message();
  switch(type) {
  case DNSProtoBufMessage::DNSProtoBufMessageType::Query:
    message->set_type(dnstap::Message_Type_FORWARDER_QUERY);
    break;
  case DNSProtoBufMessage::DNSProtoBufMessageType::Response:
    message->set_type(dnstap::Message_Type_FORWARDER_RESPONSE);
    break;
  case DNSProtoBufMessage::DNSProtoBufMessageType::OutgoingQuery:
    message->set_type(dnstap::Message_Type_RESOLVER_QUERY);
    break;
  case DNSProtoBufMessage::DNSProtoBufMessageType::IncomingResponse:
    message->set_type(dnstap::Message_Type_RESOLVER_RESPONSE);
    break;
  default:
    throw std::runtime_error("Unsupported protobuf type: "+std::to_string(type));
  }
#endif /* HAVE_PROTOBUF */
}

std::string DnstapProtoBufMessage::toDebugString() const
{
#ifdef HAVE_PROTOBUF
  return proto_message.DebugString();
#else
  return std::string();
#endif /* HAVE_PROTOBUF */
}

#ifdef HAVE_PROTOBUF

void DnstapProtoBufMessage::setInitialRequestID(const boost::uuids::uuid& uuid)
{
  std::string* identity = proto_message.mutable_identity();
  identity->resize(uuid.size());
  std::copy(uuid.begin(), uuid.end(), identity->begin());
}

void DnstapProtoBufMessage::setUUID(const boost::uuids::uuid& uuid)
{
  std::string* extra = proto_message.mutable_extra();
  extra->resize(uuid.size());
  std::copy(uuid.begin(), uuid.end(), extra->begin());
}

void DnstapProtoBufMessage::update(const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, uint16_t id)
{
  struct timespec ts;
  gettime(&ts, true);
  setTime(ts.tv_sec, ts.tv_nsec / 1000);
  setUUID(uuid);

  char identity[MAXHOSTNAMELEN+1];
  if (gethostname(identity, MAXHOSTNAMELEN) == 0) {
    identity[MAXHOSTNAMELEN] = 0;
    proto_message.set_identity(identity);
  } else {
#ifdef WE_ARE_RECURSOR
    L<<Logger::Warning<<"Error: gethostname() failed."<<std::endl;
#else
    warnlog("Error: gethostname() failed.\n");
#endif
  }

  proto_message.set_version(PACKAGE_STRING);

  dnstap::Message* message = proto_message.mutable_message();

  if (requestor) {
    message->set_socket_family(requestor->sin4.sin_family == AF_INET ? dnstap::INET : dnstap::INET6);
  }
  else if (responder) {
    message->set_socket_family(responder->sin4.sin_family == AF_INET ? dnstap::INET : dnstap::INET6);
  }

  message->set_socket_protocol(isTCP ? dnstap::TCP : dnstap::UDP);

  if (responder) {
    setResponder(*responder);
  }
  if (requestor) {
    setRequestor(*requestor);
  }
}

DnstapProtoBufMessage::DnstapProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type, const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, const DNSName& domain, int qtype, uint16_t qclass, uint16_t qid, bool isTCP, size_t bytes)
{
  setType(type);
  update(uuid, requestor, responder, isTCP, qid);
  setBytes(bytes);
  setQuestion(domain, qtype, qclass);
}

#endif /* HAVE_PROTOBUF */