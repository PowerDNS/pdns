#include "protobuf.hh"
#include "protobuf-default.hh"
#include "protobuf-dnstap.hh"

DNSProtoBufMessage::~DNSProtoBufMessage()
{
  delete d_message;
}

DNSProtoBufMessage::DNSProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type)
{
  setType(type);
}

void DNSProtoBufMessage::addRRsFromPacket(const char* packet, const size_t len, bool includeCNAME)
{
#ifdef HAVE_PROTOBUF
  d_message->addRRsFromPacket(packet, len, includeCNAME);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::serialize(std::string& data) const
{
#ifdef HAVE_PROTOBUF
  d_message->serialize(data);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setBytes(size_t bytes)
{
#ifdef HAVE_PROTOBUF
  d_message->setBytes(bytes);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setEDNSSubnet(const Netmask& subnet, uint8_t mask)
{
#ifdef HAVE_PROTOBUF
  d_message->setEDNSSubnet(subnet, mask);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setQueryTime(time_t sec, uint32_t usec)
{
#ifdef HAVE_PROTOBUF
  d_message->setQueryTime(sec, usec);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setQuestion(const char* packet, const size_t len)
{
#ifdef HAVE_PROTOBUF
  d_message->setQuestion(packet, len);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setQuestion(const DNSName& qname, uint16_t qtype, uint16_t qclass)
{
#ifdef HAVE_PROTOBUF
  d_message->setQuestion(qname, qtype, qclass);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setRequestor(const ComboAddress& requestor)
{
#ifdef HAVE_PROTOBUF
  d_message->setRequestor(requestor);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setRequestor(const std::string& requestor)
{
#ifdef HAVE_PROTOBUF
  d_message->setRequestor(requestor);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setResponder(const ComboAddress& responder)
{
#ifdef HAVE_PROTOBUF
  d_message->setResponder(responder);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setRequestorId(const std::string& requestorId)
{
#ifdef HAVE_PROTOBUF
  d_message.set_requestorid(requestorId);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setResponder(const std::string& responder)
{
#ifdef HAVE_PROTOBUF
  d_message->setResponder(responder);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setResponseCode(uint8_t rcode)
{
#ifdef HAVE_PROTOBUF
  d_message->setResponseCode(rcode);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setTime(time_t sec, uint32_t usec)
{
#ifdef HAVE_PROTOBUF
  d_message->setTime(sec, usec);
#endif /* HAVE_PROTOBUF */
}

void DNSProtoBufMessage::setType(DNSProtoBufMessage::DNSProtoBufMessageType type)
{
#ifdef HAVE_PROTOBUF
  d_message->setType(type);
#endif /* HAVE_PROTOBUF */
}

std::string DNSProtoBufMessage::toDebugString() const
{
#ifdef HAVE_PROTOBUF
  return d_message->toDebugString();
#else
  return std::string();
#endif /* HAVE_PROTOBUF */
}

#ifdef HAVE_PROTOBUF

void DNSProtoBufMessage::setInitialRequestID(const boost::uuids::uuid& uuid)
{
  d_message->setInitialRequestID(uuid);
}

void DNSProtoBufMessage::setUUID(const boost::uuids::uuid& uuid)
{
  d_message->setUUID(uuid);
}

void DNSProtoBufMessage::update(const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, uint16_t id)
{
  d_message->update(uuid, requestor, responder, isTCP, id);
}

DNSProtoBufMessage::DNSProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type, const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, const DNSName& domain, int qtype, uint16_t qclass, uint16_t qid, bool isTCP, size_t bytes, bool useDnstap)
{
  if (useDnstap) {
    d_message = new DnstapProtoBufMessage(type);
  } else {
    d_message = new DefaultDNSProtoBufMessage(type);
  }

  d_message->update(uuid, requestor, responder, isTCP, qid);
  d_message->setType(type);
  d_message->setBytes(bytes);
  d_message->setQuestion(domain, qtype, qclass);
}

#endif /* HAVE_PROTOBUF */
