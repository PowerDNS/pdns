
#pragma once

#include <cstddef>
#include <string>

#include "config.h"

#include "dnsname.hh"
#include "iputils.hh"

#ifdef HAVE_PROTOBUF
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include "dnsmessage.pb.h"
#endif /* HAVE_PROTOBUF */

class DNSProtoBufMessage
{
public:
  enum DNSProtoBufMessageType {
    Query,
    Response
  };

  DNSProtoBufMessage()
  {
  }

  DNSProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type);

  ~DNSProtoBufMessage()
  {
  }

  void setQuestion(const DNSName& qname, uint16_t qtype, uint16_t qclass);
  void setEDNSSubnet(const Netmask& subnet);
  void setBytes(size_t bytes);
  void setTime(time_t sec, uint32_t usec);
  void setQueryTime(time_t sec, uint32_t usec);
  void setResponseCode(uint8_t rcode);
  void addRRsFromPacket(const char* packet, const size_t len);
  void serialize(std::string& data) const;
  std::string toDebugString() const;

#ifdef HAVE_PROTOBUF
  DNSProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type, const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, const DNSName& domain, int qtype, uint16_t qclass, uint16_t qid, bool isTCP, size_t bytes);
  void update(const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, uint16_t id);
  void setUUID(const boost::uuids::uuid& uuid);

protected:
  PBDNSMessage d_message;
#endif /* HAVE_PROTOBUF */
};
