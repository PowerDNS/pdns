#pragma once

#include "protobuf.hh"

class DNSDistProtoBufMessage: public DNSProtoBufMessage
{
public:
  DNSDistProtoBufMessage(DNSProtoBufMessageType type, const DNSQuestion& dq);
};
