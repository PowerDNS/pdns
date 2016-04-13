
#pragma once
#include "config.h"

#ifdef HAVE_PROTOBUF
void protobufMessageFromQuestion(const DNSQuestion& dq, std::string& data);
void protobufMessageFromResponse(const DNSQuestion& dr, std::string& data);

#endif /* HAVE_PROTOBUF */
