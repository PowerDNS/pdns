#include <boost/uuid/uuid.hpp>
#include "config.h"
#include "gettime.hh"
#include "dnstap.hh"

#include "ext/protozero/include/protozero/pbf_writer.hpp"

DnstapMessage::DnstapMessage(std::string& buffer, int32_t type, const std::string& identity, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, const char* packet, const size_t len, const struct timespec* queryTime, const struct timespec* responseTime, boost::optional<const DNSName&> auth): d_buffer(buffer)
{
  protozero::pbf_writer pbf{d_buffer};

  pbf.add_bytes(1, identity);
  pbf.add_bytes(2, PACKAGE_STRING);
  pbf.add_enum(15, 1);

  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(packet);
  protozero::pbf_writer pbf_message{pbf, 14};

  pbf_message.add_enum(1, type);
  pbf_message.add_enum(3, isTCP ? 2 : 1);

  if (requestor != nullptr) {
    pbf_message.add_enum(2, requestor->sin4.sin_family == AF_INET ? 1 : 2);
    if (requestor->sin4.sin_family == AF_INET) {
      pbf_message.add_bytes(4, reinterpret_cast<const char*>(&requestor->sin4.sin_addr.s_addr), sizeof(requestor->sin4.sin_addr.s_addr));
    }
    else if (requestor->sin4.sin_family == AF_INET6) {
      pbf_message.add_bytes(4, reinterpret_cast<const char*>(&requestor->sin6.sin6_addr.s6_addr), sizeof(requestor->sin6.sin6_addr.s6_addr));
    }
    pbf_message.add_uint32(6, ntohs(requestor->sin4.sin_port));
  }

  if (responder != nullptr) {
    if (responder->sin4.sin_family == AF_INET) {
      pbf_message.add_bytes(5, reinterpret_cast<const char*>(&responder->sin4.sin_addr.s_addr), sizeof(responder->sin4.sin_addr.s_addr));
    }
    else if (responder->sin4.sin_family == AF_INET6) {
      pbf_message.add_bytes(5, reinterpret_cast<const char*>(&responder->sin6.sin6_addr.s6_addr), sizeof(responder->sin6.sin6_addr.s6_addr));
    }
    pbf_message.add_uint32(7, ntohs(responder->sin4.sin_port));
  }

  if (queryTime != nullptr) {
    pbf_message.add_uint64(8, queryTime->tv_sec);
    pbf_message.add_fixed32(9, queryTime->tv_nsec);
  }

  if (responseTime != nullptr) {
    pbf_message.add_uint64(12, responseTime->tv_sec);
    pbf_message.add_fixed32(13, responseTime->tv_nsec);
  }

  if (!dh->qr) {
    pbf_message.add_bytes(10, packet, len);
  } else {
    pbf_message.add_bytes(14, packet, len);
  }

  if (auth) {
    pbf_message.add_bytes(11, auth->toDNSString());
  }
}

void DnstapMessage::setExtra(const std::string& extra)
{
  protozero::pbf_writer pbf{d_buffer};
  pbf.add_bytes(3, extra);
}
