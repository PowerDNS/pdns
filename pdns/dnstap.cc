#include <boost/uuid/uuid.hpp>
#include "config.h"
#include "gettime.hh"
#include "protozero/types.hpp"
#include "dnstap.hh"

#ifndef DISABLE_PROTOBUF

#include <protozero/pbf_writer.hpp>

namespace DnstapBaseFields
{
enum : protozero::pbf_tag_type
{
  identity = 1,
  version = 2,
  extra = 3,
  message = 14,
  type = 15
};
}

namespace DnstapMessageTypes
{
enum : protozero::pbf_tag_type
{
  message = 1
};
}

namespace DnstapSocketFamilyTypes
{
enum : protozero::pbf_tag_type
{
  inet = 1,
  inet6 = 2
};
}

namespace DnstapMessageFields
{
enum : protozero::pbf_tag_type
{
  type = 1,
  socket_family = 2,
  socket_protocol = 3,
  query_address = 4,
  response_address = 5,
  query_port = 6,
  response_port = 7,
  query_time_sec = 8,
  query_time_nsec = 9,
  query_message = 10,
  query_zone = 11,
  response_time_sec = 12,
  response_time_nsec = 13,
  response_message = 14,
  policy = 15,
  http_protocol = 16,
};
}

std::string&& DnstapMessage::getBuffer()
{
  return std::move(d_buffer);
}

DnstapMessage::DnstapMessage(std::string&& buffer, DnstapMessage::MessageType type, const std::string& identity, const ComboAddress* requestor, const ComboAddress* responder, DnstapMessage::ProtocolType protocol, const char* packet, const size_t len, const struct timespec* queryTime, const struct timespec* responseTime, const DNSName& auth, const std::optional<HttpProtocolType> httpProtocol) :
  d_buffer(std::move(buffer))
{
  protozero::pbf_writer pbf{d_buffer};

  pbf.add_bytes(DnstapBaseFields::identity, identity);
  pbf.add_bytes(DnstapBaseFields::version, PACKAGE_STRING);
  pbf.add_enum(DnstapBaseFields::type, DnstapMessageTypes::message);

  protozero::pbf_writer pbf_message{pbf, DnstapBaseFields::message};

  // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
  pbf_message.add_enum(DnstapMessageFields::type, static_cast<protozero::pbf_tag_type>(type));
  // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
  pbf_message.add_enum(DnstapMessageFields::socket_protocol, static_cast<protozero::pbf_tag_type>(protocol));

  if (requestor != nullptr) {
    pbf_message.add_enum(DnstapMessageFields::socket_family, requestor->sin4.sin_family == AF_INET ? DnstapSocketFamilyTypes::inet : DnstapSocketFamilyTypes::inet6);
  }
  else if (responder != nullptr) {
    pbf_message.add_enum(DnstapMessageFields::socket_family, responder->sin4.sin_family == AF_INET ? DnstapSocketFamilyTypes::inet : DnstapSocketFamilyTypes::inet6);
  }

  if (requestor != nullptr) {
    if (requestor->sin4.sin_family == AF_INET) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      pbf_message.add_bytes(DnstapMessageFields::query_address, reinterpret_cast<const char*>(&requestor->sin4.sin_addr.s_addr), sizeof(requestor->sin4.sin_addr.s_addr));
    }
    else if (requestor->sin4.sin_family == AF_INET6) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      pbf_message.add_bytes(DnstapMessageFields::query_address, reinterpret_cast<const char*>(&requestor->sin6.sin6_addr.s6_addr), sizeof(requestor->sin6.sin6_addr.s6_addr));
    }
    pbf_message.add_uint32(DnstapMessageFields::query_port, ntohs(requestor->sin4.sin_port));
  }

  if (responder != nullptr) {
    if (responder->sin4.sin_family == AF_INET) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      pbf_message.add_bytes(DnstapMessageFields::response_address, reinterpret_cast<const char*>(&responder->sin4.sin_addr.s_addr), sizeof(responder->sin4.sin_addr.s_addr));
    }
    else if (responder->sin4.sin_family == AF_INET6) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      pbf_message.add_bytes(DnstapMessageFields::response_address, reinterpret_cast<const char*>(&responder->sin6.sin6_addr.s6_addr), sizeof(responder->sin6.sin6_addr.s6_addr));
    }
    pbf_message.add_uint32(DnstapMessageFields::response_port, ntohs(responder->sin4.sin_port));
  }

  if (queryTime != nullptr) {
    pbf_message.add_uint64(DnstapMessageFields::query_time_sec, queryTime->tv_sec);
    pbf_message.add_fixed32(DnstapMessageFields::query_time_nsec, queryTime->tv_nsec);
  }

  if (responseTime != nullptr) {
    pbf_message.add_uint64(DnstapMessageFields::response_time_sec, responseTime->tv_sec);
    pbf_message.add_fixed32(DnstapMessageFields::response_time_nsec, responseTime->tv_nsec);
  }

  if (packet != nullptr && len >= sizeof(dnsheader)) {
    const dnsheader_aligned dnsheader(packet);
    if (!dnsheader->qr) {
      pbf_message.add_bytes(DnstapMessageFields::query_message, packet, len);
    }
    else {
      pbf_message.add_bytes(DnstapMessageFields::response_message, packet, len);
    }
  }
  if (httpProtocol) {
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    pbf_message.add_enum(DnstapMessageFields::http_protocol, static_cast<protozero::pbf_tag_type>(*httpProtocol));
  }

  if (!auth.empty()) {
    pbf_message.add_bytes(DnstapMessageFields::query_zone, auth.toDNSString());
  }

  pbf_message.commit();
}

void DnstapMessage::setExtra(const std::string& extra)
{
  protozero::pbf_writer pbf{d_buffer};
  pbf.add_bytes(DnstapBaseFields::extra, extra);
}

#endif /* DISABLE_PROTOBUF */
