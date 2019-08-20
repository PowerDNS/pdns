#include "config.h"
#include "gettime.hh"
#include "dnstap.hh"

DnstapMessage::DnstapMessage(const std::string& identity, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, const char* packet, const size_t len, const struct timespec* queryTime, const struct timespec* responseTime)
{
#ifdef HAVE_PROTOBUF
  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(packet);

  proto_message.set_identity(identity);
  proto_message.set_version(PACKAGE_STRING);
  proto_message.set_type(dnstap::Dnstap::MESSAGE);

  dnstap::Message* message = proto_message.mutable_message();

  message->set_type(!dh->qr ? dnstap::Message_Type_CLIENT_QUERY : dnstap::Message_Type_CLIENT_RESPONSE);
  message->set_socket_protocol(isTCP ? dnstap::TCP : dnstap::UDP);

  if (requestor != nullptr) {
    message->set_socket_family(requestor->sin4.sin_family == AF_INET ? dnstap::INET : dnstap::INET6);
    if (requestor->sin4.sin_family == AF_INET) {
      message->set_query_address(&requestor->sin4.sin_addr.s_addr, sizeof(requestor->sin4.sin_addr.s_addr));
    } else if (requestor->sin4.sin_family == AF_INET6) {
      message->set_query_address(&requestor->sin6.sin6_addr.s6_addr, sizeof(requestor->sin6.sin6_addr.s6_addr));
    }
    message->set_query_port(ntohs(requestor->sin4.sin_port));
  }
  if (responder != nullptr) {
    message->set_socket_family(responder->sin4.sin_family == AF_INET ? dnstap::INET : dnstap::INET6);
    if (responder->sin4.sin_family == AF_INET) {
      message->set_response_address(&responder->sin4.sin_addr.s_addr, sizeof(responder->sin4.sin_addr.s_addr));
    } else if (responder->sin4.sin_family == AF_INET6) {
      message->set_response_address(&responder->sin6.sin6_addr.s6_addr, sizeof(responder->sin6.sin6_addr.s6_addr));
    }
    message->set_response_port(ntohs(responder->sin4.sin_port));
  }
  if (queryTime != nullptr) {
    message->set_query_time_sec(queryTime->tv_sec);
    message->set_query_time_nsec(queryTime->tv_nsec);
  }
  if (responseTime != nullptr) {
    message->set_response_time_sec(responseTime->tv_sec);
    message->set_response_time_nsec(responseTime->tv_nsec);
  }

  if (!dh->qr) {
    message->set_query_message(packet, len);
  } else {
    message->set_response_message(packet, len);
  }
#endif /* HAVE_PROTOBUF */
}

void DnstapMessage::serialize(std::string& data) const
{
#ifdef HAVE_PROTOBUF
  proto_message.SerializeToString(&data);
#endif /* HAVE_PROTOBUF */
}

std::string DnstapMessage::toDebugString() const
{
  return
#ifdef HAVE_PROTOBUF
    proto_message.DebugString();
#else
    "";
#endif /* HAVE_PROTOBUF */
}

void DnstapMessage::setExtra(const std::string& extra)
{
#ifdef HAVE_PROTOBUF
  proto_message.set_extra(extra);
#endif /* HAVE_PROTOBUF */
}
