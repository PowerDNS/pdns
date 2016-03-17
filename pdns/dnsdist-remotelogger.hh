#pragma once
#include "config.h"

class RemoteLogger
{
public:
  RemoteLogger(const ComboAddress& remote): d_remote(remote)
  {
#ifdef HAVE_PROTOBUF
    reconnect();
#else
    throw new std::runtime_error("Remote logging requires protobuf support, which is not enabled.");
#endif /* HAVE_PROTOBUF */
  }
  ~RemoteLogger()
  {
    if (d_socket >= 0)
      close(d_socket);
  }
  void logQuery(const DNSQuestion& dq);
  void logResponse(const DNSQuestion& dr);
  std::string toString()
  {
    return d_remote.toStringWithPort();
  }
private:
  void reconnect();
  bool sendData(const char* buffer, size_t bufferSize);

  ComboAddress d_remote;
  int d_socket{-1};
};

