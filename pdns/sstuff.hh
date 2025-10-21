/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include <string>
#include <sstream>
#include <iostream>
#include "iputils.hh"
#include <cerrno>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <stdexcept>

#include <csignal>
#include "namespaces.hh"
#include "noinitvector.hh"

using ProtocolType = int; //!< Supported protocol types

//! Representation of a Socket and many of the Berkeley functions available
class Socket
{
public:
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  Socket(int socketDesc) :
    d_socket(socketDesc)
  {
  }

  //! Construct a socket of specified address family and socket type.
  Socket(int addressFamily, int socketType, ProtocolType protocolType = 0) :
    d_socket(socket(addressFamily, socketType, protocolType))
  {
    if (d_socket < 0) {
      throw NetworkError(stringerror());
    }
    setCloseOnExec(d_socket);
  }

  Socket(Socket&& rhs) noexcept :
    d_buffer(std::move(rhs.d_buffer)), d_socket(rhs.d_socket)
  {
    rhs.d_socket = -1;
  }

  Socket& operator=(Socket&& rhs) noexcept
  {
    if (d_socket != -1) {
      close(d_socket);
    }
    d_socket = rhs.d_socket;
    rhs.d_socket = -1;
    d_buffer = std::move(rhs.d_buffer);
    return *this;
  }

  ~Socket()
  {
    try {
      if (d_socket != -1) {
        closesocket(d_socket);
      }
    }
    catch (const PDNSException& e) {
    }
  }

  //! If the socket is capable of doing so, this function will wait for a connection
  [[nodiscard]] std::unique_ptr<Socket> accept() const
  {
    sockaddr_in remote{};
    socklen_t remlen = sizeof(remote);
    memset(&remote, 0, sizeof(remote));
    int sock = ::accept(d_socket, reinterpret_cast<sockaddr*>(&remote), &remlen); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
    if (sock < 0) {
      if (errno == EAGAIN) {
        return nullptr;
      }

      throw NetworkError("Accepting a connection: " + stringerror());
    }

    return std::make_unique<Socket>(sock);
  }

  //! Get remote address
  bool getRemote(ComboAddress& remote) const
  {
    socklen_t remotelen = sizeof(remote);
    return getpeername(d_socket, reinterpret_cast<struct sockaddr*>(&remote), &remotelen) >= 0; // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
  }

  //! Check remote address against netmaskgroup ng
  [[nodiscard]] bool acl(const NetmaskGroup& netmaskGroup) const
  {
    ComboAddress remote;
    if (getRemote(remote)) {
      return netmaskGroup.match(remote);
    }

    return false;
  }

  //! Set the socket to non-blocking
  void setNonBlocking() const
  {
    ::setNonBlocking(d_socket);
  }

  //! Set the socket to blocking
  void setBlocking() const
  {
    ::setBlocking(d_socket);
  }

  void setReuseAddr() const
  {
    try {
      ::setReuseAddr(d_socket);
    }
    catch (const PDNSException& e) {
      throw NetworkError(e.reason);
    }
  }

  void setFastOpenConnect()
  {
#ifdef TCP_FASTOPEN_CONNECT
    int on = 1;
    if (setsockopt(d_socket, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &on, sizeof(on)) < 0) {
      throw NetworkError("While setting TCP_FASTOPEN_CONNECT: " + stringerror());
    }
#else
    throw NetworkError("While setting TCP_FASTOPEN_CONNECT: not compiled in");
#endif
  }

  //! Bind the socket to a specified endpoint
  template <typename T>
  void bind(const T& local, bool reuseaddr = true) const
  {
    int tmp = 1;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (reuseaddr && setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&tmp), sizeof tmp) < 0) {
      throw NetworkError("Setsockopt failed: " + stringerror());
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::bind(d_socket, reinterpret_cast<const struct sockaddr*>(&local), local.getSocklen()) < 0) {
      throw NetworkError("While binding: " + stringerror());
    }
  }

  //! Connect the socket to a specified endpoint
  void connect(const ComboAddress& address, int timeout = 0) const
  {
    SConnectWithTimeout(d_socket, false, address, timeval{timeout, 0});
  }

  //! For datagram sockets, receive a datagram and learn where it came from
  /** For datagram sockets, receive a datagram and learn where it came from
      \param dgram Will be filled with the datagram
      \param ep Will be filled with the origin of the datagram */
  void recvFrom(string& dgram, ComboAddress& remote) const
  {
    socklen_t remlen = sizeof(remote);
    if (dgram.size() < s_buflen) {
      dgram.resize(s_buflen);
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto bytes = recvfrom(d_socket, dgram.data(), dgram.size(), 0, reinterpret_cast<sockaddr*>(&remote), &remlen);
    if (bytes < 0) {
      throw NetworkError("After recvfrom: " + stringerror());
    }
    dgram.resize(static_cast<size_t>(bytes));
  }

  bool recvFromAsync(PacketBuffer& dgram, ComboAddress& remote) const
  {
    socklen_t remlen = sizeof(remote);
    if (dgram.size() < s_buflen) {
      dgram.resize(s_buflen);
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto bytes = recvfrom(d_socket, dgram.data(), dgram.size(), 0, reinterpret_cast<sockaddr*>(&remote), &remlen);
    if (bytes < 0) {
      if (errno != EAGAIN) {
        throw NetworkError("After async recvfrom: " + stringerror());
      }
      return false;
    }
    dgram.resize(static_cast<size_t>(bytes));
    return true;
  }

  //! For datagram sockets, send a datagram to a destination
  void sendTo(const char* msg, size_t len, const ComboAddress& remote) const
  {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (sendto(d_socket, msg, len, 0, reinterpret_cast<const sockaddr*>(&remote), remote.getSocklen()) < 0) {
      throw NetworkError("After sendto: " + stringerror());
    }
  }

  //! For connected datagram sockets, send a datagram
  void send(const std::string& msg) const
  {
    if (::send(d_socket, msg.data(), msg.size(), 0) < 0) {
      throw NetworkError("After send: " + stringerror());
    }
  }

  /** For datagram sockets, send a datagram to a destination
      \param dgram The datagram
      \param remote The intended destination of the datagram */
  void sendTo(const string& dgram, const ComboAddress& remote) const
  {
    sendTo(dgram.data(), dgram.length(), remote);
  }

  //! Write this data to the socket, taking care that all bytes are written out
  void writen(const string& data) const
  {
    if (data.empty()) {
      return;
    }

    size_t toWrite = data.length();
    const char* ptr = data.data();

    do {
      auto res = ::send(d_socket, ptr, toWrite, 0);
      if (res < 0) {
        throw NetworkError("Writing to a socket: " + stringerror());
      }
      if (res == 0) {
        throw NetworkError("EOF on socket");
      }
      toWrite -= static_cast<size_t>(res);
      ptr += static_cast<size_t>(res); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    } while (toWrite > 0);
  }

  //! tries to write toWrite bytes from ptr to the socket
  /** tries to write toWrite bytes from ptr to the socket, but does not make sure they al get written out
      \param ptr Location to write from
      \param toWrite number of bytes to try
  */
  size_t tryWrite(const char* ptr, size_t toWrite) const
  {
    auto res = ::send(d_socket, ptr, toWrite, 0);
    if (res == 0) {
      throw NetworkError("EOF on writing to a socket");
    }
    if (res > 0) {
      return res;
    }

    if (errno == EAGAIN) {
      return 0;
    }

    throw NetworkError("Writing to a socket: " + stringerror());
  }

  //! Writes toWrite bytes from ptr to the socket
  /** Writes toWrite bytes from ptr to the socket. Returns how many bytes were written */
  size_t write(const char* ptr, size_t toWrite) const
  {
    auto res = ::send(d_socket, ptr, toWrite, 0);
    if (res < 0) {
      throw NetworkError("Writing to a socket: " + stringerror());
    }
    return res;
  }

  void writenWithTimeout(const void* buffer, size_t n, int timeout) const
  {
    size_t bytes = n;
    const char* ptr = static_cast<const char*>(buffer);

    while (bytes > 0) {
      auto ret = ::write(d_socket, ptr, bytes);
      if (ret < 0) {
        if (errno == EAGAIN) {
          ret = waitForRWData(d_socket, false, timeout, 0);
          if (ret < 0) {
            throw NetworkError("Waiting for data write");
          }
          if (ret == 0) {
            throw NetworkError("Timeout writing data");
          }
          continue;
        }
        throw NetworkError("Writing data: " + stringerror());
      }
      if (ret == 0) {
        throw NetworkError("Did not fulfill TCP write due to EOF");
      }

      ptr += static_cast<size_t>(ret); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      bytes -= static_cast<size_t>(ret);
    }
  }

  //! reads one character from the socket
  [[nodiscard]] int getChar() const
  {
    char character{};
    ssize_t res = ::recv(d_socket, &character, 1, 0);
    if (res > 0) {
      return static_cast<unsigned char>(character);
    }
    return -1;
  }

  void getline(string& data) const
  {
    data.clear();
    while (true) {
      int character = getChar();
      if (character == -1) {
        break;
      }
      data += (char)character;
      if (character == '\n') {
        break;
      }
    }
  }

  //! Reads a block of data from the socket to a string
  void read(string& data)
  {
    d_buffer.resize(s_buflen);
    ssize_t res = ::recv(d_socket, d_buffer.data(), s_buflen, 0);
    if (res < 0) {
      throw NetworkError("Reading from a socket: " + stringerror());
    }
    data.assign(d_buffer, 0, static_cast<size_t>(res));
  }

  //! Reads a block of data from the socket to a block of memory
  size_t read(char* buffer, size_t bytes) const
  {
    auto res = ::recv(d_socket, buffer, bytes, 0);
    if (res < 0) {
      throw NetworkError("Reading from a socket: " + stringerror());
    }
    return static_cast<size_t>(res);
  }

  /** Read a bock of data from the socket to a block of memory,
   *   waiting at most 'timeout' seconds for the data to become
   *   available. Be aware that this does _NOT_ handle partial reads
   *   for you.
   */
  size_t readWithTimeout(char* buffer, size_t n, int timeout) const
  {
    int err = waitForRWData(d_socket, true, timeout, 0);

    if (err == 0) {
      throw NetworkError("timeout reading");
    }
    if (err < 0) {
      throw NetworkError("nonblocking read failed: " + stringerror());
    }

    return read(buffer, n);
  }

  //! Sets the socket to listen with a default listen backlog of 10 pending connections
  void listen(int length = 10) const
  {
    if (::listen(d_socket, length) < 0) {
      throw NetworkError("Setting socket to listen: " + stringerror());
    }
  }

  //! Returns the internal file descriptor of the socket
  [[nodiscard]] int getHandle() const
  {
    return d_socket;
  }

  int releaseHandle()
  {
    int ret = d_socket;
    d_socket = -1;
    return ret;
  }

private:
  static constexpr size_t s_buflen{4096};
  std::string d_buffer;
  int d_socket;
};
