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

class MockupTLSCtx : public TLSCtx
{
public:
  ~MockupTLSCtx()
  {
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, const struct timeval& timeout, time_t now) override
  {
    (void)timeout;
    (void)now;
    return std::make_unique<MockupTLSConnection>(socket);
  }

  std::unique_ptr<TLSConnection> getClientConnection(const std::string& host, bool hostIsAddr, int socket, const struct timeval& timeout) override
  {
    (void)host;
    (void)hostIsAddr;
    (void)timeout;
    return std::make_unique<MockupTLSConnection>(socket, true, d_needProxyProtocol);
  }

  void rotateTicketsKey(time_t now) override
  {
    (void)now;
  }

  size_t getTicketsKeysCount() override
  {
    return 0;
  }

  std::string getName() const override
  {
    return "Mockup TLS";
  }

  bool d_needProxyProtocol{false};
};

class MockupFDMultiplexer : public FDMultiplexer
{
public:
  MockupFDMultiplexer()
  {
  }

  ~MockupFDMultiplexer()
  {
  }

  int run(struct timeval* tv, int timeout = 500) override
  {
    (void)timeout;
    int ret = 0;

    gettimeofday(tv, nullptr); // MANDATORY

    /* 'ready' might be altered by a callback while we are iterating */
    const auto readyFDs = ready;
    for (const auto fd : readyFDs) {
      {
        const auto& it = d_readCallbacks.find(fd);

        if (it != d_readCallbacks.end()) {
          it->d_callback(it->d_fd, it->d_parameter);
        }
      }

      {
        const auto& it = d_writeCallbacks.find(fd);

        if (it != d_writeCallbacks.end()) {
          it->d_callback(it->d_fd, it->d_parameter);
        }
      }
    }

    return ret;
  }

  void getAvailableFDs(std::vector<int>& fds, int timeout) override
  {
    (void)fds;
    (void)timeout;
  }

  void addFD(int fd, FDMultiplexer::EventKind kind) override
  {
    (void)fd;
    (void)kind;
  }

  void removeFD(int fd, FDMultiplexer::EventKind) override
  {
    (void)fd;
  }

  string getName() const override
  {
    return "mockup";
  }

  void setReady(int fd)
  {
    ready.insert(fd);
  }

  void setNotReady(int fd)
  {
    ready.erase(fd);
  }

private:
  std::set<int> ready;
};

static bool isIPv6Supported()
{
  try {
    ComboAddress addr("[2001:db8:53::1]:53");
    auto socket = std::make_unique<Socket>(addr.sin4.sin_family, SOCK_STREAM, 0);
    socket->setNonBlocking();
    int res = SConnectWithTimeout(socket->getHandle(), false, addr, timeval{0, 0});
    if (res == 0 || res == EINPROGRESS) {
      return true;
    }
    return false;
  }
  catch (const std::exception& e) {
    return false;
  }
}

static ComboAddress getBackendAddress(const std::string& lastDigit, uint16_t port)
{
  static const bool useV6 = isIPv6Supported();

  if (useV6) {
    return ComboAddress("2001:db8:53::" + lastDigit, port);
  }

  return ComboAddress("192.0.2." + lastDigit, port);
}
