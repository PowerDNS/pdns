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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iputils.hh"

#include <fstream>
#include <sys/socket.h>
#include <boost/format.hpp>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

/** these functions provide a very lightweight wrapper to the Berkeley sockets API. Errors -> exceptions! */

static void RuntimeError(const std::string& error)
{
  throw runtime_error(error);
}

static void NetworkErr(const std::string& error)
{
  throw NetworkError(error);
}

int SSocket(int family, int type, int flags)
{
  int ret = socket(family, type, flags);
  if (ret < 0) {
    RuntimeError("creating socket of type " + std::to_string(family) + ": " + stringerror());
  }
  return ret;
}

int SConnect(int sockfd, const ComboAddress& remote)
{
  int ret = connect(sockfd, reinterpret_cast<const struct sockaddr*>(&remote), remote.getSocklen()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  if (ret < 0) {
    int savederrno = errno;
    RuntimeError("connecting socket to " + remote.toStringWithPort() + ": " + stringerror(savederrno));
  }
  return ret;
}

int SConnectWithTimeout(int sockfd, const ComboAddress& remote, const struct timeval& timeout)
{
  int ret = connect(sockfd, reinterpret_cast<const struct sockaddr*>(&remote), remote.getSocklen()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  if (ret < 0) {
    int savederrno = errno;
    if (savederrno == EINPROGRESS) {
      if (timeout <= timeval{0, 0}) {
        return savederrno;
      }

      /* we wait until the connection has been established */
      bool error = false;
      bool disconnected = false;
      int res = waitForRWData(sockfd, false, timeout, &error, &disconnected);
      if (res == 1) {
        if (error) {
          savederrno = 0;
          socklen_t errlen = sizeof(savederrno);
          if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void*)&savederrno, &errlen) == 0) {
            NetworkErr("connecting to " + remote.toStringWithPort() + " failed: " + stringerror(savederrno));
          }
          else {
            NetworkErr("connecting to " + remote.toStringWithPort() + " failed");
          }
        }
        if (disconnected) {
          NetworkErr(remote.toStringWithPort() + " closed the connection");
        }
        return 0;
      }
      if (res == 0) {
        NetworkErr("timeout while connecting to " + remote.toStringWithPort());
      }
      else if (res < 0) {
        savederrno = errno;
        NetworkErr("waiting to connect to " + remote.toStringWithPort() + ": " + stringerror(savederrno));
      }
    }
    else {
      NetworkErr("connecting to " + remote.toStringWithPort() + ": " + stringerror(savederrno));
    }
  }

  return 0;
}

int SBind(int sockfd, const ComboAddress& local)
{
  int ret = bind(sockfd, reinterpret_cast<const struct sockaddr*>(&local), local.getSocklen()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  if (ret < 0) {
    int savederrno = errno;
    RuntimeError("binding socket to " + local.toStringWithPort() + ": " + stringerror(savederrno));
  }
  return ret;
}

int SAccept(int sockfd, ComboAddress& remote)
{
  socklen_t remlen = remote.getSocklen();

  int ret = accept(sockfd, reinterpret_cast<struct sockaddr*>(&remote), &remlen); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  if (ret < 0) {
    RuntimeError("accepting new connection on socket: " + stringerror());
  }
  return ret;
}

int SListen(int sockfd, int limit)
{
  int ret = listen(sockfd, limit);
  if (ret < 0) {
    RuntimeError("setting socket to listen: " + stringerror());
  }
  return ret;
}

int SSetsockopt(int sockfd, int level, int opname, int value)
{
  int ret = setsockopt(sockfd, level, opname, &value, sizeof(value));
  if (ret < 0) {
    RuntimeError("setsockopt for level " + std::to_string(level) + " and opname " + std::to_string(opname) + " to " + std::to_string(value) + " failed: " + stringerror());
  }
  return ret;
}

void setSocketIgnorePMTU([[maybe_unused]] int sockfd, [[maybe_unused]] int family)
{
  if (family == AF_INET) { // NOLINT(bugprone-branch-clone)
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
#ifdef IP_PMTUDISC_OMIT
    /* Linux 3.15+ has IP_PMTUDISC_OMIT, which discards PMTU information to prevent
       poisoning, but still allows fragmentation if the packet size exceeds the
       outgoing interface MTU, which is good.
    */
    try {
      SSetsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_OMIT);
      return;
    }
    catch (const std::exception& e) {
      /* failed, let's try IP_PMTUDISC_DONT instead */
    }
#endif /* IP_PMTUDISC_OMIT */

    /* IP_PMTUDISC_DONT disables Path MTU discovery */
    SSetsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT);
#endif /* defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT) */
  }
  else {
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DONT)
#ifdef IPV6_PMTUDISC_OMIT
    /* Linux 3.15+ has IPV6_PMTUDISC_OMIT, which discards PMTU information to prevent
       poisoning, but still allows fragmentation if the packet size exceeds the
       outgoing interface MTU, which is good.
    */
    try {
      SSetsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_OMIT);
      return;
    }
    catch (const std::exception& e) {
      /* failed, let's try IP_PMTUDISC_DONT instead */
    }
#endif /* IPV6_PMTUDISC_OMIT */

    /* IPV6_PMTUDISC_DONT disables Path MTU discovery */
    SSetsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DONT);
#endif /* defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DONT) */
  }
}

void setSocketForcePMTU([[maybe_unused]] int sockfd, [[maybe_unused]] int family)
{
  if (family == AF_INET) {
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
    /* IP_PMTUDISC_DO enables Path MTU discovery and prevents fragmentation */
    SSetsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO);
#elif defined(IP_DONTFRAG)
    /* at least this prevents fragmentation */
    SSetsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, 1);
#endif /* defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO) */
  }
  else {
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
    /* IPV6_PMTUDISC_DO enables Path MTU discovery and prevents fragmentation */
    SSetsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO);
#elif defined(IPV6_DONTFRAG)
    /* at least this prevents fragmentation */
    SSetsockopt(sockfd, IPPROTO_IPV6, IPV6_DONTFRAG, 1);
#endif /* defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO) */
  }
}

bool setReusePort(int sockfd)
{
#if defined(SO_REUSEPORT_LB)
  try {
    SSetsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT_LB, 1);
    return true;
  }
  catch (const std::exception& e) {
    return false;
  }
#elif defined(SO_REUSEPORT)
  try {
    SSetsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, 1);
    return true;
  }
  catch (const std::exception& e) {
    return false;
  }
#endif
  return false;
}

bool HarvestTimestamp(struct msghdr* msgh, struct timeval* timeval)
{
  // NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast, cppcoreguidelines-pro-bounds-pointer-arithmetic, cppcoreguidelines-pro-type-const-cast, cppcoreguidelines-pro-type-reinterpret-cast)
#ifdef SO_TIMESTAMP
  struct cmsghdr* cmsg{};
  for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != nullptr; cmsg = CMSG_NXTHDR(msgh, cmsg)) {
    if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SO_TIMESTAMP || cmsg->cmsg_type == SCM_TIMESTAMP) && CMSG_LEN(sizeof(*timeval)) == cmsg->cmsg_len) {
      memcpy(timeval, CMSG_DATA(cmsg), sizeof(*timeval));
      return true;
    }
  }
#endif
  return false;
}
bool HarvestDestinationAddress(const struct msghdr* msgh, ComboAddress* destination)
{
  destination->reset();
#ifdef __NetBSD__
  struct cmsghdr* cmsg{};
#else
  const struct cmsghdr* cmsg{};
#endif
  for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != nullptr; cmsg = CMSG_NXTHDR(const_cast<struct msghdr*>(msgh), const_cast<struct cmsghdr*>(cmsg))) {
#if defined(IP_PKTINFO)
    if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
      const auto* ptr = reinterpret_cast<const struct in_pktinfo*>(CMSG_DATA(cmsg));
      destination->sin4.sin_addr = ptr->ipi_addr;
      destination->sin4.sin_family = AF_INET;
      return true;
    }
#elif defined(IP_RECVDSTADDR)
    if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
      const auto* ptr = reinterpret_cast<const struct in_addr*>(CMSG_DATA(cmsg));
      destination->sin4.sin_addr = *ptr;
      destination->sin4.sin_family = AF_INET;
      return true;
    }
#endif

    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
      const auto* ptr = reinterpret_cast<const struct in6_pktinfo*>(CMSG_DATA(cmsg));
      destination->sin6.sin6_addr = ptr->ipi6_addr;
      destination->sin4.sin_family = AF_INET6;
      return true;
    }
  }
  return false;
  // NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast, cppcoreguidelines-pro-bounds-pointer-arithmetic, cppcoreguidelines-pro-type-const-cast, cppcoreguidelines-pro-type-reinterpret-cast)
}

bool IsAnyAddress(const ComboAddress& addr)
{
  if (addr.sin4.sin_family == AF_INET) {
    return addr.sin4.sin_addr.s_addr == 0;
  }
  if (addr.sin4.sin_family == AF_INET6) {
    return memcmp(&addr.sin6.sin6_addr, &in6addr_any, sizeof(addr.sin6.sin6_addr)) == 0;
  }
  return false;
}

int sendOnNBSocket(int fileDesc, const struct msghdr* msgh)
{
  int sendErr = 0;
#ifdef __OpenBSD__
  // OpenBSD can and does return EAGAIN on non-blocking datagram sockets
  for (int i = 0; i < 10; i++) { // Arbitrary upper bound
    if (sendmsg(fileDesc, msgh, 0) != -1) {
      sendErr = 0;
      break;
    }
    sendErr = errno;
    if (sendErr != EAGAIN) {
      break;
    }
  }
#else
  if (sendmsg(fileDesc, msgh, 0) == -1) {
    sendErr = errno;
  }
#endif
  return sendErr;
}

// be careful: when using this for receive purposes, make sure addr->sin4.sin_family is set appropriately so getSocklen works!
// be careful: when using this function for *send* purposes, be sure to set cbufsize to 0!
// be careful: if you don't call addCMsgSrcAddr after fillMSGHdr, make sure to set msg_control to NULL
void fillMSGHdr(struct msghdr* msgh, struct iovec* iov, cmsgbuf_aligned* cbuf, size_t cbufsize, char* data, size_t datalen, ComboAddress* addr)
{
  iov->iov_base = data;
  iov->iov_len = datalen;

  memset(msgh, 0, sizeof(struct msghdr));

  msgh->msg_control = cbuf;
  msgh->msg_controllen = cbufsize;
  msgh->msg_name = addr;
  msgh->msg_namelen = addr->getSocklen();
  msgh->msg_iov = iov;
  msgh->msg_iovlen = 1;
  msgh->msg_flags = 0;
}

// warning: various parts of PowerDNS assume 'truncate' will never throw
void ComboAddress::truncate(unsigned int bits) noexcept
{
  uint8_t* start{};
  int len = 4;
  if (sin4.sin_family == AF_INET) {
    if (bits >= 32) {
      return;
    }
    start = reinterpret_cast<uint8_t*>(&sin4.sin_addr.s_addr); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    len = 4;
  }
  else {
    if (bits >= 128) {
      return;
    }
    start = reinterpret_cast<uint8_t*>(&sin6.sin6_addr.s6_addr); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    len = 16;
  }

  auto tozero = len * 8 - bits; // if set to 22, this will clear 1 byte, as it should

  memset(start + len - tozero / 8, 0, tozero / 8); // blot out the whole bytes on the right NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

  auto bitsleft = tozero % 8; // 2 bits left to clear

  // a b c d, to truncate to 22 bits, we just zeroed 'd' and need to zero 2 bits from c
  // so and by '11111100', which is ~((1<<2)-1)  = ~3
  uint8_t* place = start + len - 1 - tozero / 8; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  *place &= (~((1 << bitsleft) - 1));
}

size_t sendMsgWithOptions(int socketDesc, const void* buffer, size_t len, const ComboAddress* dest, const ComboAddress* local, unsigned int localItf, int flags)
{
  msghdr msgh{};
  iovec iov{};
  cmsgbuf_aligned cbuf;

  /* Set up iov and msgh structures. */
  memset(&msgh, 0, sizeof(msgh));
  msgh.msg_control = nullptr;
  msgh.msg_controllen = 0;
  if (dest != nullptr) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-type-const-cast): it's the API
    msgh.msg_name = reinterpret_cast<void*>(const_cast<ComboAddress*>(dest));
    msgh.msg_namelen = dest->getSocklen();
  }
  else {
    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;
  }

  msgh.msg_flags = 0;

  if (local != nullptr && local->sin4.sin_family != 0) {
    addCMsgSrcAddr(&msgh, &cbuf, local, static_cast<int>(localItf));
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): it's the API
  iov.iov_base = const_cast<void*>(buffer);
  iov.iov_len = len;
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  msgh.msg_flags = 0;

  size_t sent = 0;
#ifdef MSG_FASTOPEN
  bool firstTry = true;
#endif

  do {

#ifdef MSG_FASTOPEN
    if ((flags & MSG_FASTOPEN) != 0 && !firstTry) {
      flags &= ~MSG_FASTOPEN;
    }
#endif /* MSG_FASTOPEN */

    ssize_t res = sendmsg(socketDesc, &msgh, flags);

    if (res > 0) {
      auto written = static_cast<size_t>(res);
      sent += written;

      if (sent == len) {
        return sent;
      }

      /* partial write */
#ifdef MSG_FASTOPEN
      firstTry = false;
#endif
      iov.iov_len -= written;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic): it's the API
      iov.iov_base = reinterpret_cast<void*>(reinterpret_cast<char*>(iov.iov_base) + written);
    }
    else if (res == 0) {
      return res;
    }
    else if (res == -1) {
      int err = errno;
      if (err == EINTR) {
        continue;
      }
      if (err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS || err == ENOTCONN) {
        /* EINPROGRESS might happen with non blocking socket,
           especially with TCP Fast Open */
        return sent;
      }
      unixDie("failed in sendMsgWithOptions");
    }
  } while (true);

  return 0;
}

template class NetmaskTree<bool, Netmask>;

/* requires a non-blocking socket.
   On Linux, we could use MSG_DONTWAIT on a blocking socket
   but this is not portable.
*/
bool isTCPSocketUsable(int sock)
{
  int err = 0;
  char buf = '\0';
  size_t buf_size = sizeof(buf);

  do {
    ssize_t got = recv(sock, &buf, buf_size, MSG_PEEK);

    if (got > 0) {
      /* socket is usable, some data is even waiting to be read */
      return true;
    }
    if (got == 0) {
      /* other end has closed the socket */
      return false;
    }
    err = errno;
    if (err == EAGAIN || err == EWOULDBLOCK) {
      /* socket is usable, no data waiting */
      return true;
    }
    if (err != EINTR) {
      /* something is wrong, could be ECONNRESET,
         ENOTCONN, EPIPE, but anyway this socket is
         not usable. */
      return false;
    }
  } while (err == EINTR);

  return false;
}
/* mission in life: parse four cases
   1) [2002::1]:53
   2) 1.2.3.4
   3) 1.2.3.4:5300
   4) 2001::1 no port allowed
*/

ComboAddress parseIPAndPort(const std::string& input, uint16_t port)
{
  if (input[0] == '[') { // case 1
    auto both = splitField(input.substr(1), ']');
    return ComboAddress(both.first, both.second.empty() ? port : pdns::checked_stoi<uint16_t>(both.second.substr(1)));
  }

  string::size_type count = 0;
  for (char chr : input) {
    if (chr == ':') {
      count++;
    }
    if (count > 1) {
      break;
    }
  }
  switch (count) {
  case 0: // case 2
    return ComboAddress(input, port);
  case 1: { // case 3
    string::size_type cpos = input.rfind(':');
    pair<std::string, std::string> both;
    both.first = input.substr(0, cpos);
    both.second = input.substr(cpos + 1);

    auto newport = pdns::checked_stoi<uint16_t>(both.second);
    return ComboAddress(both.first, newport);
  }
  default: // case 4
    return ComboAddress(input, port);
  }
}

void setSocketBuffer(int fileDesc, int optname, uint32_t size)
{
  uint32_t psize = 0;
  socklen_t len = sizeof(psize);

  if (getsockopt(fileDesc, SOL_SOCKET, optname, &psize, &len) != 0) {
    throw std::runtime_error("Unable to retrieve socket buffer size:" + stringerror());
  }
  if (psize >= size) {
    return;
  }
  if (setsockopt(fileDesc, SOL_SOCKET, optname, &size, sizeof(size)) != 0) {
    throw std::runtime_error("Unable to raise socket buffer size to " + std::to_string(size) + ": " + stringerror());
  }
}

void setSocketReceiveBuffer(int fileDesc, uint32_t size)
{
  setSocketBuffer(fileDesc, SO_RCVBUF, size);
}

void setSocketSendBuffer(int fileDesc, uint32_t size)
{
  setSocketBuffer(fileDesc, SO_SNDBUF, size);
}

#ifdef __linux__
static uint32_t raiseSocketBufferToMax(int socket, int optname, const std::string& readMaxFromFile)
{
  std::ifstream ifs(readMaxFromFile);
  if (ifs) {
    std::string line;
    if (getline(ifs, line)) {
      auto max = pdns::checked_stoi<uint32_t>(line);
      setSocketBuffer(socket, optname, max);
      return max;
    }
  }
  return 0;
}
#endif

uint32_t raiseSocketReceiveBufferToMax([[maybe_unused]] int socket)
{
#ifdef __linux__
  return raiseSocketBufferToMax(socket, SO_RCVBUF, "/proc/sys/net/core/rmem_max");
#else
  return 0;
#endif
}

uint32_t raiseSocketSendBufferToMax([[maybe_unused]] int socket)
{
#ifdef __linux__
  return raiseSocketBufferToMax(socket, SO_SNDBUF, "/proc/sys/net/core/wmem_max");
#else
  return 0;
#endif
}

std::set<std::string> getListOfNetworkInterfaces()
{
  std::set<std::string> result;
#ifdef HAVE_GETIFADDRS
  struct ifaddrs* ifaddr{};
  if (getifaddrs(&ifaddr) == -1) {
    return result;
  }

  for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_name == nullptr) {
      continue;
    }
    result.insert(ifa->ifa_name);
  }

  freeifaddrs(ifaddr);
#endif
  return result;
}

#ifdef HAVE_GETIFADDRS
std::vector<ComboAddress> getListOfAddressesOfNetworkInterface(const std::string& itf)
{
  std::vector<ComboAddress> result;
  struct ifaddrs* ifaddr = nullptr;
  if (getifaddrs(&ifaddr) == -1) {
    return result;
  }

  for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_name == nullptr || strcmp(ifa->ifa_name, itf.c_str()) != 0) {
      continue;
    }
    if (ifa->ifa_addr == nullptr || (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6)) {
      continue;
    }
    ComboAddress addr;
    try {
      addr.setSockaddr(ifa->ifa_addr, ifa->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    }
    catch (...) {
      continue;
    }

    result.push_back(addr);
  }

  freeifaddrs(ifaddr);
  return result;
}
#else
std::vector<ComboAddress> getListOfAddressesOfNetworkInterface(const std::string& /* itf */)
{
  std::vector<ComboAddress> result;
  return result;
}
#endif // HAVE_GETIFADDRS

#ifdef HAVE_GETIFADDRS
static uint8_t convertNetmaskToBits(const uint8_t* mask, socklen_t len)
{
  if (mask == nullptr || len > 16) {
    throw std::runtime_error("Invalid parameters passed to convertNetmaskToBits");
  }

  uint8_t result = 0;
  // for all bytes in the address (4 for IPv4, 16 for IPv6)
  for (size_t idx = 0; idx < len; idx++) {
    uint8_t byte = *(mask + idx); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    // count the number of bits set
    while (byte > 0) {
      result += (byte & 1);
      byte >>= 1;
    }
  }
  return result;
}
#endif /* HAVE_GETIFADDRS */

#ifdef HAVE_GETIFADDRS
std::vector<Netmask> getListOfRangesOfNetworkInterface(const std::string& itf)
{
  std::vector<Netmask> result;
  struct ifaddrs* ifaddr = nullptr;
  if (getifaddrs(&ifaddr) == -1) {
    return result;
  }

  for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_name == nullptr || strcmp(ifa->ifa_name, itf.c_str()) != 0) {
      continue;
    }
    if (ifa->ifa_addr == nullptr || (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6)) {
      continue;
    }
    ComboAddress addr;
    try {
      addr.setSockaddr(ifa->ifa_addr, ifa->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    }
    catch (...) {
      continue;
    }

    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    if (ifa->ifa_addr->sa_family == AF_INET) {
      const auto* netmask = reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_netmask);
      uint8_t maskBits = convertNetmaskToBits(reinterpret_cast<const uint8_t*>(&netmask->sin_addr.s_addr), sizeof(netmask->sin_addr.s_addr));
      result.emplace_back(addr, maskBits);
    }
    else if (ifa->ifa_addr->sa_family == AF_INET6) {
      const auto* netmask = reinterpret_cast<const struct sockaddr_in6*>(ifa->ifa_netmask);
      uint8_t maskBits = convertNetmaskToBits(reinterpret_cast<const uint8_t*>(&netmask->sin6_addr.s6_addr), sizeof(netmask->sin6_addr.s6_addr));
      result.emplace_back(addr, maskBits);
    }
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  }

  freeifaddrs(ifaddr);
  return result;
}
#else
std::vector<Netmask> getListOfRangesOfNetworkInterface(const std::string& /* itf */)
{
  std::vector<Netmask> result;
  return result;
}
#endif // HAVE_GETIFADDRS
