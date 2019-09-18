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
#include <sys/socket.h> 

/** these functions provide a very lightweight wrapper to the Berkeley sockets API. Errors -> exceptions! */

static void RuntimeError(const boost::format& fmt)
{
  throw runtime_error(fmt.str());
}

static void NetworkErr(const boost::format& fmt)
{
  throw NetworkError(fmt.str());
}

int SSocket(int family, int type, int flags)
{
  int ret = socket(family, type, flags);
  if(ret < 0)
    RuntimeError(boost::format("creating socket of type %d: %s") % family % stringerror());
  return ret;
}

int SConnect(int sockfd, const ComboAddress& remote)
{
  int ret = connect(sockfd, reinterpret_cast<const struct sockaddr*>(&remote), remote.getSocklen());
  if(ret < 0) {
    int savederrno = errno;
    RuntimeError(boost::format("connecting socket to %s: %s") % remote.toStringWithPort() % strerror(savederrno));
  }
  return ret;
}

int SConnectWithTimeout(int sockfd, const ComboAddress& remote, int timeout)
{
  int ret = connect(sockfd, reinterpret_cast<const struct sockaddr*>(&remote), remote.getSocklen());
  if(ret < 0) {
    int savederrno = errno;
    if (savederrno == EINPROGRESS) {
      if (timeout <= 0) {
        return savederrno;
      }

      /* we wait until the connection has been established */
      bool error = false;
      bool disconnected = false;
      int res = waitForRWData(sockfd, false, timeout, 0, &error, &disconnected);
      if (res == 1) {
        if (error) {
          savederrno = 0;
          socklen_t errlen = sizeof(savederrno);
          if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)&savederrno, &errlen) == 0) {
            NetworkErr(boost::format("connecting to %s failed: %s") % remote.toStringWithPort() % string(strerror(savederrno)));
          }
          else {
            NetworkErr(boost::format("connecting to %s failed") % remote.toStringWithPort());
          }
        }
        if (disconnected) {
          NetworkErr(boost::format("%s closed the connection") % remote.toStringWithPort());
        }
        return 0;
      }
      else if (res == 0) {
        NetworkErr(boost::format("timeout while connecting to %s") % remote.toStringWithPort());
      } else if (res < 0) {
        savederrno = errno;
        NetworkErr(boost::format("waiting to connect to %s: %s") % remote.toStringWithPort() % string(strerror(savederrno)));
      }
    }
    else {
      NetworkErr(boost::format("connecting to %s: %s") % remote.toStringWithPort() % string(strerror(savederrno)));
    }
  }

  return 0;
}

int SBind(int sockfd, const ComboAddress& local)
{
  int ret = bind(sockfd, (struct sockaddr*)&local, local.getSocklen());
  if(ret < 0) {
    int savederrno = errno;
    RuntimeError(boost::format("binding socket to %s: %s") % local.toStringWithPort() % strerror(savederrno));
  }
  return ret;
}

int SAccept(int sockfd, ComboAddress& remote)
{
  socklen_t remlen = remote.getSocklen();

  int ret = accept(sockfd, (struct sockaddr*)&remote, &remlen);
  if(ret < 0)
    RuntimeError(boost::format("accepting new connection on socket: %s") % stringerror());
  return ret;
}

int SListen(int sockfd, int limit)
{
  int ret = listen(sockfd, limit);
  if(ret < 0)
    RuntimeError(boost::format("setting socket to listen: %s") % stringerror());
  return ret;
}

int SSetsockopt(int sockfd, int level, int opname, int value)
{
  int ret = setsockopt(sockfd, level, opname, &value, sizeof(value));
  if(ret < 0)
    RuntimeError(boost::format("setsockopt for level %d and opname %d to %d failed: %s") % level % opname % value % stringerror());
  return ret;
}

void setSocketIgnorePMTU(int sockfd)
{
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
  catch(const std::exception& e) {
    /* failed, let's try IP_PMTUDISC_DONT instead */
  }
#endif /* IP_PMTUDISC_OMIT */

  /* IP_PMTUDISC_DONT disables Path MTU discovery */
  SSetsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT);
#endif /* defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT) */
}

bool HarvestTimestamp(struct msghdr* msgh, struct timeval* tv) 
{
#ifdef SO_TIMESTAMP
  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(msgh,cmsg)) {
    if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SO_TIMESTAMP || cmsg->cmsg_type == SCM_TIMESTAMP) && 
	CMSG_LEN(sizeof(*tv)) == cmsg->cmsg_len) {
      memcpy(tv, CMSG_DATA(cmsg), sizeof(*tv));
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
  struct cmsghdr* cmsg;
#else
  const struct cmsghdr* cmsg;
#endif
  for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(const_cast<struct msghdr*>(msgh), const_cast<struct cmsghdr*>(cmsg))) {
#if defined(IP_PKTINFO)
     if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
        struct in_pktinfo *i = (struct in_pktinfo *) CMSG_DATA(cmsg);
        destination->sin4.sin_addr = i->ipi_addr;
        destination->sin4.sin_family = AF_INET;
        return true;
    }
#elif defined(IP_RECVDSTADDR)
    if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
      struct in_addr *i = (struct in_addr *) CMSG_DATA(cmsg);
      destination->sin4.sin_addr = *i;
      destination->sin4.sin_family = AF_INET;      
      return true;
    }
#endif

    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
        struct in6_pktinfo *i = (struct in6_pktinfo *) CMSG_DATA(cmsg);
        destination->sin6.sin6_addr = i->ipi6_addr;
        destination->sin4.sin_family = AF_INET6;
        return true;
    }
  }
  return false;
}

bool IsAnyAddress(const ComboAddress& addr)
{
  if(addr.sin4.sin_family == AF_INET)
    return addr.sin4.sin_addr.s_addr == 0;
  else if(addr.sin4.sin_family == AF_INET6)
    return !memcmp(&addr.sin6.sin6_addr, &in6addr_any, sizeof(addr.sin6.sin6_addr));
  
  return false;
}

ssize_t sendfromto(int sock, const char* data, size_t len, int flags, const ComboAddress& from, const ComboAddress& to)
{
  struct msghdr msgh;
  struct iovec iov;
  cmsgbuf_aligned cbuf;

  /* Set up iov and msgh structures. */
  memset(&msgh, 0, sizeof(struct msghdr));
  iov.iov_base = (void*)data;
  iov.iov_len = len;
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  msgh.msg_name = (struct sockaddr*)&to;
  msgh.msg_namelen = to.getSocklen();

  if(from.sin4.sin_family) {
    addCMsgSrcAddr(&msgh, &cbuf, &from, 0);
  }
  else {
    msgh.msg_control=NULL;
  }
  return sendmsg(sock, &msgh, flags);
}

// be careful: when using this for receive purposes, make sure addr->sin4.sin_family is set appropriately so getSocklen works!
// be careful: when using this function for *send* purposes, be sure to set cbufsize to 0!
// be careful: if you don't call addCMsgSrcAddr after fillMSGHdr, make sure to set msg_control to NULL
void fillMSGHdr(struct msghdr* msgh, struct iovec* iov, cmsgbuf_aligned* cbuf, size_t cbufsize, char* data, size_t datalen, ComboAddress* addr)
{
  iov->iov_base = data;
  iov->iov_len  = datalen;

  memset(msgh, 0, sizeof(struct msghdr));
  
  msgh->msg_control = cbuf;
  msgh->msg_controllen = cbufsize;
  msgh->msg_name = addr;
  msgh->msg_namelen = addr->getSocklen();
  msgh->msg_iov  = iov;
  msgh->msg_iovlen = 1;
  msgh->msg_flags = 0;
}

// warning: various parts of PowerDNS assume 'truncate' will never throw
void ComboAddress::truncate(unsigned int bits) noexcept
{
  uint8_t* start;
  int len=4;
  if(sin4.sin_family==AF_INET) {
    if(bits >= 32)
      return;
    start = (uint8_t*)&sin4.sin_addr.s_addr;
    len=4;
  }
  else {
    if(bits >= 128)
      return;
    start = (uint8_t*)&sin6.sin6_addr.s6_addr;
    len=16;
  }

  auto tozero= len*8 - bits; // if set to 22, this will clear 1 byte, as it should

  memset(start + len - tozero/8, 0, tozero/8); // blot out the whole bytes on the right
  
  auto bitsleft=tozero % 8; // 2 bits left to clear

  // a b c d, to truncate to 22 bits, we just zeroed 'd' and need to zero 2 bits from c
  // so and by '11111100', which is ~((1<<2)-1)  = ~3
  uint8_t* place = start + len - 1 - tozero/8; 
  *place &= (~((1<<bitsleft)-1));
}

size_t sendMsgWithOptions(int fd, const char* buffer, size_t len, const ComboAddress* dest, const ComboAddress* local, unsigned int localItf, int flags)
{
  struct msghdr msgh;
  struct iovec iov;
  cmsgbuf_aligned cbuf;

  /* Set up iov and msgh structures. */
  memset(&msgh, 0, sizeof(struct msghdr));
  msgh.msg_control = nullptr;
  msgh.msg_controllen = 0;
  if (dest) {
    msgh.msg_name = reinterpret_cast<void*>(const_cast<ComboAddress*>(dest));
    msgh.msg_namelen = dest->getSocklen();
  }
  else {
    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;
  }

  msgh.msg_flags = 0;

  if (localItf != 0 && local) {
    addCMsgSrcAddr(&msgh, &cbuf, local, localItf);
  }

  iov.iov_base = reinterpret_cast<void*>(const_cast<char*>(buffer));
  iov.iov_len = len;
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  msgh.msg_flags = 0;

  size_t sent = 0;
  bool firstTry = true;

  do {

#ifdef MSG_FASTOPEN
    if (flags & MSG_FASTOPEN && firstTry == false) {
      flags &= ~MSG_FASTOPEN;
    }
#endif /* MSG_FASTOPEN */

    ssize_t res = sendmsg(fd, &msgh, flags);

    if (res > 0) {
      size_t written = static_cast<size_t>(res);
      sent += written;

      if (sent == len) {
        return sent;
      }

      /* partial write */
      firstTry = false;
      iov.iov_len -= written;
      iov.iov_base = reinterpret_cast<void*>(reinterpret_cast<char*>(iov.iov_base) + written);
      written = 0;
    }
    else if (res == 0) {
      return res;
    }
    else if (res == -1) {
      int err = errno;
      if (err == EINTR) {
        continue;
      }
      else if (err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS || err == ENOTCONN) {
        /* EINPROGRESS might happen with non blocking socket,
           especially with TCP Fast Open */
        return sent;
      }
      else {
        unixDie("failed in sendMsgWithTimeout");
      }
    }
  }
  while (true);

  return 0;
}

template class NetmaskTree<bool>;

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
    else if (got == 0) {
      /* other end has closed the socket */
      return false;
    }
    else {
      err = errno;

      if (err == EAGAIN || err == EWOULDBLOCK) {
        /* socket is usable, no data waiting */
        return true;
      }
      else {
        if (err != EINTR) {
          /* something is wrong, could be ECONNRESET,
             ENOTCONN, EPIPE, but anyway this socket is
             not usable. */
          return false;
        }
      }
    }
  } while (err == EINTR);

  return false;
}
