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


int SSocket(int family, int type, int flags)
{
  int ret = socket(family, type, flags);
  if(ret < 0)
    RuntimeError(boost::format("creating socket of type %d: %s") % family % strerror(errno));
  return ret;
}

int SConnect(int sockfd, const ComboAddress& remote)
{
  int ret = connect(sockfd, (struct sockaddr*)&remote, remote.getSocklen());
  if(ret < 0) {
    int savederrno = errno;
    RuntimeError(boost::format("connecting socket to %s: %s") % remote.toStringWithPort() % strerror(savederrno));
  }
  return ret;
}

int SConnectWithTimeout(int sockfd, const ComboAddress& remote, int timeout)
{
  int ret = connect(sockfd, (struct sockaddr*)&remote, remote.getSocklen());
  if(ret < 0) {
    int savederrno = errno;
    if (savederrno == EINPROGRESS) {
      /* we wait until the connection has been established */
      bool error = false;
      bool disconnected = false;
      int res = waitForRWData(sockfd, false, timeout, 0, &error, &disconnected);
      if (res == 1) {
        if (error) {
          savederrno = 0;
          socklen_t errlen = sizeof(savederrno);
          if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)&savederrno, &errlen) == 0) {
            RuntimeError(boost::format("connecting to %s failed: %s") % remote.toStringWithPort() % string(strerror(savederrno)));
          }
          else {
            RuntimeError(boost::format("connecting to %s failed") % remote.toStringWithPort());
          }
        }
        if (disconnected) {
          RuntimeError(boost::format("%s closed the connection") % remote.toStringWithPort());
        }
        return 0;
      }
      else if (res == 0) {
        RuntimeError(boost::format("timeout while connecting to %s") % remote.toStringWithPort());
      } else if (res < 0) {
        savederrno = errno;
        RuntimeError(boost::format("waiting to connect to %s: %s") % remote.toStringWithPort() % string(strerror(savederrno)));
      }
    }
    else {
      RuntimeError(boost::format("connecting to %s: %s") % remote.toStringWithPort() % string(strerror(savederrno)));
    }
  }

  return ret;
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
    RuntimeError(boost::format("accepting new connection on socket: %s") % strerror(errno));
  return ret;
}

int SListen(int sockfd, int limit)
{
  int ret = listen(sockfd, limit);
  if(ret < 0)
    RuntimeError(boost::format("setting socket to listen: %s") % strerror(errno));
  return ret;
}

int SSetsockopt(int sockfd, int level, int opname, int value)
{
  int ret = setsockopt(sockfd, level, opname, &value, sizeof(value));
  if(ret < 0)
    RuntimeError(boost::format("setsockopt for level %d and opname %d to %d failed: %s") % level % opname % value % strerror(errno));
  return ret;
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
bool HarvestDestinationAddress(struct msghdr* msgh, ComboAddress* destination)
{
  memset(destination, 0, sizeof(*destination));
  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != NULL; cmsg = CMSG_NXTHDR(msgh,cmsg)) {
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
  char cbuf[256];

  /* Set up iov and msgh structures. */
  memset(&msgh, 0, sizeof(struct msghdr));
  iov.iov_base = (void*)data;
  iov.iov_len = len;
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  msgh.msg_name = (struct sockaddr*)&to;
  msgh.msg_namelen = to.getSocklen();

  if(from.sin4.sin_family) {
    addCMsgSrcAddr(&msgh, cbuf, &from, 0);
  }
  else {
    msgh.msg_control=NULL;
  }
  return sendmsg(sock, &msgh, flags);
}

// be careful: when using this for receive purposes, make sure addr->sin4.sin_family is set appropriately so getSocklen works!
// be careful: when using this function for *send* purposes, be sure to set cbufsize to 0!
// be careful: if you don't call addCMsgSrcAddr after fillMSGHdr, make sure to set msg_control to NULL
void fillMSGHdr(struct msghdr* msgh, struct iovec* iov, char* cbuf, size_t cbufsize, char* data, size_t datalen, ComboAddress* addr)
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

ssize_t sendMsgWithTimeout(int fd, const char* buffer, size_t len, int timeout, ComboAddress& dest, const ComboAddress& local, unsigned int localItf)
{
  struct msghdr msgh;
  struct iovec iov;
  char cbuf[256];
  bool firstTry = true;
  fillMSGHdr(&msgh, &iov, cbuf, sizeof(cbuf), const_cast<char*>(buffer), len, &dest);
  addCMsgSrcAddr(&msgh, cbuf, &local, localItf);

  do {
    ssize_t written = sendmsg(fd, &msgh, 0);

    if (written > 0)
      return written;

    if (errno == EAGAIN) {
      if (firstTry) {
        int res = waitForRWData(fd, false, timeout, 0);
        if (res > 0) {
          /* there is room available */
          firstTry = false;
        }
        else if (res == 0) {
          throw runtime_error("Timeout while waiting to write data");
        } else {
          throw runtime_error("Error while waiting for room to write data");
        }
      }
      else {
        throw runtime_error("Timeout while waiting to write data");
      }
    }
    else {
      unixDie("failed in write2WithTimeout");
    }
  }
  while (firstTry);

  return 0;
}

template class NetmaskTree<bool>;

bool sendSizeAndMsgWithTimeout(int sock, uint16_t bufferLen, const char* buffer, int idleTimeout, const ComboAddress* dest, const ComboAddress* local, unsigned int localItf, int totalTimeout, int flags)
{
  uint16_t size = htons(bufferLen);
  char cbuf[256];
  struct msghdr msgh;
  struct iovec iov[2];
  int remainingTime = totalTimeout;
  time_t start = 0;
  if (totalTimeout) {
    start = time(NULL);
  }

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
    addCMsgSrcAddr(&msgh, cbuf, local, localItf);
  }

  iov[0].iov_base = &size;
  iov[0].iov_len = sizeof(size);
  iov[1].iov_base = reinterpret_cast<void*>(const_cast<char*>(buffer));
  iov[1].iov_len = bufferLen;

  size_t pos = 0;
  size_t sent = 0;
  size_t nbElements = sizeof(iov)/sizeof(*iov);
  while (true) {
    msgh.msg_iov = &iov[pos];
    msgh.msg_iovlen = nbElements - pos;

    ssize_t res = sendmsg(sock, &msgh, flags);
    if (res > 0) {
      size_t written = static_cast<size_t>(res);
      sent += written;

      if (sent == (sizeof(size) + bufferLen)) {
        return true;
      }
      /* partial write, we need to keep only the (parts of) elements
         that have not been written.
      */
      do {
        if (written < iov[pos].iov_len) {
          iov[pos].iov_len -= written;
          written = 0;
        }
        else {
          written -= iov[pos].iov_len;
          iov[pos].iov_len = 0;
          pos++;
        }
      }
      while (written > 0 && pos < nbElements);
    }
    else if (res == -1) {
      if (errno == EINTR) {
        continue;
      }
      else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
        /* EINPROGRESS might happen with non blocking socket,
           especially with TCP Fast Open */
        int ret = waitForRWData(sock, false, (totalTimeout == 0 || idleTimeout <= remainingTime) ? idleTimeout : remainingTime, 0);
        if (ret > 0) {
          /* there is room available */
        }
        else if (ret == 0) {
          throw runtime_error("Timeout while waiting to send data");
        } else {
          throw runtime_error("Error while waiting for room to send data");
        }
      }
      else {
        unixDie("failed in sendSizeAndMsgWithTimeout");
      }
    }
    if (totalTimeout) {
      time_t now = time(NULL);
      int elapsed = now - start;
      if (elapsed >= remainingTime) {
        throw runtime_error("Timeout while sending data");
      }
      start = now;
      remainingTime -= elapsed;
    }
  }

  return false;
}
