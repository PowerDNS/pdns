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
  if(ret < 0)
    RuntimeError(boost::format("connecting socket to %s: %s") % remote.toStringWithPort() % strerror(errno));
  return ret;
}

int SBind(int sockfd, const ComboAddress& local)
{
  int ret = bind(sockfd, (struct sockaddr*)&local, local.getSocklen());
  if(ret < 0)
    RuntimeError(boost::format("binding socket to %s: %s") % local.toStringWithPort() % strerror(errno));
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

int sendfromto(int sock, const char* data, int len, int flags, const ComboAddress& from, const ComboAddress& to)
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
    addCMsgSrcAddr(&msgh, cbuf, &from);
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

void ComboAddress::truncate(unsigned int bits)
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

template class NetmaskTree<bool>;
