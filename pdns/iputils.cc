#include "iputils.hh"
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


