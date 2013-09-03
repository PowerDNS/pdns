#include "rec_channel.hh"
#include <sys/socket.h>
#include <cerrno>
#include "misc.hh"
#include <string.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>

#include "pdnsexception.hh"

#include "namespaces.hh"

RecursorControlChannel::RecursorControlChannel()
{
  d_fd=-1;
  *d_local.sun_path=0;
}

RecursorControlChannel::~RecursorControlChannel() 
{
  if(d_fd > 0)
    close(d_fd);
  if(*d_local.sun_path)
    unlink(d_local.sun_path);
}

int RecursorControlChannel::listen(const string& fname)
{
  d_fd=socket(AF_UNIX,SOCK_DGRAM,0);
  Utility::setCloseOnExec(d_fd);

  if(d_fd < 0) 
    throw PDNSException("Creating UNIX domain socket: "+stringerror());
  
  int tmp=1;
  if(setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
    throw PDNSException("Setsockopt failed: "+stringerror());
  
  int err=unlink(fname.c_str());
  if(err < 0 && errno!=ENOENT)
    throw PDNSException("Can't remove (previous) controlsocket '"+fname+"': "+stringerror() + " (try --socket-dir)");

  if(makeUNsockaddr(fname, &d_local))
    throw PDNSException("Unable to bind to controlsocket, path '"+fname+"' is not a valid UNIX socket path.");
    
  if(bind(d_fd, (sockaddr*)&d_local,sizeof(d_local))<0) 
    throw PDNSException("Unable to bind to controlsocket '"+fname+"': "+stringerror());

  return d_fd;
}

void RecursorControlChannel::connect(const string& path, const string& fname)
{
  struct sockaddr_un remote;

  d_fd=socket(AF_UNIX,SOCK_DGRAM,0);
  Utility::setCloseOnExec(d_fd);

  if(d_fd < 0) 
    throw PDNSException("Creating UNIX domain socket: "+string(strerror(errno)));

  try {
    int tmp=1;
    if(setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
      throw PDNSException("Setsockopt failed: "+stringerror());
  
    string localname=path+"/lsockXXXXXX";
    if (makeUNsockaddr(localname, &d_local))
      throw PDNSException("Unable to bind to local temporary file, path '"+localname+"' is not a valid UNIX socket path.");

    if(mkstemp(d_local.sun_path) < 0)
      throw PDNSException("Unable to generate local temporary file in directory '"+path+"': "+stringerror());

    int err=unlink(d_local.sun_path);
    if(err < 0 && errno!=ENOENT)
      throw PDNSException("Unable to remove local controlsocket: "+stringerror());

    if(bind(d_fd, (sockaddr*)&d_local,sizeof(d_local))<0)
      throw PDNSException("Unable to bind to local temporary file: "+stringerror());

    if(chmod(d_local.sun_path,0666)<0) // make sure that pdns can reply!
      throw PDNSException("Unable to chmod local temporary socket: "+stringerror());

    string remotename=path+"/"+fname;
    if (makeUNsockaddr(remotename, &remote))
      throw PDNSException("Unable to connect to controlsocket, path '"+remotename+"' is not a valid UNIX socket path.");

    if(::connect(d_fd, (sockaddr*)&remote, sizeof(remote)) < 0)
      throw PDNSException("Unable to connect to remote '"+string(remote.sun_path)+"': "+stringerror());

  } catch (...) {
    close(d_fd);
    d_fd=-1;
    d_local.sun_path[0]=0;
    throw;
  }
}

void RecursorControlChannel::send(const std::string& msg, const std::string* remote)
{
  if(remote) {
    struct sockaddr_un remoteaddr;
    memset(&remoteaddr, 0, sizeof(remoteaddr));
  
    remoteaddr.sun_family=AF_UNIX;
    strcpy(remoteaddr.sun_path, remote->c_str());

    if(::sendto(d_fd, msg.c_str(), msg.length(), 0, (struct sockaddr*) &remoteaddr, sizeof(remoteaddr) ) < 0)
      throw PDNSException("Unable to send message over control channel '"+*remote+"': "+string(strerror(errno)));
  }
  else if(::send(d_fd, msg.c_str(), msg.length(), 0) < 0)
    throw PDNSException("Unable to send message over control channel: "+string(strerror(errno)));
}

string RecursorControlChannel::recv(std::string* remote, unsigned int timeout)
{
  char buffer[16384];
  ssize_t len;
  struct sockaddr_un remoteaddr;
  socklen_t addrlen=sizeof(remoteaddr);
    
  if((waitForData(d_fd, timeout, 0 ) != 1) || (len=::recvfrom(d_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&remoteaddr, &addrlen)) < 0)
    throw PDNSException("Unable to receive message over control channel: "+string(strerror(errno)));

  if(remote)
    *remote=remoteaddr.sun_path;

  return string(buffer, buffer+len);
}

