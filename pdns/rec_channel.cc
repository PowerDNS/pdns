#include "rec_channel.hh"
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>

#include "ahuexception.hh"

using namespace std;

int RecursorControlChannel::listen(const string& fname)
{
  struct sockaddr_un local;
  d_fd=socket(AF_UNIX,SOCK_DGRAM,0);
    
  if(d_fd < 0) 
    throw AhuException("Creating UNIX domain socket: "+string(strerror(errno)));
  
  int tmp=1;
  if(setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
    throw AhuException(string("Setsockopt failed: ")+strerror(errno));
  
  int err=unlink(fname.c_str());
  if(err < 0 && errno!=ENOENT)
    throw AhuException("Unable to remove (previous) controlsocket: "+string(strerror(errno)));

  memset(&local,0,sizeof(local));
  local.sun_family=AF_UNIX;
  strcpy(local.sun_path, fname.c_str());
    
  if(bind(d_fd, (sockaddr*)&local,sizeof(local))<0) 
    throw AhuException("Unable to bind to controlsocket: "+string(strerror(errno)));

  return d_fd;
}

void RecursorControlChannel::connect(const string& fname)
{
  struct sockaddr_un local, remote;

  d_fd=socket(AF_UNIX,SOCK_DGRAM,0);
    
  if(d_fd < 0) 
    throw AhuException("Creating UNIX domain socket: "+string(strerror(errno)));
  
  int tmp=1;
  if(setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
    throw AhuException(string("Setsockopt failed: ")+strerror(errno));
  
  string localname="./blah";

  local.sun_family=AF_UNIX;
  strcpy(local.sun_path,localname.c_str());

  int err=unlink(localname.c_str());
  if(err < 0 && errno!=ENOENT)
    throw AhuException("Unable to remove local controlsocket: "+string(strerror(errno)));

  if(bind(d_fd, (sockaddr*)&local,sizeof(local))<0) {
    unlink(local.sun_path);
    throw AhuException("Unable to bind to local temporary file: "+string(strerror(errno)));
  }

  if(chmod(local.sun_path,0666)<0) { // make sure that pdns can reply!
    unlink(local.sun_path);
    throw AhuException("Unable to chmnod local temporary socket: "+string(strerror(errno)));
  }

  memset(&remote,0,sizeof(remote));
  
  remote.sun_family=AF_UNIX;
  strcpy(remote.sun_path,fname.c_str());
  if(::connect(d_fd, (sockaddr*)&remote, sizeof(remote)) < 0) {
    unlink(local.sun_path);
    throw AhuException("Unable to connect to remote '"+fname+"': "+string(strerror(errno)));
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
      throw AhuException("Unable to send message over control channel: "+string(strerror(errno)));
  }
  else if(::send(d_fd, msg.c_str(), msg.length(), 0) < 0)
    throw AhuException("Unable to send message over control channel: "+string(strerror(errno)));
}

string RecursorControlChannel::recv(std::string* remote)
{
  char buffer[16384];
  ssize_t len;
  struct sockaddr_un remoteaddr;
  socklen_t addrlen=sizeof(remoteaddr);

  if((len=::recvfrom(d_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&remoteaddr, &addrlen)) < 0)
    throw AhuException("Unable to receive message over control channel: "+string(strerror(errno)));

  if(remote)
    *remote=remoteaddr.sun_path;

  return string(buffer, buffer+len);
}

