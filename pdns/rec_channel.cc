#include "rec_channel.hh"
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
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

}
