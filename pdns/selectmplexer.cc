#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include <unistd.h>
#include "misc.hh"
#include <boost/lexical_cast.hpp>

using namespace boost;

using namespace std;

void SelectFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, boost::any parameter)
{
  Callback cb;
  cb.d_callback=toDo;
  cb.d_parameter=parameter;
  if(cbmap.count(fd))
    throw FDMultiplexerException("Tried to add fd "+lexical_cast<string>(fd)+ " to multiplexer twice");
  cbmap[fd]=cb;
}

void SelectFDMultiplexer::removeFD(callbackmap_t& cbmap, int fd)
{
  if(!cbmap.erase(fd))
    throw FDMultiplexerException("Tried to remove unlisted fd "+lexical_cast<string>(fd)+ " from multiplexer");
}


int SelectFDMultiplexer::run(struct timeval* now)
{
  fd_set readfds, writefds;
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  
  int fdmax=0;

  for(callbackmap_t::const_iterator i=d_readCallbacks.begin(); i != d_readCallbacks.end(); ++i) {
    FD_SET(i->first, &readfds);
    fdmax=max(i->first, fdmax);
  }
  
  struct timeval tv={0,500000};
  int ret=select(fdmax + 1, &readfds, &writefds, 0, &tv);
  if(now)
    gettimeofday(now,0);
  
  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("select returned error: "+stringerror());

  if(ret==0) // nothing
    return 0;

  d_inrun=true;
  d_newReadCallbacks=d_readCallbacks;
  d_newWriteCallbacks=d_writeCallbacks;

  for(callbackmap_t::iterator i=d_readCallbacks.begin(); i != d_readCallbacks.end(); ++i) {
    if(FD_ISSET(i->first, &readfds))
      i->second.d_callback(i->first, i->second.d_parameter);
  }
  for(callbackmap_t::iterator i=d_writeCallbacks.begin(); i != d_writeCallbacks.end(); ++i) {
    if(FD_ISSET(i->first, &writefds))
      i->second.d_callback(i->first, i->second.d_parameter);
  }

  d_readCallbacks.swap(d_newReadCallbacks);
  d_writeCallbacks.swap(d_newWriteCallbacks);

  d_inrun=false;
  
  return 0;
}

void acceptData(int fd, boost::any& parameter)
{
  cout<<"Have data on fd "<<fd<<endl;
  Socket* sock=boost::any_cast<Socket*>(parameter);
  string packet;
  IPEndpoint rem;
  sock->recvFrom(packet, rem);
  cout<<"Received "<<packet.size()<<" bytes!\n";
}

#if 0
int main()
{
  Socket s(InterNetwork, Datagram);
  
  IPEndpoint loc("0.0.0.0", 2000);
  s.bind(loc);

  SelectFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif

