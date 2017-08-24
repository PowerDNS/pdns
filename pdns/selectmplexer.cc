#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include "misc.hh"

#include "namespaces.hh"

static FDMultiplexer* make()
{
  return new SelectFDMultiplexer();
}

static struct RegisterOurselves
{
  RegisterOurselves() {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(1, &make));
  }
} doIt;

void SelectFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const boost::any& parameter)
{
  Callback cb;
  cb.d_callback=toDo;
  cb.d_parameter=parameter;
  memset(&cb.d_ttd, 0, sizeof(cb.d_ttd));
  if(cbmap.count(fd))
    throw FDMultiplexerException("Tried to add fd "+std::to_string(fd)+ " to multiplexer twice");
  cbmap[fd]=cb;
}

void SelectFDMultiplexer::removeFD(callbackmap_t& cbmap, int fd)
{
  if(d_inrun && d_iter->first==fd)  // trying to remove us!
    d_iter++;

  if(!cbmap.erase(fd))
    throw FDMultiplexerException("Tried to remove unlisted fd "+std::to_string(fd)+ " from multiplexer");
}

int SelectFDMultiplexer::run(struct timeval* now, int timeout)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  fd_set readfds, writefds;
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  
  int fdmax=0;

  for(callbackmap_t::const_iterator i=d_readCallbacks.begin(); i != d_readCallbacks.end(); ++i) {
    FD_SET(i->first, &readfds);
    fdmax=max(i->first, fdmax);
  }

  for(callbackmap_t::const_iterator i=d_writeCallbacks.begin(); i != d_writeCallbacks.end(); ++i) {
    FD_SET(i->first, &writefds);
    fdmax=max(i->first, fdmax);
  }
  
  struct timeval tv={timeout / 1000 , (timeout % 1000) * 1000};
  int ret=select(fdmax + 1, &readfds, &writefds, 0, &tv);
  gettimeofday(now, 0); // MANDATORY!
  
  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("select returned error: "+stringerror());

  if(ret < 1) // nothing - thanks AB
    return 0;

  d_iter=d_readCallbacks.end();
  d_inrun=true;

  int got = 0;
  for(callbackmap_t::iterator i=d_readCallbacks.begin(); i != d_readCallbacks.end() && i->first <= fdmax; ) {
    d_iter=i++;

    if(FD_ISSET(d_iter->first, &readfds)) {
      d_iter->second.d_callback(d_iter->first, d_iter->second.d_parameter);
      got++;
      continue;  // so we don't refind ourselves as writable
    }
  }

  for(callbackmap_t::iterator i=d_writeCallbacks.begin(); i != d_writeCallbacks.end() && i->first <= fdmax; ) {
    d_iter=i++;
    if(FD_ISSET(d_iter->first, &writefds)) {
      d_iter->second.d_callback(d_iter->first, d_iter->second.d_parameter);
      got++;
    }
  }

  d_inrun=false;
  return got;
}

#if 0

void acceptData(int fd, boost::any& parameter)
{
  cout<<"Have data on fd "<<fd<<endl;
  Socket* sock=boost::any_cast<Socket*>(parameter);
  string packet;
  IPEndpoint rem;
  sock->recvFrom(packet, rem);
  cout<<"Received "<<packet.size()<<" bytes!\n";
}


int main()
{
  Socket s(AF_INET, SOCK_DGRAM);
  
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

