#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include <unistd.h>
#include "misc.hh"
#include <boost/lexical_cast.hpp>
#include "syncres.hh"
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

using namespace boost;
using namespace std;

class KqueueFDMultiplexer : public FDMultiplexer
{
public:
  KqueueFDMultiplexer();
  virtual ~KqueueFDMultiplexer()
  {
    close(d_kqueuefd);
  }

  virtual int run(struct timeval* tv);

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const boost::any& parameter);
  virtual void removeFD(callbackmap_t& cbmap, int fd);
  string getName()
  {
    return "kqueue";
  }
private:
  int d_kqueuefd;
  boost::shared_array<struct kevent> d_kevents;
  static unsigned int s_maxevents; // not a hard maximum
};

unsigned int KqueueFDMultiplexer::s_maxevents=1024;

static FDMultiplexer* make()
{
  return new KqueueFDMultiplexer();
}

static struct RegisterOurselves
{
  RegisterOurselves() {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(0, &make)); // priority 0!
  }
} doIt;

KqueueFDMultiplexer::KqueueFDMultiplexer() : d_kevents(new struct kevent[s_maxevents])
{
  d_kqueuefd=kqueue();
  if(d_kqueuefd < 0)
    throw FDMultiplexerException("Setting up kqueue: "+stringerror());
}

void KqueueFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const boost::any& parameter)
{
  accountingAddFD(cbmap, fd, toDo, parameter);

  struct kevent kqevent;
  EV_SET(&kqevent, fd, (&cbmap == &d_readCallbacks) ? EVFILT_READ : EVFILT_WRITE, EV_ADD, 0,0,0);
  
  if(kevent(d_kqueuefd, &kqevent, 1, 0, 0, 0) < 0) {
    cbmap.erase(fd);
    throw FDMultiplexerException("Adding fd to kqueue set: "+stringerror());
  }
}

void KqueueFDMultiplexer::removeFD(callbackmap_t& cbmap, int fd)
{
  accountingRemoveFD(cbmap, fd);

  struct kevent kqevent;
  EV_SET(&kqevent, fd, (&cbmap == &d_readCallbacks) ? EVFILT_READ : EVFILT_WRITE, EV_DELETE, 0,0,0);
  
  if(kevent(d_kqueuefd, &kqevent, 1, 0, 0, 0) < 0) // ponder putting Callback back on the map..
    throw FDMultiplexerException("Removing fd from kqueue set: "+stringerror());
}

int KqueueFDMultiplexer::run(struct timeval* now)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  
  struct timespec ts;
  ts.tv_sec=0;
  ts.tv_nsec=500000000U;

  int ret=kevent(d_kqueuefd, 0, 0, d_kevents.get(), s_maxevents, &ts);
  gettimeofday(now,0);
  
  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("kqueue returned error: "+stringerror());

  if(ret==0) // nothing
    return 0;

  d_inrun=true;

  for(int n=0; n < ret; ++n) {
    d_iter=d_readCallbacks.find(d_kevents[n].ident);
    if(d_iter != d_readCallbacks.end()) {
      d_iter->second.d_callback(d_iter->first, d_iter->second.d_parameter);
    }

    d_iter=d_writeCallbacks.find(d_kevents[n].ident);

    if(d_iter != d_writeCallbacks.end()) {
      d_iter->second.d_callback(d_iter->first, d_iter->second.d_parameter);
    }
  }

  d_inrun=false;
  return 0;
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
  Socket s(InterNetwork, Datagram);
  
  IPEndpoint loc("0.0.0.0", 2000);
  s.bind(loc);

  KqueueFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif



