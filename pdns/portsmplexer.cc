#if defined(__sun__) && defined(__svr4__)
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <port.h>
#include <sys/port_impl.h>
#endif
#include <unistd.h>
#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>

#include "misc.hh"

#include "namespaces.hh"

class PortsFDMultiplexer : public FDMultiplexer
{
public:
  PortsFDMultiplexer();
  virtual ~PortsFDMultiplexer()
  {
    close(d_portfd);
  }

  virtual int run(struct timeval* tv, int timeout=500);

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const boost::any& parameter, const struct timeval* ttd=nullptr);
  virtual void removeFD(callbackmap_t& cbmap, int fd);
  string getName()
  {
    return "solaris completion ports";
  }
private:
  int d_portfd;
  boost::shared_array<port_event_t> d_pevents;
  static int s_maxevents; // not a hard maximum
};


static FDMultiplexer* makePorts()
{
  return new PortsFDMultiplexer();
}

static struct PortsRegisterOurselves
{
  PortsRegisterOurselves() {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(0, &makePorts)); // priority 0!
  }
} doItPorts;


int PortsFDMultiplexer::s_maxevents=1024;
PortsFDMultiplexer::PortsFDMultiplexer() : d_pevents(new port_event_t[s_maxevents])
{
  d_portfd=port_create(); // not hard max
  if(d_portfd < 0)
    throw FDMultiplexerException("Setting up port: "+stringerror());
}

void PortsFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const boost::any& parameter, const struct timeval* ttd)
{
  accountingAddFD(cbmap, fd, toDo, parameter, ttd);

  if(port_associate(d_portfd, PORT_SOURCE_FD, fd, (&cbmap == &d_readCallbacks) ? POLLIN : POLLOUT, 0) < 0) {
    cbmap.erase(fd);
    throw FDMultiplexerException("Adding fd to port set: "+stringerror());
  }
}

void PortsFDMultiplexer::removeFD(callbackmap_t& cbmap, int fd)
{
  if(!cbmap.erase(fd))
    throw FDMultiplexerException("Tried to remove unlisted fd "+std::to_string(fd)+ " from multiplexer");

  if(port_dissociate(d_portfd, PORT_SOURCE_FD, fd) < 0 && errno != ENOENT) // it appears under some circumstances, ENOENT will be returned, without this being an error. Apache has this same "fix"
    throw FDMultiplexerException("Removing fd from port set: "+stringerror());
}

int PortsFDMultiplexer::run(struct timeval* now, int timeout)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  
  struct timespec timeoutspec;
  timeoutspec.tv_sec = time / 1000;
  timeoutspec.tv_nsec = (time % 1000) * 1000000;
  unsigned int numevents=1;
  int ret= port_getn(d_portfd, d_pevents.get(), min(PORT_MAX_LIST, s_maxevents), &numevents, &timeoutspec);
  
  /* port_getn has an unusual API - (ret == -1, errno == ETIME) can
     mean partial success; you must check (*numevents) in this case
     and process anything in there, otherwise you'll never see any
     events from that object again. We don't care about pure timeouts
     (ret == -1, errno == ETIME, *numevents == 0) so we don't bother
     with that case. */
  if(ret == -1 && errno!=ETIME) {
    if(errno!=EINTR)
      throw FDMultiplexerException("completion port_getn returned error: "+stringerror());
    // EINTR is not really an error
    gettimeofday(now,0);
    return 0;
  }
  gettimeofday(now,0);
  if(!numevents) // nothing
    return 0;

  d_inrun=true;

  for(unsigned int n=0; n < numevents; ++n) {
    d_iter=d_readCallbacks.find(d_pevents[n].portev_object);
    
    if(d_iter != d_readCallbacks.end()) {
      d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
      if(d_readCallbacks.count(d_pevents[n].portev_object) && port_associate(d_portfd, PORT_SOURCE_FD, d_pevents[n].portev_object, 
                        POLLIN, 0) < 0)
        throw FDMultiplexerException("Unable to add fd back to ports (read): "+stringerror());
      continue; // so we don't find ourselves as writable again
    }

    d_iter=d_writeCallbacks.find(d_pevents[n].portev_object);
    
    if(d_iter != d_writeCallbacks.end()) {
      d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
      if(d_writeCallbacks.count(d_pevents[n].portev_object) && port_associate(d_portfd, PORT_SOURCE_FD, d_pevents[n].portev_object, 
                        POLLOUT, 0) < 0)
        throw FDMultiplexerException("Unable to add fd back to ports (write): "+stringerror());
    }

  }

  d_inrun=false;
  return numevents;
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

  PortsFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif


