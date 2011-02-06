#include <sys/devpoll.h>
#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include <unistd.h>
#include "misc.hh"
#include <boost/lexical_cast.hpp>
#include "syncres.hh"

#include "namespaces.hh"
#include "namespaces.hh"

class DevPollFDMultiplexer : public FDMultiplexer
{
public:
  DevPollFDMultiplexer();
  virtual ~DevPollFDMultiplexer()
  {
    close(d_devpollfd);
  }

  virtual int run(struct timeval* tv);

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter);
  virtual void removeFD(callbackmap_t& cbmap, int fd);
  string getName()
  {
    return "/dev/poll";
  }
private:
  int d_devpollfd;
};


static FDMultiplexer* makeDevPoll()
{
  return new DevPollFDMultiplexer();
}

static struct DevPollRegisterOurselves
{
  DevPollRegisterOurselves() {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(0, &makeDevPoll)); // priority 0!
  }
} doItDevPoll;


//int DevPollFDMultiplexer::s_maxevents=1024;
DevPollFDMultiplexer::DevPollFDMultiplexer() 
{
  d_devpollfd=open("/dev/poll", O_RDWR);
  if(d_devpollfd < 0)
    throw FDMultiplexerException("Setting up /dev/poll: "+stringerror());
    
}

void DevPollFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter)
{
  accountingAddFD(cbmap, fd, toDo, parameter);

  struct pollfd devent;
  devent.fd=fd;
  devent.events= (&cbmap == &d_readCallbacks) ? POLLIN : POLLOUT;
  devent.revents = 0;

  if(write(d_devpollfd, &devent, sizeof(devent)) != sizeof(devent)) {
    cbmap.erase(fd);
    throw FDMultiplexerException("Adding fd to /dev/poll/ set: "+stringerror());
  }
}

void DevPollFDMultiplexer::removeFD(callbackmap_t& cbmap, int fd)
{
  if(!cbmap.erase(fd))
    throw FDMultiplexerException("Tried to remove unlisted fd "+lexical_cast<string>(fd)+ " from multiplexer");

  struct pollfd devent;
  devent.fd=fd;
  devent.events= POLLREMOVE;
  devent.revents = 0;

  if(write(d_devpollfd, &devent, sizeof(devent)) != sizeof(devent)) {
    cbmap.erase(fd);
    throw FDMultiplexerException("Removing fd from epoll set: "+stringerror());
  }
}

int DevPollFDMultiplexer::run(struct timeval* now)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  struct dvpoll dvp;
  dvp.dp_nfds = d_readCallbacks.size() + d_writeCallbacks.size();
  dvp.dp_fds = new pollfd[dvp.dp_nfds];
  dvp.dp_timeout = 500;
  int ret=ioctl(d_devpollfd, DP_POLL, &dvp); 
  gettimeofday(now,0); // MANDATORY!
  
  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("/dev/poll returned error: "+stringerror());

  if(ret < 1) // thanks AB!
    return 0;

  d_inrun=true;
  for(int n=0; n < ret; ++n) {
    d_iter=d_readCallbacks.find(dvp.dp_fds[n].fd);
    
    if(d_iter != d_readCallbacks.end()) {
      d_iter->second.d_callback(d_iter->first, d_iter->second.d_parameter);
      continue; // so we don't refind ourselves as writable!
    }
    d_iter=d_writeCallbacks.find(dvp.dp_fds[n].fd);
    
    if(d_iter != d_writeCallbacks.end()) {
      d_iter->second.d_callback(d_iter->first, d_iter->second.d_parameter);
    }
  }
  delete[] dvp.dp_fds;
  d_inrun=false;
  return 0;
}

#if 0
void acceptData(int fd, funcparam_t& parameter)
{
  cout<<"Have data on fd "<<fd<<endl;
  Socket* sock=funcparam_t_cast<Socket*>(parameter);
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

  DevPollFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif


