/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include <unistd.h>
#include "misc.hh"
#ifdef __linux__
#include <sys/epoll.h>
#endif

#include "namespaces.hh"

class EpollFDMultiplexer : public FDMultiplexer
{
public:
  EpollFDMultiplexer();
  virtual ~EpollFDMultiplexer()
  {
    close(d_epollfd);
  }

  virtual int run(struct timeval* tv, int timeout=500) override;
  virtual void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd=nullptr) override;
  virtual void removeFD(callbackmap_t& cbmap, int fd) override;
  string getName() const override
  {
    return "epoll";
  }
private:
  int d_epollfd;
  boost::shared_array<epoll_event> d_eevents;
  static int s_maxevents; // not a hard maximum
};


static FDMultiplexer* makeEpoll()
{
  return new EpollFDMultiplexer();
}

static struct EpollRegisterOurselves
{
  EpollRegisterOurselves() {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(0, &makeEpoll)); // priority 0!
  }
} doItEpoll;

int EpollFDMultiplexer::s_maxevents=1024;

EpollFDMultiplexer::EpollFDMultiplexer() : d_eevents(new epoll_event[s_maxevents])
{
  d_epollfd=epoll_create(s_maxevents); // not hard max
  if(d_epollfd < 0)
    throw FDMultiplexerException("Setting up epoll: "+stringerror());
  int fd=socket(AF_INET, SOCK_DGRAM, 0); // for self-test
  if(fd < 0)
    return;
  try {
    addReadFD(fd, 0);
    removeReadFD(fd);
    close(fd);
    return;
  }
  catch(FDMultiplexerException &fe) {
    close(fd);
    close(d_epollfd);
    throw FDMultiplexerException("epoll multiplexer failed self-test: "+string(fe.what()));
  }
    
}

void EpollFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd)
{
  accountingAddFD(cbmap, fd, toDo, parameter, ttd);

  struct epoll_event eevent;
  
  eevent.events = (&cbmap == &d_readCallbacks) ? EPOLLIN : EPOLLOUT;
  
  eevent.data.u64=0; // placate valgrind (I love it so much)
  eevent.data.fd=fd; 

  if(epoll_ctl(d_epollfd, EPOLL_CTL_ADD, fd, &eevent) < 0) {
    cbmap.erase(fd);
    throw FDMultiplexerException("Adding fd to epoll set: "+stringerror());
  }
}

void EpollFDMultiplexer::removeFD(callbackmap_t& cbmap, int fd)
{
  if(!cbmap.erase(fd))
    throw FDMultiplexerException("Tried to remove unlisted fd "+std::to_string(fd)+ " from multiplexer");

  struct epoll_event dummy;
  dummy.events = 0;
  dummy.data.u64 = 0;

  if(epoll_ctl(d_epollfd, EPOLL_CTL_DEL, fd, &dummy) < 0)
    throw FDMultiplexerException("Removing fd from epoll set: "+stringerror());
}

void EpollFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  int ret=epoll_wait(d_epollfd, d_eevents.get(), s_maxevents, timeout);

  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("epoll returned error: "+stringerror());

  for(int n=0; n < ret; ++n) {
    fds.push_back(d_eevents[n].data.fd);
  }
}

int EpollFDMultiplexer::run(struct timeval* now, int timeout)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  
  int ret=epoll_wait(d_epollfd, d_eevents.get(), s_maxevents, timeout);
  gettimeofday(now,0); // MANDATORY

  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("epoll returned error: "+stringerror());

  if(ret < 1) // thanks AB!
    return 0;

  d_inrun=true;
  for(int n=0; n < ret; ++n) {
    d_iter=d_readCallbacks.find(d_eevents[n].data.fd);
    
    if(d_iter != d_readCallbacks.end()) {
      d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
      continue; // so we don't refind ourselves as writable!
    }
    d_iter=d_writeCallbacks.find(d_eevents[n].data.fd);
    
    if(d_iter != d_writeCallbacks.end()) {
      d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
    }
  }
  d_inrun=false;
  return ret;
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
  Socket s(AF_INET, SOCK_DGRAM);
  
  IPEndpoint loc("0.0.0.0", 2000);
  s.bind(loc);

  EpollFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif


