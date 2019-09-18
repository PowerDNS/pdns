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
/*
 * NOTE: sys/devpoll.h relies on sigset_t being already defined so we need
 * to include sys/signal.h *before* including sys/devpoll.h.
 */
#include <sys/signal.h>
#include <sys/devpoll.h>
#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include <unistd.h>
#include "misc.hh"

#include "namespaces.hh"

class DevPollFDMultiplexer : public FDMultiplexer
{
public:
  DevPollFDMultiplexer();
  virtual ~DevPollFDMultiplexer()
  {
    close(d_devpollfd);
  }

  virtual int run(struct timeval* tv, int timeout=500) override;
  virtual void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd=nullptr) override;
  virtual void removeFD(callbackmap_t& cbmap, int fd) override;
  string getName() const override
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

void DevPollFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd)
{
  accountingAddFD(cbmap, fd, toDo, parameter, ttd);

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
    throw FDMultiplexerException("Tried to remove unlisted fd "+std::to_string(fd)+ " from multiplexer");

  struct pollfd devent;
  devent.fd=fd;
  devent.events= POLLREMOVE;
  devent.revents = 0;

  if(write(d_devpollfd, &devent, sizeof(devent)) != sizeof(devent)) {
    cbmap.erase(fd);
    throw FDMultiplexerException("Removing fd from epoll set: "+stringerror());
  }
}

void DevPollFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  struct dvpoll dvp;
  dvp.dp_nfds = d_readCallbacks.size() + d_writeCallbacks.size();
  dvp.dp_fds = new pollfd[dvp.dp_nfds];
  dvp.dp_timeout = timeout;
  int ret=ioctl(d_devpollfd, DP_POLL, &dvp);

  if(ret < 0 && errno!=EINTR) {
    delete[] dvp.dp_fds;
    throw FDMultiplexerException("/dev/poll returned error: "+stringerror());
  }

  for(int n=0; n < ret; ++n) {
    fds.push_back(dvp.dp_fds[n].fd);
  }

  delete[] dvp.dp_fds;
}

int DevPollFDMultiplexer::run(struct timeval* now, int timeout)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  struct dvpoll dvp;
  dvp.dp_nfds = d_readCallbacks.size() + d_writeCallbacks.size();
  dvp.dp_fds = new pollfd[dvp.dp_nfds];
  dvp.dp_timeout = timeout;
  int ret=ioctl(d_devpollfd, DP_POLL, &dvp);
  int err = errno;
  gettimeofday(now,0); // MANDATORY!

  if(ret < 0 && err!=EINTR) {
    delete[] dvp.dp_fds;
    throw FDMultiplexerException("/dev/poll returned error: "+stringerror(err));
  }

  if(ret < 1) { // thanks AB!
    delete[] dvp.dp_fds;
    return 0;
  }

  d_inrun=true;
  for(int n=0; n < ret; ++n) {
    d_iter=d_readCallbacks.find(dvp.dp_fds[n].fd);
    
    if(d_iter != d_readCallbacks.end()) {
      d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
      continue; // so we don't refind ourselves as writable!
    }
    d_iter=d_writeCallbacks.find(dvp.dp_fds[n].fd);
    
    if(d_iter != d_writeCallbacks.end()) {
      d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
    }
  }
  delete[] dvp.dp_fds;
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

  DevPollFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif


