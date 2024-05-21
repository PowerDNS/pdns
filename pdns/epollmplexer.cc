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
  EpollFDMultiplexer(unsigned int maxEventsHint);
  ~EpollFDMultiplexer() override
  {
    if (d_epollfd >= 0) {
      close(d_epollfd);
    }
  }

  int run(struct timeval* tv, int timeout = 500) override;
  void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  void addFD(int fd, FDMultiplexer::EventKind kind) override;
  void removeFD(int fd, FDMultiplexer::EventKind kind) override;
  void alterFD(int fd, FDMultiplexer::EventKind from, FDMultiplexer::EventKind to) override;

  string getName() const override
  {
    return "epoll";
  }

private:
  int d_epollfd;
  std::vector<epoll_event> d_eevents;
};

static FDMultiplexer* makeEpoll(unsigned int maxEventsHint)
{
  return new EpollFDMultiplexer(maxEventsHint);
}

static struct EpollRegisterOurselves
{
  EpollRegisterOurselves()
  {
    FDMultiplexer::getMultiplexerMap().emplace(0, &makeEpoll); // priority 0!
  }
} doItEpoll;

EpollFDMultiplexer::EpollFDMultiplexer(unsigned int maxEventsHint) :
  d_eevents(maxEventsHint)
{
  d_epollfd = epoll_create(static_cast<int>(maxEventsHint)); // not hard max, just a hint that is actually ignored since Linux 2.6.8
  if (d_epollfd < 0) {
    throw FDMultiplexerException("Setting up epoll: " + stringerror());
  }
  int fd = socket(AF_INET, SOCK_DGRAM, 0); // for self-test

  if (fd < 0) {
    return;
  }

  try {
    addReadFD(fd, 0);
    removeReadFD(fd);
    close(fd);
    return;
  }
  catch (const FDMultiplexerException& fe) {
    close(fd);
    close(d_epollfd);
    throw FDMultiplexerException("epoll multiplexer failed self-test: " + string(fe.what()));
  }
}

static uint32_t convertEventKind(FDMultiplexer::EventKind kind)
{
  switch (kind) {
  case FDMultiplexer::EventKind::Read:
    return EPOLLIN;
  case FDMultiplexer::EventKind::Write:
    return EPOLLOUT;
  case FDMultiplexer::EventKind::Both:
    return EPOLLIN | EPOLLOUT;
  }

  throw std::runtime_error("Unhandled event kind in the epoll multiplexer");
}

void EpollFDMultiplexer::addFD(int fd, FDMultiplexer::EventKind kind)
{
  struct epoll_event eevent;

  eevent.events = convertEventKind(kind);

  eevent.data.u64 = 0; // placate valgrind (I love it so much)
  eevent.data.fd = fd;

  if (epoll_ctl(d_epollfd, EPOLL_CTL_ADD, fd, &eevent) < 0) {
    throw FDMultiplexerException("Adding fd to epoll set: " + stringerror());
  }
}

void EpollFDMultiplexer::removeFD(int fd, FDMultiplexer::EventKind)
{
  struct epoll_event dummy;
  dummy.events = 0;
  dummy.data.u64 = 0;

  if (epoll_ctl(d_epollfd, EPOLL_CTL_DEL, fd, &dummy) < 0) {
    throw FDMultiplexerException("Removing fd from epoll set: " + stringerror());
  }
}

void EpollFDMultiplexer::alterFD(int fd, FDMultiplexer::EventKind, FDMultiplexer::EventKind to)
{
  struct epoll_event eevent;
  eevent.events = convertEventKind(to);
  eevent.data.u64 = 0; // placate valgrind (I love it so much)
  eevent.data.fd = fd;

  if (epoll_ctl(d_epollfd, EPOLL_CTL_MOD, fd, &eevent) < 0) {
    throw FDMultiplexerException("Altering fd in epoll set: " + stringerror());
  }
}

void EpollFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  int ret = epoll_wait(d_epollfd, d_eevents.data(), d_eevents.size(), timeout);

  if (ret < 0 && errno != EINTR) {
    throw FDMultiplexerException("epoll returned error: " + stringerror());
  }

  for (int n = 0; n < ret; ++n) {
    fds.push_back(d_eevents[n].data.fd);
  }
}

int EpollFDMultiplexer::run(struct timeval* now, int timeout)
{
  InRun guard(d_inrun);

  int ret = epoll_wait(d_epollfd, d_eevents.data(), d_eevents.size(), timeout);
  gettimeofday(now, nullptr); // MANDATORY

  if (ret < 0 && errno != EINTR) {
    throw FDMultiplexerException("epoll returned error: " + stringerror());
  }

  if (ret < 1) { // thanks AB!
    return 0;
  }

  int count = 0;

  for (int n = 0; n < ret; ++n) {
    if ((d_eevents[n].events & EPOLLIN) || (d_eevents[n].events & EPOLLERR) || (d_eevents[n].events & EPOLLHUP)) {
      const auto& iter = d_readCallbacks.find(d_eevents[n].data.fd);
      if (iter != d_readCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
        count++;
      }
    }

    if ((d_eevents[n].events & EPOLLOUT) || (d_eevents[n].events & EPOLLERR) || (d_eevents[n].events & EPOLLHUP)) {
      const auto& iter = d_writeCallbacks.find(d_eevents[n].data.fd);
      if (iter != d_writeCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
        count++;
      }
    }
  }

  return count;
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
