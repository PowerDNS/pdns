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
  ~DevPollFDMultiplexer()
  {
    if (d_devpollfd >= 0) {
      close(d_devpollfd);
    }
  }

  int run(struct timeval* tv, int timeout = 500) override;
  void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  void addFD(int fd, FDMultiplexer::EventKind kind) override;
  void removeFD(int fd, FDMultiplexer::EventKind kind) override;

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
  DevPollRegisterOurselves()
  {
    FDMultiplexer::getMultiplexerMap().emplace(1, &makeDevPoll); // priority 1, so that /dev/poll is preferred over poll, but not over completion ports!
  }
} doItDevPoll;

DevPollFDMultiplexer::DevPollFDMultiplexer()
{
  d_devpollfd = open("/dev/poll", O_RDWR);
  if (d_devpollfd < 0) {
    throw FDMultiplexerException("Setting up /dev/poll: " + stringerror());
  }
}

static int convertEventKind(FDMultiplexer::EventKind kind)
{
  switch (kind) {
  case FDMultiplexer::EventKind::Read:
    return POLLIN;
  case FDMultiplexer::EventKind::Write:
    return POLLOUT;
  case FDMultiplexer::EventKind::Both:
    return POLLIN | POLLOUT;
  }
  throw std::runtime_error("Unhandled event kind in the /dev/poll multiplexer");
}

void DevPollFDMultiplexer::addFD(int fd, FDMultiplexer::EventKind kind)
{
  struct pollfd devent;
  devent.fd = fd;
  devent.events = convertEventKind(kind);
  devent.revents = 0;

  if (write(d_devpollfd, &devent, sizeof(devent)) != sizeof(devent)) {
    throw FDMultiplexerException("Adding fd to /dev/poll/ set: " + stringerror());
  }
}

void DevPollFDMultiplexer::removeFD(int fd, FDMultiplexer::EventKind)
{
  struct pollfd devent;
  devent.fd = fd;
  devent.events = POLLREMOVE;
  devent.revents = 0;

  if (write(d_devpollfd, &devent, sizeof(devent)) != sizeof(devent)) {
    throw FDMultiplexerException("Removing fd from epoll set: " + stringerror());
  }
}

void DevPollFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  std::vector<struct pollfd> pollfds(d_readCallbacks.size() + d_writeCallbacks.size());
  struct dvpoll dvp;
  dvp.dp_nfds = d_readCallbacks.size() + d_writeCallbacks.size();
  dvp.dp_fds = pollfds.data();
  dvp.dp_timeout = timeout;
  int ret = ioctl(d_devpollfd, DP_POLL, &dvp);

  if (ret < 0 && errno != EINTR) {
    throw FDMultiplexerException("/dev/poll returned error: " + stringerror());
  }

  for (int n = 0; n < ret; ++n) {
    fds.push_back(pollfds.at(n).fd);
  }
}

int DevPollFDMultiplexer::run(struct timeval* now, int timeout)
{
  if (d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  std::vector<struct pollfd> fds(d_readCallbacks.size() + d_writeCallbacks.size());
  struct dvpoll dvp;
  dvp.dp_nfds = d_readCallbacks.size() + d_writeCallbacks.size();
  dvp.dp_fds = fds.data();
  dvp.dp_timeout = timeout;
  int ret = ioctl(d_devpollfd, DP_POLL, &dvp);
  int err = errno;
  gettimeofday(now, nullptr); // MANDATORY!

  if (ret < 0 && err != EINTR) {
    throw FDMultiplexerException("/dev/poll returned error: " + stringerror(err));
  }

  if (ret < 1) { // thanks AB!
    return 0;
  }

  d_inrun = true;
  int count = 0;
  for (int n = 0; n < ret; ++n) {
    if ((fds.at(n).revents & POLLIN) || (fds.at(n).revents & POLLERR) || (fds.at(n).revents & POLLHUP)) {
      const auto& iter = d_readCallbacks.find(fds.at(n).fd);
      if (iter != d_readCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
        count++;
      }
    }

    if ((fds.at(n).revents & POLLOUT) || (fds.at(n).revents & POLLERR)) {
      const auto& iter = d_writeCallbacks.find(fds.at(n).fd);
      if (iter != d_writeCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
        count++;
      }
    }
  }

  d_inrun = false;
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

  DevPollFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif
