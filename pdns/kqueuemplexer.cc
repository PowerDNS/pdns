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
#include <sys/types.h>
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <sys/event.h>
#endif
#include <sys/time.h>

#include "namespaces.hh"

class KqueueFDMultiplexer : public FDMultiplexer
{
public:
  KqueueFDMultiplexer(unsigned int maxEventsHint);
  ~KqueueFDMultiplexer()
  {
    if (d_kqueuefd >= 0) {
      close(d_kqueuefd);
    }
  }

  int run(struct timeval* tv, int timeout = 500) override;
  void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  void addFD(int fd, FDMultiplexer::EventKind kind) override;
  void removeFD(int fd, FDMultiplexer::EventKind kind) override;

  string getName() const override
  {
    return "kqueue";
  }

private:
  int d_kqueuefd;
  std::vector<struct kevent> d_kevents;
};

static FDMultiplexer* make(unsigned int maxEventsHint)
{
  return new KqueueFDMultiplexer(maxEventsHint);
}

static struct KqueueRegisterOurselves
{
  KqueueRegisterOurselves()
  {
    FDMultiplexer::getMultiplexerMap().emplace(0, &make); // priority 0!
  }
} kQueueDoIt;

KqueueFDMultiplexer::KqueueFDMultiplexer(unsigned int maxEventsHint) :
  d_kevents(maxEventsHint)
{
  d_kqueuefd = kqueue();
  if (d_kqueuefd < 0) {
    throw FDMultiplexerException("Setting up kqueue: " + stringerror());
  }
}

static uint32_t convertEventKind(FDMultiplexer::EventKind kind)
{
  switch (kind) {
  case FDMultiplexer::EventKind::Read:
    return EVFILT_READ;
  case FDMultiplexer::EventKind::Write:
    return EVFILT_WRITE;
  case FDMultiplexer::EventKind::Both:
    throw std::runtime_error("Read and write events cannot be combined in one go with kqueue");
  }

  throw std::runtime_error("Unhandled event kind in the kqueue multiplexer");
}

void KqueueFDMultiplexer::addFD(int fd, FDMultiplexer::EventKind kind)
{
  struct kevent kqevents[2];
  int nevents = 0;

  if (kind == FDMultiplexer::EventKind::Both || kind == FDMultiplexer::EventKind::Read) {
    EV_SET(&kqevents[nevents], fd, convertEventKind(FDMultiplexer::EventKind::Read), EV_ADD, 0, 0, 0);
    nevents++;
  }

  if (kind == FDMultiplexer::EventKind::Both || kind == FDMultiplexer::EventKind::Write) {
    EV_SET(&kqevents[nevents], fd, convertEventKind(FDMultiplexer::EventKind::Write), EV_ADD, 0, 0, 0);
    nevents++;
  }

  if (kevent(d_kqueuefd, kqevents, nevents, 0, 0, 0) < 0) {
    throw FDMultiplexerException("Adding fd to kqueue set: " + stringerror());
  }
}

void KqueueFDMultiplexer::removeFD(int fd, FDMultiplexer::EventKind kind)
{
  struct kevent kqevents[2];
  int nevents = 0;

  if (kind == FDMultiplexer::EventKind::Both || kind == FDMultiplexer::EventKind::Read) {
    EV_SET(&kqevents[nevents], fd, convertEventKind(FDMultiplexer::EventKind::Read), EV_DELETE, 0, 0, 0);
    nevents++;
  }

  if (kind == FDMultiplexer::EventKind::Both || kind == FDMultiplexer::EventKind::Write) {
    EV_SET(&kqevents[nevents], fd, convertEventKind(FDMultiplexer::EventKind::Write), EV_DELETE, 0, 0, 0);
    nevents++;
  }

  if (kevent(d_kqueuefd, kqevents, nevents, 0, 0, 0) < 0) {
    // ponder putting Callback back on the map..
    throw FDMultiplexerException("Removing fd from kqueue set: " + stringerror());
  }
}

void KqueueFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  struct timespec ts;
  ts.tv_sec = timeout / 1000;
  ts.tv_nsec = (timeout % 1000) * 1000000;

  int ret = kevent(d_kqueuefd, 0, 0, d_kevents.data(), d_kevents.size(), timeout != -1 ? &ts : nullptr);

  if (ret < 0 && errno != EINTR) {
    throw FDMultiplexerException("kqueue returned error: " + stringerror());
  }

  // we de-duplicate here, since if a descriptor is readable AND writable
  // we will get two events
  std::unordered_set<int> fdSet;
  fdSet.reserve(ret);
  for (int n = 0; n < ret; ++n) {
    fdSet.insert(d_kevents[n].ident);
  }

  for (const auto fd : fdSet) {
    fds.push_back(fd);
  }
}

int KqueueFDMultiplexer::run(struct timeval* now, int timeout)
{
  InRun guard(d_inrun);

  struct timespec ts;
  ts.tv_sec = timeout / 1000;
  ts.tv_nsec = (timeout % 1000) * 1000000;

  int ret = kevent(d_kqueuefd, 0, 0, d_kevents.data(), d_kevents.size(), timeout != -1 ? &ts : nullptr);
  gettimeofday(now, nullptr); // MANDATORY!

  if (ret < 0 && errno != EINTR) {
    throw FDMultiplexerException("kqueue returned error: " + stringerror());
  }

  if (ret < 0) {
    // nothing - thanks AB!
    return 0;
  }

  for (int n = 0; n < ret; ++n) {
    if (d_kevents[n].filter == EVFILT_READ) {
      const auto& iter = d_readCallbacks.find(d_kevents[n].ident);
      if (iter != d_readCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
      }
    }

    if (d_kevents[n].filter == EVFILT_WRITE) {
      const auto& iter = d_writeCallbacks.find(d_kevents[n].ident);
      if (iter != d_writeCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
      }
    }
  }

  return ret;
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

  KqueueFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif
