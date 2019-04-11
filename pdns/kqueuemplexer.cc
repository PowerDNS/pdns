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
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__)
#include <sys/event.h>
#endif
#include <sys/time.h>

#include "namespaces.hh"

class KqueueFDMultiplexer : public FDMultiplexer
{
public:
  KqueueFDMultiplexer();
  virtual ~KqueueFDMultiplexer()
  {
    close(d_kqueuefd);
  }

  virtual int run(struct timeval* tv, int timeout=500) override;
  virtual void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const boost::any& parameter, const struct timeval* ttd=nullptr) override;
  virtual void removeFD(callbackmap_t& cbmap, int fd) override;
  string getName() const override
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

static struct KqueueRegisterOurselves
{
  KqueueRegisterOurselves() {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(0, &make)); // priority 0!
  }
} kQueuedoIt;

KqueueFDMultiplexer::KqueueFDMultiplexer() : d_kevents(new struct kevent[s_maxevents])
{
  d_kqueuefd=kqueue();
  if(d_kqueuefd < 0)
    throw FDMultiplexerException("Setting up kqueue: "+stringerror());
}

void KqueueFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const boost::any& parameter, const struct timeval* ttd)
{
  accountingAddFD(cbmap, fd, toDo, parameter, ttd);

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

void KqueueFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  struct timespec ts;
  ts.tv_sec=timeout/1000;
  ts.tv_nsec=(timeout % 1000) * 1000000;

  int ret = kevent(d_kqueuefd, 0, 0, d_kevents.get(), s_maxevents, &ts);

  if(ret < 0 && errno != EINTR)
    throw FDMultiplexerException("kqueue returned error: "+stringerror());

  for(int n=0; n < ret; ++n) {
    fds.push_back(d_kevents[n].ident);
  }
}

int KqueueFDMultiplexer::run(struct timeval* now, int timeout)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }
  
  struct timespec ts;
  ts.tv_sec=timeout/1000;
  ts.tv_nsec=(timeout % 1000) * 1000000;

  int ret=kevent(d_kqueuefd, 0, 0, d_kevents.get(), s_maxevents, &ts);
  gettimeofday(now,0); // MANDATORY!

  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("kqueue returned error: "+stringerror());

  if(ret < 0) // nothing - thanks AB!
    return 0;

  d_inrun=true;

  for(int n=0; n < ret; ++n) {
    d_iter=d_readCallbacks.find(d_kevents[n].ident);
    if(d_iter != d_readCallbacks.end()) {
      d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
      continue; // so we don't find ourselves as writable again
    }

    d_iter=d_writeCallbacks.find(d_kevents[n].ident);

    if(d_iter != d_writeCallbacks.end()) {
      d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
    }
  }

  d_inrun=false;
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



