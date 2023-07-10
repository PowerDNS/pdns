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
  PortsFDMultiplexer(unsigned int maxEventsHint);
  ~PortsFDMultiplexer()
  {
    close(d_portfd);
  }

  int run(struct timeval* tv, int timeout = 500) override;
  void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  void addFD(int fd, FDMultiplexer::EventKind kind) override;
  void removeFD(int fd, FDMultiplexer::EventKind kind) override;

  string getName() const override
  {
    return "solaris completion ports";
  }

private:
  int d_portfd;
  std::vector<port_event_t> d_pevents;
};

static FDMultiplexer* makePorts(unsigned int maxEventsHint)
{
  return new PortsFDMultiplexer(maxEventsHint);
}

static struct PortsRegisterOurselves
{
  PortsRegisterOurselves()
  {
    FDMultiplexer::getMultiplexerMap().emplace(0, &makePorts); // priority 0!
  }
} doItPorts;

PortsFDMultiplexer::PortsFDMultiplexer(unsigned int maxEventsHint) :
  d_pevents(maxEventsHint)
{
  d_portfd = port_create(); // not hard max
  if (d_portfd < 0) {
    throw FDMultiplexerException("Setting up port: " + stringerror());
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
  throw std::runtime_error("Unhandled event kind in the ports multiplexer");
}

void PortsFDMultiplexer::addFD(int fd, FDMultiplexer::EventKind kind)
{
  if (port_associate(d_portfd, PORT_SOURCE_FD, fd, convertEventKind(kind), 0) < 0) {
    throw FDMultiplexerException("Adding fd to port set: " + stringerror());
  }
}

void PortsFDMultiplexer::removeFD(int fd, FDMultiplexer::EventKind)
{
  if (port_dissociate(d_portfd, PORT_SOURCE_FD, fd) < 0 && errno != ENOENT) { // it appears under some circumstances, ENOENT will be returned, without this being an error. Apache has this same "fix"
    throw FDMultiplexerException("Removing fd from port set: " + stringerror());
  }
}

void PortsFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  struct timespec timeoutspec;
  timeoutspec.tv_sec = timeout / 1000;
  timeoutspec.tv_nsec = (timeout % 1000) * 1000000;
  unsigned int numevents = 1;
  int ret = port_getn(d_portfd, d_pevents.data(), min(PORT_MAX_LIST, static_cast<int>(d_pevents.size())), &numevents, timeout != -1 ? &timeoutspec : nullptr);

  /* port_getn has an unusual API - (ret == -1, errno == ETIME) can
     mean partial success; you must check (*numevents) in this case
     and process anything in there, otherwise you'll never see any
     events from that object again. We don't care about pure timeouts
     (ret == -1, errno == ETIME, *numevents == 0) so we don't bother
     with that case. */
  if (ret == -1 && errno != ETIME) {
    if (errno != EINTR) {
      throw FDMultiplexerException("completion port_getn returned error: " + stringerror());
    }

    // EINTR is not really an error
    return;
  }

  if (numevents == 0) {
    // nothing
    return;
  }

  fds.reserve(numevents);

  for (unsigned int n = 0; n < numevents; ++n) {
    const auto fd = d_pevents[n].portev_object;

    /* we need to re-associate the FD */
    if ((d_pevents[n].portev_events & POLLIN || d_pevents[n].portev_events & POLLERR || d_pevents[n].portev_events & POLLHUP)) {
      if (d_readCallbacks.count(fd)) {
        if (port_associate(d_portfd, PORT_SOURCE_FD, fd, d_writeCallbacks.count(fd) > 0 ? POLLIN | POLLOUT : POLLIN, 0) < 0) {
          throw FDMultiplexerException("Unable to add fd back to ports (read): " + stringerror());
        }
      }
    }
    else if ((d_pevents[n].portev_events & POLLOUT || d_pevents[n].portev_events & POLLERR)) {
      if (d_writeCallbacks.count(fd)) {
        if (port_associate(d_portfd, PORT_SOURCE_FD, fd, d_readCallbacks.count(fd) > 0 ? POLLIN | POLLOUT : POLLOUT, 0) < 0) {
          throw FDMultiplexerException("Unable to add fd back to ports (write): " + stringerror());
        }
      }
    }
    else {
      /* not registered, this is unexpected */
      continue;
    }

    fds.push_back(fd);
  }
}

int PortsFDMultiplexer::run(struct timeval* now, int timeout)
{
  if (d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }

  struct timespec timeoutspec;
  timeoutspec.tv_sec = timeout / 1000;
  timeoutspec.tv_nsec = (timeout % 1000) * 1000000;
  unsigned int numevents = 1;
  int ret = port_getn(d_portfd, d_pevents.data(), min(PORT_MAX_LIST, static_cast<int>(d_pevents.size())), &numevents, timeout != -1 ? &timeoutspec : nullptr);

  /* port_getn has an unusual API - (ret == -1, errno == ETIME) can
     mean partial success; you must check (*numevents) in this case
     and process anything in there, otherwise you'll never see any
     events from that object again. We don't care about pure timeouts
     (ret == -1, errno == ETIME, *numevents == 0) so we don't bother
     with that case. */
  if (ret == -1 && errno != ETIME) {
    if (errno != EINTR) {
      throw FDMultiplexerException("completion port_getn returned error: " + stringerror());
    }
    // EINTR is not really an error
    gettimeofday(now, nullptr);
    return 0;
  }
  gettimeofday(now, nullptr);
  if (!numevents) {
    // nothing
    return 0;
  }

  d_inrun = true;
  int count = 0;
  for (unsigned int n = 0; n < numevents; ++n) {
    if (d_pevents[n].portev_events & POLLIN || d_pevents[n].portev_events & POLLERR || d_pevents[n].portev_events & POLLHUP) {
      const auto& iter = d_readCallbacks.find(d_pevents[n].portev_object);
      if (iter != d_readCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
        count++;
        if (d_readCallbacks.count(d_pevents[n].portev_object) && port_associate(d_portfd, PORT_SOURCE_FD, d_pevents[n].portev_object, d_writeCallbacks.count(d_pevents[n].portev_object) ? POLLIN | POLLOUT : POLLIN, 0) < 0) {
          throw FDMultiplexerException("Unable to add fd back to ports (read): " + stringerror());
        }
      }
    }
    if (d_pevents[n].portev_events & POLLOUT || d_pevents[n].portev_events & POLLERR) {
      const auto& iter = d_writeCallbacks.find(d_pevents[n].portev_object);
      if (iter != d_writeCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
        count++;
        if (d_writeCallbacks.count(d_pevents[n].portev_object) && port_associate(d_portfd, PORT_SOURCE_FD, d_pevents[n].portev_object, d_readCallbacks.count(d_pevents[n].portev_object) ? POLLIN | POLLOUT : POLLOUT, 0) < 0) {
          throw FDMultiplexerException("Unable to add fd back to ports (write): " + stringerror());
        }
      }
    }
  }

  d_inrun = false;
  return count;
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
