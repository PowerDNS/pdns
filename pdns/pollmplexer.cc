#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include <poll.h>
#include <unordered_map>
#include "misc.hh"
#include "namespaces.hh"

FDMultiplexer* FDMultiplexer::getMultiplexerSilent()
{
  FDMultiplexer* ret = nullptr;
  for (const auto& i : FDMultiplexer::getMultiplexerMap()) {
    try {
      ret = i.second();
      return ret;
    }
    catch (const FDMultiplexerException& fe) {
    }
    catch (...) {
    }
  }
  return ret;
}

class PollFDMultiplexer : public FDMultiplexer
{
public:
  PollFDMultiplexer()
  {}
  ~PollFDMultiplexer()
  {
  }

  int run(struct timeval* tv, int timeout = 500) override;
  void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  void addFD(int fd, FDMultiplexer::EventKind) override;
  void removeFD(int fd, FDMultiplexer::EventKind) override;

  string getName() const override
  {
    return "poll";
  }

private:
  vector<struct pollfd> preparePollFD() const;
};

static FDMultiplexer* make()
{
  return new PollFDMultiplexer();
}

static struct RegisterOurselves
{
  RegisterOurselves()
  {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(1, &make));
  }
} doIt;

void PollFDMultiplexer::addFD(int fd, FDMultiplexer::EventKind kind)
{
}

void PollFDMultiplexer::removeFD(int fd, FDMultiplexer::EventKind)
{
}

vector<struct pollfd> PollFDMultiplexer::preparePollFD() const
{
  std::unordered_map<int, struct pollfd> pollfds;
  pollfds.reserve(d_readCallbacks.size() + d_writeCallbacks.size());

  for (const auto& cb : d_readCallbacks) {
    if (pollfds.count(cb.d_fd) == 0) {
      auto& pollfd = pollfds[cb.d_fd];
      pollfd.fd = cb.d_fd;
      pollfd.events = 0;
    }
    auto& pollfd = pollfds.at(cb.d_fd);
    pollfd.events |= POLLIN;
  }

  for (const auto& cb : d_writeCallbacks) {
    if (pollfds.count(cb.d_fd) == 0) {
      auto& pollfd = pollfds[cb.d_fd];
      pollfd.fd = cb.d_fd;
      pollfd.events = 0;
    }
    auto& pollfd = pollfds.at(cb.d_fd);
    pollfd.events |= POLLOUT;
  }

  std::vector<struct pollfd> result;
  result.reserve(pollfds.size());
  for (const auto& entry : pollfds) {
    result.push_back(entry.second);
  }

  return result;
}

void PollFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  auto pollfds = preparePollFD();
  if (pollfds.empty()) {
    return;
  }

  int ret = poll(&pollfds[0], pollfds.size(), timeout);

  if (ret < 0 && errno != EINTR) {
    throw FDMultiplexerException("poll returned error: " + stringerror());
  }

  for (const auto& pollfd : pollfds) {
    if (pollfd.revents & POLLIN || pollfd.revents & POLLOUT || pollfd.revents & POLLERR || pollfd.revents & POLLHUP) {
      fds.push_back(pollfd.fd);
    }
  }
}

int PollFDMultiplexer::run(struct timeval* now, int timeout)
{
  if (d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }

  auto pollfds = preparePollFD();
  if (pollfds.empty()) {
    gettimeofday(now, nullptr); // MANDATORY!
    return 0;
  }

  int ret = poll(&pollfds[0], pollfds.size(), timeout);
  gettimeofday(now, nullptr); // MANDATORY!

  if (ret < 0 && errno != EINTR) {
    throw FDMultiplexerException("poll returned error: " + stringerror());
  }

  d_inrun = true;
  int count = 0;
  for (const auto& pollfd : pollfds) {
    if (pollfd.revents & POLLIN || pollfd.revents & POLLERR || pollfd.revents & POLLHUP) {
      const auto& iter = d_readCallbacks.find(pollfd.fd);
      if (iter != d_readCallbacks.end()) {
        iter->d_callback(iter->d_fd, iter->d_parameter);
        count++;
      }
    }

    if (pollfd.revents & POLLOUT || pollfd.revents & POLLERR) {
      const auto& iter = d_writeCallbacks.find(pollfd.fd);
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

  PollFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif
