#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "mplexer.hh"
#include "sstuff.hh"
#include <iostream>
#include <poll.h>
#include "misc.hh"
#include "namespaces.hh"

FDMultiplexer* FDMultiplexer::getMultiplexerSilent()
{
  FDMultiplexer* ret = nullptr;
  for(const auto& i : FDMultiplexer::getMultiplexerMap()) {
    try {
      ret = i.second();
      return ret;
    }
    catch(const FDMultiplexerException& fe) {
    }
    catch(...) {
    }
  }
  return ret;
}


class PollFDMultiplexer : public FDMultiplexer
{
public:
  PollFDMultiplexer()
  {}
  virtual ~PollFDMultiplexer()
  {
  }

  virtual int run(struct timeval* tv, int timeout=500) override;
  virtual void getAvailableFDs(std::vector<int>& fds, int timeout) override;

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd=nullptr) override;
  virtual void removeFD(callbackmap_t& cbmap, int fd) override;

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
  RegisterOurselves() {
    FDMultiplexer::getMultiplexerMap().insert(make_pair(1, &make));
  }
} doIt;

void PollFDMultiplexer::addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const boost::any& parameter, const struct timeval* ttd)
{
  accountingAddFD(cbmap, fd, toDo, parameter, ttd);
}

void PollFDMultiplexer::removeFD(callbackmap_t& cbmap, int fd)
{
  if(d_inrun && d_iter->d_fd==fd)  // trying to remove us!
    ++d_iter;

  if(!cbmap.erase(fd))
    throw FDMultiplexerException("Tried to remove unlisted fd "+std::to_string(fd)+ " from multiplexer");
}

vector<struct pollfd> PollFDMultiplexer::preparePollFD() const
{
  vector<struct pollfd> pollfds;
  pollfds.reserve(d_readCallbacks.size() + d_writeCallbacks.size());

  struct pollfd pollfd;
  for(const auto& cb : d_readCallbacks) {
    pollfd.fd = cb.d_fd;
    pollfd.events = POLLIN;
    pollfds.push_back(pollfd);
  }

  for(const auto& cb : d_writeCallbacks) {
    pollfd.fd = cb.d_fd;
    pollfd.events = POLLOUT;
    pollfds.push_back(pollfd);
  }

  return pollfds;
}

void PollFDMultiplexer::getAvailableFDs(std::vector<int>& fds, int timeout)
{
  auto pollfds = preparePollFD();
  int ret = poll(&pollfds[0], pollfds.size(), timeout);

  if (ret < 0 && errno != EINTR)
    throw FDMultiplexerException("poll returned error: " + stringerror());

  for(const auto& pollfd : pollfds) {
    if (pollfd.revents & POLLIN || pollfd.revents & POLLOUT) {
      fds.push_back(pollfd.fd);
    }
  }
}

int PollFDMultiplexer::run(struct timeval* now, int timeout)
{
  if(d_inrun) {
    throw FDMultiplexerException("FDMultiplexer::run() is not reentrant!\n");
  }

  auto pollfds = preparePollFD();

  int ret=poll(&pollfds[0], pollfds.size(), timeout);
  gettimeofday(now, 0); // MANDATORY!
  
  if(ret < 0 && errno!=EINTR)
    throw FDMultiplexerException("poll returned error: "+stringerror());

  d_iter=d_readCallbacks.end();
  d_inrun=true;

  for(const auto& pollfd : pollfds) {
    if(pollfd.revents & POLLIN) {
      d_iter=d_readCallbacks.find(pollfd.fd);
    
      if(d_iter != d_readCallbacks.end()) {
        d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
        continue; // so we don't refind ourselves as writable!
      }
    }
    else if(pollfd.revents & POLLOUT) {
      d_iter=d_writeCallbacks.find(pollfd.fd);
    
      if(d_iter != d_writeCallbacks.end()) {
        d_iter->d_callback(d_iter->d_fd, d_iter->d_parameter);
      }
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

  PollFDMultiplexer sfm;

  sfm.addReadFD(s.getHandle(), &acceptData, &s);

  for(int n=0; n < 100 ; ++n) {
    sfm.run();
  }
  sfm.removeReadFD(s.getHandle());
  sfm.removeReadFD(s.getHandle());
}
#endif

