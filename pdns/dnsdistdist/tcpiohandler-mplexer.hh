
#pragma once

#include "mplexer.hh"
#include "tcpiohandler.hh"

class IOStateHandler
{
public:
  IOStateHandler(std::unique_ptr<FDMultiplexer>& mplexer, const int fd): d_mplexer(mplexer), d_fd(fd), d_currentState(IOState::Done)
  {
  }

  IOStateHandler(std::unique_ptr<FDMultiplexer>& mplexer): d_mplexer(mplexer), d_fd(-1), d_currentState(IOState::Done)
  {
  }

  ~IOStateHandler()
  {
    /* be careful that this won't save us if the callback is still registered to the multiplexer,
       because in that case the shared pointer count will never reach zero so this destructor won't
       be called */
    reset();
  }

  IOState getState() const
  {
    return d_currentState;
  }

  void setSocket(int fd)
  {
    if (d_fd != -1) {
      throw std::runtime_error("Trying to set the socket descriptor on an already initialized IOStateHandler");
    }
    d_fd = fd;
  }

  void reset()
  {
    update(IOState::Done);
  }

  void update(IOState iostate, FDMultiplexer::callbackfunc_t callback = FDMultiplexer::callbackfunc_t(), FDMultiplexer::funcparam_t callbackData = boost::any(), boost::optional<struct timeval> ttd = boost::none)
  {
    cerr<<"in "<<__PRETTY_FUNCTION__<<" for fd "<<d_fd<<", last state was "<<(int)d_currentState<<", new state is "<<(int)iostate<<endl;
    if (d_currentState == IOState::NeedRead && iostate != IOState::NeedRead) {
      cerr<<__PRETTY_FUNCTION__<<": remove read FD "<<d_fd<<endl;
      d_mplexer->removeReadFD(d_fd);
      d_currentState = IOState::Done;
    }
    else if (d_currentState == IOState::NeedWrite && iostate != IOState::NeedWrite) {
      cerr<<__PRETTY_FUNCTION__<<": remove write FD "<<d_fd<<endl;
      d_mplexer->removeWriteFD(d_fd);
      d_currentState = IOState::Done;
    }

    if (iostate == IOState::NeedRead) {
      if (d_currentState == IOState::NeedRead) {
        if (ttd) {
          /* let's update the TTD ! */
          d_mplexer->setReadTTD(d_fd, *ttd, /* we pass 0 here because we already have a TTD */0);
        }
        return;
      }

      d_currentState = IOState::NeedRead;
      cerr<<__PRETTY_FUNCTION__<<": add read FD "<<d_fd<<endl;
      d_mplexer->addReadFD(d_fd, callback, callbackData, ttd ? &*ttd : nullptr);
    }
    else if (iostate == IOState::NeedWrite) {
      if (d_currentState == IOState::NeedWrite) {
        return;
      }

      d_currentState = IOState::NeedWrite;
      cerr<<__PRETTY_FUNCTION__<<": add write FD "<<d_fd<<endl;
      d_mplexer->addWriteFD(d_fd, callback, callbackData, ttd ? &*ttd : nullptr);
    }
    else if (iostate == IOState::Done) {
      d_currentState = IOState::Done;
      cerr<<__PRETTY_FUNCTION__<<": done"<<endl;
    }
  }

private:
  std::unique_ptr<FDMultiplexer>& d_mplexer;
  int d_fd;
  IOState d_currentState;
};

class IOStateGuard
{
public:
  /* this class is using RAII to make sure we don't forget to release an IOStateHandler
     from the IO multiplexer in case of exception / error handling */
  IOStateGuard(std::unique_ptr<IOStateHandler>& handler): d_handler(handler), d_enabled(true)
  {
  }

  ~IOStateGuard()
  {
    /* if we are still owning the state when we go out of scope,
       let's reset the state so it's not registered to the IO multiplexer anymore
       and its reference count goes to zero */
    if (d_enabled && d_handler) {
      cerr<<"IOStateGuard destroyed while holding a state, let's reset it"<<endl;
      d_handler->reset();
      d_enabled = false;
    }
  }

  void release()
  {
    d_enabled = false;
  }

private:
  std::unique_ptr<IOStateHandler>& d_handler;
  bool d_enabled;
};
