#pragma once
#include <map>
#include <time.h>
#include <thread>

/**
   General idea: many threads submit work to this class, but only one executes it. The work should therefore be entirely trivial.
   The implementatin is that submitter threads create an object that represents the work, and it gets sent over a pipe 
   to the worker thread.

   The worker thread meanwhile listens on this pipe (non-blocking), with a delay set to the next object that needs to be executed.
   If meanwhile new work comes in, all objects who's time has come are executed, a new sleep time is calculated.
*/


/* ObjectPipe facilitates the type-safe passing of types over a pipe */

template<class T>
class ObjectPipe
{
public:
  ObjectPipe();
  ~ObjectPipe();
  void write(T& t);
  bool read(T* t); // returns false on EOF
  int readTimeout(T* t, double msec); //!< -1 is timeout, 0 is no data, 1 is data. msec<0 waits infinitely wrong. msec==0 = undefined
  void close(); 
private:
  int d_fds[2];
};

template<class T>
class DelayPipe
{
public:
  DelayPipe();
  ~DelayPipe();
  void submit(T& t, int msec); //!< don't try for more than 4294 msec

private:
  std::thread d_thread;
  void worker();
  struct Combo
  {
    T what;
    struct timespec when;
  };

  double tsdelta(const struct timespec& a, const struct timespec& b) // read as a-b
  {
    return 1.0*(a.tv_sec-b.tv_sec)+1.0*(a.tv_nsec-b.tv_nsec)/1000000000.0;
  }

  ObjectPipe<Combo> d_pipe;
  struct tscomp {
    bool operator()(const struct timespec& a, const struct timespec& b) const
    {
      return std::tie(a.tv_sec, a.tv_nsec) < std::tie(b.tv_sec, b.tv_nsec);
    }
  };
  std::multimap<struct timespec, T, tscomp> d_work;
  void gettime(struct timespec* ts);
};

#include "delaypipe.cc"
