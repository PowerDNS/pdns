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
  int readTimeout(T* t, int msec); // -1 is timeout, 0 is no data, 1 is data
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
  void submit(T& t, int msec);

private:
  std::thread d_thread;
  void worker();
  struct Combo
  {
    T what;
    struct timespec when;
  };

  ObjectPipe<Combo> d_pipe;
  struct tscomp {
    bool operator()(const struct timespec& a, const struct timespec& b) const
    {
      return std::tie(a.tv_sec, a.tv_nsec) < std::tie(b.tv_sec, b.tv_nsec);
    }
  };
  std::multimap<struct timespec, T, tscomp> d_work;
};

#include "delaypipe.cc"
