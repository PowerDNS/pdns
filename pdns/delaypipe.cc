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
#include "delaypipe.hh"
#include "misc.hh"
#include "gettime.hh"
#include <thread>
#include "threadname.hh"

template<class T>
ObjectPipe<T>::ObjectPipe()
{
  if(pipe(d_fds))
    unixDie("pipe");
}

template<class T>
ObjectPipe<T>::~ObjectPipe()
{
  ::close(d_fds[0]);
  if(d_fds[1] >= 0)
    ::close(d_fds[1]);
}

template<class T>
void ObjectPipe<T>::close()
{
  if(d_fds[1] < 0)
    return;
  ::close(d_fds[1]); // the writing side
  d_fds[1]=-1;
}

template<class T>
void ObjectPipe<T>::write(T& t)
{
  auto ptr = new T(t);
  if(::write(d_fds[1], &ptr, sizeof(ptr)) != sizeof(ptr)) {
    delete ptr;
    unixDie("write");
  }
}

template<class T>
int ObjectPipe<T>::readTimeout(T* t, double msec)
{
  while (true) {
    int ret = waitForData(d_fds[0], 0, 1000*msec);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      unixDie("waiting for data in object pipe");
    }
    else if (ret == 0) {
      return -1;
    }

    T* ptr = nullptr;
    ret = ::read(d_fds[0], &ptr, sizeof(ptr)); // this is BLOCKING!

    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      unixDie("read");
    }
    else if (ret == 0) {
      return false;
    }

    if (ret != sizeof(ptr)) {
      throw std::runtime_error("Partial read, should not happen 2");
    }

    *t = *ptr;
    delete ptr;
    return 1;
  }
}


template<class T>
DelayPipe<T>::DelayPipe() : d_thread(&DelayPipe<T>::worker, this)
{
}

template<class T>
void DelayPipe<T>::gettime(struct timespec* ts)
{
  ::gettime(ts);
}


template<class T>
void DelayPipe<T>::submit(T& t, int msec)
{
  struct timespec now;
  gettime(&now);
  now.tv_nsec += msec*1e6;
  while(now.tv_nsec > 1e9) {
    now.tv_sec++;
    now.tv_nsec-=1e9;
  }
  Combo c{t, now};
  d_pipe.write(c);
}

template<class T>
DelayPipe<T>::~DelayPipe()
{
  d_pipe.close();
  d_thread.join();
}



template<class T>
void DelayPipe<T>::worker()
{
  setThreadName("delayPipe");
  Combo c;
  for(;;) {
    /* this code is slightly too subtle, but I don't see how it could be any simpler.
       So we have a set of work to do, and we need to wait until the time arrives to do it.
       Simultaneously new work might come in. So we try to combine both of these things by
       setting a timeout on listening to the pipe over which new work comes in. This timeout
       is equal to the wait until the first thing that needs to be done.

       Two additional cases exist: we have no work to wait for, so we can wait infinitely long.
       The other special case is that the first we have to do.. is in the past, so we need to do it
       immediately. */

       
    double delay=-1;  // infinite
    struct timespec now;
    if(!d_work.empty()) {
      gettime(&now);
      delay=1000*tsdelta(d_work.begin()->first, now);
      if(delay < 0) {
	delay=0;   // don't wait - we have work that is late already!
      }
    }
    if(delay != 0 ) {
      int ret = d_pipe.readTimeout(&c, delay); 
      if(ret > 0) {  // we got an object
        d_work.emplace(c.when, c.what);
      }
      else if(ret==0) { // EOF
	break;
      }
      else {
	;
      }
      gettime(&now);
    }

    tscomp cmp;

    for(auto iter = d_work.begin() ; iter != d_work.end(); ) { // do the needful
      if(cmp(iter->first, now)) {
	iter->second();
	d_work.erase(iter++);
      }
      else {
	break;
      }
    }
  }
}
