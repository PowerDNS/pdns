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

template <class T>
ObjectPipe<T>::ObjectPipe()
{
  auto [sender, receiver] = pdns::channel::createObjectQueue<T>(pdns::channel::SenderBlockingMode::SenderBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, 0, false);
  d_sender = std::move(sender);
  d_receiver = std::move(receiver);
}

template <class T>
void ObjectPipe<T>::close()
{
  d_sender.close();
}

template <class T>
void ObjectPipe<T>::write(T& t)
{
  auto ptr = std::make_unique<T>(t);
  if (!d_sender.send(std::move(ptr))) {
    unixDie("writing to the DelayPipe");
  }
}

template <class T>
int ObjectPipe<T>::readTimeout(T* t, double msec)
{
  while (true) {
    int ret = waitForData(d_receiver.getDescriptor(), 0, 1000 * msec);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      unixDie("waiting for data in object pipe");
    }
    else if (ret == 0) {
      return -1;
    }

    try {
      auto tmp = d_receiver.receive();
      if (!tmp) {
        if (d_receiver.isClosed()) {
          return 0;
        }
        continue;
      }

      *t = **tmp;
      return 1;
    }
    catch (const std::exception& e) {
      throw std::runtime_error("reading from the delay pipe: " + std::string(e.what()));
    }
  }
}

template <class T>
DelayPipe<T>::DelayPipe() :
  d_thread(&DelayPipe<T>::worker, this)
{
}

template <class T>
void DelayPipe<T>::gettime(struct timespec* ts)
{
  ::gettime(ts);
}

template <class T>
void DelayPipe<T>::submit(T& t, int msec)
{
  struct timespec now;
  gettime(&now);
  now.tv_nsec += msec * 1e6;
  while (now.tv_nsec > 1e9) {
    now.tv_sec++;
    now.tv_nsec -= 1e9;
  }
  Combo c{t, now};
  d_pipe.write(c);
}

template <class T>
DelayPipe<T>::~DelayPipe()
{
  d_pipe.close();
  d_thread.join();
}

template <class T>
void DelayPipe<T>::worker()
{
  setThreadName("dnsdist/delayPi");
  Combo c;
  for (;;) {
    /* this code is slightly too subtle, but I don't see how it could be any simpler.
       So we have a set of work to do, and we need to wait until the time arrives to do it.
       Simultaneously new work might come in. So we try to combine both of these things by
       setting a timeout on listening to the pipe over which new work comes in. This timeout
       is equal to the wait until the first thing that needs to be done.

       Two additional cases exist: we have no work to wait for, so we can wait infinitely long.
       The other special case is that the first we have to do.. is in the past, so we need to do it
       immediately. */

    double delay = -1; // infinite
    struct timespec now;
    if (!d_work.empty()) {
      gettime(&now);
      delay = 1000 * tsdelta(d_work.begin()->first, now);
      if (delay < 0) {
        delay = 0; // don't wait - we have work that is late already!
      }
    }
    if (delay != 0) {
      int ret = d_pipe.readTimeout(&c, delay);
      if (ret > 0) { // we got an object
        d_work.emplace(c.when, c.what);
      }
      else if (ret == 0) { // EOF
        break;
      }
      else {
        ;
      }
      gettime(&now);
    }

    tscomp cmp;

    for (auto iter = d_work.begin(); iter != d_work.end();) { // do the needful
      if (cmp(iter->first, now)) {
        iter->second();
        d_work.erase(iter++);
      }
      else {
        break;
      }
    }
  }
}
