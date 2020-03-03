#include <unistd.h>
#include "threadname.hh"
#include "remote_logger.hh"
#include <sys/uio.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef PDNS_CONFIG_ARGS
#include "logger.hh"
#define WE_ARE_RECURSOR
#else
#include "dolog.hh"
#endif

bool CircularWriteBuffer::hasRoomFor(const std::string& str) const
{
  if (d_buffer.size() + 2 + str.size() > d_buffer.capacity()) {
    return false;
  }

  return true;
}

bool CircularWriteBuffer::write(const std::string& str)
{
  if (!hasRoomFor(str)) {
    return false;
  }

  uint16_t len = htons(str.size());
  const char* ptr = reinterpret_cast<const char*>(&len);
  d_buffer.insert(d_buffer.end(), ptr, ptr + 2);
  d_buffer.insert(d_buffer.end(), str.begin(), str.end());

  return true;
}

bool CircularWriteBuffer::flush(int fd)
{
  if (d_buffer.empty()) {
    // not optional, we report EOF otherwise
    return false;
  }

  auto arr1 = d_buffer.array_one();
  auto arr2 = d_buffer.array_two();

  struct iovec iov[2];
  int pos = 0;
  size_t total = 0;
  for(const auto& arr : {arr1, arr2}) {
    if(arr.second) {
      iov[pos].iov_base = arr.first;
      iov[pos].iov_len = arr.second;
      total += arr.second;
      ++pos;
    }
  }

  ssize_t res = 0;
  do {
    res = writev(fd, iov, pos);

    if (res < 0) {
      if (errno == EINTR) {
        continue;
      }

      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return false;
      }

      /* we can't be sure we haven't sent a partial message,
         and we don't want to send the remaining part after reconnecting */
      d_buffer.clear();
      throw std::runtime_error("Couldn't flush a thing: " + stringerror());
    }
    else if (!res) {
      /* we can't be sure we haven't sent a partial message,
         and we don't want to send the remaining part after reconnecting */
      d_buffer.clear();
      throw std::runtime_error("EOF");
    }
  }
  while (res < 0);

  //  cout<<"Flushed "<<res<<" bytes out of " << total <<endl;
  if (static_cast<size_t>(res) == d_buffer.size()) {
    d_buffer.clear();
  }
  else {
    while (res--) {
      d_buffer.pop_front();
    }
  }

  return true;
}

RemoteLogger::RemoteLogger(const ComboAddress& remote, uint16_t timeout, uint64_t maxQueuedBytes, uint8_t reconnectWaitTime, bool asyncConnect): d_writer(maxQueuedBytes), d_remote(remote), d_maxQueuedBytes(maxQueuedBytes), d_timeout(timeout), d_reconnectWaitTime(reconnectWaitTime), d_asyncConnect(asyncConnect)
{
  if (!d_asyncConnect) {
    reconnect();
  }

  d_thread = std::thread(&RemoteLogger::maintenanceThread, this);
}

bool RemoteLogger::reconnect()
{
  try {
    auto newSock = make_unique<Socket>(d_remote.sin4.sin_family, SOCK_STREAM, 0);
    newSock->setNonBlocking();
    newSock->connect(d_remote, d_timeout);

    {
      /* we are now successfully connected, time to take the lock and update the
         socket */
      std::unique_lock<std::mutex> lock(d_mutex);
      d_socket = std::move(newSock);
    }
  }
  catch (const std::exception& e) {
#ifdef WE_ARE_RECURSOR
    g_log<<Logger::Warning<<"Error connecting to remote logger "<<d_remote.toStringWithPort()<<": "<<e.what()<<std::endl;
#else
    warnlog("Error connecting to remote logger %s: %s", d_remote.toStringWithPort(), e.what());
#endif

    return false;
  }
  return true;
}

void RemoteLogger::queueData(const std::string& data)
{
  std::unique_lock<std::mutex> lock(d_mutex);

  if (!d_writer.hasRoomFor(data)) {
    /* not connected, queue is full, just drop */
    if (!d_socket) {
      ++d_drops;
      return;
    }
    try {
      /* we try to flush some data */
      if (!d_writer.flush(d_socket->getHandle())) {
        /* but failed, let's just drop */
        ++d_drops;
        return;
      }

      /* see if we freed enough data */
      if (!d_writer.hasRoomFor(data)) {
        /* we didn't */
        ++d_drops;
        return;
      }
    }
    catch(const std::exception& e) {
      //      cout << "Got exception writing: "<<e.what()<<endl;
      ++d_drops;
      d_socket.reset();
      return;
    }
  }

  d_writer.write(data);
  ++d_queued;
}

void RemoteLogger::maintenanceThread()
try
{
#ifdef WE_ARE_RECURSOR
  string threadName = "pdns-r/remLog";
#else
  string threadName = "dnsdist/remLog";
#endif
  setThreadName(threadName);

  for (;;) {
    if (d_exiting) {
      break;
    }

    bool connected = true;
    if (d_socket == nullptr) {
      // if it was unset, it will remain so, we are the only ones setting it!
      connected = reconnect();
    }

    /* we will just go to sleep if the reconnection just failed */
    if (connected) {
      try {
        /* we don't want to take the lock while trying to reconnect */
        std::unique_lock<std::mutex> lock(d_mutex);
        if (d_socket) { // check if it is set
          d_writer.flush(d_socket->getHandle());
        }
        else {
          connected = false;
        }
      }
      catch(const std::exception& e) {
        d_socket.reset();
        connected = false;
      }

      if (!connected) {
        /* let's try to reconnect right away, we are about to sleep anyway */
        reconnect();
      }
    }

    sleep(d_reconnectWaitTime);
  }
}
catch(const std::exception& e)
{
  cerr<<"Thead died on: "<<e.what()<<endl;
}

RemoteLogger::~RemoteLogger()
{
  d_exiting = true;

  d_thread.join();
}
