#include <unistd.h>
#include "threadname.hh"
#include "remote_logger.hh"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef PDNS_CONFIG_ARGS
#include "logger.hh"
#define WE_ARE_RECURSOR
#else
#include "dolog.hh"
#endif

bool RemoteLogger::reconnect()
{
  if (d_socket >= 0) {
    close(d_socket);
    d_socket = -1;
  }
  d_connected = false;
  try {
    d_socket = SSocket(d_remote.sin4.sin_family, SOCK_STREAM, 0);
    setNonBlocking(d_socket);
    SConnectWithTimeout(d_socket, d_remote, d_timeout);
  }
  catch(const std::exception& e) {
#ifdef WE_ARE_RECURSOR
    g_log<<Logger::Warning<<"Error connecting to remote logger "<<d_remote.toStringWithPort()<<": "<<e.what()<<std::endl;
#else
    warnlog("Error connecting to remote logger %s: %s", d_remote.toStringWithPort(), e.what());
#endif
    return false;
  }
  d_connected = true;
  return true;
}

void RemoteLogger::busyReconnectLoop()
{
  while (!reconnect()) {
    sleep(d_reconnectWaitTime);
  }
}

void RemoteLogger::worker()
{
#ifdef WE_ARE_RECURSOR
  string threadName = "pdns-r/remLog";
#else
  string threadName = "dnsdist/remLog";
#endif
  setThreadName(threadName);
  while(true) {
    std::string data;
    {
      std::unique_lock<std::mutex> lock(d_writeMutex);
      d_queueCond.wait(lock, [this]{return (!d_writeQueue.empty()) || d_exiting;});
      if (d_exiting) {
        return;
      }
      data = d_writeQueue.front();
      d_writeQueue.pop();
    }

    if (!d_connected) {
      busyReconnectLoop();
    }

    try {
      uint16_t len = static_cast<uint16_t>(data.length());
      sendSizeAndMsgWithTimeout(d_socket, len, data.c_str(), static_cast<int>(d_timeout), nullptr, nullptr, 0, 0, 0);
    }
    catch(const std::runtime_error& e) {
#ifdef WE_ARE_RECURSOR
      g_log<<Logger::Info<<"Error sending data to remote logger "<<d_remote.toStringWithPort()<<": "<< e.what()<<endl;
#else
      vinfolog("Error sending data to remote logger (%s): %s", d_remote.toStringWithPort(), e.what());
#endif
      busyReconnectLoop();
    }
  }
}

void RemoteLogger::queueData(const std::string& data)
{
  {
    std::lock_guard<std::mutex> lock(d_writeMutex);
    if (d_writeQueue.size() >= d_maxQueuedEntries) {
      d_writeQueue.pop();
    }
    d_writeQueue.push(data);
  }
  d_queueCond.notify_one();
}

RemoteLogger::RemoteLogger(const ComboAddress& remote, uint16_t timeout, uint64_t maxQueuedEntries, uint8_t reconnectWaitTime, bool asyncConnect): d_remote(remote), d_maxQueuedEntries(maxQueuedEntries), d_timeout(timeout), d_reconnectWaitTime(reconnectWaitTime), d_asyncConnect(asyncConnect), d_thread(&RemoteLogger::worker, this)
{
  if (!d_asyncConnect) {
    reconnect();
  }
}

RemoteLogger::~RemoteLogger()
{
  d_exiting = true;
  if (d_socket >= 0) {
    close(d_socket);
    d_socket = -1;
    d_connected = false;
  }
  d_queueCond.notify_one();
  d_thread.join();
}
