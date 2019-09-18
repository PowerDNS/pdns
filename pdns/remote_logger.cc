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

void CircularWriteBuffer::write(const std::string& str)
{
  if(d_buffer.size() + 2 + str.size() > d_buffer.capacity())
    flush();

  if(d_buffer.size() + 2 + str.size() > d_buffer.capacity())
    throw std::runtime_error("Full!");

  uint16_t len = htons(str.size());
  char* ptr = (char*)&len;
  d_buffer.insert(d_buffer.end(), ptr, ptr + 2);
  d_buffer.insert(d_buffer.end(), str.begin(), str.end());
}

void CircularWriteBuffer::flush()
{
  if(d_buffer.empty()) // not optional, we report EOF otherwise
    return;

  auto arr1 = d_buffer.array_one();
  auto arr2 = d_buffer.array_two();

  struct iovec iov[2];
  int pos=0;
  size_t total=0;
  for(const auto& arr : {arr1, arr2}) {
    if(arr.second) {
      iov[pos].iov_base = arr.first;
      iov[pos].iov_len = arr.second;
      total += arr.second;
      ++pos;
    }
  }

  int res = writev(d_fd, iov, pos);
  if(res < 0) {
    throw std::runtime_error("Couldn't flush a thing: "+stringerror());
  }
  if(!res) {
    throw std::runtime_error("EOF");
  }
  //  cout<<"Flushed "<<res<<" bytes out of " << total <<endl;
  if((size_t)res == d_buffer.size())
    d_buffer.clear();
  else {
    while(res--)
      d_buffer.pop_front();
  }
}

RemoteLogger::RemoteLogger(const ComboAddress& remote, uint16_t timeout, uint64_t maxQueuedBytes, uint8_t reconnectWaitTime, bool asyncConnect): d_remote(remote), d_maxQueuedBytes(maxQueuedBytes), d_timeout(timeout), d_reconnectWaitTime(reconnectWaitTime), d_asyncConnect(asyncConnect)
{
  if (!d_asyncConnect) {
    if(reconnect())
      d_writer = make_unique<CircularWriteBuffer>(d_socket, d_maxQueuedBytes);
  }
  d_thread = std::thread(&RemoteLogger::maintenanceThread, this);
}

bool RemoteLogger::reconnect()
{
  if (d_socket >= 0) {
    close(d_socket);
    d_socket = -1;
  }
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
  return true;
}

void RemoteLogger::queueData(const std::string& data)
{
  if(!d_writer) {
    d_drops++;
    return;
  }
  std::unique_lock<std::mutex> lock(d_mutex);
  if(d_writer) {
    try {
      d_writer->write(data);
    }
    catch(std::exception& e) {
      //      cout << "Got exception writing: "<<e.what()<<endl;
      d_drops++;
      d_writer.reset();
      close(d_socket);
      d_socket = -1;
    }
  }
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

  for(;;) {
    if(d_exiting)
      break;

    if(d_writer) {
      std::unique_lock<std::mutex> lock(d_mutex);
      if(d_writer) { // check if it is still set
        //        cout<<"Flush"<<endl;
        try {
          d_writer->flush();
        }
        catch(std::exception& e) {
          //          cout<<"Flush failed!"<<endl;
          d_writer.reset();
          close(d_socket);
          d_socket = -1;
        }
      }
    }
    else if(reconnect()) { // if it was zero, it will remain zero, we are the only ones setting it!
      std::unique_lock<std::mutex> lock(d_mutex);
      d_writer = make_unique<CircularWriteBuffer>(d_socket, d_maxQueuedBytes);
    }
    sleep(d_reconnectWaitTime);
  }
}
catch(std::exception& e)
{
  cerr<<"Thead died on: "<<e.what()<<endl;
}

RemoteLogger::~RemoteLogger()
{
  d_exiting = true;
  if (d_socket >= 0) {
    close(d_socket);
    d_socket = -1;
  }

  d_thread.join();
}
