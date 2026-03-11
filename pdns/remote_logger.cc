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
#include "remote_logger.hh"

#include <unistd.h>
#include <sys/uio.h>

#include "threadname.hh"

#ifdef RECURSOR
#include "logger.hh"
#else /* !RECURSOR */
#include "dolog.hh"
#if defined(DNSDIST)
#include "dnsdist-logging.hh"
#endif /* DNSDIST */
#endif /* !RECURSOR */
#include "logging.hh"

bool CircularWriteBuffer::hasRoomFor(const std::string& str) const
{
  return d_buffer.size() + 2 + str.size() <= d_buffer.capacity();
}

bool CircularWriteBuffer::write(const std::string& str)
{
  if (str.size() > std::numeric_limits<uint16_t>::max() || !hasRoomFor(str)) {
    return false;
  }

  uint16_t len = htons(str.size());
  const char* ptr = reinterpret_cast<const char*>(&len); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  d_buffer.insert(d_buffer.end(), ptr, ptr + sizeof(len)); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  d_buffer.insert(d_buffer.end(), str.begin(), str.end());

  return true;
}

bool CircularWriteBuffer::flush(int fileDesc)
{
  if (d_buffer.empty()) {
    // not optional, we report EOF otherwise
    return false;
  }

  auto arr1 = d_buffer.array_one();
  auto arr2 = d_buffer.array_two();

  std::array<iovec,2> iov{};
  int pos = 0;
  for(const auto& arr : {arr1, arr2}) {
    if (arr.second != 0) {
      iov.at(pos).iov_base = arr.first;
      iov.at(pos).iov_len = arr.second;
      ++pos;
    }
  }

  ssize_t res = 0;
  do {
    res = ::writev(fileDesc, iov.data(), pos);

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
    if (res == 0) {
      /* we can't be sure we haven't sent a partial message,
         and we don't want to send the remaining part after reconnecting */
      d_buffer.clear();
      throw std::runtime_error("EOF");
    }
  }
  while (res < 0);

  if (static_cast<size_t>(res) == d_buffer.size()) {
    d_buffer.clear();
  }
  else {
    while (res-- != 0) {
      d_buffer.pop_front();
    }
  }

  return true;
}

const std::string& RemoteLoggerInterface::toErrorString(Result result)
{
  static const std::array<std::string,5> str = {
    "Queued",
    "Queue full, dropping",
    "Not sending too large protobuf message",
    "Submiting to queue failed",
    "?"
  };
  auto tmp = static_cast<unsigned int>(result);
  return str.at(std::min(tmp, 4U));
}

RemoteLogger::RemoteLogger(const ComboAddress& remote, uint16_t timeout, uint64_t maxQueuedBytes, uint8_t reconnectWaitTime, bool asyncConnect): d_remote(remote), d_timeout(timeout), d_reconnectWaitTime(reconnectWaitTime), d_asyncConnect(asyncConnect), d_runtime({CircularWriteBuffer(maxQueuedBytes), nullptr})
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
      auto runtime = d_runtime.lock();
      runtime->d_socket = std::move(newSock);
    }
  }
  catch (const std::exception& e) {
#ifdef RECURSOR
    SLOG(g_log<<Logger::Warning<<"Error connecting to remote logger "<<d_remote.toStringWithPort()<<": "<<e.what()<<std::endl,
         g_slog->withName("protobuf")->error(Logr::Error, e.what(), "Exception while connecting to remote logger", "address", Logging::Loggable(d_remote)));
#else
    SLOG(warnlog("Error connecting to remote logger %s: %s", d_remote.toStringWithPort(), e.what()),
         dnsdist::logging::getTopLogger("protobuf")->error(Logr::Warning, e.what(), "Exception while connecting to remote logger", "address", Logging::Loggable(d_remote))
      );
#endif

    return false;
  }
  return true;
}

RemoteLoggerInterface::Result RemoteLogger::queueData(const std::string& data)
{
  auto runtime = d_runtime.lock();

  if (data.size() > std::numeric_limits<uint16_t>::max()) {
    ++runtime->d_stats.d_tooLarge;
    return Result::TooLarge;
  }

  if (!runtime->d_writer.hasRoomFor(data)) {
    /* not connected, queue is full, just drop */
    if (!runtime->d_socket) {
      ++runtime->d_stats.d_pipeFull;
      return Result::PipeFull;
    }
    try {
      /* we try to flush some data */
      if (!runtime->d_writer.flush(runtime->d_socket->getHandle())) {
        /* but failed, let's just drop */
        ++runtime->d_stats.d_pipeFull;
        return Result::PipeFull;
      }

      /* see if we freed enough data */
      if (!runtime->d_writer.hasRoomFor(data)) {
        /* we didn't */
        ++runtime->d_stats.d_pipeFull;
        return Result::PipeFull;
      }
    }
    catch(const std::exception& e) {
      //      cout << "Got exception writing: "<<e.what()<<endl;
      runtime->d_socket.reset();
      ++runtime->d_stats.d_otherError;
      return Result::OtherError;
    }
  }

  runtime->d_writer.write(data);
#ifdef RECURSOR
  extern bool g_regressionTestMode;
  if (g_regressionTestMode) {
    runtime->d_writer.flush(runtime->d_socket->getHandle());
  }
#endif
  ++runtime->d_stats.d_queued;
  return Result::Queued;
}

void RemoteLogger::maintenanceThread()
{
  try {
#ifdef RECURSOR
    string threadName = "rec/remlog";
#else
    string threadName = "dnsdist/remLog";
#endif
    setThreadName(threadName);

    for (;;) {
      if (d_exiting) {
        break;
      }

      bool connected = true;
      if (d_runtime.lock()->d_socket == nullptr) {
        // if it was unset, it will remain so, we are the only ones setting it!
        connected = reconnect();
      }

      /* we will just go to sleep if the reconnection just failed */
      if (connected) {
        try {
          /* we don't want to take the lock while trying to reconnect */
          auto runtime = d_runtime.lock();
          if (runtime->d_socket) { // check if it is set
            /* if flush() returns false, it means that we couldn't flush anything yet
               either because there is nothing to flush, or because the outgoing TCP
               buffer is full. That's fine by us */
            runtime->d_writer.flush(runtime->d_socket->getHandle());
          }
          else {
            connected = false;
          }
        }
        catch (const std::exception& e) {
          d_runtime.lock()->d_socket.reset();
          connected = false;
        }

        if (!connected) {
          /* let's try to reconnect right away, we are about to sleep anyway */
          reconnect();
        }
      }
      std::this_thread::sleep_for(std::chrono::seconds(d_reconnectWaitTime));
    }
  }
  catch (const std::exception& e)
  {
#ifdef RECURSOR
    SLOG(cerr << "Remote Logger's maintenance thread died on: " << e.what() << endl,
         g_slog->withName("protobuf")->error(Logr::Error, e.what(), "Remote Logger's maintenance thread died"));
#else
    SLOG(errlog("Remote Logger's maintenance thread died on: %s", e.what()),
         dnsdist::logging::getTopLogger("protobuf")->error(Logr::Error, e.what(), "Remote Logger's maintenance thread died")
      );
#endif
  }
  catch (...) {
#ifdef RECURSOR
    SLOG(cerr << "Remote Logger's maintenance thread died on unknown exception" << endl,
         g_slog->withName("protobuf")->info(Logr::Error, "Remote Logger's maintenance thread died"));
#else
    SLOG(errlog("Remote Logger's maintenance thread died on: %s"),
         dnsdist::logging::getTopLogger("protobuf")->info(Logr::Error, "Remote Logger's maintenance thread died")
      );
#endif
  }
}

RemoteLogger::~RemoteLogger()
{
  d_exiting = true;

  d_thread.join();
}
