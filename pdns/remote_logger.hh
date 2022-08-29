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
#pragma once
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <atomic>
#include <queue>
#include <thread>

#include "iputils.hh"
#include "circular_buffer.hh"
#include "lock.hh"
#include "sstuff.hh"

/* Writes can be submitted and they are atomically accepted. Either the whole write
   ends up in the buffer or nothing ends up in the buffer.
   In case nothing ends up in the buffer, an exception is thrown.
   Similarly, EOF leads to this treatment

   The filedescriptor can be in non-blocking mode.

   This class is not threadsafe.
*/

class CircularWriteBuffer
{
public:
  explicit CircularWriteBuffer(size_t size) : d_buffer(size)
  {
  }

  bool hasRoomFor(const std::string& str) const;
  bool write(const std::string& str);
  bool flush(int fd);
private:
  boost::circular_buffer<char> d_buffer;
};

class RemoteLoggerInterface
{
public:
  enum class Result : uint8_t { Queued, PipeFull, TooLarge, OtherError };
  static const std::string& toErrorString(Result r);


  virtual ~RemoteLoggerInterface() {};
  virtual Result queueData(const std::string& data) = 0;
  virtual std::string toString() const = 0;
  virtual const std::string name() const = 0;
  bool logQueries(void) const { return d_logQueries; }
  bool logResponses(void) const { return d_logResponses; }
  void setLogQueries(bool flag) { d_logQueries = flag; }
  void setLogResponses(bool flag) { d_logResponses = flag; }

  struct Stats
  {
    uint64_t d_queued{};
    uint64_t d_pipeFull{};
    uint64_t d_tooLarge{};
    uint64_t d_otherError{};
  };

  virtual Stats getStats() const = 0;

private:
  bool d_logQueries{true};
  bool d_logResponses{true};
};

/* Thread safe. Will connect asynchronously on request.
   Runs a reconnection thread that also periodicall flushes.
   Note that the buffer only runs as long as there is a connection.
   If there is no connection we don't buffer a thing
*/
class RemoteLogger : public RemoteLoggerInterface
{
public:
  RemoteLogger(const ComboAddress& remote, uint16_t timeout=2,
               uint64_t maxQueuedBytes=100000,
               uint8_t reconnectWaitTime=1,
               bool asyncConnect=false);
  ~RemoteLogger();

  [[nodiscard]] Result queueData(const std::string& data) override;
  const std::string name() const override
  {
    return "protobuf";
  }
  std::string toString() const override
  {
    auto runtime = d_runtime.lock();
    return d_remote.toStringWithPort() + " (" + std::to_string(runtime->d_stats.d_queued) + " processed, " + std::to_string(runtime->d_stats.d_pipeFull + runtime->d_stats.d_tooLarge + runtime->d_stats.d_otherError) + " dropped)";
  }

  virtual RemoteLoggerInterface::Stats getStats() const override
  {
    return d_runtime.lock()->d_stats;
  }

  void stop()
  {
    d_exiting = true;
  }

private:
  bool reconnect();
  void maintenanceThread();

  struct RuntimeData
  {
    CircularWriteBuffer d_writer;
    std::unique_ptr<Socket> d_socket{nullptr};
    RemoteLoggerInterface::Stats d_stats{};
  };

  ComboAddress d_remote;
  uint16_t d_timeout;
  uint8_t d_reconnectWaitTime;
  std::atomic<bool> d_exiting{false};
  bool d_asyncConnect{false};

  mutable LockGuarded<RuntimeData> d_runtime;
  std::thread d_thread;
};

