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
  [[nodiscard]] virtual std::string address() const = 0;
  [[nodiscard]] virtual std::string toString() = 0;
  [[nodiscard]] virtual std::string name() const = 0;
  bool logQueries(void) const { return d_logQueries; }
  bool logResponses(void) const { return d_logResponses; }
  bool logNODs(void) const { return d_logNODs; }
  bool logUDRs(void) const { return d_logUDRs; }
  void setLogQueries(bool flag) { d_logQueries = flag; }
  void setLogResponses(bool flag) { d_logResponses = flag; }
  void setLogNODs(bool flag) { d_logNODs = flag; }
  void setLogUDRs(bool flag) { d_logUDRs = flag; }

  struct Stats
  {
    uint64_t d_queued{};
    uint64_t d_pipeFull{};
    uint64_t d_tooLarge{};
    uint64_t d_otherError{};

    Stats& operator += (const Stats& rhs)
    {
      d_queued += rhs.d_queued;
      d_pipeFull += rhs.d_pipeFull;
      d_tooLarge += rhs.d_tooLarge;
      d_otherError += rhs.d_otherError;
      return *this;
    }
  };

  [[nodiscard]] virtual Stats getStats() = 0;

private:
  bool d_logQueries{true};
  bool d_logResponses{true};
  bool d_logNODs{true};
  bool d_logUDRs{false};
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

  std::string address() const override
  {
    return d_remote.toStringWithPort();
  }

  [[nodiscard]] Result queueData(const std::string& data) override;
  [[nodiscard]] std::string name() const override
  {
    return "protobuf";
  }
  [[nodiscard]] std::string toString() override
  {
    auto runtime = d_runtime.lock();
    return d_remote.toStringWithPort() + " (" + std::to_string(runtime->d_stats.d_queued) + " processed, " + std::to_string(runtime->d_stats.d_pipeFull + runtime->d_stats.d_tooLarge + runtime->d_stats.d_otherError) + " dropped)";
  }

  [[nodiscard]] RemoteLoggerInterface::Stats getStats() override
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

  LockGuarded<RuntimeData> d_runtime;
  std::thread d_thread;
};

