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
#include <condition_variable>
#include <queue>
#include <thread>

#include "iputils.hh"
#include "circular_buffer.hh"

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
  explicit CircularWriteBuffer(int fd, size_t size) : d_fd(fd), d_buffer(size)
  {
  }

  void write(const std::string& str);
  void flush();
private:
  int d_fd;
  boost::circular_buffer<char> d_buffer;
};

class RemoteLoggerInterface
{
public:
  virtual ~RemoteLoggerInterface() {};
  virtual void queueData(const std::string& data) = 0;
  virtual std::string toString() const = 0;

  bool logQueries(void) const { return d_logQueries; }
  bool logResponses(void) const { return d_logResponses; }
  void setLogQueries(bool flag) { d_logQueries = flag; }
  void setLogResponses(bool flag) { d_logResponses = flag; }

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
  void queueData(const std::string& data) override;
  std::string toString() const override
  {
    return d_remote.toStringWithPort();
  }
  void stop()
  {
    d_exiting = true;
  }
  std::atomic<uint32_t> d_drops{0};

private:
  bool reconnect();
  void maintenanceThread();

  ComboAddress d_remote;
  uint64_t d_maxQueuedBytes;
  int d_socket{-1};
  std::unique_ptr<CircularWriteBuffer> d_writer;
  uint16_t d_timeout;
  uint8_t d_reconnectWaitTime;
  std::atomic<bool> d_exiting{false};
  bool d_asyncConnect{false};

  std::mutex d_mutex;
  std::thread d_thread;
};
