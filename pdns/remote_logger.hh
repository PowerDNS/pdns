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
#include "config.h"

#include <atomic>
#include <condition_variable>
#include <queue>
#include <thread>

#include "iputils.hh"

class RemoteLogger
{
public:
  RemoteLogger(const ComboAddress& remote, uint16_t timeout=2, uint64_t maxQueuedEntries=100, uint8_t reconnectWaitTime=1, bool asyncConnect=false);
  ~RemoteLogger();
  void queueData(const std::string& data);
  std::string toString()
  {
    return d_remote.toStringWithPort();
  }
private:
  bool reconnect();
  void worker();

  std::queue<std::string> d_writeQueue;
  std::mutex d_writeMutex;
  std::condition_variable d_queueCond;
  ComboAddress d_remote;
  uint64_t d_maxQueuedEntries;
  int d_socket{-1};
  uint16_t d_timeout;
  uint8_t d_reconnectWaitTime;
  std::atomic<bool> d_exiting{false};
  bool d_asyncConnect{false};
  std::thread d_thread;
};
