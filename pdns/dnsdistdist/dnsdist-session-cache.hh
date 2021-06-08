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

#include <deque>
#include <map>

#include "tcpiohandler.hh"
#include "uuid-utils.hh"

class TLSSessionCache
{
public:
  TLSSessionCache()
  {
  }
  void cleanup(time_t now, const std::lock_guard<std::mutex>& lock);

  void putSession(const boost::uuids::uuid& backendID, time_t now, std::unique_ptr<TLSSession>&& session);
  std::unique_ptr<TLSSession> getSession(const boost::uuids::uuid& backendID, time_t now);

  static void setCleanupDelay(time_t delay)
  {
    s_cleanupDelay = delay;
  }

  static void setSessionValidity(time_t validity)
  {
    s_sessionValidity = validity;
  }

  static void setMaxTicketsPerBackend(uint16_t max)
  {
    s_maxSessionsPerBackend = max;
  }

private:
  static time_t s_cleanupDelay;
  static time_t s_sessionValidity;
  static uint16_t s_maxSessionsPerBackend;

  struct BackendEntry
  {
    std::deque<std::unique_ptr<TLSSession>> d_sessions;
    time_t d_lastUsed{0};
  };

  std::map<boost::uuids::uuid, BackendEntry> d_sessions;
  // do we need to shard this?
  std::mutex d_lock;
  time_t d_nextCleanup{0};
};

extern TLSSessionCache g_sessionCache;
