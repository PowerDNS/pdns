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

#include "lock.hh"
#include "tcpiohandler.hh"
#include "uuid-utils.hh"

class TLSSessionCache
{
public:
  TLSSessionCache()
  {
  }

  void putSessions(const boost::uuids::uuid& backendID, time_t now, std::vector<std::unique_ptr<TLSSession>>&& sessions);
  std::unique_ptr<TLSSession> getSession(const boost::uuids::uuid& backendID, time_t now);

  size_t getSize();

private:
  struct BackendEntry
  {
    std::deque<std::unique_ptr<TLSSession>> d_sessions;
    time_t d_lastUsed{0};
  };

  struct CacheData
  {
    // do we need to shard this?
    std::map<boost::uuids::uuid, BackendEntry> d_sessions;
    time_t d_nextCleanup{0};
  };
  LockGuarded<CacheData> d_data;

  void cleanup(time_t now, LockGuardedHolder<CacheData>& data);
};

extern TLSSessionCache g_sessionCache;
