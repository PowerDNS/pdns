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
#include "dnsdist-session-cache.hh"

TLSSessionCache g_sessionCache;

time_t const TLSSessionCache::s_cleanupDelay{60};
time_t const TLSSessionCache::s_sessionValidity{600};

void TLSSessionCache::cleanup(time_t now, const std::lock_guard<std::mutex>& lock)
{
  time_t cutOff = now + s_sessionValidity;

  for (auto it = d_sessions.begin(); it != d_sessions.end();) {
    if (it->second.d_lastUsed > cutOff || it->second.d_sessions.size() == 0) {
      it = d_sessions.erase(it);
    }
    else {
      ++it;
    }
  }

  d_nextCleanup = now + s_cleanupDelay;
}

void TLSSessionCache::putSession(const boost::uuids::uuid& backendID, time_t now, std::unique_ptr<TLSSession>&& session)
{
  std::lock_guard<decltype(d_lock)> lock(d_lock);
  if (d_nextCleanup == 0 || now > d_nextCleanup) {
    cleanup(now, lock);
  }

  auto& entry = d_sessions[backendID];
  if (entry.d_sessions.size() >= d_maxSessionsPerBackend) {
    entry.d_sessions.pop_back();
  }
  entry.d_sessions.push_front(std::move(session));
}

std::unique_ptr<TLSSession> TLSSessionCache::getSession(const boost::uuids::uuid& backendID, time_t now)
{
  std::lock_guard<decltype(d_lock)> lock(d_lock);
  auto it = d_sessions.find(backendID);
  if (it == d_sessions.end()) {
    return nullptr;
  }

  auto& entry = it->second;
  if (entry.d_sessions.size() == 0) {
    return nullptr;
  }

  entry.d_lastUsed = now;
  auto value = std::move(entry.d_sessions.front());
  entry.d_sessions.pop_front();

  return value;
}
