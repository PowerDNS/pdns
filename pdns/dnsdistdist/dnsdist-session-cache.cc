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

#include "dnsdist-configuration.hh"

TLSSessionCache g_sessionCache;

void TLSSessionCache::cleanup(time_t now, LockGuardedHolder<TLSSessionCache::CacheData>& data)
{
  const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  time_t cutOff = now + runtimeConfig.d_tlsSessionCacheSessionValidity;

  for (auto it = data->d_sessions.begin(); it != data->d_sessions.end();) {
    if (it->second.d_lastUsed > cutOff || it->second.d_sessions.size() == 0) {
      it = data->d_sessions.erase(it);
    }
    else {
      ++it;
    }
  }

  data->d_nextCleanup = now + runtimeConfig.d_tlsSessionCacheCleanupDelay;
}

void TLSSessionCache::putSessions(const boost::uuids::uuid& backendID, time_t now, std::vector<std::unique_ptr<TLSSession>>&& sessions)
{
  auto data = d_data.lock();
  if (data->d_nextCleanup == 0 || now > data->d_nextCleanup) {
    cleanup(now, data);
  }

  const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  for (auto& session : sessions) {
    auto& entry = data->d_sessions[backendID];
    if (entry.d_sessions.size() >= runtimeConfig.d_tlsSessionCacheMaxSessionsPerBackend) {
      entry.d_sessions.pop_back();
    }
    entry.d_sessions.push_front(std::move(session));
  }
}

std::unique_ptr<TLSSession> TLSSessionCache::getSession(const boost::uuids::uuid& backendID, time_t now)
{
  auto data = d_data.lock();
  auto it = data->d_sessions.find(backendID);
  if (it == data->d_sessions.end()) {
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

size_t TLSSessionCache::getSize()
{
  size_t count = 0;
  auto data = d_data.lock();
  for (const auto& backend : data->d_sessions) {
    count += backend.second.d_sessions.size();
  }
  return count;
}
