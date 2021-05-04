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

void TLSSessionCache::cleanup(time_t now)
{
  #warning WRITEME
}

void TLSSessionCache::putSession(const ComboAddress& remote, std::unique_ptr<TLSSession>&& session)
{
  std::lock_guard<decltype(d_lock)> lock(d_lock);
  auto& entry = d_sessions[remote];
  entry.d_session = std::move(session);
}

std::unique_ptr<TLSSession> TLSSessionCache::getSession(const ComboAddress& remote, time_t now)
{
  std::lock_guard<decltype(d_lock)> lock(d_lock);
  auto it = d_sessions.find(remote);
  if (it == d_sessions.end()) {
    return nullptr;
  }

  auto& entry = it->second;
  if (entry.d_session == nullptr) {
    return nullptr;
  }

  entry.d_lastUse = now;
  return std::move(entry.d_session);
}
