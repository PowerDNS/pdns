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

#include "rec-xfr.hh"
#include "lock.hh"

// As there can be multiple threads doing updates (due to config reloads), we use a multimap.
// The value contains the actual thread id that owns the struct.

static LockGuarded<std::multimap<DNSName, ZoneWaiter&>> condVars;

// Notify all threads tracking the RPZ name
bool notifyZoneTracker(const DNSName& name)
{
  auto lock = condVars.lock();
  auto [start, end] = lock->equal_range(name);
  if (start == end) {
    // Did not find any thread tracking that name
    return false;
  }
  while (start != end) {
    start->second.stop = true;
    start->second.condVar.notify_one();
    ++start;
  }
  return true;
}

void insertZoneTracker(const DNSName& zoneName, ZoneWaiter& waiter)
{
  auto lock = condVars.lock();
  lock->emplace(zoneName, waiter);
}

void clearZoneTracker(const DNSName& zoneName)
{
  // Zap our (and only our) ZoneWaiter struct out of the multimap
  auto lock = condVars.lock();
  auto [start, end] = lock->equal_range(zoneName);
  while (start != end) {
    if (start->second.id == std::this_thread::get_id()) {
      lock->erase(start);
      break;
    }
    ++start;
  }
}
