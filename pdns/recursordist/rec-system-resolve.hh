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

#include <condition_variable>
#include <functional>
#include <thread>

#include "namespaces.hh"
#include "iputils.hh"
#include "lock.hh"
#include "logr.hh"

/************************************************************************************************
The pdns::RecResolve class implements a facility to use the system configured resolver. At the moment
of writing, this can only be used to configure forwarding by name instead of IP.
 ************************************************************************************************/

/************************************************************************************************
DESIGN CONSIDERATIONS

- all names looked up with lookupAndRegister() will be entered into a table.

- the names in the table will ber periodically checked by a refresh thread. Set the period (before
  starting to use the system resolver) by calling pdns::RecResolve::setInstanceParameters().

- if *a* name resolves to a different result than stored, we will call the callback. Currently this is
   used to call the equivalent of rec_control reload-zones

- A manual rec_control reload-zones will *also* flush the existing table before doing the reload, so
  we force a re-resolve all names. See
  rec_channel_rec.cc:reloadZoneConfigurationWithSysResolveReset()

**************************************************************************************************/

/************************************************************************************************
PRACTICAL CONSIDERATIONS/IMPLEMENTATION LIMITS

- Currently the facility is *only* used by the forwarding code

- We resolve with AI_ADDRCONFIG, the address families enabled will depend on the network config
  of the machine

- We pick the first address that getaddrinfo() produced. Currently no handling of multiple addresses
  and/or multiple address families.

- There is a check to detect *some* cases of self-resolve. This is done by resolving
  id.server/CH/TXT and comparing the result to the system-id set. Both false positives and false
  negatives can occur.

**************************************************************************************************/
namespace pdns
{
class RecResolve
{
public:
  // Should be called before any getInstance() call is done
  static void setInstanceParameters(std::string serverID, time_t ttl, time_t interval, bool selfResolveCheck, const std::function<void()>& callback);
  // Get "the" instance of the system resolver.
  static RecResolve& getInstance();

  RecResolve(time_t ttl, time_t interval, bool selfResolveCheck, const std::function<void()>& callback = nullptr);
  ~RecResolve();
  // Lookup a name and register it in the names to be checked if not already there
  ComboAddress lookupAndRegister(const std::string& name, time_t now);
  // Lookup a name which must be already registered
  ComboAddress lookup(const std::string& name);

  // When an instance is created, it will run a refresh thread, stop it with this method
  void stopRefresher();
  // And restart it again
  void startRefresher();
  // Wipe one or all names
  void wipe(const std::string& name = "");

private:
  bool refresh(time_t now);
  struct AddressData
  {
    ComboAddress d_address;
    time_t d_ttd{0};
  };
  struct ResolveData
  {
    std::map<std::string, AddressData> d_map;
  };
  LockGuarded<ResolveData> d_data;
  const time_t d_ttl;

  // This private class implements the refresher thread
  class Refresher
  {
  public:
    Refresher(time_t interval, const std::function<void()>& callback, bool selfResolveCheck, pdns::RecResolve& res);
    Refresher(const Refresher&) = delete;
    Refresher(Refresher&&) = delete;
    Refresher& operator=(const Refresher&) = delete;
    Refresher& operator=(Refresher&&) = delete;
    ~Refresher();

    void start();
    void finish();
    void trigger();

  private:
    void refreshLoop();

    pdns::RecResolve& d_resolver;
    std::function<void()> d_callback;
    const time_t d_interval;
    std::thread d_thread;
    std::mutex mutex;
    std::condition_variable condVar;
    std::atomic<bool> wakeup{false};
    std::atomic<bool> stop{false};
    const bool d_selfResolveCheck;
  };

  Refresher d_refresher;

  static std::string s_serverID;
  static std::function<void()> s_callback;
  static time_t s_ttl;
  static time_t s_interval;
  static bool s_selfResolveCheck;
};

ComboAddress fromNameOrIP(const string& str, uint16_t defPort, Logr::log_t log);
}
