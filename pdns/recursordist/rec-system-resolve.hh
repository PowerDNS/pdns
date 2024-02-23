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

#include <functional>
#include <thread>

#include "namespaces.hh"
#include "iputils.hh"
#include "lock.hh"

namespace pdns
{
class RecResolve
{
public:
  // Should be called before any getInstance() call is done
  static void setInstanceParameters(time_t ttl, const std::function<void()>& callback);
  static RecResolve& getInstance();

  RecResolve(time_t ttl = 60, const std::function<void()>& callback = nullptr);
  ~RecResolve();
  ComboAddress lookupAndRegister(const std::string& name, time_t now);
  ComboAddress lookup(const std::string& name);
  void stopRefresher();
  void startRefresher();
  void wipe(const std::string& name = "");
  bool refresh(time_t now);
  bool changeDetected();

private:
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

  class Refresher
  {
  public:
    Refresher(time_t interval, const std::function<void()>& callback, pdns::RecResolve& res);
    Refresher(const Refresher&) = delete;
    Refresher(Refresher&&) = delete;
    Refresher& operator=(const Refresher&) = delete;
    Refresher& operator=(Refresher&&) = delete;
    ~Refresher();

    void start();
    void finish();
    void trigger();

    std::atomic<bool> changes{false};
  private:
    void refreshLoop();

    pdns::RecResolve& d_resolver;
    std::function<void()> d_callback;
    time_t d_interval;
    std::thread d_thread;
    std::mutex mutex;
    std::condition_variable condVar;
    std::atomic<bool> wakeup{false};
    std::atomic<bool> stop{false};
  };

  Refresher d_refresher;

  static std::function<void()> s_callback;
  static time_t s_ttl;
};

}
