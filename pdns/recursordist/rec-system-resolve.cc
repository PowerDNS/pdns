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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "rec-system-resolve.hh"
#include "logging.hh"
#include "noinitvector.hh"
#include "threadname.hh"
#include "syncres.hh"

namespace
{
ComboAddress resolve(const std::string& name)
{
  struct addrinfo hints = {};
  hints.ai_flags = AI_ADDRCONFIG;
  hints.ai_family = 0;

  struct addrinfo* res = nullptr;
  auto ret = getaddrinfo(name.c_str(), nullptr, &hints, &res);
  // We pick the first address returned for now
  if (ret == 0) {
    auto address = ComboAddress{res->ai_addr, res->ai_addrlen};
    freeaddrinfo(res);
    return address;
  }
  return {};
}

PacketBuffer resolve(const string& name, QClass cls, QType type)
{
  PacketBuffer answer(512);
  auto ret = res_query(name.c_str(), cls, type, answer.data(), static_cast<int>(answer.size()));
  if (ret == -1) {
    answer.resize(0);
  }
  else {
    answer.resize(ret);
  }
  return answer;
}

std::string serverID()
{
  auto buffer = resolve("id.server", QClass::CHAOS, QType::TXT);
  if (buffer.empty()) {
    return {};
  }
  MOADNSParser parser(false, reinterpret_cast<char*>(buffer.data()), buffer.size()); // NOLINT
  if (parser.d_header.rcode != RCode::NoError || parser.d_answers.size() != 1) {
    return {};
  }
  const auto& dnsrecord = parser.d_answers.at(0).first;
  if (dnsrecord.d_type == QType::TXT) {
    if (auto txt = getRR<TXTRecordContent>(dnsrecord); txt != nullptr) {
      const auto& text = txt->d_text;
      if (text.size() >= 2 && text.at(0) == '"' && text.at(text.size() - 1) == '"') {
        // remove quotes around text
        return txt->d_text.substr(1, txt->d_text.size() - 2);
      }
      return txt->d_text;
    }
  }
  return {};
}
} // anonymous namespace

std::function<void()> pdns::RecResolve::s_callback;
time_t pdns::RecResolve::s_ttl{0};

void pdns::RecResolve::setInstanceParameters(time_t ttl, const std::function<void()>& callback)
{
  pdns::RecResolve::s_ttl = ttl;
  pdns::RecResolve::s_callback = callback;
}

pdns::RecResolve& pdns::RecResolve::getInstance()
{
  static unique_ptr<RecResolve> res = make_unique<pdns::RecResolve>(s_ttl, s_callback);
  return *res;
}

pdns::RecResolve::RecResolve(time_t ttl, const std::function<void()>& callback) :
  d_ttl(ttl), d_refresher(ttl / 6, callback, *this)
{
}

pdns::RecResolve::~RecResolve() = default;

void pdns::RecResolve::stopRefresher()
{
  d_refresher.finish();
}

void pdns::RecResolve::startRefresher()
{
  d_refresher.start();
}

ComboAddress pdns::RecResolve::lookupAndRegister(const std::string& name, time_t now)
{
  if (s_ttl == 0) {
    throw PDNSException("config tried to resolve `" + name + "' but system resolver feature not enabled");
  }
  auto data = d_data.lock();
  if (auto iter = data->d_map.find(name); iter != data->d_map.end()) {
    if (iter->second.d_ttd < now) {
      return iter->second.d_address;
    }
    // If it's stale, re-resolve below
  }
  // We keep the lock while resolving, even though this might take a while...
  auto address = resolve(name);

  time_t ttd = now + d_ttl;
  auto iter = data->d_map.emplace(name, AddressData{address, ttd}).first;
  return iter->second.d_address;
}

ComboAddress pdns::RecResolve::lookup(const std::string& name)
{
  auto data = d_data.lock();
  if (auto iter = data->d_map.find(name); iter != data->d_map.end()) {
    // always return it, even if it's stale
    return iter->second.d_address;
  }
  throw PDNSException("system resolve of unregistered name: " + name);
}

void pdns::RecResolve::wipe(const string& name)
{
  auto data = d_data.lock();
  if (name.empty()) {
    data->d_map.clear();
  }
  else {
    data->d_map.erase(name);
  }
}

bool pdns::RecResolve::refresh(time_t now)
{
  // The refrsh taks shol dnot take the lock for a long time, so we're working on a copy
  ResolveData copy;
  {
    auto data = d_data.lock();
    copy = *data;
  }
  std::map<std::string, AddressData> newData;

  auto log = g_slog->withName("system-resolver");

  bool updated = false;
  for (const auto& entry : copy.d_map) {
    if (entry.second.d_ttd <= now) {
      auto newAddress = resolve(entry.first);
      time_t ttd = now;
      if (newAddress != ComboAddress()) {
        // positive resolve, good for ttl
        ttd += d_ttl;
      }
      else {
        log->error(Logr::Error, "Name did not resolve", "name", Logging::Loggable(entry.first));
      }
      if (newAddress != entry.second.d_address) {
        log->info(Logr::Debug, "Name resolved to new address", "name", Logging::Loggable(entry.first),
                  "address", Logging::Loggable(newAddress.toString()));
        // An address changed
        updated = true;
      }
      newData.emplace(entry.first, AddressData{newAddress, ttd});
    }
  }

  if (!newData.empty()) {
    auto data = d_data.lock();
    for (const auto& entry : newData) {
      data->d_map.insert_or_assign(entry.first, entry.second);
    }
  }
  if (updated) {
    log->info(Logr::Info, "Changes in names detected");
  }
  return updated;
}

bool pdns::RecResolve::changeDetected()
{
  bool change = d_refresher.changes.exchange(false);
  return change;
}

pdns::RecResolve::Refresher::Refresher(time_t interval, const std::function<void()>& callback, pdns::RecResolve& res) :
  d_resolver(res), d_callback(callback), d_interval(std::max(static_cast<time_t>(1), interval))
{
  start();
}

pdns::RecResolve::Refresher::~Refresher()
{
  finish();
}

void pdns::RecResolve::Refresher::refreshLoop()
{
  setThreadName("rec/sysres");
  time_t lastSelfCheck = 0;

  while (!stop) {
    const time_t startTime = time(nullptr);
    time_t wakeTime = startTime;
    while (wakeTime - startTime < d_interval) {
      std::unique_lock lock(mutex);
      time_t remaining = d_interval - (wakeTime - startTime);
      if (remaining <= 0) {
        break;
      }
      condVar.wait_for(lock, std::chrono::seconds(remaining),
                       [&wakeup = wakeup] { return wakeup.load(); });
      wakeup = false;
      if (stop) {
        break;
      }
      if (lastSelfCheck < time(nullptr) - 3600) {
        lastSelfCheck = time(nullptr);
        auto resolvedServerID = serverID();
        if (resolvedServerID == SyncRes::s_serverID) {
          auto log = g_slog->withName("system-resolver");
          log->info(Logr::Error, "id.server/CH/TXT resolves to my own server identidy", "id.server", Logging::Loggable(resolvedServerID));
        }
      }
      changes = d_resolver.refresh(time(nullptr));
      wakeTime = time(nullptr);
      if (changes) {
        d_callback();
        changes = false;
      }
    }
  }
}

void pdns::RecResolve::Refresher::finish()
{
  stop = true;
  wakeup = true;
  condVar.notify_one();
  d_thread.join();
}

void pdns::RecResolve::Refresher::start()
{
  stop = false;
  wakeup = false;
  d_thread = std::thread([this]() { refreshLoop(); });
}

void pdns::RecResolve::Refresher::trigger()
{
  stop = true;
  wakeup = true;
  condVar.notify_one();
}
