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
#include <string>
#include <thread>
#include <vector>

#include "iputils.hh"
#include "lock.hh"
#include "logr.hh"
#include "dnsrecords.hh"
#include "rust/lib.rs.h"

class DNSName;
class SOARecordContent;
struct FWCatalogZone;

// All members of this struct must be copyable, as they are used as parameters in a thread constructor
struct ZoneXFRParams
{
  std::string name;
  std::vector<std::string> primaries;
  ComboAddress localAddress;
  std::shared_ptr<const SOARecordContent> soaRecordContent;
  TSIGTriplet tsigtriplet;
  size_t maxReceivedMBytes{0};
  size_t zoneSizeHint{0};
  size_t zoneIdx{0};
  uint32_t refreshFromConf{0};
  uint16_t xfrTimeout{20};
};

class CatalogZone
{
public:
  void setRefresh(uint32_t refresh)
  {
    d_refresh = refresh;
  }
  [[nodiscard]] auto getRefresh() const
  {
    return d_refresh;
  }
  void setSerial(uint32_t serial)
  {
    d_serial = serial;
  }
  void setName(const DNSName& name)
  {
    d_name = name;
  }
  [[nodiscard]] const DNSName& getName() const
  {
    return d_name;
  }
  void clear()
  {
    d_records.clear();
  }
  void add(const DNSRecord& record, Logr::log_t logger);
  void remove(const DNSRecord& record, Logr::log_t logger);
  void registerForwarders(const FWCatalogZone& params, Logr::log_t logger) const;
  [[nodiscard]] bool versionCheck() const;
  [[nodiscard]] bool dupsCheck() const;

private:
  std::multimap<std::pair<DNSName, QType>, DNSRecord> d_records;
  DNSName d_name;
  uint32_t d_refresh{0};
  uint32_t d_serial{0};
};

struct FWCatalogZone
{
  ZoneXFRParams d_params;
  std::map<std::string, pdns::rust::settings::rec::FCZDefault> d_defaults;
  std::shared_ptr<CatalogZone> d_catz;
};

class ZoneXFR
{
public:
  // A struct that holds the condition var and related stuff to allow notifies to be sent to the thread owning
  // the struct.
  struct ZoneWaiter
  {
    ZoneWaiter(std::thread::id arg) :
      id(arg) {}
    std::thread::id id;
    std::mutex mutex;
    std::condition_variable condVar;
    std::atomic<bool> stop{false};
  };

  static bool notifyZoneTracker(const DNSName& name);
  static void insertZoneTracker(const DNSName& zoneName, ZoneWaiter& waiter);
  static void clearZoneTracker(const DNSName& zoneName);

  // coverity[pass_by_value] clang-tidy and coverity do not agree here
  ZoneXFR(ZoneXFRParams params) :
    d_params(std::move(params))
  {}

  ZoneXFRParams d_params;

  // As there can be multiple threads doing updates (due to config reloads), we use a multimap.
  // The value contains the actual thread id that owns the struct.
  static LockGuarded<std::multimap<DNSName, ZoneXFR::ZoneWaiter&>> condVars;
};

class FWCatZoneXFR : ZoneXFR
{
public:
  // coverity[pass_by_value] clang-tidy and coverity do not agree here
  FWCatZoneXFR(ZoneXFRParams params) :
    ZoneXFR(std::move(params))
  {}

  static void zoneXFRTracker(ZoneXFRParams params, uint64_t configGeneration);

private:
  void preloadZoneFile(const DNSName& zoneName, const std::shared_ptr<const CatalogZone>& oldZone, uint32_t& refresh, uint64_t configGeneration, ZoneWaiter& waiter, Logr::log_t logger);
  bool zoneTrackerIteration(const DNSName& zoneName, std::shared_ptr<const CatalogZone>& oldZone, uint32_t& refresh, bool& skipRefreshDelay, uint64_t configGeneration, ZoneWaiter& waiter, Logr::log_t logger);
};

std::string reloadZoneConfiguration(bool yaml);
