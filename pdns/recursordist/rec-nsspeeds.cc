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

#include <protozero/pbf_builder.hpp>
#include <protozero/pbf_message.hpp>
#include "protozero-helpers.hh"

#include "logging.hh"
#include "version.hh"

#include "rec-nsspeeds.hh"

enum class PBNSSpeedDump : protozero::pbf_tag_type
{
  required_string_version = 1,
  required_string_identity = 2,
  required_uint64_protocolVersion = 3,
  required_int64_time = 4,
  required_string_type = 5,
  repeated_message_nsspeedEntry = 6,
};

enum class PBNSSpeedEntry : protozero::pbf_tag_type
{
  required_bytes_name = 1,
  required_int64_lastgets = 2,
  required_int64_lastgetus = 3,
  repeated_message_map = 4,
};

enum class PBNSSpeedMap : protozero::pbf_tag_type
{
  required_bytes_address = 1,
  required_float_val = 2,
  required_int32_last = 3,
};

template <typename T, typename U>
void nsspeeds_t::getPBEntry(T& message, U& entry)
{
  if (!entry.d_name.empty()) {
    message.add_bytes(PBNSSpeedEntry::required_bytes_name, entry.d_name.toString());
  }
  message.add_int64(PBNSSpeedEntry::required_int64_lastgets, entry.d_lastget.tv_sec);
  message.add_int64(PBNSSpeedEntry::required_int64_lastgetus, entry.d_lastget.tv_usec);
  for (const auto& [address, collection] : entry.d_collection) {
    protozero::pbf_builder<PBNSSpeedMap> map(message, PBNSSpeedEntry::repeated_message_map);
    encodeComboAddress(map, PBNSSpeedMap::required_bytes_address, address);
    map.add_float(PBNSSpeedMap::required_float_val, collection.d_val);
    map.add_int32(PBNSSpeedMap::required_int32_last, collection.d_last);
  }
}

size_t nsspeeds_t::getPB(const string& serverID, size_t maxSize, std::string& ret) const
{
  auto log = g_slog->withName("syncres")->withValues("maxSize", Logging::Loggable(maxSize));
  log->info(Logr::Info, "Producing nsspeed dump");

  // A observed average record size is 60;
  size_t estimate = maxSize == 0 ? size() * 60 : maxSize + 4096; // We may overshoot (will be rolled back)

  protozero::pbf_builder<PBNSSpeedDump> full(ret);
  full.add_string(PBNSSpeedDump::required_string_version, getPDNSVersion());
  full.add_string(PBNSSpeedDump::required_string_identity, serverID);
  full.add_uint64(PBNSSpeedDump::required_uint64_protocolVersion, 1);
  full.add_int64(PBNSSpeedDump::required_int64_time, time(nullptr));
  full.add_string(PBNSSpeedDump::required_string_type, "PBNSSpeedDump");

  size_t theCount = 0;
  ret.reserve(estimate);

  for (const auto& entry : *this) {
    protozero::pbf_builder<PBNSSpeedEntry> message(full, PBNSSpeedDump::repeated_message_nsspeedEntry);
    getPBEntry(message, entry);
    if (maxSize > 0 && ret.size() > maxSize) {
      message.rollback();
      log->info(Logr::Info, "Produced nsspeed dump (max size reached)", "size", Logging::Loggable(ret.size()), "count", Logging::Loggable(theCount));
      return theCount;
    }
    ++theCount;
  }
  log->info(Logr::Info, "Produced nsspeed dump", "size", Logging::Loggable(ret.size()), "count", Logging::Loggable(theCount));
  return theCount;
}

template <typename T>
bool nsspeeds_t::putPBEntry(time_t cutoff, T& message)
{
  DecayingEwmaCollection entry{{}};
  while (message.next()) {
    switch (message.tag()) {
    case PBNSSpeedEntry::required_bytes_name:
      entry.d_name = DNSName(message.get_bytes());
      break;
    case PBNSSpeedEntry::required_int64_lastgets:
      entry.d_lastget.tv_sec = message.get_int64();
      break;
    case PBNSSpeedEntry::required_int64_lastgetus:
      entry.d_lastget.tv_usec = message.get_int64();
      break;
    case PBNSSpeedEntry::repeated_message_map: {
      protozero::pbf_message<PBNSSpeedMap> map = message.get_message();
      ComboAddress address;
      float val{};
      int last{};
      while (map.next()) {
        switch (map.tag()) {
        case PBNSSpeedMap::required_bytes_address:
          decodeComboAddress(map, address);
          break;
        case PBNSSpeedMap::required_float_val:
          val = map.get_float();
          break;
        case PBNSSpeedMap::required_int32_last:
          last = map.get_int32();
          break;
        }
      }
      entry.insert(address, val, last);
      break;
    }
    }
  }
  if (!entry.stale(cutoff)) {
    return insert(std::move(entry)).second;
  }
  return false;
}

size_t nsspeeds_t::putPB(time_t cutoff, const std::string& pbuf)
{
  auto log = g_slog->withName("syncres")->withValues("size", Logging::Loggable(pbuf.size()));
  log->info(Logr::Debug, "Processing nsspeed dump");

  protozero::pbf_message<PBNSSpeedDump> full(pbuf);
  size_t theCount = 0;
  size_t inserted = 0;
  try {
    bool protocolVersionSeen = false;
    bool typeSeen = false;
    while (full.next()) {
      switch (full.tag()) {
      case PBNSSpeedDump::required_string_version: {
        auto version = full.get_string();
        log = log->withValues("version", Logging::Loggable(version));
        break;
      }
      case PBNSSpeedDump::required_string_identity: {
        auto identity = full.get_string();
        log = log->withValues("identity", Logging::Loggable(identity));
        break;
      }
      case PBNSSpeedDump::required_uint64_protocolVersion: {
        auto protocolVersion = full.get_uint64();
        log = log->withValues("protocolVersion", Logging::Loggable(protocolVersion));
        if (protocolVersion != 1) {
          throw std::runtime_error("Protocol version mismatch");
        }
        protocolVersionSeen = true;
        break;
      }
      case PBNSSpeedDump::required_int64_time: {
        auto time = full.get_int64();
        log = log->withValues("time", Logging::Loggable(time));
        break;
      }
      case PBNSSpeedDump::required_string_type: {
        auto type = full.get_string();
        if (type != "PBNSSpeedDump") {
          throw std::runtime_error("Data type mismatch");
        }
        typeSeen = true;
        break;
      }
      case PBNSSpeedDump::repeated_message_nsspeedEntry: {
        if (!protocolVersionSeen || !typeSeen) {
          throw std::runtime_error("Required field missing");
        }
        protozero::pbf_message<PBNSSpeedEntry> message = full.get_message();
        if (putPBEntry(cutoff, message)) {
          ++inserted;
        }
        ++theCount;
        break;
      }
      }
    }
    log->info(Logr::Info, "Processed nsspeed dump", "processed", Logging::Loggable(theCount), "inserted", Logging::Loggable(inserted));
    return inserted;
  }
  catch (const std::runtime_error& e) {
    log->error(Logr::Error, e.what(), "Runtime exception processing cache dump");
  }
  catch (const std::exception& e) {
    log->error(Logr::Error, e.what(), "Exception processing cache dump");
  }
  catch (...) {
    log->error(Logr::Error, "Other exception processing cache dump");
  }
  return 0;
}
