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
#include <set>

#include "sholder.hh"
#include "sortlist.hh"
#include "filterpo.hh"
#include "validate.hh"
#include "rec-zonetocache.hh"
#include "logging.hh"
#include "fstrm_logger.hh"

struct ProtobufExportConfig
{
  std::set<uint16_t> exportTypes = {QType::A, QType::AAAA, QType::CNAME};
  std::vector<ComboAddress> servers;
  uint64_t maxQueuedEntries{100};
  uint16_t timeout{2};
  uint16_t reconnectWaitTime{1};
  bool asyncConnect{false};
  bool enabled{false};
  bool logQueries{true};
  bool logResponses{true};
  bool taggedOnly{false};
  bool logMappedFrom{false};
};

bool operator==(const ProtobufExportConfig& configA, const ProtobufExportConfig& configB);
bool operator!=(const ProtobufExportConfig& configA, const ProtobufExportConfig& configB);

struct FrameStreamExportConfig
{
  std::vector<string> servers;
  bool enabled{false};
  bool logQueries{true};
  bool logResponses{true};
  bool logNODs{true};
  bool logUDRs{false};
  unsigned bufferHint{0};
  unsigned flushTimeout{0};
  unsigned inputQueueSize{0};
  unsigned outputQueueSize{0};
  unsigned queueNotifyThreshold{0};
  unsigned reopenInterval{0};
};

bool operator==(const FrameStreamExportConfig& configA, const FrameStreamExportConfig& configB);
bool operator!=(const FrameStreamExportConfig& configA, const FrameStreamExportConfig& configB);

struct TrustAnchorFileInfo
{
  uint32_t interval{24};
  std::string fname;
};

enum class AdditionalMode : uint8_t
{
  Ignore,
  CacheOnly,
  CacheOnlyRequireAuth,
  ResolveImmediately,
  ResolveDeferred
};

struct ProxyMappingCounts
{
  uint64_t netmaskMatches{};
  uint64_t suffixMatches{};
};

struct ProxyByTableValue
{
  ComboAddress address;
  boost::optional<SuffixMatchNode> suffixMatchNode;
  mutable ProxyMappingCounts stats{};
};

using ProxyMapping = NetmaskTree<ProxyByTableValue, Netmask>;

class LuaConfigItems
{
public:
  LuaConfigItems();
  SortList sortlist;
  DNSFilterEngine dfe;
  TrustAnchorFileInfo trustAnchorFileInfo; // Used to update the Trust Anchors from file periodically
  map<DNSName, dsmap_t> dsAnchors;
  map<DNSName, std::string> negAnchors;
  map<DNSName, RecZoneToCache::Config> ztcConfigs;
  std::map<QType, std::pair<std::set<QType>, AdditionalMode>> allowAdditionalQTypes;
  ProtobufExportConfig protobufExportConfig;
  ProtobufExportConfig outgoingProtobufExportConfig;
  FrameStreamExportConfig frameStreamExportConfig;
  FrameStreamExportConfig nodFrameStreamExportConfig;
  std::shared_ptr<Logr::Logger> d_slog;
  /* we need to increment this every time the configuration
     is reloaded, so we know if we need to reload the protobuf
     remote loggers */
  uint64_t generation{0};
  uint8_t protobufMaskV4{32};
  uint8_t protobufMaskV6{128};
};

extern GlobalStateHolder<LuaConfigItems> g_luaconfs;

struct luaConfigDelayedThreads
{
  // Please make sure that the tuple below only contains value types since they are used as parameters in a thread ct
  std::vector<std::tuple<std::vector<ComboAddress>, boost::optional<DNSFilterEngine::Policy>, bool, uint32_t, size_t, TSIGTriplet, size_t, ComboAddress, uint16_t, uint32_t, std::shared_ptr<const SOARecordContent>, std::string>> rpzPrimaryThreads;
};

void loadRecursorLuaConfig(const std::string& fname, luaConfigDelayedThreads& delayedThreads, ProxyMapping&);
void startLuaConfigDelayedThreads(const luaConfigDelayedThreads& delayedThreads, uint64_t generation);
