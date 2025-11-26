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

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_set>

struct DNSQuestion;
struct DNSResponse;

#include "dnsdist-actions.hh"
#include "dnsdist-protobuf.hh"
#include "dnsdist-svc.hh"
#include "dnstap.hh"
#include "iputils.hh"
#include "noinitvector.hh"

struct dnsdist_ffi_dnsquestion_t;
struct dnsdist_ffi_dnsresponse_t;
class RemoteLoggerInterface;
class KeyValueStore;
class KeyValueLookupKey;

namespace dnsdist::actions
{
using LuaActionFunction = std::function<std::tuple<int, std::optional<string>>(DNSQuestion* dnsquestion)>;
using LuaResponseActionFunction = std::function<std::tuple<int, std::optional<string>>(DNSResponse* response)>;
using LuaActionFFIFunction = std::function<int(dnsdist_ffi_dnsquestion_t* dnsquestion)>;
using LuaResponseActionFFIFunction = std::function<int(dnsdist_ffi_dnsresponse_t* dnsquestion)>;

struct SOAParams
{
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minimum;
};

#include "dnsdist-actions-factory-generated.hh"
#include "dnsdist-response-actions-factory-generated.hh"

std::shared_ptr<DNSAction> getLuaAction(dnsdist::actions::LuaActionFunction function);
std::shared_ptr<DNSAction> getLuaFFIAction(dnsdist::actions::LuaActionFFIFunction function);
std::shared_ptr<DNSResponseAction> getLuaResponseAction(dnsdist::actions::LuaResponseActionFunction function);
std::shared_ptr<DNSResponseAction> getLuaFFIResponseAction(dnsdist::actions::LuaResponseActionFFIFunction function);

std::shared_ptr<DNSAction> getContinueAction(std::shared_ptr<DNSAction> action);
std::shared_ptr<DNSAction> getHTTPStatusAction(uint16_t status, PacketBuffer&& body, const std::string& contentType, const dnsdist::ResponseConfig& responseConfig);
std::shared_ptr<DNSAction> getNegativeAndSOAAction(bool nxd, const DNSName& zone, uint32_t ttl, const DNSName& mname, const DNSName& rname, const SOAParams& params, bool soaInAuthority, dnsdist::ResponseConfig responseConfig);
std::shared_ptr<DNSAction> getSetProxyProtocolValuesAction(const std::vector<std::pair<uint8_t, std::string>>& values);
std::shared_ptr<DNSAction> getRCodeAction(uint8_t rcode, const dnsdist::ResponseConfig& responseConfig);
std::shared_ptr<DNSAction> getERCodeAction(uint8_t rcode, const dnsdist::ResponseConfig& responseConfig);

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
std::shared_ptr<DNSAction> getKeyValueStoreLookupAction(std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag);
std::shared_ptr<DNSAction> getKeyValueStoreRangeLookupAction(std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag);
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */

std::shared_ptr<DNSAction> getSetECSAction(const std::string& ipv4);
std::shared_ptr<DNSAction> getSetECSAction(const std::string& ipv4, const std::string& ipv6);
std::shared_ptr<DNSAction> getSpoofAction(const std::vector<ComboAddress>& addresses, const dnsdist::ResponseConfig& config);
std::shared_ptr<DNSAction> getSpoofAction(const std::vector<std::string>& rawRDatas, std::optional<uint16_t> qtypeForAny, const dnsdist::ResponseConfig& config);
std::shared_ptr<DNSAction> getSpoofAction(const DNSName& cname, const dnsdist::ResponseConfig& config);
std::shared_ptr<DNSAction> getSpoofAction(const PacketBuffer& packet);

std::shared_ptr<DNSAction> getSpoofSVCAction(const std::vector<SVCRecordParameters>& parameters, const dnsdist::ResponseConfig& responseConfig);

std::shared_ptr<DNSAction> getSetMaxReturnedTTLAction(uint32_t max);
std::shared_ptr<DNSResponseAction> getLimitTTLResponseAction(uint32_t min, uint32_t max = std::numeric_limits<uint32_t>::max(), std::unordered_set<QType> types = {});
std::shared_ptr<DNSResponseAction> getMinTTLResponseAction(uint32_t min);
std::shared_ptr<DNSResponseAction> getSetMaxReturnedTTLResponseAction(uint32_t max);
std::shared_ptr<DNSResponseAction> getSetMaxTTLResponseAction(uint32_t max);

std::shared_ptr<DNSResponseAction> getClearRecordTypesResponseAction(std::unordered_set<QType> types);

std::shared_ptr<DNSAction> getTeeAction(const ComboAddress& rca, std::optional<ComboAddress> lca, bool addECS, bool addProxyProtocol);

#ifndef DISABLE_PROTOBUF
using ProtobufAlterFunction = std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)>;
using ProtobufAlterResponseFunction = std::function<void(DNSResponse*, DNSDistProtoBufMessage*)>;
using DnstapAlterFunction = std::function<void(DNSQuestion*, DnstapMessage*)>;
using DnstapAlterResponseFunction = std::function<void(DNSResponse*, DnstapMessage*)>;

struct RemoteLogActionConfiguration
{
  std::vector<std::pair<std::string, ProtoBufMetaKey>> metas;
  std::optional<std::unordered_set<std::string>> tagsToExport{std::nullopt};
  std::optional<ProtobufAlterFunction> alterQueryFunc;
  std::optional<ProtobufAlterResponseFunction> alterResponseFunc;
  std::shared_ptr<RemoteLoggerInterface> logger;
  std::string serverID;
  std::string ipEncryptKey;
  std::string ipEncryptMethod{"legacy"};
  std::optional<std::string> exportExtendedErrorsToMeta{std::nullopt};
  bool includeCNAME{false};
  bool delay{false};
};
std::shared_ptr<DNSAction> getRemoteLogAction(RemoteLogActionConfiguration& config);
std::shared_ptr<DNSResponseAction> getRemoteLogResponseAction(RemoteLogActionConfiguration& config);
std::shared_ptr<DNSAction> getDnstapLogAction(const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, std::optional<DnstapAlterFunction> alterFunc);
std::shared_ptr<DNSResponseAction> getDnstapLogResponseAction(const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, std::optional<DnstapAlterResponseFunction> alterFunc);

struct SetTraceActionConfiguration
{
  bool value = false;
  std::vector<std::shared_ptr<RemoteLoggerInterface>> remote_loggers;
  bool use_incoming_traceid = false;
  std::uint16_t trace_edns_option = 0;
};
std::shared_ptr<DNSAction> getSetTraceAction(SetTraceActionConfiguration& config);
#endif /* DISABLE_PROTOBUF */
}
