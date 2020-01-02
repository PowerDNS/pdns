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

#include "dnsdist-lua-ffi.hh"
#include "dnsdist-ecs.hh"

uint16_t dnsdist_ffi_dnsquestion_get_qtype(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->qtype;
}

uint16_t dnsdist_ffi_dnsquestion_get_qclass(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->qclass;
}

static void dnsdist_ffi_comboaddress_to_raw(const ComboAddress& ca, const void** addr, size_t* addrSize)
{
  if (ca.isIPv4()) {
    *addr = &ca.sin4.sin_addr.s_addr;
    *addrSize = sizeof(ca.sin4.sin_addr.s_addr);
  }
  else {
    *addr = &ca.sin6.sin6_addr.s6_addr;
    *addrSize = sizeof(ca.sin6.sin6_addr.s6_addr);
  }
}

void dnsdist_ffi_dnsquestion_get_localaddr(const dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize)
{
  dnsdist_ffi_comboaddress_to_raw(*dq->dq->local, addr, addrSize);
}

void dnsdist_ffi_dnsquestion_get_remoteaddr(const dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize)
{
  dnsdist_ffi_comboaddress_to_raw(*dq->dq->remote, addr, addrSize);
}

uint16_t dnsdist_ffi_dnsquestion_get_local_port(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->local->getPort();
}

uint16_t dnsdist_ffi_dnsquestion_get_remote_port(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->remote->getPort();
}

void dnsdist_ffi_dnsquestion_get_qname_raw(const dnsdist_ffi_dnsquestion_t* dq, const char** qname, size_t* qnameSize)
{
  const auto& storage = dq->dq->qname->getStorage();
  *qname = storage.data();
  *qnameSize = storage.size();
}

size_t dnsdist_ffi_dnsquestion_get_qname_hash(const dnsdist_ffi_dnsquestion_t* dq, size_t init)
{
  return dq->dq->qname->hash(init);
}

int dnsdist_ffi_dnsquestion_get_rcode(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->dh->rcode;
}

void* dnsdist_ffi_dnsquestion_get_header(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->dh;
}

uint16_t dnsdist_ffi_dnsquestion_get_len(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->len;
}

size_t dnsdist_ffi_dnsquestion_get_size(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->size;
}

uint8_t dnsdist_ffi_dnsquestion_get_opcode(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->dh->opcode;
}

bool dnsdist_ffi_dnsquestion_get_tcp(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->tcp;
}

bool dnsdist_ffi_dnsquestion_get_skip_cache(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->skipCache;
}

bool dnsdist_ffi_dnsquestion_get_use_ecs(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->useECS;
}

bool dnsdist_ffi_dnsquestion_get_add_xpf(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->addXPF;
}

bool dnsdist_ffi_dnsquestion_get_ecs_override(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ecsOverride;
}

uint16_t dnsdist_ffi_dnsquestion_get_ecs_prefix_length(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ecsPrefixLength;
}

bool dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->tempFailureTTL != boost::none;
}

uint32_t dnsdist_ffi_dnsquestion_get_temp_failure_ttl(const dnsdist_ffi_dnsquestion_t* dq)
{
  if (dq->dq->tempFailureTTL) {
    return *dq->dq->tempFailureTTL;
  }
  return 0;
}

bool dnsdist_ffi_dnsquestion_get_do(const dnsdist_ffi_dnsquestion_t* dq)
{
  return getEDNSZ(*dq->dq) & EDNS_HEADER_FLAG_DO;
}

void dnsdist_ffi_dnsquestion_get_sni(const dnsdist_ffi_dnsquestion_t* dq, const char** sni, size_t* sniSize)
{
  *sniSize = dq->dq->sni.size();
  *sni = dq->dq->sni.c_str();
}

const char* dnsdist_ffi_dnsquestion_get_tag(const dnsdist_ffi_dnsquestion_t* dq, const char* label)
{
  const char * result = nullptr;

  if (dq->dq->qTag != nullptr) {
    const auto it = dq->dq->qTag->find(label);
    if (it != dq->dq->qTag->cend()) {
      result = it->second.c_str();
    }
  }

  return result;
}

const char* dnsdist_ffi_dnsquestion_get_http_path(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpPath) {
    if (dq->dq->du == nullptr) {
      return nullptr;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    dq->httpPath = dq->dq->du->getHTTPPath();
#endif /* HAVE_DNS_OVER_HTTPS */
  }
  if (dq->httpPath) {
    return dq->httpPath->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_query_string(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpQueryString) {
    if (dq->dq->du == nullptr) {
      return nullptr;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    dq->httpQueryString = dq->dq->du->getHTTPQueryString();
#endif /* HAVE_DNS_OVER_HTTPS */
  }
  if (dq->httpQueryString) {
    return dq->httpQueryString->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_host(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpHost) {
    if (dq->dq->du == nullptr) {
      return nullptr;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    dq->httpHost = dq->dq->du->getHTTPHost();
#endif /* HAVE_DNS_OVER_HTTPS */
  }
  if (dq->httpHost) {
    return dq->httpHost->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_scheme(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpScheme) {
    if (dq->dq->du == nullptr) {
      return nullptr;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    dq->httpScheme = dq->dq->du->getHTTPScheme();
#endif /* HAVE_DNS_OVER_HTTPS */
  }
  if (dq->httpScheme) {
    return dq->httpScheme->c_str();
  }
  return nullptr;
}

static void fill_edns_option(const EDNSOptionViewValue& value, dnsdist_ednsoption_t& option)
{
  option.len = value.size;
  option.data = nullptr;

  if (value.size > 0) {
    option.data = value.content;
  }
}

// returns the length of the resulting 'out' array. 'out' is not set if the length is 0
size_t dnsdist_ffi_dnsquestion_get_edns_options(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_ednsoption_t** out)
{
  if (dq->dq->ednsOptions == nullptr) {
    parseEDNSOptions(*(dq->dq));
  }

  size_t totalCount = 0;
  for (const auto& option : *dq->dq->ednsOptions) {
    totalCount += option.second.values.size();
  }

  dq->ednsOptionsVect.clear();
  dq->ednsOptionsVect.resize(totalCount);
  size_t pos = 0;
  for (const auto& option : *dq->dq->ednsOptions) {
    for (const auto& entry : option.second.values) {
      fill_edns_option(entry, dq->ednsOptionsVect.at(pos));
      dq->ednsOptionsVect.at(pos).optionCode = option.first;
      pos++;
    }
  }

  if (totalCount > 0) {
    *out = dq->ednsOptionsVect.data();
  }

  return totalCount;
}

size_t dnsdist_ffi_dnsquestion_get_http_headers(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_http_header_t** out)
{
  if (dq->dq->du == nullptr) {
    return 0;
  }

#ifdef HAVE_DNS_OVER_HTTPS
  dq->httpHeaders = dq->dq->du->getHTTPHeaders();
  dq->httpHeadersVect.clear();
  dq->httpHeadersVect.resize(dq->httpHeaders.size());
  size_t pos = 0;
  for (const auto& header : dq->httpHeaders) {
    dq->httpHeadersVect.at(pos).name = header.first.c_str();
    dq->httpHeadersVect.at(pos).value = header.second.c_str();
    ++pos;
  }

  if (!dq->httpHeadersVect.empty()) {
    *out = dq->httpHeadersVect.data();
  }

  return dq->httpHeadersVect.size();
#else
  return 0;
#endif
}

size_t dnsdist_ffi_dnsquestion_get_tag_array(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_tag_t** out)
{
  if (dq->dq->qTag == nullptr || dq->dq->qTag->size() == 0) {
    return 0;
  }

  dq->tagsVect.clear();
  dq->tagsVect.resize(dq->dq->qTag->size());
  size_t pos = 0;

  for (const auto& tag : *dq->dq->qTag) {
    auto& entry = dq->tagsVect.at(pos);
    entry.name = tag.first.c_str();
    entry.value = tag.second.c_str();
    ++pos;
  }


  if (!dq->tagsVect.empty()) {
    *out = dq->tagsVect.data();
  }

  return dq->tagsVect.size();
}

void dnsdist_ffi_dnsquestion_set_result(dnsdist_ffi_dnsquestion_t* dq, const char* str, size_t strSize)
{
  dq->result = std::string(str, strSize);
}

void dnsdist_ffi_dnsquestion_set_http_response(dnsdist_ffi_dnsquestion_t* dq, uint16_t statusCode, const char* body, const char* contentType)
{
  if (dq->dq->du == nullptr) {
    return;
  }

#ifdef HAVE_DNS_OVER_HTTPS
  dq->dq->du->setHTTPResponse(statusCode, body, contentType);
  dq->dq->dh->qr = true;
#endif
}

void dnsdist_ffi_dnsquestion_set_rcode(dnsdist_ffi_dnsquestion_t* dq, int rcode)
{
  dq->dq->dh->rcode = rcode;
  dq->dq->dh->qr = true;
}

void dnsdist_ffi_dnsquestion_set_len(dnsdist_ffi_dnsquestion_t* dq, uint16_t len)
{
  dq->dq->len = len;
}

void dnsdist_ffi_dnsquestion_set_skip_cache(dnsdist_ffi_dnsquestion_t* dq, bool skipCache)
{
  dq->dq->skipCache = skipCache;
}

void dnsdist_ffi_dnsquestion_set_use_ecs(dnsdist_ffi_dnsquestion_t* dq, bool useECS)
{
  dq->dq->useECS = useECS;
}

void dnsdist_ffi_dnsquestion_set_ecs_override(dnsdist_ffi_dnsquestion_t* dq, bool ecsOverride)
{
  dq->dq->ecsOverride = ecsOverride;
}

void dnsdist_ffi_dnsquestion_set_ecs_prefix_length(dnsdist_ffi_dnsquestion_t* dq, uint16_t ecsPrefixLength)
{
  dq->dq->ecsPrefixLength = ecsPrefixLength;
}

void dnsdist_ffi_dnsquestion_set_temp_failure_ttl(dnsdist_ffi_dnsquestion_t* dq, uint32_t tempFailureTTL)
{
  dq->dq->tempFailureTTL = tempFailureTTL;
}

void dnsdist_ffi_dnsquestion_unset_temp_failure_ttl(dnsdist_ffi_dnsquestion_t* dq)
{
  dq->dq->tempFailureTTL = boost::none;
}

void dnsdist_ffi_dnsquestion_set_tag(dnsdist_ffi_dnsquestion_t* dq, const char* label, const char* value)
{
  if (!dq->dq->qTag) {
    dq->dq->qTag = std::make_shared<QTag>();
  }

  dq->dq->qTag->insert({label, value});
}

size_t dnsdist_ffi_dnsquestion_get_trailing_data(dnsdist_ffi_dnsquestion_t* dq, const char** out)
{
  dq->trailingData = dq->dq->getTrailingData();
  if (!dq->trailingData.empty()) {
    *out = dq->trailingData.data();
  }

  return dq->trailingData.size();
}

bool dnsdist_ffi_dnsquestion_set_trailing_data(dnsdist_ffi_dnsquestion_t* dq, const char* data, size_t dataLen)
{
  return dq->dq->setTrailingData(std::string(data, dataLen));
}

void dnsdist_ffi_dnsquestion_send_trap(dnsdist_ffi_dnsquestion_t* dq, const char* reason, size_t reasonLen)
{
  if (g_snmpAgent && g_snmpTrapsEnabled) {
    g_snmpAgent->sendDNSTrap(*dq->dq, std::string(reason, reasonLen));
  }
}

size_t dnsdist_ffi_servers_list_get_count(const dnsdist_ffi_servers_list_t* list)
{
  return list->ffiServers.size();
}

void dnsdist_ffi_servers_list_get_server(const dnsdist_ffi_servers_list_t* list, size_t idx, const dnsdist_ffi_server_t** out)
{
  *out = &list->ffiServers.at(idx);
}

static size_t dnsdist_ffi_servers_get_index_from_server(const ServerPolicy::NumberedServerVector& servers, const std::shared_ptr<DownstreamState>& server)
{
  for (const auto& pair : servers) {
    if (pair.second == server) {
      return pair.first - 1;
    }
  }
  throw std::runtime_error("Unable to find servers in server list");
}

size_t dnsdist_ffi_servers_list_chashed(const dnsdist_ffi_servers_list_t* list, const dnsdist_ffi_dnsquestion_t* dq, size_t hash)
{
  auto server = chashedFromHash(list->servers, hash);
  return dnsdist_ffi_servers_get_index_from_server(list->servers, server);
}

size_t dnsdist_ffi_servers_list_whashed(const dnsdist_ffi_servers_list_t* list, const dnsdist_ffi_dnsquestion_t* dq, size_t hash)
{
  auto server = whashedFromHash(list->servers, hash);
  return dnsdist_ffi_servers_get_index_from_server(list->servers, server);
}

uint64_t dnsdist_ffi_server_get_outstanding(const dnsdist_ffi_server_t* server)
{
  return server->server->outstanding;
}

int dnsdist_ffi_server_get_weight(const dnsdist_ffi_server_t* server)
{
  return server->server->weight;
}

int dnsdist_ffi_server_get_order(const dnsdist_ffi_server_t* server)
{
  return server->server->order;
}

bool dnsdist_ffi_server_is_up(const dnsdist_ffi_server_t* server)
{
  return server->server->isUp();
}

const char* dnsdist_ffi_server_get_name(const dnsdist_ffi_server_t* server)
{
  return server->server->getName().c_str();
}

const char* dnsdist_ffi_server_get_name_with_addr(const dnsdist_ffi_server_t* server)
{
  return server->server->getNameWithAddr().c_str();
}

const std::string& getLuaFFIWrappers()
{
  static const std::string interface =
#include "dnsdist-lua-ffi-interface.inc"
    ;
  static const std::string code = R"FFICodeContent(
  local ffi = require("ffi")
  local C = ffi.C

  ffi.cdef[[
)FFICodeContent" + interface + R"FFICodeContent(
  ]]

)FFICodeContent";
  return code;
}
