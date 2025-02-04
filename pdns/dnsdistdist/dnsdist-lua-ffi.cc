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

#include "dnsdist-async.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-mac-address.hh"
#include "dnsdist-metrics.hh"
#include "dnsdist-lua-network.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-self-answers.hh"
#include "dnsdist-svc.hh"
#include "dnsdist-snmp.hh"
#include "dolog.hh"

uint16_t dnsdist_ffi_dnsquestion_get_qtype(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ids.qtype;
}

uint16_t dnsdist_ffi_dnsquestion_get_qclass(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ids.qclass;
}

uint16_t dnsdist_ffi_dnsquestion_get_id(const dnsdist_ffi_dnsquestion_t* dq)
{
  if (dq == nullptr) {
    return 0;
  }
  return ntohs(dq->dq->getHeader()->id);
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
  dnsdist_ffi_comboaddress_to_raw(dq->dq->ids.origDest, addr, addrSize);
}

bool dnsdist_ffi_dnsquestion_is_remote_v6(const dnsdist_ffi_dnsquestion_t* dnsQuestion)
{
  if (dnsQuestion == nullptr || dnsQuestion->dq == nullptr) {
    return false;
  }

  return dnsQuestion->dq->ids.origRemote.isIPv6();
}

void dnsdist_ffi_dnsquestion_get_remoteaddr(const dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize)
{
  dnsdist_ffi_comboaddress_to_raw(dq->dq->ids.origRemote, addr, addrSize);
}

size_t dnsdist_ffi_dnsquestion_get_mac_addr(const dnsdist_ffi_dnsquestion_t* dq, void* buffer, size_t bufferSize)
{
  if (dq == nullptr) {
    return 0;
  }
  auto ret = dnsdist::MacAddressesCache::get(dq->dq->ids.origRemote, reinterpret_cast<unsigned char*>(buffer), bufferSize);
  if (ret != 0) {
    return 0;
  }

  return 6;
}

uint64_t dnsdist_ffi_dnsquestion_get_elapsed_us(const dnsdist_ffi_dnsquestion_t* dq)
{
  if (dq == nullptr) {
    return 0;
  }

  return static_cast<uint64_t>(std::round(dq->dq->ids.queryRealTime.udiff()));
}

void dnsdist_ffi_dnsquestion_get_masked_remoteaddr(dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize, uint8_t bits)
{
  dq->maskedRemote = Netmask(dq->dq->ids.origRemote, bits).getMaskedNetwork();
  dnsdist_ffi_comboaddress_to_raw(dq->maskedRemote, addr, addrSize);
}

uint16_t dnsdist_ffi_dnsquestion_get_local_port(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ids.origDest.getPort();
}

uint16_t dnsdist_ffi_dnsquestion_get_remote_port(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ids.origRemote.getPort();
}

void dnsdist_ffi_dnsquestion_get_qname_raw(const dnsdist_ffi_dnsquestion_t* dq, const char** qname, size_t* qnameSize)
{
  const auto& storage = dq->dq->ids.qname.getStorage();
  *qname = storage.data();
  *qnameSize = storage.size();
}

size_t dnsdist_ffi_dnsquestion_get_qname_hash(const dnsdist_ffi_dnsquestion_t* dq, size_t init)
{
  return dq->dq->ids.qname.hash(init);
}

int dnsdist_ffi_dnsquestion_get_rcode(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->getHeader()->rcode;
}

void* dnsdist_ffi_dnsquestion_get_header(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->getMutableHeader();
}

uint16_t dnsdist_ffi_dnsquestion_get_len(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->getData().size();
}

size_t dnsdist_ffi_dnsquestion_get_size(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->getData().size();
}

bool dnsdist_ffi_dnsquestion_set_size(dnsdist_ffi_dnsquestion_t* dq, size_t newSize)
{
  try {
    dq->dq->getMutableData().resize(newSize);
    return true;
  }
  catch (const std::exception& e) {
    return false;
  }
}

uint8_t dnsdist_ffi_dnsquestion_get_opcode(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->getHeader()->opcode;
}

bool dnsdist_ffi_dnsquestion_get_tcp(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->overTCP();
}

dnsdist_ffi_protocol_type dnsdist_ffi_dnsquestion_get_protocol(const dnsdist_ffi_dnsquestion_t* dq)
{
  if (dq != nullptr) {
    auto proto = dq->dq->getProtocol();
    if (proto == dnsdist::Protocol::DoUDP) {
      return dnsdist_ffi_protocol_type_doudp;
    }
    else if (proto == dnsdist::Protocol::DoTCP) {
      return dnsdist_ffi_protocol_type_dotcp;
    }
    else if (proto == dnsdist::Protocol::DNSCryptUDP) {
      return dnsdist_ffi_protocol_type_dnscryptudp;
    }
    else if (proto == dnsdist::Protocol::DNSCryptTCP) {
      return dnsdist_ffi_protocol_type_dnscrypttcp;
    }
    else if (proto == dnsdist::Protocol::DoT) {
      return dnsdist_ffi_protocol_type_dot;
    }
    else if (proto == dnsdist::Protocol::DoH) {
      return dnsdist_ffi_protocol_type_doh;
    }
  }
  return dnsdist_ffi_protocol_type_doudp;
}

bool dnsdist_ffi_dnsquestion_get_skip_cache(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->ids.skipCache;
}

bool dnsdist_ffi_dnsquestion_get_use_ecs(const dnsdist_ffi_dnsquestion_t* dq)
{
  return dq->dq->useECS;
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
  return dq->dq->ids.tempFailureTTL != boost::none;
}

uint32_t dnsdist_ffi_dnsquestion_get_temp_failure_ttl(const dnsdist_ffi_dnsquestion_t* dq)
{
  if (dq->dq->ids.tempFailureTTL) {
    return *dq->dq->ids.tempFailureTTL;
  }
  return 0;
}

bool dnsdist_ffi_dnsquestion_get_do(const dnsdist_ffi_dnsquestion_t* dnsQuestion)
{
  return (dnsdist::getEDNSZ(*dnsQuestion->dq) & EDNS_HEADER_FLAG_DO) != 0;
}

uint8_t dnsdist_ffi_dnsquestion_get_edns_version(const dnsdist_ffi_dnsquestion_t* dnsQuestion)
{
  auto version = dnsdist::getEDNSVersion(*dnsQuestion->dq);
  return version ? *version : 0U;
}

uint8_t dnsdist_ffi_dnsquestion_get_edns_extended_rcode(const dnsdist_ffi_dnsquestion_t* dnsQuestion)
{
  auto rcode = dnsdist::getEDNSExtendedRCode(*dnsQuestion->dq);
  return rcode ? *rcode : 0U;
}

void dnsdist_ffi_dnsquestion_get_sni(const dnsdist_ffi_dnsquestion_t* dq, const char** sni, size_t* sniSize)
{
  *sniSize = dq->dq->sni.size();
  *sni = dq->dq->sni.c_str();
}

const char* dnsdist_ffi_dnsquestion_get_tag(const dnsdist_ffi_dnsquestion_t* dq, const char* label)
{
  const char* result = nullptr;

  if (dq != nullptr && dq->dq != nullptr && dq->dq->ids.qTag != nullptr) {
    const auto it = dq->dq->ids.qTag->find(label);
    if (it != dq->dq->ids.qTag->cend()) {
      result = it->second.c_str();
    }
  }

  return result;
}

size_t dnsdist_ffi_dnsquestion_get_tag_raw(const dnsdist_ffi_dnsquestion_t* dq, const char* label, char* buffer, size_t bufferSize)
{
  if (dq == nullptr || dq->dq == nullptr || dq->dq->ids.qTag == nullptr || label == nullptr || buffer == nullptr || bufferSize == 0) {
    return 0;
  }

  const auto it = dq->dq->ids.qTag->find(label);
  if (it == dq->dq->ids.qTag->cend()) {
    return 0;
  }

  if (it->second.size() > bufferSize) {
    return 0;
  }

  memcpy(buffer, it->second.c_str(), it->second.size());
  return it->second.size();
}

const char* dnsdist_ffi_dnsquestion_get_http_path(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpPath) {
    if (dq->dq->ids.du) {
#if defined(HAVE_DNS_OVER_HTTPS)
      dq->httpPath = dq->dq->ids.du->getHTTPPath();
#endif /* HAVE_DNS_OVER_HTTPS */
    }
    else if (dq->dq->ids.doh3u) {
#if defined(HAVE_DNS_OVER_HTTP3)
      dq->httpPath = dq->dq->ids.doh3u->getHTTPPath();
#endif /* HAVE_DNS_OVER_HTTP3 */
    }
  }
  if (dq->httpPath) {
    return dq->httpPath->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_query_string(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpQueryString) {
    if (dq->dq->ids.du) {
#ifdef HAVE_DNS_OVER_HTTPS
      dq->httpQueryString = dq->dq->ids.du->getHTTPQueryString();
#endif /* HAVE_DNS_OVER_HTTPS */
    }
    else if (dq->dq->ids.doh3u) {
#if defined(HAVE_DNS_OVER_HTTP3)
      dq->httpQueryString = dq->dq->ids.doh3u->getHTTPQueryString();
#endif /* HAVE_DNS_OVER_HTTP3 */
    }
  }
  if (dq->httpQueryString) {
    return dq->httpQueryString->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_host(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpHost) {
    if (dq->dq->ids.du) {
#ifdef HAVE_DNS_OVER_HTTPS
      dq->httpHost = dq->dq->ids.du->getHTTPHost();
#endif /* HAVE_DNS_OVER_HTTPS */
    }
    else if (dq->dq->ids.doh3u) {
#if defined(HAVE_DNS_OVER_HTTP3)
      dq->httpHost = dq->dq->ids.doh3u->getHTTPHost();
#endif /* HAVE_DNS_OVER_HTTP3 */
    }
  }
  if (dq->httpHost) {
    return dq->httpHost->c_str();
  }
  return nullptr;
}

const char* dnsdist_ffi_dnsquestion_get_http_scheme(dnsdist_ffi_dnsquestion_t* dq)
{
  if (!dq->httpScheme) {
    if (dq->dq->ids.du) {
#ifdef HAVE_DNS_OVER_HTTPS
      dq->httpScheme = dq->dq->ids.du->getHTTPScheme();
#endif /* HAVE_DNS_OVER_HTTPS */
    }
    else if (dq->dq->ids.doh3u) {
#if defined(HAVE_DNS_OVER_HTTP3)
      dq->httpScheme = dq->dq->ids.doh3u->getHTTPScheme();
#endif /* HAVE_DNS_OVER_HTTP3 */
    }
  }
  if (dq->httpScheme) {
    return dq->httpScheme->c_str();
  }
  return nullptr;
}

static void fill_edns_option(const EDNSOptionViewValue& value, dnsdist_ffi_ednsoption_t& option)
{
  option.len = value.size;
  option.data = nullptr;

  if (value.size > 0) {
    option.data = value.content;
  }
}

// returns the length of the resulting 'out' array. 'out' is not set if the length is 0
size_t dnsdist_ffi_dnsquestion_get_edns_options(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_ffi_ednsoption_t** out)
{
  if (dq->dq->ednsOptions == nullptr) {
    parseEDNSOptions(*(dq->dq));

    if (dq->dq->ednsOptions == nullptr) {
      return 0;
    }
  }

  size_t totalCount = 0;
  for (const auto& option : *dq->dq->ednsOptions) {
    totalCount += option.second.values.size();
  }

  if (!dq->ednsOptionsVect) {
    dq->ednsOptionsVect = std::make_unique<std::vector<dnsdist_ffi_ednsoption_t>>();
  }
  dq->ednsOptionsVect->clear();
  dq->ednsOptionsVect->resize(totalCount);
  size_t pos = 0;
  for (const auto& option : *dq->dq->ednsOptions) {
    for (const auto& entry : option.second.values) {
      fill_edns_option(entry, dq->ednsOptionsVect->at(pos));
      dq->ednsOptionsVect->at(pos).optionCode = option.first;
      pos++;
    }
  }

  if (totalCount > 0) {
    *out = dq->ednsOptionsVect->data();
  }

  return totalCount;
}

size_t dnsdist_ffi_dnsquestion_get_http_headers(dnsdist_ffi_dnsquestion_t* ref, [[maybe_unused]] const dnsdist_ffi_http_header_t** out)
{
#if defined(HAVE_DNS_OVER_HTTPS) || defined(HAVE_DNS_OVER_HTTP3)
  const auto processHeaders = [&ref](const std::unordered_map<std::string, std::string>& headers) {
    if (headers.empty()) {
      return;
    }
    ref->httpHeaders = std::make_unique<std::unordered_map<std::string, std::string>>(headers);
    if (!ref->httpHeadersVect) {
      ref->httpHeadersVect = std::make_unique<std::vector<dnsdist_ffi_http_header_t>>();
    }
    ref->httpHeadersVect->clear();
    ref->httpHeadersVect->resize(ref->httpHeaders->size());
    size_t pos = 0;
    for (const auto& header : *ref->httpHeaders) {
      ref->httpHeadersVect->at(pos).name = header.first.c_str();
      ref->httpHeadersVect->at(pos).value = header.second.c_str();
      ++pos;
    }
  };

#if defined(HAVE_DNS_OVER_HTTPS)
  if (ref->dq->ids.du) {
    const auto& headers = ref->dq->ids.du->getHTTPHeaders();
    processHeaders(headers);
  }
#endif /* HAVE_DNS_OVER_HTTPS */
#if defined(HAVE_DNS_OVER_HTTP3)
  if (ref->dq->ids.doh3u) {
    const auto& headers = ref->dq->ids.doh3u->getHTTPHeaders();
    processHeaders(headers);
  }
#endif /* HAVE_DNS_OVER_HTTP3 */

  if (!ref->httpHeadersVect) {
    return 0;
  }

  if (!ref->httpHeadersVect->empty()) {
    *out = ref->httpHeadersVect->data();
  }
  return ref->httpHeadersVect->size();
#else /* HAVE_DNS_OVER_HTTPS || HAVE_DNS_OVER_HTTP3 */
  return 0;
#endif /* HAVE_DNS_OVER_HTTPS || HAVE_DNS_OVER_HTTP3 */
}

size_t dnsdist_ffi_dnsquestion_get_tag_array(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_ffi_tag_t** out)
{
  if (dq == nullptr || dq->dq == nullptr || dq->dq->ids.qTag == nullptr || dq->dq->ids.qTag->size() == 0) {
    return 0;
  }

  if (!dq->tagsVect) {
    dq->tagsVect = std::make_unique<std::vector<dnsdist_ffi_tag_t>>();
  }
  dq->tagsVect->clear();
  dq->tagsVect->resize(dq->dq->ids.qTag->size());
  size_t pos = 0;

  for (const auto& tag : *dq->dq->ids.qTag) {
    auto& entry = dq->tagsVect->at(pos);
    entry.name = tag.first.c_str();
    entry.value = tag.second.c_str();
    ++pos;
  }

  if (!dq->tagsVect->empty()) {
    *out = dq->tagsVect->data();
  }

  return dq->tagsVect->size();
}

void dnsdist_ffi_dnsquestion_set_result(dnsdist_ffi_dnsquestion_t* dq, const char* str, size_t strSize)
{
  dq->result = std::string(str, strSize);
}

void dnsdist_ffi_dnsquestion_set_http_response(dnsdist_ffi_dnsquestion_t* ref, [[maybe_unused]] uint16_t statusCode, [[maybe_unused]] const char* body, [[maybe_unused]] size_t bodyLen, [[maybe_unused]] const char* contentType)
{
#if defined(HAVE_DNS_OVER_HTTPS)
  if (ref->dq->ids.du) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): C API
    PacketBuffer bodyVect(body, body + bodyLen);
    ref->dq->ids.du->setHTTPResponse(statusCode, std::move(bodyVect), contentType);
    dnsdist::PacketMangling::editDNSHeaderFromPacket(ref->dq->getMutableData(), [](dnsheader& header) {
      header.qr = true;
      return true;
    });
  }
#endif
#if defined(HAVE_DNS_OVER_HTTP3)
  if (ref->dq->ids.doh3u) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): C API
    PacketBuffer bodyVect(body, body + bodyLen);
    ref->dq->ids.doh3u->setHTTPResponse(statusCode, std::move(bodyVect), contentType);
    dnsdist::PacketMangling::editDNSHeaderFromPacket(ref->dq->getMutableData(), [](dnsheader& header) {
      header.qr = true;
      return true;
    });
  }
#endif
}

void dnsdist_ffi_dnsquestion_set_extended_dns_error(dnsdist_ffi_dnsquestion_t* dnsQuestion, uint16_t infoCode, const char* extraText, size_t extraTextSize)
{
  EDNSExtendedError ede;
  ede.infoCode = infoCode;
  if (extraText != nullptr && extraTextSize > 0) {
    ede.extraText = std::string(extraText, extraTextSize);
  }
  dnsQuestion->dq->ids.d_extendedError = std::make_unique<EDNSExtendedError>(ede);
}

void dnsdist_ffi_dnsquestion_set_rcode(dnsdist_ffi_dnsquestion_t* dq, int rcode)
{
  dnsdist::PacketMangling::editDNSHeaderFromPacket(dq->dq->getMutableData(), [rcode](dnsheader& header) {
    header.rcode = rcode;
    header.qr = true;
    return true;
  });
}

void dnsdist_ffi_dnsquestion_set_len(dnsdist_ffi_dnsquestion_t* dq, uint16_t len)
{
  dq->dq->getMutableData().resize(len);
}

void dnsdist_ffi_dnsquestion_set_skip_cache(dnsdist_ffi_dnsquestion_t* dq, bool skipCache)
{
  dq->dq->ids.skipCache = skipCache;
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
  dq->dq->ids.tempFailureTTL = tempFailureTTL;
}

void dnsdist_ffi_dnsquestion_unset_temp_failure_ttl(dnsdist_ffi_dnsquestion_t* dq)
{
  dq->dq->ids.tempFailureTTL = boost::none;
}

void dnsdist_ffi_dnsquestion_set_tag(dnsdist_ffi_dnsquestion_t* dq, const char* label, const char* value)
{
  dq->dq->setTag(label, value);
}

void dnsdist_ffi_dnsquestion_set_tag_raw(dnsdist_ffi_dnsquestion_t* dq, const char* label, const char* value, size_t valueSize)
{
  dq->dq->setTag(label, std::string(value, valueSize));
}

void dnsdist_ffi_dnsquestion_set_requestor_id(dnsdist_ffi_dnsquestion_t* dq, const char* value, size_t valueSize)
{
  if (!dq || !dq->dq || !value) {
    return;
  }
  if (!dq->dq->ids.d_protoBufData) {
    dq->dq->ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
  }
  dq->dq->ids.d_protoBufData->d_requestorID = std::string(value, valueSize);
}

void dnsdist_ffi_dnsquestion_set_device_id(dnsdist_ffi_dnsquestion_t* dq, const char* value, size_t valueSize)
{
  if (!dq || !dq->dq || !value) {
    return;
  }
  if (!dq->dq->ids.d_protoBufData) {
    dq->dq->ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
  }
  dq->dq->ids.d_protoBufData->d_deviceID = std::string(value, valueSize);
}

void dnsdist_ffi_dnsquestion_set_device_name(dnsdist_ffi_dnsquestion_t* dq, const char* value, size_t valueSize)
{
  if (!dq || !dq->dq || !value) {
    return;
  }
  if (!dq->dq->ids.d_protoBufData) {
    dq->dq->ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
  }
  dq->dq->ids.d_protoBufData->d_deviceName = std::string(value, valueSize);
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
  if (g_snmpAgent != nullptr && dnsdist::configuration::getImmutableConfiguration().d_snmpTrapsEnabled) {
    g_snmpAgent->sendDNSTrap(*dq->dq, std::string(reason, reasonLen));
  }
}

void dnsdist_ffi_dnsquestion_spoof_packet(dnsdist_ffi_dnsquestion_t* dq, const char* raw, size_t len)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  dnsdist::self_answers::generateAnswerFromRawPacket(*dq->dq, PacketBuffer(raw, raw + len));
}

void dnsdist_ffi_dnsquestion_spoof_raw(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_ffi_raw_value_t* values, size_t valuesCount)
{
  std::vector<std::string> data;
  data.reserve(valuesCount);

  for (size_t idx = 0; idx < valuesCount; idx++) {
    data.emplace_back(values[idx].value, values[idx].size);
  }

  dnsdist::ResponseConfig config{};
  dnsdist::self_answers::generateAnswerFromRDataEntries(*dq->dq, data, std::nullopt, config);
}

void dnsdist_ffi_dnsquestion_spoof_addrs(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_ffi_raw_value_t* values, size_t valuesCount)
{
  std::vector<ComboAddress> data;
  data.reserve(valuesCount);

  for (size_t idx = 0; idx < valuesCount; idx++) {
    if (values[idx].size == 4) {
      sockaddr_in sin;
      sin.sin_family = AF_INET;
      sin.sin_port = 0;
      memcpy(&sin.sin_addr.s_addr, values[idx].value, sizeof(sin.sin_addr.s_addr));
      data.emplace_back(&sin);
    }
    else if (values[idx].size == 16) {
      sockaddr_in6 sin6;
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = 0;
      sin6.sin6_scope_id = 0;
      sin6.sin6_flowinfo = 0;
      memcpy(&sin6.sin6_addr.s6_addr, values[idx].value, sizeof(sin6.sin6_addr.s6_addr));
      data.emplace_back(&sin6);
    }
  }

  dnsdist::ResponseConfig config{};
  dnsdist::self_answers::generateAnswerFromIPAddresses(*dq->dq, data, config);
}

void dnsdist_ffi_dnsquestion_set_max_returned_ttl(dnsdist_ffi_dnsquestion_t* dq, uint32_t max)
{
  if (dq != nullptr && dq->dq != nullptr) {
    dq->dq->ids.ttlCap = max;
  }
}

bool dnsdist_ffi_dnsquestion_set_restartable(dnsdist_ffi_dnsquestion_t* dq)
{
  if (dq == nullptr || dq->dq == nullptr) {
    return false;
  }

  dq->dq->ids.d_packet = std::make_unique<PacketBuffer>(dq->dq->getData());
  return true;
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
  (void)dq;
  auto server = chashedFromHash(list->servers, hash);
  return dnsdist_ffi_servers_get_index_from_server(list->servers, server);
}

size_t dnsdist_ffi_servers_list_whashed(const dnsdist_ffi_servers_list_t* list, const dnsdist_ffi_dnsquestion_t* dq, size_t hash)
{
  (void)dq;
  auto server = whashedFromHash(list->servers, hash);
  return dnsdist_ffi_servers_get_index_from_server(list->servers, server);
}

uint64_t dnsdist_ffi_server_get_outstanding(const dnsdist_ffi_server_t* server)
{
  return server->server->outstanding;
}

int dnsdist_ffi_server_get_weight(const dnsdist_ffi_server_t* server)
{
  return server->server->d_config.d_weight;
}

int dnsdist_ffi_server_get_order(const dnsdist_ffi_server_t* server)
{
  return server->server->d_config.order;
}

double dnsdist_ffi_server_get_latency(const dnsdist_ffi_server_t* server)
{
  return server->server->getRelevantLatencyUsec();
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

void dnsdist_ffi_dnsresponse_set_min_ttl(dnsdist_ffi_dnsresponse_t* dr, uint32_t min)
{
  dnsdist_ffi_dnsresponse_limit_ttl(dr, min, std::numeric_limits<uint32_t>::max());
}

void dnsdist_ffi_dnsresponse_set_max_ttl(dnsdist_ffi_dnsresponse_t* dr, uint32_t max)
{
  dnsdist_ffi_dnsresponse_limit_ttl(dr, 0, max);
}

void dnsdist_ffi_dnsresponse_limit_ttl(dnsdist_ffi_dnsresponse_t* dr, uint32_t min, uint32_t max)
{
  if (dr != nullptr && dr->dr != nullptr) {
    dnsdist::PacketMangling::restrictDNSPacketTTLs(dr->dr->getMutableData(), min, max);
  }
}

void dnsdist_ffi_dnsresponse_set_max_returned_ttl(dnsdist_ffi_dnsresponse_t* dr, uint32_t max)
{
  if (dr != nullptr && dr->dr != nullptr) {
    dr->dr->ids.ttlCap = max;
  }
}

void dnsdist_ffi_dnsresponse_clear_records_type(dnsdist_ffi_dnsresponse_t* dr, uint16_t qtype)
{
  if (dr != nullptr && dr->dr != nullptr) {
    clearDNSPacketRecordTypes(dr->dr->getMutableData(), std::unordered_set<QType>{qtype});
  }
}

bool dnsdist_ffi_dnsresponse_rebase(dnsdist_ffi_dnsresponse_t* dr, const char* initialName, size_t initialNameSize)
{
  if (dr == nullptr || dr->dr == nullptr || initialName == nullptr || initialNameSize == 0) {
    return false;
  }

  try {
    DNSName parsed(initialName, initialNameSize, 0, false);

    if (!dnsdist::changeNameInDNSPacket(dr->dr->getMutableData(), dr->dr->ids.qname, parsed)) {
      return false;
    }

    // set qname to new one
    dr->dr->ids.qname = std::move(parsed);
    dr->dr->ids.skipCache = true;
  }
  catch (const std::exception& e) {
    vinfolog("Error rebasing packet on a new DNSName: %s", e.what());
    return false;
  }

  return true;
}

bool dnsdist_ffi_dnsquestion_set_async(dnsdist_ffi_dnsquestion_t* dq, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)
{
  try {
    dq->dq->asynchronous = true;
    return dnsdist::suspendQuery(*dq->dq, asyncID, queryID, timeoutMs);
  }
  catch (const std::exception& e) {
    vinfolog("Error in dnsdist_ffi_dnsquestion_set_async: %s", e.what());
  }
  catch (...) {
    vinfolog("Exception in dnsdist_ffi_dnsquestion_set_async");
  }

  return false;
}

bool dnsdist_ffi_dnsresponse_set_async(dnsdist_ffi_dnsquestion_t* dq, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)
{
  try {
    dq->dq->asynchronous = true;
    auto dr = dynamic_cast<DNSResponse*>(dq->dq);
    if (!dr) {
      vinfolog("Passed a DNSQuestion instead of a DNSResponse to dnsdist_ffi_dnsresponse_set_async");
      return false;
    }

    return dnsdist::suspendResponse(*dr, asyncID, queryID, timeoutMs);
  }
  catch (const std::exception& e) {
    vinfolog("Error in dnsdist_ffi_dnsresponse_set_async: %s", e.what());
  }
  catch (...) {
    vinfolog("Exception in dnsdist_ffi_dnsresponse_set_async");
  }
  return false;
}

bool dnsdist_ffi_resume_from_async(uint16_t asyncID, uint16_t queryID, const char* tag, size_t tagSize, const char* tagValue, size_t tagValueSize, bool useCache)
{
  if (!dnsdist::g_asyncHolder) {
    vinfolog("Unable to resume, no asynchronous holder");
    return false;
  }

  auto query = dnsdist::g_asyncHolder->get(asyncID, queryID);
  if (!query) {
    vinfolog("Unable to resume, no object found for asynchronous ID %d and query ID %d", asyncID, queryID);
    return false;
  }

  auto& ids = query->query.d_idstate;
  if (tag != nullptr && tagSize > 0) {
    if (!ids.qTag) {
      ids.qTag = std::make_unique<QTag>();
    }
    (*ids.qTag)[std::string(tag, tagSize)] = std::string(tagValue, tagValueSize);
  }

  ids.skipCache = !useCache;

  return dnsdist::queueQueryResumptionEvent(std::move(query));
}

bool dnsdist_ffi_set_rcode_from_async(uint16_t asyncID, uint16_t queryID, uint8_t rcode, bool clearAnswers)
{
  if (!dnsdist::g_asyncHolder) {
    return false;
  }

  auto query = dnsdist::g_asyncHolder->get(asyncID, queryID);
  if (!query) {
    vinfolog("Unable to resume with a custom response code, no object found for asynchronous ID %d and query ID %d", asyncID, queryID);
    return false;
  }

  if (!dnsdist::setInternalQueryRCode(query->query.d_idstate, query->query.d_buffer, rcode, clearAnswers)) {
    return false;
  }

  query->query.d_idstate.skipCache = true;

  return dnsdist::queueQueryResumptionEvent(std::move(query));
}

bool dnsdist_ffi_resume_from_async_with_alternate_name(uint16_t asyncID, uint16_t queryID, const char* alternateName, size_t alternateNameSize, const char* tag, size_t tagSize, const char* tagValue, size_t tagValueSize, const char* formerNameTagName, size_t formerNameTagSize)
{
  if (!dnsdist::g_asyncHolder) {
    return false;
  }

  auto query = dnsdist::g_asyncHolder->get(asyncID, queryID);
  if (!query) {
    vinfolog("Unable to resume with an alternate name, no object found for asynchronous ID %d and query ID %d", asyncID, queryID);
    return false;
  }

  auto& ids = query->query.d_idstate;
  DNSName originalName = ids.qname;

  try {
    DNSName parsed(alternateName, alternateNameSize, 0, false);

    PacketBuffer initialPacket;
    if (query->d_isResponse) {
      if (!ids.d_packet) {
        return false;
      }
      initialPacket = std::move(*ids.d_packet);
    }
    else {
      initialPacket = std::move(query->query.d_buffer);
    }

    // edit qname in query packet
    if (!dnsdist::changeNameInDNSPacket(initialPacket, originalName, parsed)) {
      return false;
    }
    if (query->d_isResponse) {
      query->d_isResponse = false;
    }
    query->query.d_buffer = std::move(initialPacket);
    // set qname to new one
    ids.qname = std::move(parsed);
  }
  catch (const std::exception& e) {
    vinfolog("Error rebasing packet on a new DNSName: %s", e.what());
    return false;
  }

  // save existing qname in tag
  if (formerNameTagName != nullptr && formerNameTagSize > 0) {
    if (!ids.qTag) {
      ids.qTag = std::make_unique<QTag>();
    }
    (*ids.qTag)[std::string(formerNameTagName, formerNameTagSize)] = originalName.getStorage();
  }

  if (tag != nullptr && tagSize > 0) {
    if (!ids.qTag) {
      ids.qTag = std::make_unique<QTag>();
    }
    (*ids.qTag)[std::string(tag, tagSize)] = std::string(tagValue, tagValueSize);
  }

  ids.skipCache = true;

  // resume as query
  return dnsdist::queueQueryResumptionEvent(std::move(query));
}

bool dnsdist_ffi_drop_from_async(uint16_t asyncID, uint16_t queryID)
{
  if (!dnsdist::g_asyncHolder) {
    return false;
  }

  auto query = dnsdist::g_asyncHolder->get(asyncID, queryID);
  if (!query) {
    vinfolog("Unable to drop, no object found for asynchronous ID %d and query ID %d", asyncID, queryID);
    return false;
  }

  auto sender = query->getTCPQuerySender();
  if (!sender) {
    return false;
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  TCPResponse tresponse(std::move(query->query));
  sender->notifyIOError(now, std::move(tresponse));

  return true;
}

bool dnsdist_ffi_set_answer_from_async(uint16_t asyncID, uint16_t queryID, const char* raw, size_t rawSize)
{
  if (rawSize < sizeof(dnsheader)) {
    return false;
  }
  if (!dnsdist::g_asyncHolder) {
    return false;
  }

  auto query = dnsdist::g_asyncHolder->get(asyncID, queryID);
  if (!query) {
    vinfolog("Unable to resume with a custom answer, no object found for asynchronous ID %d and query ID %d", asyncID, queryID);
    return false;
  }

  dnsheader_aligned alignedHeader(query->query.d_buffer.data());
  auto oldID = alignedHeader->id;
  query->query.d_buffer.clear();
  query->query.d_buffer.insert(query->query.d_buffer.begin(), raw, raw + rawSize);

  dnsdist::PacketMangling::editDNSHeaderFromPacket(query->query.d_buffer, [oldID](dnsheader& header) {
    header.id = oldID;
    return true;
  });
  query->query.d_idstate.skipCache = true;

  return dnsdist::queueQueryResumptionEvent(std::move(query));
}

static constexpr char s_lua_ffi_code[] = R"FFICodeContent(
  local ffi = require("ffi")
  local C = ffi.C

  ffi.cdef[[
)FFICodeContent"
#include "dnsdist-lua-ffi-interface.inc"
                                         R"FFICodeContent(
  ]]

)FFICodeContent";

const char* getLuaFFIWrappers()
{
  return s_lua_ffi_code;
}

void setupLuaLoadBalancingContext(LuaContext& luaCtx)
{
  setupLuaBindings(luaCtx, true, false);
  setupLuaBindingsDNSQuestion(luaCtx);
  setupLuaBindingsLogging(luaCtx);
  setupLuaBindingsKVS(luaCtx, true);
  setupLuaVars(luaCtx);

#ifdef LUAJIT_VERSION
  luaCtx.executeCode(getLuaFFIWrappers());
#endif
}

void setupLuaFFIPerThreadContext(LuaContext& luaCtx)
{
  setupLuaVars(luaCtx);
  setupLuaBindingsLogging(luaCtx);

#ifdef LUAJIT_VERSION
  luaCtx.executeCode(getLuaFFIWrappers());
#endif
}

size_t dnsdist_ffi_generate_proxy_protocol_payload(const size_t addrSize, const void* srcAddr, const void* dstAddr, const uint16_t srcPort, const uint16_t dstPort, const bool tcp, const size_t valuesCount, const dnsdist_ffi_proxy_protocol_value* values, void* out, const size_t outSize)
{
  try {
    ComboAddress src, dst;
    if (addrSize != sizeof(src.sin4.sin_addr) && addrSize != sizeof(src.sin6.sin6_addr.s6_addr)) {
      return 0;
    }

    src = makeComboAddressFromRaw(addrSize == sizeof(src.sin4.sin_addr) ? 4 : 6, reinterpret_cast<const char*>(srcAddr), addrSize);
    src.sin4.sin_port = htons(srcPort);
    dst = makeComboAddressFromRaw(addrSize == sizeof(dst.sin4.sin_addr) ? 4 : 6, reinterpret_cast<const char*>(dstAddr), addrSize);
    dst.sin4.sin_port = htons(dstPort);

    std::vector<ProxyProtocolValue> valuesVect;
    if (valuesCount > 0) {
      valuesVect.reserve(valuesCount);
      for (size_t idx = 0; idx < valuesCount; idx++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        valuesVect.push_back({std::string(values[idx].value, values[idx].size), values[idx].type});
      }
    }

    std::string payload = makeProxyHeader(tcp, src, dst, valuesVect);
    if (payload.size() > outSize) {
      return 0;
    }

    memcpy(out, payload.c_str(), payload.size());

    return payload.size();
  }
  catch (const std::exception& e) {
    vinfolog("Exception in dnsdist_ffi_generate_proxy_protocol_payload: %s", e.what());
    return 0;
  }
  catch (...) {
    vinfolog("Unhandled exception in dnsdist_ffi_generate_proxy_protocol_payload");
    return 0;
  }
}

size_t dnsdist_ffi_dnsquestion_generate_proxy_protocol_payload(const dnsdist_ffi_dnsquestion_t* dq, const size_t valuesCount, const dnsdist_ffi_proxy_protocol_value* values, void* out, const size_t outSize)
{
  std::vector<ProxyProtocolValue> valuesVect;
  if (valuesCount > 0) {
    valuesVect.reserve(valuesCount);
    for (size_t idx = 0; idx < valuesCount; idx++) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      valuesVect.push_back({std::string(values[idx].value, values[idx].size), values[idx].type});
    }
  }

  std::string payload = makeProxyHeader(dq->dq->overTCP(), dq->dq->ids.origRemote, dq->dq->ids.origDest, valuesVect);
  if (payload.size() > outSize) {
    return 0;
  }

  memcpy(out, payload.c_str(), payload.size());

  return payload.size();
}

bool dnsdist_ffi_dnsquestion_add_proxy_protocol_values(dnsdist_ffi_dnsquestion_t* dnsQuestion, const size_t valuesCount, const dnsdist_ffi_proxy_protocol_value_t* values)
{
  if (dnsQuestion == nullptr || dnsQuestion->dq == nullptr || values == nullptr || valuesCount == 0) {
    return false;
  }

  if (!dnsQuestion->dq->proxyProtocolValues) {
    dnsQuestion->dq->proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>();
  }

  dnsQuestion->dq->proxyProtocolValues->reserve(dnsQuestion->dq->proxyProtocolValues->size() + valuesCount);
  for (size_t idx = 0; idx < valuesCount; idx++) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): the Lua FFI API is a C API..
    dnsQuestion->dq->proxyProtocolValues->push_back({std::string(values[idx].value, values[idx].size), values[idx].type});
  }

  return true;
}

size_t dnsdist_ffi_dnsquestion_get_proxy_protocol_values(dnsdist_ffi_dnsquestion_t* dnsQuestion, const dnsdist_ffi_proxy_protocol_value_t** out)
{
  if (dnsQuestion == nullptr || dnsQuestion->dq == nullptr || !dnsQuestion->dq->proxyProtocolValues) {
    return 0;
  }

  if (out == nullptr) {
    return dnsQuestion->proxyProtocolValuesVect->size();
  }

  dnsQuestion->proxyProtocolValuesVect = std::make_unique<std::vector<dnsdist_ffi_proxy_protocol_value_t>>(dnsQuestion->dq->proxyProtocolValues->size());
  for (size_t counter = 0; counter < dnsQuestion->dq->proxyProtocolValues->size(); ++counter) {
    const auto& entry = dnsQuestion->dq->proxyProtocolValues->at(counter);
    auto& targetEntry = dnsQuestion->proxyProtocolValuesVect->at(counter);
    targetEntry.size = entry.content.size();
    targetEntry.value = entry.content.data();
    targetEntry.type = entry.type;
  }

  *out = dnsQuestion->proxyProtocolValuesVect->data();
  return dnsQuestion->proxyProtocolValuesVect->size();
}

struct dnsdist_ffi_domain_list_t
{
  std::vector<std::string> d_domains;
};
struct dnsdist_ffi_address_list_t
{
  std::vector<std::string> d_addresses;
};

const char* dnsdist_ffi_domain_list_get(const dnsdist_ffi_domain_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_domains.size()) {
    return nullptr;
  }

  return list->d_domains.at(idx).c_str();
}

void dnsdist_ffi_domain_list_free(dnsdist_ffi_domain_list_t* list)
{
  delete list;
}

const char* dnsdist_ffi_address_list_get(const dnsdist_ffi_address_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_addresses.size()) {
    return nullptr;
  }

  return list->d_addresses.at(idx).c_str();
}

void dnsdist_ffi_address_list_free(dnsdist_ffi_address_list_t* list)
{
  delete list;
}

size_t dnsdist_ffi_packetcache_get_domain_list_by_addr(const char* poolName, const char* addr, dnsdist_ffi_domain_list_t** out)
{
  if (poolName == nullptr || addr == nullptr || out == nullptr) {
    return 0;
  }

  ComboAddress ca;
  try {
    ca = ComboAddress(addr);
  }
  catch (const std::exception& e) {
    vinfolog("Error parsing address passed to dnsdist_ffi_packetcache_get_domain_list_by_addr: %s", e.what());
    return 0;
  }
  catch (const PDNSException& e) {
    vinfolog("Error parsing address passed to dnsdist_ffi_packetcache_get_domain_list_by_addr: %s", e.reason);
    return 0;
  }

  const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
  auto poolIt = pools.find(poolName);
  if (poolIt == pools.end()) {
    return 0;
  }

  auto pool = poolIt->second;
  if (!pool->packetCache) {
    return 0;
  }

  auto domains = pool->packetCache->getDomainsContainingRecords(ca);
  if (domains.size() == 0) {
    return 0;
  }

  auto list = std::make_unique<dnsdist_ffi_domain_list_t>();
  list->d_domains.reserve(domains.size());
  for (const auto& domain : domains) {
    try {
      list->d_domains.push_back(domain.toString());
    }
    catch (const std::exception& e) {
      vinfolog("Error converting domain to string in dnsdist_ffi_packetcache_get_domain_list_by_addr: %s", e.what());
    }
  }

  size_t count = list->d_domains.size();
  if (count > 0) {
    *out = list.release();
  }
  return count;
}

size_t dnsdist_ffi_packetcache_get_address_list_by_domain(const char* poolName, const char* domain, dnsdist_ffi_address_list_t** out)
{
  if (poolName == nullptr || domain == nullptr || out == nullptr) {
    return 0;
  }

  DNSName name;
  try {
    name = DNSName(domain);
  }
  catch (const std::exception& e) {
    vinfolog("Error parsing domain passed to dnsdist_ffi_packetcache_get_address_list_by_domain: %s", e.what());
    return 0;
  }

  const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
  auto poolIt = pools.find(poolName);
  if (poolIt == pools.end()) {
    return 0;
  }

  auto pool = poolIt->second;
  if (!pool->packetCache) {
    return 0;
  }

  auto addresses = pool->packetCache->getRecordsForDomain(name);
  if (addresses.size() == 0) {
    return 0;
  }

  auto list = std::make_unique<dnsdist_ffi_address_list_t>();
  list->d_addresses.reserve(addresses.size());
  for (const auto& addr : addresses) {
    try {
      list->d_addresses.push_back(addr.toString());
    }
    catch (const std::exception& e) {
      vinfolog("Error converting address to string in dnsdist_ffi_packetcache_get_address_list_by_domain: %s", e.what());
    }
  }

  size_t count = list->d_addresses.size();
  if (count > 0) {
    *out = list.release();
  }
  return count;
}

struct dnsdist_ffi_ring_entry_list_t
{
  struct entry
  {
    std::string qname;
    std::string requestor;
    std::string macAddr;
    std::string ds;
    dnsheader dh;
    double age;
    unsigned int latency;
    uint16_t size;
    uint16_t qtype;
    dnsdist::Protocol protocol;
    bool isResponse;
  };

  std::vector<entry> d_entries;
};

bool dnsdist_ffi_ring_entry_is_response(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return false;
  }

  return list->d_entries.at(idx).isResponse;
}

double dnsdist_ffi_ring_entry_get_age(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return list->d_entries.at(idx).age;
}

const char* dnsdist_ffi_ring_entry_get_name(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return nullptr;
  }

  return list->d_entries.at(idx).qname.c_str();
}

uint16_t dnsdist_ffi_ring_entry_get_type(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return list->d_entries.at(idx).qtype;
}

const char* dnsdist_ffi_ring_entry_get_requestor(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return nullptr;
  }

  return list->d_entries.at(idx).requestor.c_str();
}

const char* dnsdist_ffi_ring_entry_get_backend(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return nullptr;
  }

  return list->d_entries.at(idx).ds.c_str();
}

uint8_t dnsdist_ffi_ring_entry_get_protocol(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return list->d_entries.at(idx).protocol.toNumber();
}

uint16_t dnsdist_ffi_ring_entry_get_size(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return list->d_entries.at(idx).size;
}

uint16_t dnsdist_ffi_ring_entry_get_latency(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return list->d_entries.at(idx).latency;
}

uint16_t dnsdist_ffi_ring_entry_get_id(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return ntohs(list->d_entries.at(idx).dh.id);
}

uint8_t dnsdist_ffi_ring_entry_get_rcode(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return list->d_entries.at(idx).dh.rcode;
}

bool dnsdist_ffi_ring_entry_get_aa(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return false;
  }

  return list->d_entries.at(idx).dh.aa == 1;
}

bool dnsdist_ffi_ring_entry_get_rd(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return false;
  }

  return list->d_entries.at(idx).dh.rd == 1;
}

bool dnsdist_ffi_ring_entry_get_tc(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return false;
  }

  return list->d_entries.at(idx).dh.tc == 1;
}

uint16_t dnsdist_ffi_ring_entry_get_ancount(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return ntohs(list->d_entries.at(idx).dh.ancount);
}

uint16_t dnsdist_ffi_ring_entry_get_nscount(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return ntohs(list->d_entries.at(idx).dh.nscount);
}

uint16_t dnsdist_ffi_ring_entry_get_arcount(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return 0;
  }

  return ntohs(list->d_entries.at(idx).dh.arcount);
}

bool dnsdist_ffi_ring_entry_has_mac_address(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return false;
  }

  return !list->d_entries.at(idx).macAddr.empty();
}

const char* dnsdist_ffi_ring_entry_get_mac_address(const dnsdist_ffi_ring_entry_list_t* list, size_t idx)
{
  if (list == nullptr || idx >= list->d_entries.size()) {
    return nullptr;
  }

  return list->d_entries.at(idx).macAddr.data();
}

void dnsdist_ffi_ring_entry_list_free(dnsdist_ffi_ring_entry_list_t* list)
{
  delete list;
}

template <typename T>
static void addRingEntryToList(std::unique_ptr<dnsdist_ffi_ring_entry_list_t>& list, const struct timespec& now, const T& entry)
{
  auto age = DiffTime(entry.when, now);

  constexpr bool response = std::is_same_v<T, Rings::Response>;
  if constexpr (!response) {
#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
    dnsdist_ffi_ring_entry_list_t::entry tmp{entry.name.toString(), entry.requestor.toStringWithPort(), entry.hasmac ? std::string(reinterpret_cast<const char*>(entry.macaddress.data()), entry.macaddress.size()) : std::string(), std::string(), entry.dh, age, 0, entry.size, entry.qtype, entry.protocol, response};
#else
    dnsdist_ffi_ring_entry_list_t::entry tmp{entry.name.toString(), entry.requestor.toStringWithPort(), std::string(), std::string(), entry.dh, age, 0, entry.size, entry.qtype, entry.protocol, response};
#endif
    list->d_entries.push_back(std::move(tmp));
  }
  else {
    dnsdist_ffi_ring_entry_list_t::entry tmp{entry.name.toString(), entry.requestor.toStringWithPort(), std::string(), entry.ds.toStringWithPort(), entry.dh, age, entry.usec, entry.size, entry.qtype, entry.protocol, response};
    list->d_entries.push_back(std::move(tmp));
  }
}

size_t dnsdist_ffi_ring_get_entries(dnsdist_ffi_ring_entry_list_t** out)
{
  if (out == nullptr) {
    return 0;
  }
  auto list = std::make_unique<dnsdist_ffi_ring_entry_list_t>();
  struct timespec now
  {
  };
  gettime(&now);

  for (const auto& shard : g_rings.d_shards) {
    {
      auto ql = shard->queryRing.lock();
      for (const auto& entry : *ql) {
        addRingEntryToList(list, now, entry);
      }
    }
    {
      auto rl = shard->respRing.lock();
      for (const auto& entry : *rl) {
        addRingEntryToList(list, now, entry);
      }
    }
  }

  auto count = list->d_entries.size();
  if (count > 0) {
    *out = list.release();
  }
  return count;
}

size_t dnsdist_ffi_ring_get_entries_by_addr(const char* addr, dnsdist_ffi_ring_entry_list_t** out)
{
  if (out == nullptr || addr == nullptr) {
    return 0;
  }
  ComboAddress ca;
  try {
    ca = ComboAddress(addr);
  }
  catch (const std::exception& e) {
    vinfolog("Unable to convert address in dnsdist_ffi_ring_get_entries_by_addr: %s", e.what());
    return 0;
  }
  catch (const PDNSException& e) {
    vinfolog("Unable to convert address in dnsdist_ffi_ring_get_entries_by_addr: %s", e.reason);
    return 0;
  }

  auto list = std::make_unique<dnsdist_ffi_ring_entry_list_t>();
  struct timespec now
  {
  };
  gettime(&now);

  auto compare = ComboAddress::addressOnlyEqual();
  for (const auto& shard : g_rings.d_shards) {
    {
      auto ql = shard->queryRing.lock();
      for (const auto& entry : *ql) {
        if (!compare(entry.requestor, ca)) {
          continue;
        }

        addRingEntryToList(list, now, entry);
      }
    }
    {
      auto rl = shard->respRing.lock();
      for (const auto& entry : *rl) {
        if (!compare(entry.requestor, ca)) {
          continue;
        }

        addRingEntryToList(list, now, entry);
      }
    }
  }

  auto count = list->d_entries.size();
  if (count > 0) {
    *out = list.release();
  }
  return count;
}

size_t dnsdist_ffi_ring_get_entries_by_mac(const char* addr, dnsdist_ffi_ring_entry_list_t** out)
{
  if (out == nullptr || addr == nullptr) {
    return 0;
  }

#if !defined(DNSDIST_RINGS_WITH_MACADDRESS)
  return 0;
#else
  auto list = std::make_unique<dnsdist_ffi_ring_entry_list_t>();
  struct timespec now
  {
  };
  gettime(&now);

  for (const auto& shard : g_rings.d_shards) {
    auto ql = shard->queryRing.lock();
    for (const auto& entry : *ql) {
      if (memcmp(addr, entry.macaddress.data(), entry.macaddress.size()) != 0) {
        continue;
      }

      addRingEntryToList(list, now, entry);
    }
  }

  auto count = list->d_entries.size();
  if (count > 0) {
    *out = list.release();
  }
  return count;
#endif
}

struct dnsdist_ffi_network_endpoint_t
{
  dnsdist::NetworkEndpoint d_endpoint;
};

bool dnsdist_ffi_network_endpoint_new(const char* path, size_t pathSize, dnsdist_ffi_network_endpoint_t** out)
{
  if (path == nullptr || pathSize == 0 || out == nullptr) {
    return false;
  }
  try {
    dnsdist::NetworkEndpoint endpoint(std::string(path, pathSize));
    *out = new dnsdist_ffi_network_endpoint_t{std::move(endpoint)};
    return true;
  }
  catch (const std::exception& e) {
    vinfolog("Error creating a new network endpoint: %s", e.what());
    return false;
  }
}

bool dnsdist_ffi_network_endpoint_is_valid(const dnsdist_ffi_network_endpoint_t* endpoint)
{
  return endpoint != nullptr;
}

bool dnsdist_ffi_network_endpoint_send(const dnsdist_ffi_network_endpoint_t* endpoint, const char* payload, size_t payloadSize)
{
  if (endpoint != nullptr && payload != nullptr && payloadSize != 0) {
    return endpoint->d_endpoint.send(std::string_view(payload, payloadSize));
  }
  return false;
}

void dnsdist_ffi_network_endpoint_free(dnsdist_ffi_network_endpoint_t* endpoint)
{
  delete endpoint;
}

struct dnsdist_ffi_dnspacket_t
{
  dnsdist::DNSPacketOverlay overlay;
};

bool dnsdist_ffi_dnspacket_parse(const char* packet, size_t packetSize, dnsdist_ffi_dnspacket_t** out)
{
  if (packet == nullptr || out == nullptr || packetSize < sizeof(dnsheader)) {
    return false;
  }

  try {
    dnsdist::DNSPacketOverlay overlay(std::string_view(packet, packetSize));
    *out = new dnsdist_ffi_dnspacket_t{std::move(overlay)};
    return true;
  }
  catch (const std::exception& e) {
    vinfolog("Error in dnsdist_ffi_dnspacket_parse: %s", e.what());
  }
  catch (...) {
    vinfolog("Error in dnsdist_ffi_dnspacket_parse");
  }
  return false;
}

void dnsdist_ffi_dnspacket_get_qname_raw(const dnsdist_ffi_dnspacket_t* packet, const char** qname, size_t* qnameSize)
{
  if (packet == nullptr || qname == nullptr || qnameSize == nullptr) {
    return;
  }
  const auto& storage = packet->overlay.d_qname.getStorage();
  *qname = storage.data();
  *qnameSize = storage.size();
}

uint16_t dnsdist_ffi_dnspacket_get_qtype(const dnsdist_ffi_dnspacket_t* packet)
{
  if (packet != nullptr) {
    return packet->overlay.d_qtype;
  }
  return 0;
}

uint16_t dnsdist_ffi_dnspacket_get_qclass(const dnsdist_ffi_dnspacket_t* packet)
{
  if (packet != nullptr) {
    return packet->overlay.d_qclass;
  }
  return 0;
}

uint16_t dnsdist_ffi_dnspacket_get_records_count_in_section(const dnsdist_ffi_dnspacket_t* packet, uint8_t section)
{
  if (packet == nullptr || section > DNSResourceRecord::ADDITIONAL) {
    return 0;
  }

  uint16_t count = 0;
  for (const auto& record : packet->overlay.d_records) {
    if (record.d_place == section) {
      count++;
    }
  }

  return count;
}

void dnsdist_ffi_dnspacket_get_record_name_raw(const dnsdist_ffi_dnspacket_t* packet, size_t idx, const char** name, size_t* nameSize)
{
  if (packet == nullptr || name == nullptr || nameSize == nullptr || idx >= packet->overlay.d_records.size()) {
    return;
  }
  const auto& storage = packet->overlay.d_records.at(idx).d_name.getStorage();
  *name = storage.data();
  *nameSize = storage.size();
}

uint16_t dnsdist_ffi_dnspacket_get_record_type(const dnsdist_ffi_dnspacket_t* packet, size_t idx)
{
  if (packet == nullptr || idx >= packet->overlay.d_records.size()) {
    return 0;
  }
  return packet->overlay.d_records.at(idx).d_type;
}

uint16_t dnsdist_ffi_dnspacket_get_record_class(const dnsdist_ffi_dnspacket_t* packet, size_t idx)
{
  if (packet == nullptr || idx >= packet->overlay.d_records.size()) {
    return 0;
  }
  return packet->overlay.d_records.at(idx).d_class;
}

uint32_t dnsdist_ffi_dnspacket_get_record_ttl(const dnsdist_ffi_dnspacket_t* packet, size_t idx)
{
  if (packet == nullptr || idx >= packet->overlay.d_records.size()) {
    return 0;
  }
  return packet->overlay.d_records.at(idx).d_ttl;
}

uint16_t dnsdist_ffi_dnspacket_get_record_content_length(const dnsdist_ffi_dnspacket_t* packet, size_t idx)
{
  if (packet == nullptr || idx >= packet->overlay.d_records.size()) {
    return 0;
  }
  return packet->overlay.d_records.at(idx).d_contentLength;
}

uint16_t dnsdist_ffi_dnspacket_get_record_content_offset(const dnsdist_ffi_dnspacket_t* packet, size_t idx)
{
  if (packet == nullptr || idx >= packet->overlay.d_records.size()) {
    return 0;
  }
  return packet->overlay.d_records.at(idx).d_contentOffset;
}

size_t dnsdist_ffi_dnspacket_get_name_at_offset_raw(const char* packet, size_t packetSize, size_t offset, char* name, size_t nameSize)
{
  if (packet == nullptr || name == nullptr || nameSize == 0 || offset >= packetSize) {
    return 0;
  }
  try {
    DNSName parsed(packet, packetSize, offset, true);
    const auto& storage = parsed.getStorage();
    if (nameSize < storage.size()) {
      return 0;
    }
    memcpy(name, storage.data(), storage.size());
    return storage.size();
  }
  catch (const std::exception& e) {
    vinfolog("Error parsing DNSName via dnsdist_ffi_dnspacket_get_name_at_offset_raw: %s", e.what());
  }
  return 0;
}

void dnsdist_ffi_dnspacket_free(dnsdist_ffi_dnspacket_t* packet)
{
  if (packet != nullptr) {
    delete packet;
  }
}

bool dnsdist_ffi_metric_declare(const char* name, size_t nameLen, const char* type, const char* description, const char* customName)
{
  if (name == nullptr || nameLen == 0 || type == nullptr || description == nullptr) {
    return false;
  }
  auto result = dnsdist::metrics::declareCustomMetric(name, type, description, customName != nullptr ? std::optional<std::string>(customName) : std::nullopt, false);
  return !result;
}

void dnsdist_ffi_metric_inc(const char* metricName, size_t metricNameLen)
{
  auto result = dnsdist::metrics::incrementCustomCounter(std::string_view(metricName, metricNameLen), 1U, {});
  if (std::get_if<dnsdist::metrics::Error>(&result) != nullptr) {
    return;
  }
}

void dnsdist_ffi_metric_inc_by(const char* metricName, size_t metricNameLen, uint64_t value)
{
  auto result = dnsdist::metrics::incrementCustomCounter(std::string_view(metricName, metricNameLen), value, {});
  if (std::get_if<dnsdist::metrics::Error>(&result) != nullptr) {
    return;
  }
}

void dnsdist_ffi_metric_dec(const char* metricName, size_t metricNameLen)
{
  auto result = dnsdist::metrics::decrementCustomCounter(std::string_view(metricName, metricNameLen), 1U, {});
  if (std::get_if<dnsdist::metrics::Error>(&result) != nullptr) {
    return;
  }
}

void dnsdist_ffi_metric_set(const char* metricName, size_t metricNameLen, double value)
{
  auto result = dnsdist::metrics::setCustomGauge(std::string_view(metricName, metricNameLen), value, {});
  if (std::get_if<dnsdist::metrics::Error>(&result) != nullptr) {
    return;
  }
}

double dnsdist_ffi_metric_get(const char* metricName, size_t metricNameLen, bool isCounter)
{
  (void)isCounter;
  auto result = dnsdist::metrics::getCustomMetric(std::string_view(metricName, metricNameLen), {});
  if (std::get_if<dnsdist::metrics::Error>(&result) != nullptr) {
    return 0.;
  }
  return std::get<double>(result);
}

const char* dnsdist_ffi_network_message_get_payload(const dnsdist_ffi_network_message_t* msg)
{
  if (msg != nullptr) {
    return msg->payload.c_str();
  }
  return nullptr;
}

size_t dnsdist_ffi_network_message_get_payload_size(const dnsdist_ffi_network_message_t* msg)
{
  if (msg != nullptr) {
    return msg->payload.size();
  }
  return 0;
}

uint16_t dnsdist_ffi_network_message_get_endpoint_id(const dnsdist_ffi_network_message_t* msg)
{
  if (msg != nullptr) {
    return msg->endpointID;
  }
  return 0;
}

#ifndef DISABLE_DYNBLOCKS
bool dnsdist_ffi_dynamic_blocks_add(const char* address, const char* message, uint8_t action, unsigned int duration, uint8_t clientIPMask, uint8_t clientIPPortMask, const char* tagKey, const char* tagValue)
{
  try {
    ComboAddress clientIPCA;
    try {
      clientIPCA = ComboAddress(address);
    }
    catch (const std::exception& exp) {
      errlog("dnsdist_ffi_dynamic_blocks_add: Unable to parse '%s': %s", address, exp.what());
      return false;
    }
    catch (const PDNSException& exp) {
      errlog("dnsdist_ffi_dynamic_blocks_add: Unable to parse '%s': %s", address, exp.reason);
      return false;
    }

    AddressAndPortRange target(clientIPCA, clientIPMask, clientIPPortMask);

    timespec now{};
    gettime(&now);
    timespec until{now};
    until.tv_sec += duration;
    DynBlock dblock{message, until, DNSName(), static_cast<DNSAction::Action>(action)};

    auto dynamicRules = dnsdist::DynamicBlocks::getClientAddressDynamicRulesCopy();
    if (dblock.action == DNSAction::Action::SetTag && tagKey != nullptr) {
      dblock.tagSettings = std::make_shared<DynBlock::TagSettings>();
      dblock.tagSettings->d_name = tagKey;
      if (tagValue != nullptr) {
        dblock.tagSettings->d_value = tagValue;
      }
    }
    if (dnsdist::DynamicBlocks::addOrRefreshBlock(dynamicRules, now, target, std::move(dblock), false)) {
      dnsdist::DynamicBlocks::setClientAddressDynamicRules(std::move(dynamicRules));
      return true;
    }
  }
  catch (const std::exception& exp) {
    errlog("Exception in dnsdist_ffi_dynamic_blocks_add: %s", exp.what());
  }
  catch (const PDNSException& exp) {
    errlog("Exception in dnsdist_ffi_dynamic_blocks_add: %s", exp.reason);
  }
  catch (...) {
    errlog("Exception in dnsdist_ffi_dynamic_blocks_add");
  }
  return false;
}

bool dnsdist_ffi_dynamic_blocks_smt_add(const char* suffix, const char* message, uint8_t action, unsigned int duration, const char* tagKey, const char* tagValue)
{
  try {
    DNSName domain;
    try {
      domain = DNSName(suffix);
      domain.makeUsLowerCase();
    }
    catch (const std::exception& exp) {
      errlog("dnsdist_ffi_dynamic_blocks_smt_add: Unable to parse '%s': %s", suffix, exp.what());
      return false;
    }
    catch (const PDNSException& exp) {
      errlog("dnsdist_ffi_dynamic_blocks_smt_add: Unable to parse '%s': %s", suffix, exp.reason);
      return false;
    }

    timespec now{};
    gettime(&now);
    timespec until{now};
    until.tv_sec += duration;
    DynBlock dblock{message, until, domain, static_cast<DNSAction::Action>(action)};
    auto smtBlocks = dnsdist::DynamicBlocks::getSuffixDynamicRulesCopy();
    if (dblock.action == DNSAction::Action::SetTag && tagKey != nullptr) {
      dblock.tagSettings = std::make_shared<DynBlock::TagSettings>();
      dblock.tagSettings->d_name = tagKey;
      if (tagValue != nullptr) {
        dblock.tagSettings->d_value = tagValue;
      }
    }
    if (dnsdist::DynamicBlocks::addOrRefreshBlockSMT(smtBlocks, now, std::move(dblock), false)) {
      dnsdist::DynamicBlocks::setSuffixDynamicRules(std::move(smtBlocks));
      return true;
    }
  }
  catch (const std::exception& exp) {
    errlog("Exception in dnsdist_ffi_dynamic_blocks_smt_add: %s", exp.what());
  }
  catch (const PDNSException& exp) {
    errlog("Exception in dnsdist_ffi_dynamic_blocks_smt_add: %s", exp.reason);
  }
  catch (...) {
    errlog("Exception in dnsdist_ffi_dynamic_blocks_smt_add");
  }
  return false;
}

struct dnsdist_ffi_dynamic_blocks_list_t
{
  std::vector<dnsdist_ffi_dynamic_block_entry_t> d_entries;
};

size_t dnsdist_ffi_dynamic_blocks_get_entries(dnsdist_ffi_dynamic_blocks_list_t** out)
{
  if (out == nullptr) {
    return 0;
  }

  auto list = std::make_unique<dnsdist_ffi_dynamic_blocks_list_t>();

  timespec now{};
  gettime(&now);

  const auto& dynamicRules = dnsdist::DynamicBlocks::getClientAddressDynamicRules();
  for (const auto& entry : dynamicRules) {
    const auto& client = entry.first;
    const auto& details = entry.second;
    if (!(now < details.until)) {
      continue;
    }

    uint64_t counter = details.blocks;
    if (g_defaultBPFFilter && details.bpf) {
      counter += g_defaultBPFFilter->getHits(client.getNetwork());
    }
    list->d_entries.push_back({strdup(client.toString().c_str()), strdup(details.reason.c_str()), counter, static_cast<uint64_t>(details.until.tv_sec - now.tv_sec), static_cast<uint8_t>(details.action != DNSAction::Action::None ? details.action : dnsdist::configuration::getCurrentRuntimeConfiguration().d_dynBlockAction), g_defaultBPFFilter && details.bpf, details.warning});
  }

  auto count = list->d_entries.size();
  *out = list.release();
  return count;
}

size_t dnsdist_ffi_dynamic_blocks_smt_get_entries(dnsdist_ffi_dynamic_blocks_list_t** out)
{
  if (out == nullptr) {
    return 0;
  }

  auto list = std::make_unique<dnsdist_ffi_dynamic_blocks_list_t>();

  timespec now{};
  gettime(&now);

  const auto defaultAction = dnsdist::configuration::getCurrentRuntimeConfiguration().d_dynBlockAction;
  const auto& smtBlocks = dnsdist::DynamicBlocks::getSuffixDynamicRules();
  smtBlocks.visit([&now, &list, defaultAction](const SuffixMatchTree<DynBlock>& node) {
    if (!(now < node.d_value.until)) {
      return;
    }
    auto entry = node.d_value;
    string key("empty");
    if (!entry.domain.empty()) {
      key = entry.domain.toString();
    }
    if (entry.action == DNSAction::Action::None) {
      entry.action = defaultAction;
    }
    list->d_entries.push_back({strdup(key.c_str()), strdup(entry.reason.c_str()), entry.blocks, static_cast<uint64_t>(entry.until.tv_sec - now.tv_sec), static_cast<uint8_t>(entry.action), entry.bpf, entry.warning});
  });

  auto count = list->d_entries.size();
  *out = list.release();
  return count;
}

const dnsdist_ffi_dynamic_block_entry_t* dnsdist_ffi_dynamic_blocks_list_get(const dnsdist_ffi_dynamic_blocks_list_t* list, size_t idx)
{
  if (list == nullptr) {
    return nullptr;
  }

  if (idx >= list->d_entries.size()) {
    return nullptr;
  }

  return &list->d_entries.at(idx);
}

void dnsdist_ffi_dynamic_blocks_list_free(dnsdist_ffi_dynamic_blocks_list_t* list)
{
  if (list == nullptr) {
    return;
  }

  for (auto& entry : list->d_entries) {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory,cppcoreguidelines-no-malloc): this is a C API, RAII is not an option
    free(entry.key);
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory,cppcoreguidelines-no-malloc): this is a C API, RAII is not an option
    free(entry.reason);
  }

  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): this is a C API, RAII is not an option
  delete list;
}

#endif /* DISABLE_DYNBLOCKS */

uint32_t dnsdist_ffi_hash(uint32_t seed, const unsigned char* data, size_t dataSize, bool caseInsensitive)
{
  if (data == nullptr || dataSize == 0) {
    return seed;
  }

  if (caseInsensitive) {
    return burtleCI(data, dataSize, seed);
  }

  return burtle(data, dataSize, seed);
}

struct dnsdist_ffi_svc_record_parameters
{
  SVCRecordParameters parameters;
};

bool dnsdist_ffi_svc_record_parameters_new(const char* targetName, uint16_t priority, bool noDefaultALPN, dnsdist_ffi_svc_record_parameters** out)
{
  if (targetName == nullptr || out == nullptr) {
    return false;
  }
  try {
    auto parameters = std::make_unique<dnsdist_ffi_svc_record_parameters>();
    parameters->parameters.target = DNSName(targetName);
    parameters->parameters.priority = priority;
    parameters->parameters.noDefaultAlpn = noDefaultALPN;
    *out = parameters.release();
    return true;
  }
  catch (const std::exception& exp) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_new: %s", exp.what());
  }
  catch (const PDNSException& exp) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_new: %s", exp.reason);
  }
  catch (...) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_new");
  }

  return false;
}

void dnsdist_ffi_svc_record_parameters_set_port(dnsdist_ffi_svc_record_parameters* parameters, uint16_t port)
{
  if (parameters == nullptr) {
    return;
  }
  parameters->parameters.port = port;
}

void dnsdist_ffi_svc_record_parameters_set_ech(dnsdist_ffi_svc_record_parameters* parameters, const char* ech, size_t echLen)
{
  if (parameters == nullptr || ech == nullptr || echLen == 0) {
    return;
  }
  parameters->parameters.ech = std::string(ech, echLen);
}

void dnsdist_ffi_svc_record_parameters_set_additional_param(dnsdist_ffi_svc_record_parameters* parameters, uint16_t key, const char* value, size_t valueLen)
{
  if (parameters == nullptr || (value == nullptr && valueLen != 0)) {
    return;
  }
  parameters->parameters.additionalParams.emplace_back(key, std::string(value, valueLen));
}

void dnsdist_ffi_svc_record_parameters_add_mandatory_param(dnsdist_ffi_svc_record_parameters* parameters, uint16_t key)
{
  if (parameters == nullptr) {
    return;
  }
  parameters->parameters.mandatoryParams.insert(key);
}

void dnsdist_ffi_svc_record_parameters_add_alpn(dnsdist_ffi_svc_record_parameters* parameters, const char* value, size_t valueLen)
{
  if (parameters == nullptr || value == nullptr || valueLen == 0) {
    return;
  }
  parameters->parameters.alpns.emplace_back(value, valueLen);
}

void dnsdist_ffi_svc_record_parameters_add_ipv4_hint(dnsdist_ffi_svc_record_parameters* parameters, const char* value, size_t valueLen)
{
  if (parameters == nullptr || value == nullptr || valueLen == 0) {
    return;
  }
  try {
    parameters->parameters.ipv4hints.emplace_back(ComboAddress(std::string(value, valueLen)));
  }
  catch (const std::exception& exp) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_add_ipv4_hint: %s", exp.what());
  }
  catch (const PDNSException& exp) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_add_ipv4_hint: %s", exp.reason);
  }
  catch (...) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_add_ipv4_hint");
  }
}

void dnsdist_ffi_svc_record_parameters_add_ipv6_hint(dnsdist_ffi_svc_record_parameters* parameters, const char* value, size_t valueLen)
{
  if (parameters == nullptr || value == nullptr || valueLen == 0) {
    return;
  }
  try {
    parameters->parameters.ipv6hints.emplace_back(ComboAddress(std::string(value, valueLen)));
  }
  catch (const std::exception& exp) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_add_ipv4_hint: %s", exp.what());
  }
  catch (const PDNSException& exp) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_add_ipv4_hint: %s", exp.reason);
  }
  catch (...) {
    errlog("Exception in dnsdist_ffi_svc_record_parameters_add_ipv4_hint");
  }
}

bool dnsdist_ffi_dnsquestion_generate_svc_response(dnsdist_ffi_dnsquestion_t* dnsQuestion, const dnsdist_ffi_svc_record_parameters** parametersList, size_t parametersListSize, uint32_t ttl)
{
  if (dnsQuestion == nullptr || parametersList == nullptr || parametersListSize == 0) {
    return false;
  }
  std::vector<SVCRecordParameters> parameters;
  parameters.reserve(parametersListSize);
  for (size_t idx = 0; idx < parametersListSize; idx++) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): this is a C API
    const auto* parameter = parametersList[idx];
    if (parameter == nullptr) {
      return false;
    }
    parameters.push_back(parameter->parameters);
  }
  return dnsdist::svc::generateSVCResponse(*dnsQuestion->dq, ttl, parameters);
}

void dnsdist_ffi_svc_record_parameters_free(dnsdist_ffi_svc_record_parameters* parameters)
{
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): this is a C API, RAII is not an option
  delete parameters;
}
