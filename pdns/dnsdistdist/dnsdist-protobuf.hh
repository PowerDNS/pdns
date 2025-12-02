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

#include "dnsname.hh"
#include <optional>

#ifndef DISABLE_PROTOBUF
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include "protozero.hh"
#include "protozero-trace.hh"

struct DNSQuestion;
struct DNSResponse;

class DNSDistProtoBufMessage
{
public:
  DNSDistProtoBufMessage(const DNSQuestion& dnsquestion);
  DNSDistProtoBufMessage(const DNSResponse& dnsresponse, bool includeCNAME);
  DNSDistProtoBufMessage(const DNSQuestion&&) = delete;
  DNSDistProtoBufMessage(const DNSResponse&&, bool) = delete;

  void setServerIdentity(const std::string& serverId);
  void setRequestor(const ComboAddress& requestor);
  void setResponder(const ComboAddress& responder);
  void setRequestorPort(uint16_t port);
  void setResponderPort(uint16_t port);
  void setResponseCode(uint8_t rcode);
  void setType(pdns::ProtoZero::Message::MessageType type);
  void setHTTPVersion(pdns::ProtoZero::Message::HTTPVersion version);
  void setBytes(size_t bytes);
  void setTime(time_t sec, uint32_t usec);
  void setQueryTime(time_t sec, uint32_t usec);
  void setQuestion(const DNSName& name, uint16_t qtype, uint16_t qclass);
  void setEDNSSubnet(const Netmask& netmask);

  void addTag(const std::string& strValue);
  void addMeta(const std::string& key, std::vector<std::string>&& strValues, const std::vector<int64_t>& intValues);
  void addRR(DNSName&& qname, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& data);

  void serialize(std::string& data, bool withOpenTelemetryTraceData = true) const;

  [[nodiscard]] std::string toDebugString() const;

private:
  struct PBRecord
  {
    DNSName d_name;
    std::string d_data;
    uint32_t d_ttl;
    uint16_t d_type;
    uint16_t d_class;
  };
  struct PBQuestion
  {
    PBQuestion(DNSName name, uint16_t type, uint16_t class_) :
      d_name(std::move(name)), d_type(type), d_class(class_)
    {
    }

    DNSName d_name;
    uint16_t d_type;
    uint16_t d_class;
  };

  std::vector<PBRecord> d_additionalRRs;
  std::vector<std::string> d_additionalTags;
  struct MetaValue
  {
    std::unordered_set<std::string> d_strings;
    std::unordered_set<int64_t> d_integers;
  };
  std::unordered_map<std::string, MetaValue> d_metaTags;

  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const DNSQuestion& d_dq;
  const DNSResponse* d_dr{nullptr};
  const std::string* d_ServerIdentityRef{nullptr};

  std::optional<PBQuestion> d_question{std::nullopt};
  std::optional<std::string> d_serverIdentity{std::nullopt};
  std::optional<ComboAddress> d_requestor{std::nullopt};
  std::optional<ComboAddress> d_responder{std::nullopt};
  std::optional<Netmask> d_ednsSubnet{std::nullopt};
  std::optional<std::pair<time_t, uint32_t>> d_time{std::nullopt};
  std::optional<std::pair<time_t, uint32_t>> d_queryTime{std::nullopt};
  std::optional<size_t> d_bytes{std::nullopt};
  std::optional<uint8_t> d_rcode{std::nullopt};

  pdns::ProtoZero::Message::MessageType d_type{pdns::ProtoZero::Message::MessageType::DNSQueryType};
  bool d_includeCNAME{false};

  std::optional<std::vector<pdns::trace::Span>> d_traceSpans{std::nullopt};
};

class ProtoBufMetaKey
{
  enum class Type : uint8_t
  {
    SNI,
    Pool,
    B64Content,
    DoHHeader,
    DoHHost,
    DoHPath,
    DoHQueryString,
    DoHScheme,
    ProxyProtocolValue,
    ProxyProtocolValues,
    Tag,
    Tags
  };

  struct KeyTypeDescription
  {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const std::string d_name;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const Type d_type;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const std::function<std::vector<std::string>(const DNSQuestion&, const std::string&, uint8_t)> d_func;
    bool d_prefix{false};
    bool d_caseSensitive{true};
    bool d_numeric{false};
  };

  struct NameTag
  {
  };
  struct TypeTag
  {
  };

  using TypeContainer = boost::multi_index_container<
    KeyTypeDescription,
    boost::multi_index::indexed_by<
      boost::multi_index::hashed_unique<boost::multi_index::tag<NameTag>, boost::multi_index::member<KeyTypeDescription, const std::string, &KeyTypeDescription::d_name>>,
      boost::multi_index::hashed_unique<boost::multi_index::tag<TypeTag>, boost::multi_index::member<KeyTypeDescription, const Type, &KeyTypeDescription::d_type>>>>;

  static const TypeContainer s_types;

public:
  ProtoBufMetaKey(const std::string& key);

  [[nodiscard]] const std::string& getName() const;
  [[nodiscard]] std::vector<std::string> getValues(const DNSQuestion& dnsquestion) const;

private:
  std::string d_subKey;
  uint8_t d_numericSubKey{0};
  Type d_type;
};

#endif /* DISABLE_PROTOBUF */
