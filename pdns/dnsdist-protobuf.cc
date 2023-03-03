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
#include "config.h"

#ifndef DISABLE_PROTOBUF
#include "base64.hh"
#include "dnsdist.hh"
#include "dnsdist-protobuf.hh"
#include "protozero.hh"

DNSDistProtoBufMessage::DNSDistProtoBufMessage(const DNSQuestion& dq): d_dq(dq), d_type(pdns::ProtoZero::Message::MessageType::DNSQueryType)
{
}

DNSDistProtoBufMessage::DNSDistProtoBufMessage(const DNSResponse& dr, bool includeCNAME): d_dq(dr), d_dr(&dr), d_type(pdns::ProtoZero::Message::MessageType::DNSResponseType), d_includeCNAME(includeCNAME)
{
}

void DNSDistProtoBufMessage::setServerIdentity(const std::string& serverId)
{
  d_serverIdentity = serverId;
}

void DNSDistProtoBufMessage::setRequestor(const ComboAddress& requestor)
{
  d_requestor = requestor;
}

void DNSDistProtoBufMessage::setResponder(const ComboAddress& responder)
{
  d_responder = responder;
}

void DNSDistProtoBufMessage::setRequestorPort(uint16_t port)
{
  if (d_requestor) {
    d_requestor->setPort(port);
  }
}

void DNSDistProtoBufMessage::setResponderPort(uint16_t port)
{
  if (d_responder) {
    d_responder->setPort(port);
  }
}

void DNSDistProtoBufMessage::setResponseCode(uint8_t rcode)
{
  d_rcode = rcode;
}

void DNSDistProtoBufMessage::setType(pdns::ProtoZero::Message::MessageType type)
{
  d_type = type;
}

void DNSDistProtoBufMessage::setBytes(size_t bytes)
{
  d_bytes = bytes;
}

void DNSDistProtoBufMessage::setTime(time_t sec, uint32_t usec)
{
  d_time = std::pair(sec, usec);
}

void DNSDistProtoBufMessage::setQueryTime(time_t sec, uint32_t usec)
{
  d_queryTime = std::pair(sec, usec);
}

void DNSDistProtoBufMessage::setQuestion(const DNSName& name, uint16_t qtype, uint16_t qclass)
{
  d_question = DNSDistProtoBufMessage::PBQuestion(name, qtype, qclass);
}

void DNSDistProtoBufMessage::setEDNSSubnet(const Netmask& nm)
{
  d_ednsSubnet = nm;
}

void DNSDistProtoBufMessage::addTag(const std::string& strValue)
{
  d_additionalTags.push_back(strValue);
}

void DNSDistProtoBufMessage::addMeta(const std::string& key, std::vector<std::string>&& values)
{
  auto& entry = d_metaTags[key];
  for (auto& value : values) {
    entry.insert(std::move(value));
  }
}

void DNSDistProtoBufMessage::addRR(DNSName&& qname, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob)
{
  d_additionalRRs.push_back({std::move(qname), strBlob, uTTL, uType, uClass});
}

void DNSDistProtoBufMessage::serialize(std::string& data) const
{
  if ((data.capacity() - data.size()) < 128) {
    data.reserve(data.size() + 128);
  }
  pdns::ProtoZero::Message m{data};

  m.setType(d_type);

  if (d_time) {
    m.setTime(d_time->first, d_time->second);
  }
  else {
    struct timespec ts;
    gettime(&ts, true);
    m.setTime(ts.tv_sec, ts.tv_nsec / 1000);
  }

  const auto distProto = d_dq.getProtocol();
  pdns::ProtoZero::Message::TransportProtocol protocol = pdns::ProtoZero::Message::TransportProtocol::UDP;

  if (distProto == dnsdist::Protocol::DoTCP) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::TCP;
  }
  else if (distProto == dnsdist::Protocol::DoT) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::DoT;
  }
  else if (distProto == dnsdist::Protocol::DoH) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::DoH;
  }
  else if (distProto == dnsdist::Protocol::DNSCryptUDP) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::DNSCryptUDP;
  }
  else if (distProto == dnsdist::Protocol::DNSCryptTCP) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::DNSCryptTCP;
  }

  m.setRequest(d_dq.ids.d_protoBufData && d_dq.ids.d_protoBufData->uniqueId ? *d_dq.ids.d_protoBufData->uniqueId : getUniqueID(), d_requestor ? *d_requestor : d_dq.ids.origRemote, d_responder ? *d_responder : d_dq.ids.origDest, d_question ? d_question->d_name : d_dq.ids.qname, d_question ? d_question->d_type : d_dq.ids.qtype, d_question ? d_question->d_class : d_dq.ids.qclass, d_dq.getHeader()->id, protocol, d_bytes ? *d_bytes : d_dq.getData().size());

  if (d_serverIdentity) {
    m.setServerIdentity(*d_serverIdentity);
  }
  else if (d_ServerIdentityRef != nullptr) {
    m.setServerIdentity(*d_ServerIdentityRef);
  }

  if (d_ednsSubnet) {
    m.setEDNSSubnet(*d_ednsSubnet, 128);
  }

  m.startResponse();
  if (d_queryTime) {
    // coverity[store_truncates_time_t]
    m.setQueryTime(d_queryTime->first, d_queryTime->second);
  }
  else {
    m.setQueryTime(d_dq.getQueryRealTime().tv_sec, d_dq.getQueryRealTime().tv_nsec / 1000);
  }

  if (d_dr != nullptr) {
    m.setResponseCode(d_rcode ? *d_rcode : d_dr->getHeader()->rcode);
    m.addRRsFromPacket(reinterpret_cast<const char*>(d_dr->getData().data()), d_dr->getData().size(), d_includeCNAME);
  }
  else {
    if (d_rcode) {
      m.setResponseCode(*d_rcode);
    }
  }

  for (const auto& rr : d_additionalRRs) {
    m.addRR(rr.d_name, rr.d_type, rr.d_class, rr.d_ttl, rr.d_data);
  }

  for (const auto& tag : d_additionalTags) {
    m.addPolicyTag(tag);
  }

  m.commitResponse();

  if (d_dq.ids.d_protoBufData) {
    const auto& pbData = d_dq.ids.d_protoBufData;
    if (!pbData->d_deviceName.empty()) {
      m.setDeviceName(pbData->d_deviceName);
    }
    if (!pbData->d_deviceID.empty()) {
      m.setDeviceId(pbData->d_deviceID);
    }
    if (!pbData->d_requestorID.empty()) {
      m.setRequestorId(pbData->d_requestorID);
    }
  }

  for (const auto& [key, values] : d_metaTags) {
    if (!values.empty()) {
      m.setMeta(key, values, {});
    }
    else {
      /* the MetaValue field is _required_ to exist, even if we have no value */
      m.setMeta(key, {std::string()}, {});
    }
  }
}

ProtoBufMetaKey::ProtoBufMetaKey(const std::string& key)
{
  auto& idx = s_types.get<NameTag>();
  auto it = idx.find(key);
  if (it != idx.end()) {
    d_type = it->d_type;
    return;
  }
  else {
    auto [prefix, variable] = splitField(key, ':');
    if (!variable.empty()) {
      it = idx.find(prefix);
      if (it != idx.end() && it->d_prefix) {
        d_type = it->d_type;
        if (it->d_numeric) {
          try {
            d_numericSubKey = std::stoi(variable);
          }
          catch (const std::exception& e) {
            throw std::runtime_error("Unable to parse numeric ProtoBuf key '" + key + "'");
          }
        }
        else {
          if (!it->d_caseSensitive) {
            boost::algorithm::to_lower(variable);
          }
          d_subKey = variable;
        }
        return;
      }
    }
  }
  throw std::runtime_error("Invalid ProtoBuf key '" + key + "'");
}

std::vector<std::string> ProtoBufMetaKey::getValues(const DNSQuestion& dq) const
{
  auto& idx = s_types.get<TypeTag>();
  auto it = idx.find(d_type);
  if (it == idx.end()) {
    throw std::runtime_error("Trying to get the values of an unsupported type: " + std::to_string(static_cast<uint8_t>(d_type)));
  }
  return (it->d_func)(dq, d_subKey, d_numericSubKey);
}

const std::string& ProtoBufMetaKey::getName() const
{
  auto& idx = s_types.get<TypeTag>();
  auto it = idx.find(d_type);
  if (it == idx.end()) {
    throw std::runtime_error("Trying to get the name of an unsupported type: " + std::to_string(static_cast<uint8_t>(d_type)));
  }
  return it->d_name;
}

const ProtoBufMetaKey::TypeContainer ProtoBufMetaKey::s_types = {
  ProtoBufMetaKey::KeyTypeDescription{ "sni", Type::SNI, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> { return {dq.sni}; }, false },
  ProtoBufMetaKey::KeyTypeDescription{ "pool", Type::Pool, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> { return {dq.ids.poolName}; }, false },
  ProtoBufMetaKey::KeyTypeDescription{ "b64-content", Type::B64Content, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> { const auto& data = dq.getData(); return {Base64Encode(std::string(data.begin(), data.end()))}; }, false },
#ifdef HAVE_DNS_OVER_HTTPS
  ProtoBufMetaKey::KeyTypeDescription{ "doh-header", Type::DoHHeader, [](const DNSQuestion& dq , const std::string& name, uint8_t) -> std::vector<std::string> {
    if (!dq.ids.du) {
      return {};
    }
    auto headers = dq.ids.du->getHTTPHeaders();
    auto it = headers.find(name);
    if (it != headers.end()) {
      return {it->second};
    }
    return {};
  }, true, false },
  ProtoBufMetaKey::KeyTypeDescription{ "doh-host", Type::DoHHost, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> {
    if (dq.ids.du) {
      return {dq.ids.du->getHTTPHost()};
    }
    return {};
  }, true, false },
  ProtoBufMetaKey::KeyTypeDescription{ "doh-path", Type::DoHPath, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> {
    if (dq.ids.du) {
      return {dq.ids.du->getHTTPPath()};
    }
    return {};
    }, false },
  ProtoBufMetaKey::KeyTypeDescription{ "doh-query-string", Type::DoHQueryString, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> {
    if (dq.ids.du) {
      return {dq.ids.du->getHTTPQueryString()};
    }
    return {};
    }, false },
  ProtoBufMetaKey::KeyTypeDescription{ "doh-scheme", Type::DoHScheme, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> {
    if (dq.ids.du) {
      return {dq.ids.du->getHTTPScheme()};
    }
    return {};
    }, false, false },
#endif // HAVE_DNS_OVER_HTTPS
  ProtoBufMetaKey::KeyTypeDescription{ "proxy-protocol-value", Type::ProxyProtocolValue, [](const DNSQuestion& dq, const std::string&, uint8_t numericSubKey) -> std::vector<std::string> {
    if (!dq.proxyProtocolValues) {
      return {};
    }
    for (const auto& value : *dq.proxyProtocolValues) {
      if (value.type == numericSubKey) {
        return {value.content};
      }
    }
    return {};
  }, true, false, true },
  ProtoBufMetaKey::KeyTypeDescription{ "proxy-protocol-values", Type::ProxyProtocolValues, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> {
    std::vector<std::string> result;
    if (!dq.proxyProtocolValues) {
      return result;
    }
    for (const auto& value : *dq.proxyProtocolValues) {
      result.push_back(std::to_string(value.type) + ":" + value.content);
    }
    return result;
  } },
  ProtoBufMetaKey::KeyTypeDescription{ "tag", Type::Tag, [](const DNSQuestion& dq, const std::string& subKey, uint8_t) -> std::vector<std::string> {
    if (!dq.ids.qTag) {
      return {};
    }
    for (const auto& [key, value] : *dq.ids.qTag) {
      if (key == subKey) {
        return {value};
      }
    }
    return {};
  }, true, true },
  ProtoBufMetaKey::KeyTypeDescription{ "tags", Type::Tags, [](const DNSQuestion& dq, const std::string&, uint8_t) -> std::vector<std::string> {
    std::vector<std::string> result;
    if (!dq.ids.qTag) {
      return result;
    }
    for (const auto& [key, value] : *dq.ids.qTag) {
      if (value.empty()) {
        /* avoids a spurious ':' when the value is empty */
        result.push_back(key);
      }
      else {
        result.push_back(key + ":" + value);
      }
    }
    return result;
  } },
};

#endif /* DISABLE_PROTOBUF */
