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
#include "protozero-trace.hh"
#include <vector>

#ifndef DISABLE_PROTOBUF
#include "base64.hh"
#include "dnsdist.hh"
#include "dnsdist-protobuf.hh"
#include "protozero.hh"

DNSDistProtoBufMessage::DNSDistProtoBufMessage(const DNSQuestion& dnsquestion) :
  d_dq(dnsquestion)
{
}

DNSDistProtoBufMessage::DNSDistProtoBufMessage(const DNSResponse& dnsresponse, bool includeCNAME) :
  d_dq(dnsresponse), d_dr(&dnsresponse), d_type(pdns::ProtoZero::Message::MessageType::DNSResponseType), d_includeCNAME(includeCNAME)
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

void DNSDistProtoBufMessage::addMeta(const std::string& key, std::vector<std::string>&& strValues, const std::vector<int64_t>& intValues)
{
  auto& entry = d_metaTags[key];
  for (auto& value : strValues) {
    entry.d_strings.insert(std::move(value));
  }
  for (const auto& value : intValues) {
    entry.d_integers.insert(value);
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
  pdns::ProtoZero::Message msg{data};

  msg.setType(d_type);

  if (d_time) {
    msg.setTime(d_time->first, d_time->second);
  }
  else {
    timespec now{};
    gettime(&now, true);
    msg.setTime(now.tv_sec, now.tv_nsec / 1000);
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
    msg.setHTTPVersion(pdns::ProtoZero::Message::HTTPVersion::HTTP2);
  }
  else if (distProto == dnsdist::Protocol::DoH3) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::DoH;
    msg.setHTTPVersion(pdns::ProtoZero::Message::HTTPVersion::HTTP3);
  }
  else if (distProto == dnsdist::Protocol::DNSCryptUDP) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::DNSCryptUDP;
  }
  else if (distProto == dnsdist::Protocol::DNSCryptTCP) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::DNSCryptTCP;
  }
  else if (distProto == dnsdist::Protocol::DoQ) {
    protocol = pdns::ProtoZero::Message::TransportProtocol::DoQ;
  }

  msg.setRequest(d_dq.ids.d_protoBufData && d_dq.ids.d_protoBufData->uniqueId ? *d_dq.ids.d_protoBufData->uniqueId : getUniqueID(), d_requestor ? *d_requestor : d_dq.ids.origRemote, d_responder ? *d_responder : d_dq.ids.origDest, d_question ? d_question->d_name : d_dq.ids.qname, d_question ? d_question->d_type : d_dq.ids.qtype, d_question ? d_question->d_class : d_dq.ids.qclass, d_dq.getHeader()->id, protocol, d_bytes ? *d_bytes : d_dq.getData().size());

  if (d_serverIdentity) {
    msg.setServerIdentity(*d_serverIdentity);
  }
  else if (d_ServerIdentityRef != nullptr) {
    msg.setServerIdentity(*d_ServerIdentityRef);
  }

  if (d_ednsSubnet) {
    msg.setEDNSSubnet(*d_ednsSubnet, 128);
  }

  if (d_dr != nullptr) {
    msg.setPacketCacheHit(d_dr->ids.cacheHit);
    msg.setOutgoingQueries((d_dr->ids.cacheHit || d_dr->ids.selfGenerated) ? 0 : 1);
  }
  msg.startResponse();
  if (d_queryTime) {
    // coverity[store_truncates_time_t]
    msg.setQueryTime(d_queryTime->first, d_queryTime->second);
  }
  else {
    msg.setQueryTime(d_dq.getQueryRealTime().tv_sec, d_dq.getQueryRealTime().tv_nsec / 1000);
  }

  if (d_dr != nullptr) {
    msg.setResponseCode(d_rcode ? *d_rcode : d_dr->getHeader()->rcode);
    try {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      msg.addRRsFromPacket(reinterpret_cast<const char*>(d_dr->getData().data()), d_dr->getData().size(), d_includeCNAME);
    }
    catch (const std::exception& exp) {
      vinfolog("Error while parsing the RRs from a response packet to add them to the protobuf message: %s", exp.what());
    }
  }
  else {
    if (d_rcode) {
      msg.setResponseCode(*d_rcode);
    }
  }

  for (const auto& arr : d_additionalRRs) {
    msg.addRR(arr.d_name, arr.d_type, arr.d_class, arr.d_ttl, arr.d_data);
  }

  for (const auto& tag : d_additionalTags) {
    msg.addPolicyTag(tag);
  }

  msg.commitResponse();

  if (d_dq.ids.d_protoBufData) {
    const auto& pbData = d_dq.ids.d_protoBufData;
    if (!pbData->d_deviceName.empty()) {
      msg.setDeviceName(pbData->d_deviceName);
    }
    if (!pbData->d_deviceID.empty()) {
      msg.setDeviceId(pbData->d_deviceID);
    }
    if (!pbData->d_requestorID.empty()) {
      msg.setRequestorId(pbData->d_requestorID);
    }
  }

  for (const auto& [key, values] : d_metaTags) {
    if (!values.d_strings.empty() || !values.d_integers.empty()) {
      msg.setMeta(key, values.d_strings, values.d_integers);
    }
    else {
      /* the MetaValue field is _required_ to exist, even if we have no value */
      msg.setMeta(key, {std::string()}, {});
    }
  }

  if (d_dq.ids.tracingEnabled) {
    msg.setOpenTelemtryTraceID(d_dq.ids.d_OTTracer->getTraceID());
    msg.setOpenTelemetryData(d_dq.ids.d_OTTracer->getOTProtobuf());
  }
}

ProtoBufMetaKey::ProtoBufMetaKey(const std::string& key)
{
  auto& idx = s_types.get<NameTag>();
  auto typeIt = idx.find(key);
  if (typeIt != idx.end()) {
    d_type = typeIt->d_type;
    return;
  }
  else {
    auto [prefix, variable] = splitField(key, ':');
    if (!variable.empty()) {
      typeIt = idx.find(prefix);
      if (typeIt != idx.end() && typeIt->d_prefix) {
        d_type = typeIt->d_type;
        if (typeIt->d_numeric) {
          try {
            d_numericSubKey = std::stoi(variable);
          }
          catch (const std::exception& e) {
            throw std::runtime_error("Unable to parse numeric ProtoBuf key '" + key + "'");
          }
        }
        else {
          if (!typeIt->d_caseSensitive) {
            boost::algorithm::to_lower(variable);
          }
          d_subKey = std::move(variable);
        }
        return;
      }
    }
  }
  throw std::runtime_error("Invalid ProtoBuf key '" + key + "'");
}

std::vector<std::string> ProtoBufMetaKey::getValues(const DNSQuestion& dnsquestion) const
{
  auto& idx = s_types.get<TypeTag>();
  auto typeIt = idx.find(d_type);
  if (typeIt == idx.end()) {
    throw std::runtime_error("Trying to get the values of an unsupported type: " + std::to_string(static_cast<uint8_t>(d_type)));
  }
  return (typeIt->d_func)(dnsquestion, d_subKey, d_numericSubKey);
}

const std::string& ProtoBufMetaKey::getName() const
{
  auto& idx = s_types.get<TypeTag>();
  auto typeIt = idx.find(d_type);
  if (typeIt == idx.end()) {
    throw std::runtime_error("Trying to get the name of an unsupported type: " + std::to_string(static_cast<uint8_t>(d_type)));
  }
  return typeIt->d_name;
}

const ProtoBufMetaKey::TypeContainer ProtoBufMetaKey::s_types = {
  ProtoBufMetaKey::KeyTypeDescription{"sni", Type::SNI, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> { return {dnsquestion.sni}; }, false},
  ProtoBufMetaKey::KeyTypeDescription{"pool", Type::Pool, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> { return {dnsquestion.ids.poolName}; }, false},
  ProtoBufMetaKey::KeyTypeDescription{"b64-content", Type::B64Content, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> { const auto& data = dnsquestion.getData(); return {Base64Encode(std::string(data.begin(), data.end()))}; }, false},
#ifdef HAVE_DNS_OVER_HTTPS
  ProtoBufMetaKey::KeyTypeDescription{"doh-header", Type::DoHHeader, [](const DNSQuestion& dnsquestion, const std::string& name, uint8_t) -> std::vector<std::string> {
                                        if (!dnsquestion.ids.du) {
                                          return {};
                                        }
                                        auto headers = dnsquestion.ids.du->getHTTPHeaders();
                                        auto iter = headers.find(name);
                                        if (iter != headers.end()) {
                                          return {iter->second};
                                        }
                                        return {};
                                      },
                                      true, false},
  ProtoBufMetaKey::KeyTypeDescription{"doh-host", Type::DoHHost, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> {
                                        if (dnsquestion.ids.du) {
                                          return {dnsquestion.ids.du->getHTTPHost()};
                                        }
                                        return {};
                                      },
                                      true, false},
  ProtoBufMetaKey::KeyTypeDescription{"doh-path", Type::DoHPath, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> {
                                        if (dnsquestion.ids.du) {
                                          return {dnsquestion.ids.du->getHTTPPath()};
                                        }
                                        return {};
                                      },
                                      false},
  ProtoBufMetaKey::KeyTypeDescription{"doh-query-string", Type::DoHQueryString, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> {
                                        if (dnsquestion.ids.du) {
                                          return {dnsquestion.ids.du->getHTTPQueryString()};
                                        }
                                        return {};
                                      },
                                      false},
  ProtoBufMetaKey::KeyTypeDescription{"doh-scheme", Type::DoHScheme, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> {
                                        if (dnsquestion.ids.du) {
                                          return {dnsquestion.ids.du->getHTTPScheme()};
                                        }
                                        return {};
                                      },
                                      false, false},
#endif // HAVE_DNS_OVER_HTTPS
  ProtoBufMetaKey::KeyTypeDescription{"proxy-protocol-value", Type::ProxyProtocolValue, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t numericSubKey) -> std::vector<std::string> {
                                        if (!dnsquestion.proxyProtocolValues) {
                                          return {};
                                        }
                                        for (const auto& value : *dnsquestion.proxyProtocolValues) {
                                          if (value.type == numericSubKey) {
                                            return {value.content};
                                          }
                                        }
                                        return {};
                                      },
                                      true, false, true},
  ProtoBufMetaKey::KeyTypeDescription{"proxy-protocol-values", Type::ProxyProtocolValues, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> {
                                        std::vector<std::string> result;
                                        if (!dnsquestion.proxyProtocolValues) {
                                          return result;
                                        }
                                        for (const auto& value : *dnsquestion.proxyProtocolValues) {
                                          result.push_back(std::to_string(value.type) + ":" + value.content);
                                        }
                                        return result;
                                      }},
  ProtoBufMetaKey::KeyTypeDescription{"tag", Type::Tag, [](const DNSQuestion& dnsquestion, const std::string& subKey, uint8_t) -> std::vector<std::string> {
                                        if (!dnsquestion.ids.qTag) {
                                          return {};
                                        }
                                        for (const auto& [key, value] : *dnsquestion.ids.qTag) {
                                          if (key == subKey) {
                                            return {value};
                                          }
                                        }
                                        return {};
                                      },
                                      true, true},
  ProtoBufMetaKey::KeyTypeDescription{"tags", Type::Tags, [](const DNSQuestion& dnsquestion, const std::string&, uint8_t) -> std::vector<std::string> {
                                        std::vector<std::string> result;
                                        if (!dnsquestion.ids.qTag) {
                                          return result;
                                        }
                                        for (const auto& [key, value] : *dnsquestion.ids.qTag) {
                                          if (value.empty()) {
                                            /* avoids a spurious ':' when the value is empty */
                                            result.push_back(key);
                                          }
                                          else {
                                            auto tag = key;
                                            tag.append(":");
                                            tag.append(value);
                                            result.push_back(std::move(tag));
                                          }
                                        }
                                        return result;
                                      }},
};

#endif /* DISABLE_PROTOBUF */
