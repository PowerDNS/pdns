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
#include "dnsdist-svc.hh"
#include "dnsdist.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-lua.hh"
#include "dnswriter.hh"
#include "svc-records.hh"

bool generateSVCPayload(std::vector<uint8_t>& payload, uint16_t priority, const DNSName& target, const std::set<uint16_t>& mandatoryParams, const std::vector<std::string>& alpns, bool noDefaultAlpn, std::optional<uint16_t> port, const std::string& ech, const std::vector<ComboAddress>& ipv4hints, const std::vector<ComboAddress>& ipv6hints, const std::vector<std::pair<uint16_t, std::string>>& additionalParams)
{
  // this is an _ordered_ set and the comparison operator is properly defined,
  // so the parameters will be ordered as defined in the RFC
  std::set<SvcParam> params;

  if (!mandatoryParams.empty()) {
    std::set<SvcParam::SvcParamKey> mandatoryKeys;
    for (const auto& entry : mandatoryParams) {
      mandatoryKeys.insert(static_cast<SvcParam::SvcParamKey>(entry));
    }
    params.insert({SvcParam::SvcParamKey::mandatory, std::move(mandatoryKeys)});
  }

  if (!alpns.empty()) {
    params.insert({SvcParam::SvcParamKey::alpn, std::vector<std::string>(alpns)});
  }

  if (noDefaultAlpn) {
    params.insert({SvcParam::SvcParamKey::no_default_alpn});
  }

  if (port) {
    params.insert({SvcParam::SvcParamKey::port, *port});
  }

  if (!ipv4hints.empty()) {
    params.insert({SvcParam::SvcParamKey::ipv4hint, std::vector<ComboAddress>(ipv4hints)});
  }

  if (!ech.empty()) {
    params.insert({SvcParam::SvcParamKey::ech, ech});
  }

  if (!ipv6hints.empty()) {
    params.insert({SvcParam::SvcParamKey::ipv6hint, std::vector<ComboAddress>(ipv6hints)});
  }

  for (const auto& param : additionalParams) {
    params.insert({static_cast<SvcParam::SvcParamKey>(param.first), param.second});
  }

  if (priority == 0 && params.size() != 0) {
    return false;
  }

  payload.clear();
  /* we will remove the header, question and record header parts later */
  DNSPacketWriter pw(payload, g_rootdnsname, QType::A, QClass::IN, 0);
  pw.startRecord(g_rootdnsname, QType::A, 60, QClass::IN, DNSResourceRecord::ANSWER, false);
  size_t offset = pw.size();
  pw.xfr16BitInt(priority);
  pw.xfrName(target, false);
  pw.xfrSvcParamKeyVals(params);
  pw.commit();

  if (payload.size() <= offset) {
    return false;
  }

  payload.erase(payload.begin(), payload.begin() + offset);
  return true;
}

bool generateSVCPayload(std::vector<uint8_t>& payload, const SVCRecordParameters& parameters)
{
  return generateSVCPayload(payload, parameters.priority, parameters.target, parameters.mandatoryParams, parameters.alpns, parameters.noDefaultAlpn, parameters.port, parameters.ech, parameters.ipv4hints, parameters.ipv6hints, parameters.additionalParams);
}

struct SVCRecordParameters parseSVCParameters(const svcParamsLua_t& params)
{
  struct SVCRecordParameters parameters;
  for (const auto& p : params) {
    if (p.first == "mandatory") {
      for (auto const& entry : boost::get<std::vector<std::pair<int, std::string>>>(p.second)) {
        parameters.mandatoryParams.insert(SvcParam::keyFromString(entry.second));
      }
    }
    else if (p.first == "alpn") {
      for (auto const& entry : boost::get<std::vector<std::pair<int, std::string>>>(p.second)) {
        parameters.alpns.push_back(entry.second);
      }
    }
    else if (p.first == "noDefaultAlpn") {
      parameters.noDefaultAlpn = boost::get<bool>(p.second);
    }
    else if (p.first == "port") {
      parameters.port = boost::get<uint16_t>(p.second);
    }
    else if (p.first == "ipv4hint") {
      for (auto const& entry : boost::get<std::vector<std::pair<int, std::string>>>(p.second)) {
        parameters.ipv4hints.push_back(ComboAddress(entry.second));
      }
    }
    else if (p.first == "ech") {
      parameters.ech = boost::get<std::string>(p.second);
    }
    else if (p.first == "ipv6hint") {
      for (auto const& entry : boost::get<std::vector<std::pair<int, std::string>>>(p.second)) {
        parameters.ipv6hints.push_back(ComboAddress(entry.second));
      }
    }
    else {
      parameters.additionalParams.push_back({SvcParam::keyFromString(p.first), boost::get<std::string>(p.second)});
    }
  }
  return parameters;
}

namespace dnsdist::svc
{
bool generateSVCResponse(DNSQuestion& dnsQuestion, const std::vector<std::vector<uint8_t>>& svcRecordPayloads, const std::set<std::pair<DNSName, ComboAddress>>& additionals4, const std::set<std::pair<DNSName, ComboAddress>>& additionals6, const ResponseConfig& responseConfig)
{
  /* it will likely be a bit bigger than that because of additionals */
  size_t totalPayloadsSize = 0;
  for (const auto& payload : svcRecordPayloads) {
    totalPayloadsSize += payload.size();
  }
  const auto numberOfRecords = svcRecordPayloads.size();
  const auto qnameWireLength = dnsQuestion.ids.qname.wirelength();
  if (dnsQuestion.getMaximumSize() < (sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totalPayloadsSize)) {
    return false;
  }

  PacketBuffer newPacket;
  newPacket.reserve(sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totalPayloadsSize);
  GenericDNSPacketWriter<PacketBuffer> packetWriter(newPacket, dnsQuestion.ids.qname, dnsQuestion.ids.qtype);
  for (const auto& payload : svcRecordPayloads) {
    packetWriter.startRecord(dnsQuestion.ids.qname, dnsQuestion.ids.qtype, responseConfig.ttl);
    packetWriter.xfrBlob(payload);
    packetWriter.commit();
  }

  if (newPacket.size() < dnsQuestion.getMaximumSize()) {
    for (const auto& additional : additionals4) {
      packetWriter.startRecord(additional.first.isRoot() ? dnsQuestion.ids.qname : additional.first, QType::A, responseConfig.ttl, QClass::IN, DNSResourceRecord::ADDITIONAL);
      packetWriter.xfrCAWithoutPort(4, additional.second);
      packetWriter.commit();
    }
  }

  if (newPacket.size() < dnsQuestion.getMaximumSize()) {
    for (const auto& additional : additionals6) {
      packetWriter.startRecord(additional.first.isRoot() ? dnsQuestion.ids.qname : additional.first, QType::AAAA, responseConfig.ttl, QClass::IN, DNSResourceRecord::ADDITIONAL);
      packetWriter.xfrCAWithoutPort(6, additional.second);
      packetWriter.commit();
    }
  }

  const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (runtimeConfig.d_addEDNSToSelfGeneratedResponses && queryHasEDNS(dnsQuestion)) {
    bool dnssecOK = ((dnsdist::getEDNSZ(dnsQuestion) & EDNS_HEADER_FLAG_DO) != 0);
    packetWriter.addOpt(runtimeConfig.d_payloadSizeSelfGenAnswers, 0, dnssecOK ? EDNS_HEADER_FLAG_DO : 0);
    packetWriter.commit();
  }

  if (newPacket.size() >= dnsQuestion.getMaximumSize()) {
    /* sorry! */
    return false;
  }

  packetWriter.getHeader()->id = dnsQuestion.getHeader()->id;
  packetWriter.getHeader()->qr = true; // for good measure
  setResponseHeadersFromConfig(*packetWriter.getHeader(), responseConfig);
  dnsQuestion.getMutableData() = std::move(newPacket);

  return true;
}

bool generateSVCResponse(DNSQuestion& dnsQuestion, uint32_t ttl, const std::vector<SVCRecordParameters>& parameters)
{
  std::vector<std::vector<uint8_t>> payloads;
  std::set<std::pair<DNSName, ComboAddress>> additionals4;
  std::set<std::pair<DNSName, ComboAddress>> additionals6;
  ResponseConfig responseConfig;
  responseConfig.setAA = true;
  responseConfig.ttl = ttl;

  payloads.reserve(parameters.size());
  for (const auto& parameter : parameters) {
    std::vector<uint8_t> payload;
    if (!generateSVCPayload(payload, parameter)) {
      throw std::runtime_error("Unable to generate a valid SVC record from the supplied parameters");
    }

    payloads.push_back(std::move(payload));

    for (const auto& hint : parameter.ipv4hints) {
      additionals4.insert({parameter.target, ComboAddress(hint)});
    }

    for (const auto& hint : parameter.ipv6hints) {
      additionals6.insert({parameter.target, ComboAddress(hint)});
    }
  }

  return generateSVCResponse(dnsQuestion, payloads, additionals4, additionals6, responseConfig);
}
}
