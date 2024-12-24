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
#include <random>

#include "dnsdist-self-answers.hh"

#include "dnsdist-configuration.hh"
#include "dnsdist-ecs.hh"

namespace dnsdist::self_answers
{
static thread_local std::default_random_engine t_randomEngine;

static void addRecordHeader(PacketBuffer& packet, size_t& position, uint16_t qclass, uint32_t ttl, QType qtype, uint16_t rdataLen)
{
  std::array<unsigned char, 12> recordstart{
    0xc0, 0x0c, // compressed name
    0, 0, // QTYPE
    0, 0, // QCLASS
    0, 0, 0, 0, // TTL
    0, 0 // rdata length
  };
  ttl = htonl(ttl);
  qclass = htons(qclass);
  qtype = htons(qtype);
  rdataLen = htons(rdataLen);
  static_assert(recordstart.size() == 12, "sizeof(recordstart) must be equal to 12, otherwise the above check is invalid");
  memcpy(&recordstart.at(2), &qtype, sizeof(qtype));
  memcpy(&recordstart.at(4), &qclass, sizeof(qclass));
  memcpy(&recordstart.at(6), &ttl, sizeof(ttl));
  memcpy(&recordstart.at(10), &rdataLen, sizeof(rdataLen));
  memcpy(&packet.at(position), recordstart.data(), recordstart.size());
  position += recordstart.size();
}

bool generateAnswerFromCNAME(DNSQuestion& dnsQuestion, const DNSName& cname, const dnsdist::ResponseConfig& responseConfig)
{
  QType qtype = QType::CNAME;
  unsigned int totrdatalen = cname.getStorage().size();
  size_t numberOfRecords = 1U;
  auto qnameWireLength = dnsQuestion.ids.qname.wirelength();
  if (dnsQuestion.getMaximumSize() < (sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totrdatalen)) {
    return false;
  }

  bool dnssecOK = false;
  bool hadEDNS = false;
  if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses && queryHasEDNS(dnsQuestion)) {
    hadEDNS = true;
    dnssecOK = ((dnsdist::getEDNSZ(dnsQuestion) & EDNS_HEADER_FLAG_DO) != 0);
  }

  auto& data = dnsQuestion.getMutableData();
  data.resize(sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totrdatalen); // there goes your EDNS
  size_t position = sizeof(dnsheader) + qnameWireLength + 4;

  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [responseConfig](dnsheader& header) {
    header.qr = true; // for good measure
    setResponseHeadersFromConfig(header, responseConfig);
    header.ancount = 0;
    header.arcount = 0; // for now, forget about your EDNS, we're marching over it
    return true;
  });

  const auto& wireData = cname.getStorage(); // Note! This doesn't do compression!
  addRecordHeader(data, position, dnsQuestion.ids.qclass, responseConfig.ttl, qtype, wireData.length());
  memcpy(&data.at(position), wireData.c_str(), wireData.length());

  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [numberOfRecords](dnsheader& header) {
    header.ancount = htons(numberOfRecords);
    return true;
  });

  if (hadEDNS) {
    addEDNS(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnssecOK, dnsdist::configuration::getCurrentRuntimeConfiguration().d_payloadSizeSelfGenAnswers, 0);
  }

  return true;
}

bool generateAnswerFromIPAddresses(DNSQuestion& dnsQuestion, const std::vector<ComboAddress>& addresses, const dnsdist::ResponseConfig& responseConfig)
{
  uint16_t qtype = dnsQuestion.ids.qtype;
  std::vector<ComboAddress> addrs = {};
  unsigned int totrdatalen = 0;
  size_t numberOfRecords = 0;
  for (const auto& addr : addresses) {
    if (qtype != QType::ANY && ((addr.sin4.sin_family == AF_INET && qtype != QType::A) || (addr.sin4.sin_family == AF_INET6 && qtype != QType::AAAA))) {
      continue;
    }
    totrdatalen += addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr);
    addrs.push_back(addr);
    ++numberOfRecords;
  }

  if (addrs.size() > 1) {
    shuffle(addrs.begin(), addrs.end(), t_randomEngine);
  }

  unsigned int qnameWireLength = dnsQuestion.ids.qname.wirelength();
  if (dnsQuestion.getMaximumSize() < (sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totrdatalen)) {
    return false;
  }

  bool dnssecOK = false;
  bool hadEDNS = false;
  if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses && queryHasEDNS(dnsQuestion)) {
    hadEDNS = true;
    dnssecOK = ((dnsdist::getEDNSZ(dnsQuestion) & EDNS_HEADER_FLAG_DO) != 0);
  }

  auto& data = dnsQuestion.getMutableData();
  data.resize(sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totrdatalen); // there goes your EDNS
  size_t position = sizeof(dnsheader) + qnameWireLength + 4;

  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [responseConfig](dnsheader& header) {
    header.qr = true; // for good measure
    setResponseHeadersFromConfig(header, responseConfig);
    header.ancount = 0;
    header.arcount = 0; // for now, forget about your EDNS, we're marching over it
    return true;
  });

  for (const auto& addr : addrs) {
    uint16_t rdataLen = addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr);
    qtype = addr.sin4.sin_family == AF_INET ? QType::A : QType::AAAA;

    addRecordHeader(data, position, dnsQuestion.ids.qclass, responseConfig.ttl, qtype, rdataLen);

    memcpy(&data.at(position),
           // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
           addr.sin4.sin_family == AF_INET ? reinterpret_cast<const void*>(&addr.sin4.sin_addr.s_addr) : reinterpret_cast<const void*>(&addr.sin6.sin6_addr.s6_addr),
           addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr));

    position += (addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr));
  }

  auto finalANCount = addrs.size();
  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [finalANCount](dnsheader& header) {
    header.ancount = htons(finalANCount);
    return true;
  });

  if (hadEDNS) {
    addEDNS(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnssecOK, dnsdist::configuration::getCurrentRuntimeConfiguration().d_payloadSizeSelfGenAnswers, 0);
  }

  return true;
}

bool generateAnswerFromRDataEntries(DNSQuestion& dnsQuestion, const std::vector<std::string>& entries, std::optional<uint16_t> typeForAny, const dnsdist::ResponseConfig& responseConfig)
{
  unsigned int totrdatalen = 0;
  size_t numberOfRecords = 0;
  auto shuffledEntries = entries;
  for (const auto& entry : shuffledEntries) {
    totrdatalen += entry.size();
    ++numberOfRecords;
  }
  if (shuffledEntries.size() > 1) {
    shuffle(shuffledEntries.begin(), shuffledEntries.end(), t_randomEngine);
  }

  auto qnameWireLength = dnsQuestion.ids.qname.wirelength();
  if (dnsQuestion.getMaximumSize() < (sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totrdatalen)) {
    return false;
  }

  bool dnssecOK = false;
  bool hadEDNS = false;
  if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses && queryHasEDNS(dnsQuestion)) {
    hadEDNS = true;
    dnssecOK = ((dnsdist::getEDNSZ(dnsQuestion) & EDNS_HEADER_FLAG_DO) != 0);
  }

  auto& data = dnsQuestion.getMutableData();
  data.resize(sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totrdatalen); // there goes your EDNS
  size_t position = sizeof(dnsheader) + qnameWireLength + 4;

  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [&responseConfig](dnsheader& header) {
    header.qr = true; // for good measure
    setResponseHeadersFromConfig(header, responseConfig);
    header.ancount = 0;
    header.arcount = 0; // for now, forget about your EDNS, we're marching over it
    return true;
  });

  QType qtype = dnsQuestion.ids.qtype;
  if (qtype == QType::ANY && typeForAny) {
    qtype = *typeForAny;
  }

  for (const auto& entry : shuffledEntries) {
    uint16_t rdataLen = entry.size();
    addRecordHeader(data, position, dnsQuestion.ids.qclass, responseConfig.ttl, qtype, rdataLen);
    memcpy(&data.at(position), entry.c_str(), entry.size());
    position += entry.size();
  }

  auto finalANCount = shuffledEntries.size();
  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [finalANCount](dnsheader& header) {
    header.ancount = htons(finalANCount);
    return true;
  });

  if (hadEDNS) {
    addEDNS(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnssecOK, dnsdist::configuration::getCurrentRuntimeConfiguration().d_payloadSizeSelfGenAnswers, 0);
  }

  return true;
}

bool generateAnswerFromRawPacket(DNSQuestion& dnsQuestion, const PacketBuffer& packet)
{
  auto questionId = dnsQuestion.getHeader()->id;
  dnsQuestion.getMutableData() = packet;
  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [questionId](dnsheader& header) {
    header.id = questionId;
    return true;
  });
  return true;
}

}
