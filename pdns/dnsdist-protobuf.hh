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

#include "dnsdist.hh"
#include "dnsname.hh"
#include "protozero.hh"

class DNSDistProtoBufMessage
{
public:
  DNSDistProtoBufMessage(const DNSQuestion& dq);
  DNSDistProtoBufMessage(const DNSResponse& dr, bool includeCNAME);

  void setServerIdentity(const std::string& serverId);
  void setRequestor(const ComboAddress& requestor);
  void setResponder(const ComboAddress& responder);
  void setRequestorPort(uint16_t port);
  void setResponderPort(uint16_t port);
  void setResponseCode(uint8_t rcode);
  void setType(pdns::ProtoZero::Message::MessageType type);
  void setBytes(size_t bytes);
  void setTime(time_t sec, uint32_t usec);
  void setQueryTime(time_t sec, uint32_t usec);
  void setQuestion(const DNSName& name, uint16_t qtype, uint16_t qclass);
  void setEDNSSubnet(const Netmask& nm);

  void addTag(const std::string& strValue);
  void addRR(DNSName&& qname, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& data);

  void serialize(std::string& data) const;

  std::string toDebugString() const;

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
    PBQuestion(const DNSName& name, uint16_t type, uint16_t class_): d_name(name), d_type(type), d_class(class_)
    {
    }

    DNSName d_name;
    uint16_t d_type;
    uint16_t d_class;
  };

  std::vector<PBRecord> d_additionalRRs;
  std::vector<std::string> d_additionalTags;

  const DNSQuestion& d_dq;
  const DNSResponse* d_dr{nullptr};
  const std::string* d_ServerIdentityRef{nullptr};

  std::optional<PBQuestion> d_question{boost::none};
  std::optional<std::string> d_serverIdentity{boost::none};
  std::optional<ComboAddress> d_requestor{boost::none};
  std::optional<ComboAddress> d_responder{boost::none};
  std::optional<Netmask> d_ednsSubnet{boost::none};
  std::optional<std::pair<time_t, uint32_t>> d_time{boost::none};
  std::optional<std::pair<time_t, uint32_t>> d_queryTime{boost::none};
  std::optional<size_t> d_bytes{boost::none};
  std::optional<uint8_t> d_rcode{boost::none};

  pdns::ProtoZero::Message::MessageType d_type{pdns::ProtoZero::Message::MessageType::DNSQueryType};
  bool d_includeCNAME{false};
};
