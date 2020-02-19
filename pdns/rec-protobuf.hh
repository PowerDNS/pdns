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

#include "protobuf.hh"
#include "filterpo.hh"
#include "dnsrecords.hh"

class RecProtoBufMessage : public DNSProtoBufMessage
{
public:
  RecProtoBufMessage() :
    DNSProtoBufMessage()
  {
  }

  RecProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type) :
    DNSProtoBufMessage(type)
  {
  }

#ifdef HAVE_PROTOBUF
  RecProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type, const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, const DNSName& domain, int qtype, uint16_t qclass, uint16_t qid, bool isTCP, size_t bytes) :
    DNSProtoBufMessage(type, uuid, requestor, responder, domain, qtype, qclass, qid, isTCP, bytes)
  {
  }
#endif /* HAVE_PROTOBUF */

  void addRRs(const std::vector<DNSRecord>& records, const std::set<uint16_t>& exportTypes);
#ifdef NOD_ENABLED
  void setNOD(bool nod);
  void addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes, bool udr = false);
  void clearUDR();
#else
  void addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes);
#endif /* NOD_ENABLED */
  void setAppliedPolicy(const std::string& policy);
  void setAppliedPolicyType(const DNSFilterEngine::PolicyType& policyType);
  void setPolicyTags(const std::vector<std::string>& policyTags);
  void addPolicyTag(const std::string& policyTag);
  void removePolicyTag(const std::string& policyTag);
  std::string getAppliedPolicy() const;
  std::vector<std::string> getPolicyTags() const;
};
