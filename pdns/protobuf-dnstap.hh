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

#include <cstddef>
#include <string>

#include "config.h"

#include "dnsname.hh"
#include "iputils.hh"

#ifdef HAVE_PROTOBUF
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include "dnstap.pb.h"
#endif /* HAVE_PROTOBUF */

#include "protobuf.hh"

class DnstapProtoBufMessage : public IfaceDNSProtoBufMessage
{
public:
  DnstapProtoBufMessage()
  {
  }

  DnstapProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type);

  ~DnstapProtoBufMessage()
  {
  }

  void addRRsFromPacket(const char* packet, const size_t len, bool includeCNAME=false);
  void serialize(std::string& data) const;
  void setBytes(size_t bytes);
  void setEDNSSubnet(const Netmask& subnet, uint8_t mask=128);
  void setQueryTime(time_t sec, uint32_t usec);
  void setQuestion(const char* packet, const size_t len);
  void setQuestion(const DNSName& qname, uint16_t qtype, uint16_t qclass);
  void setRequestor(const ComboAddress& requestor);
  void setRequestor(const std::string& requestor);
  void setResponder(const ComboAddress& responder);
  void setResponder(const std::string& responder);
  void setResponseCode(uint8_t rcode);
  void setResponseTime(time_t sec, uint32_t usec);
  void setTime(time_t sec, uint32_t usec);
  void setType(DNSProtoBufMessage::DNSProtoBufMessageType type);
  std::string toDebugString() const;

#ifdef HAVE_PROTOBUF
  DnstapProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType type, const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, const DNSName& domain, int qtype, uint16_t qclass, uint16_t qid, bool isTCP, size_t bytes);
  void setInitialRequestID(const boost::uuids::uuid& uuid);
  void setUUID(const boost::uuids::uuid& uuid);
  void update(const boost::uuids::uuid& uuid, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, uint16_t id);

protected:
  dnstap::Dnstap proto_message;
#endif /* HAVE_PROTOBUF */
};