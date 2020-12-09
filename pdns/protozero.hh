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

#include "ext/protozero/include/protozero/pbf_writer.hpp"

#include "config.h"
#include "iputils.hh"
#include "gettime.hh"
#include "uuid-utils.hh"

namespace pdns {
  namespace ProtoZero {
    class Message {
    public:
      Message(std::string& buffer): d_buffer(buffer), d_message{d_buffer}
      {
      }

      Message(const Message&) = delete;
      Message(Message&&) = delete;
      Message& operator=(const Message&) = delete;
      Message& operator=(Message&&) = delete;

      void setRequest(const boost::uuids::uuid& uniqueId, const ComboAddress& requestor, const ComboAddress& local, const DNSName& qname, uint16_t qtype, uint16_t qclass, uint16_t id, bool tcp, size_t len);
      void setResponse(const DNSName& qname, uint16_t qtype, uint16_t qclass);

      void setType(uint32_t mtype)
      {
        d_message.add_enum(1, mtype);
      }

      void setMessageIdentity(const boost::uuids::uuid& uniqueId)
      {
        d_message.add_bytes(2, reinterpret_cast<const char*>(uniqueId.begin()), uniqueId.size());
      }

      void setServerIdentity(const std::string& serverIdentity)
      {
        d_message.add_bytes(3, serverIdentity.data(), serverIdentity.length());
      }

      void setSocketFamily(int family)
      {
        d_message.add_enum(4, family == AF_INET ? 1 : 2);
      }

      void setSocketProtocol(bool tcp)
      {
        d_message.add_enum(5, tcp ? 2 : 1);
      }

      void setFrom(const ComboAddress& ca)
      {
        encodeComboAddress(6, ca);
      }

      void setTo(const ComboAddress& ca)
      {
        encodeComboAddress(7, ca);
      }

      void setInBytes(uint64_t len)
      {
        if (len) {
         d_message.add_uint64(8, len);
        }
      }

      void setTime()
      {
        struct timespec ts;
        gettime(&ts, true);

        setTime(ts.tv_sec, ts.tv_nsec / 1000);
      }

      void setTime(time_t sec, uint32_t usec)
      {
        // timeSec
        d_message.add_uint32(9, sec);
        // timeUsec
        d_message.add_uint32(10, usec);
      }

      void setId(uint16_t id)
      {
       d_message.add_uint32(11, ntohs(id));
      }

      void setQuestion(const DNSName& qname, uint16_t qtype, uint16_t qclass)
      {
        protozero::pbf_writer pbf_question{d_message, 12};
        encodeDNSName(pbf_question, d_buffer, 1, qname);
        pbf_question.add_uint32(2, qtype);
        pbf_question.add_uint32(3, qclass);
      }

      void setEDNSSubnet(const Netmask& nm, uint8_t mask)
      {
        encodeNetmask(14, nm, mask);
      }

      void setRequestorId(const std::string& req)
      {
        if (!req.empty()) {
          d_message.add_string(15, req);
        }
      }

      void setInitialRequesId(const std::string& id)
      {
        if (!id.empty()) {
          d_message.add_string(16, id);
        }
      }

      void setDeviceId(const std::string& id)
      {
        if (!id.empty()) {
          d_message.add_string(17, id);
        }
      }

      void setNewlyObservedDomain(bool nod)
      {
        d_message.add_bool(18, nod);
      }

      void setDeviceName(const std::string& name)
      {
        if (!name.empty()) {
          d_message.add_string(19, name);
        }
      }

      void setFromPort(in_port_t port)
      {
        d_message.add_uint32(20, port);
      }

      void setToPort(in_port_t port)
      {
        d_message.add_uint32(21, port);
      }

      void startResponse()
      {
        d_response = protozero::pbf_writer{d_message, 13};
      }

      void commitResponse()
      {
        d_response.commit();
      }

      void setResponseCode(uint8_t rcode)
      {
        d_response.add_uint32(1, rcode);
      }

      void setAppliedPolicy(const std::string& policy)
      {
        d_response.add_string(3, policy);
      }

      void addPolicyTags(const std::unordered_set<std::string>& tags)
      {
        for (const auto& tag : tags) {
          d_response.add_string(4, tag);
        }
      }

      void addPolicyTag(const string& tag)
      {
        d_response.add_string(4, tag);
      }

      void setQueryTime(uint32_t sec, uint32_t usec)
      {
        d_response.add_uint32(5, sec);
        d_response.add_uint32(6, usec);
      }

      void addRRsFromPacket(const char* packet, const size_t len, bool includeCNAME=false);
      void addRR(const DNSName& name, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& blob);

    protected:
      void encodeComboAddress(protozero::pbf_tag_type type, const ComboAddress& ca);
      void encodeNetmask(protozero::pbf_tag_type type, const Netmask& subnet, uint8_t mask);
      void encodeDNSName(protozero::pbf_writer& pbf, std::string& buffer, protozero::pbf_tag_type type, const DNSName& name);

      std::string& d_buffer;
      protozero::pbf_writer d_message;
      protozero::pbf_writer d_response;
    };
  };
};
