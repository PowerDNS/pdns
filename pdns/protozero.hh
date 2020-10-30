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

#include <protozero/pbf_writer.hpp>
#include <string>

#include "config.h"
#include "iputils.hh"
#include "filterpo.hh"
#include "gettime.hh"
#include "uuid-utils.hh"

namespace pdns {
  namespace ProtoZero {
    class Message {
    public:
      // Start a new messagebuf, containing separate data for the response part
      Message(std::string::size_type sz1, std::string::size_type sz2) : d_message{d_msgbuf}, d_response{d_rspbuf}
      {
        if (d_msgbuf.capacity() < d_msgbuf.size() + sz1) {
          // This is extra space in addition to what's already there
          // Different from what string.reserve() does.
          d_message.reserve(sz1);
        }
        if (d_rspbuf.capacity() < d_rspbuf.size() + sz2) {
          d_response.reserve(sz2);
        }
      }

      // Construct a Message with (partially) constructed content
      Message(const std::string& buf1, const std::string& buf2, std::string::size_type sz1, std::string::size_type sz2) :
        d_msgbuf{buf1}, d_rspbuf{buf2}, d_message{d_msgbuf}, d_response{d_rspbuf}
      {
        // We expect to grow the buffers, in the end the d_message will contains the (grown) d_response
        // This is extra space in addition to what's already there
        // Different from what string.reserve() does
        std::string::size_type extra = sz1 + d_rspbuf.length() + sz2;
        if (d_msgbuf.capacity() < d_msgbuf.size() + extra) {
          d_message.reserve(extra);
        }
        if (d_rspbuf.capacity() < d_rspbuf.size() + sz2) {
          d_response.reserve(sz2);
        }
      }
      const std::string& getMessageBuf() const
      {
        return d_msgbuf;
      }
      const std::string& getResponseBuf() const
      {
        return d_rspbuf;
      }
      std::string&& finishAndMoveBuf()
      {
        if (!d_rspbuf.empty()) {
          d_message.add_message(13, d_rspbuf);
        }
        return std::move(d_msgbuf);
      }
      void encodeComboAddress(protozero::pbf_tag_type type, const ComboAddress& ca);
      void encodeNetmask(protozero::pbf_tag_type type, const Netmask& subnet, uint8_t mask);
      void encodeDNSName(protozero::pbf_writer& pbf, std::string& buffer, protozero::pbf_tag_type type, const DNSName& name);
      void setRequest(const boost::uuids::uuid& uniqueId, const ComboAddress& requestor, const ComboAddress& local, const DNSName& qname, uint16_t qtype, uint16_t qclass, uint16_t id, bool tcp, size_t len);
      void setResponse(const DNSName& qname, uint16_t qtype, uint16_t qclass);

      void setType(int mtype)
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
        // timeSec
       d_message.add_uint32(9, ts.tv_sec);
        // timeUsec
       d_message.add_uint32(10, ts.tv_nsec / 1000);
      }
      void setId(uint16_t id)
      {
       d_message.add_uint32(11, ntohs(id));
      }
      void setQuestion(const DNSName& qname, uint16_t qtype, uint16_t qclass)
      {
        protozero::pbf_writer pbf_question{d_message, 12};
        encodeDNSName(pbf_question, d_msgbuf, 1, qname);
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

      // DNSResponse related fields below

      void setResponseCode(uint8_t rcode)
      {
        d_response.add_uint32(1, rcode);
      }

      void addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes, bool udr);

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
      void setAppliedPolicyType(const DNSFilterEngine::PolicyType type)
      {
        uint32_t p;

        switch(type) {
        case DNSFilterEngine::PolicyType::None:
          p = 1;
          break;
        case DNSFilterEngine::PolicyType::QName:
          p = 2;
          break;
        case DNSFilterEngine::PolicyType::ClientIP:
          p = 3;
          break;
        case DNSFilterEngine::PolicyType::ResponseIP:
          p = 4;
          break;
        case DNSFilterEngine::PolicyType::NSDName:
          p = 5;
          break;
        case DNSFilterEngine::PolicyType::NSIP:
          p = 6;
          break;
        default:
          throw std::runtime_error("Unsupported protobuf policy type");
        }
        d_response.add_uint32(7, p);
      }
      void setAppliedPolicyTrigger(const DNSName& trigger)
      {
        encodeDNSName(d_response, d_rspbuf, 8, trigger);
      }
      void setAppliedPolicyHit(const std::string& hit)
      {
        d_response.add_string(9, hit);
      }

#ifdef NOD_ENABLED      
      void clearUDR(std::string&);
#endif

    private:
      std::string d_msgbuf;
      std::string d_rspbuf;
      protozero::pbf_writer d_message;
      protozero::pbf_writer d_response;

#ifdef NOD_ENABLED
      vector<std::string::size_type> offsets;
#endif
    };
  };
};
