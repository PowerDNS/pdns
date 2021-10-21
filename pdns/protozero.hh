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

#include "config.h"
#include "iputils.hh"
#include "gettime.hh"
#include "uuid-utils.hh"

namespace pdns {
  namespace ProtoZero {
    class Message {
    public:

      enum class MetaValueField : protozero::pbf_tag_type { stringVal = 1, intVal = 2 };
      enum class MetaField : protozero::pbf_tag_type { key = 1, value = 2 };
      enum class Event : protozero::pbf_tag_type { ts = 1, event = 2, start = 3, boolVal = 4, intVal = 5, stringVal = 6, bytesVal = 7, custom = 8 };
      enum class MessageType : int32_t { DNSQueryType = 1, DNSResponseType = 2, DNSOutgoingQueryType = 3, DNSIncomingResponseType = 4 };
      enum class Field : protozero::pbf_tag_type { type = 1, messageId = 2, serverIdentity = 3, socketFamily = 4, socketProtocol = 5, from = 6, to = 7, inBytes = 8, timeSec = 9, timeUsec = 10, id = 11, question = 12, response = 13, originalRequestorSubnet = 14, requestorId = 15, initialRequestId = 16, deviceId = 17, newlyObservedDomain = 18, deviceName = 19, fromPort = 20, toPort = 21, meta = 22, trace = 23 };
      enum class QuestionField : protozero::pbf_tag_type { qName = 1, qType = 2, qClass = 3 };
      enum class ResponseField : protozero::pbf_tag_type { rcode = 1, rrs = 2, appliedPolicy = 3, tags = 4, queryTimeSec = 5, queryTimeUsec = 6, appliedPolicyType = 7, appliedPolicyTrigger = 8, appliedPolicyHit = 9, appliedPolicyKind = 10, validationState = 11 };
      enum class RRField : protozero::pbf_tag_type { name = 1, type = 2, class_ = 3, ttl = 4, rdata = 5, udr = 6 };
      enum class TransportProtocol : protozero::pbf_tag_type { UDP = 1, TCP = 2, DoT = 3, DoH = 4, DNSCryptUDP = 5, DNSCryptTCP = 6 };

      Message(std::string& buffer): d_buffer(buffer), d_message{d_buffer}
      {
      }

      Message(const Message&) = delete;
      Message(Message&&) = delete;
      Message& operator=(const Message&) = delete;
      Message& operator=(Message&&) = delete;

      void setRequest(const boost::uuids::uuid& uniqueId, const ComboAddress& requestor, const ComboAddress& local, const DNSName& qname, uint16_t qtype, uint16_t qclass, uint16_t id, TransportProtocol proto, size_t len);
      void setResponse(const DNSName& qname, uint16_t qtype, uint16_t qclass);

      void setType(MessageType mtype)
      {
        add_enum(d_message, Field::type, static_cast<int32_t>(mtype));
      }

      void setMessageIdentity(const boost::uuids::uuid& uniqueId)
      {
        add_bytes(d_message, Field::messageId, reinterpret_cast<const char*>(uniqueId.begin()), uniqueId.size());
      }

      void setServerIdentity(const std::string& serverIdentity)
      {
        add_bytes(d_message, Field::serverIdentity, serverIdentity.data(), serverIdentity.length());
      }

      void setSocketFamily(int family)
      {
        add_enum(d_message, Field::socketFamily, family == AF_INET ? 1 : 2);
      }

      void setSocketProtocol(TransportProtocol proto)
      {
        add_enum(d_message, Field::socketProtocol, static_cast<int32_t>(proto));
      }

      void setFrom(const ComboAddress& ca)
      {
        encodeComboAddress(static_cast<protozero::pbf_tag_type>(Field::from), ca);
      }

      void setTo(const ComboAddress& ca)
      {
        encodeComboAddress(static_cast<protozero::pbf_tag_type>(Field::to), ca);
      }

      void setInBytes(uint64_t len)
      {
        add_uint64(d_message, Field::inBytes, len);
      }

      void setTime()
      {
        struct timespec ts;
        gettime(&ts, true);

        setTime(ts.tv_sec, ts.tv_nsec / 1000);
      }

      void setTime(time_t sec, uint32_t usec)
      {
        add_uint32(d_message, Field::timeSec, sec);
        add_uint32(d_message, Field::timeUsec, usec);
      }

      void setId(uint16_t id)
      {
        add_uint32(d_message, Field::id, ntohs(id));
      }

      void setQuestion(const DNSName& qname, uint16_t qtype, uint16_t qclass)
      {
        protozero::pbf_writer pbf_question{d_message, static_cast<protozero::pbf_tag_type>(Field::question)};
        encodeDNSName(pbf_question, d_buffer, static_cast<protozero::pbf_tag_type>(QuestionField::qName), qname);
        pbf_question.add_uint32(static_cast<protozero::pbf_tag_type>(QuestionField::qType), qtype);
        pbf_question.add_uint32(static_cast<protozero::pbf_tag_type>(QuestionField::qClass), qclass);
      }

      void setMeta(const std::string& key, const std::unordered_set<std::string>& stringVal, const std::unordered_set<int64_t>& intVal)
      {
        protozero::pbf_writer pbf_meta{d_message, static_cast<protozero::pbf_tag_type>(Field::meta)};
        pbf_meta.add_string(static_cast<protozero::pbf_tag_type>(MetaField::key), key);
        protozero::pbf_writer pbf_meta_value{pbf_meta, static_cast<protozero::pbf_tag_type>(MetaField::value)};
        for (const auto& s: stringVal) {
          pbf_meta_value.add_string(static_cast<protozero::pbf_tag_type>(MetaValueField::stringVal), s);
        }
        for (const auto& i: intVal) {
          pbf_meta_value.add_uint64(static_cast<protozero::pbf_tag_type>(MetaValueField::intVal), i);
        }
      }

      void setEDNSSubnet(const Netmask& nm, uint8_t mask)
      {
        encodeNetmask(static_cast<protozero::pbf_tag_type>(Field::originalRequestorSubnet), nm, mask);
      }

      void setRequestorId(const std::string& req)
      {
        if (!req.empty()) {
          add_string(d_message, Field::requestorId, req);
        }
      }

      void setInitialRequestID(const boost::uuids::uuid& uniqueId)
      {
        add_bytes(d_message, Field::initialRequestId, reinterpret_cast<const char*>(uniqueId.begin()), uniqueId.size());
      }

      void setDeviceId(const std::string& id)
      {
        if (!id.empty()) {
          add_string(d_message, Field::deviceId, id);
        }
      }

      void setNewlyObservedDomain(bool nod)
      {
        add_bool(d_message, Field::newlyObservedDomain, nod);
      }

      void setDeviceName(const std::string& name)
      {
        if (!name.empty()) {
          add_string(d_message, Field::deviceName, name);
        }
      }

      void setFromPort(in_port_t port)
      {
        add_uint32(d_message, Field::fromPort, port);
      }

      void setToPort(in_port_t port)
      {
        add_uint32(d_message, Field::toPort, port);
      }

      void startResponse()
      {
        d_response = protozero::pbf_writer{d_message, static_cast<protozero::pbf_tag_type>(Field::response)};
      }

      void commitResponse()
      {
        d_response.commit();
      }

      void setResponseCode(uint8_t rcode)
      {
        d_response.add_uint32(static_cast<protozero::pbf_tag_type>(ResponseField::rcode), rcode);
      }

      void setNetworkErrorResponseCode()
      {
        /* special code meaning 'network error', like a timeout */
        d_response.add_uint32(static_cast<protozero::pbf_tag_type>(ResponseField::rcode), 65536);
      }

      void setAppliedPolicy(const std::string& policy)
      {
        d_response.add_string(static_cast<protozero::pbf_tag_type>(ResponseField::appliedPolicy), policy);
      }

      void addPolicyTags(const std::unordered_set<std::string>& tags)
      {
        for (const auto& tag : tags) {
          addPolicyTag(tag);
        }
      }

      void addPolicyTag(const string& tag)
      {
        d_response.add_string(static_cast<protozero::pbf_tag_type>(ResponseField::tags), tag);
      }

      void setQueryTime(uint32_t sec, uint32_t usec)
      {
        d_response.add_uint32(static_cast<protozero::pbf_tag_type>(ResponseField::queryTimeSec), sec);
        d_response.add_uint32(static_cast<protozero::pbf_tag_type>(ResponseField::queryTimeUsec), usec);
      }

      void addRRsFromPacket(const char* packet, const size_t len, bool includeCNAME=false);
      void addRR(const DNSName& name, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& blob);

    protected:
      void encodeComboAddress(protozero::pbf_tag_type type, const ComboAddress& ca);
      void encodeNetmask(protozero::pbf_tag_type type, const Netmask& subnet, uint8_t mask);
      void encodeDNSName(protozero::pbf_writer& pbf, std::string& buffer, protozero::pbf_tag_type type, const DNSName& name);

      static void add_enum(protozero::pbf_writer& writer, Field type, int32_t value)
      {
        writer.add_enum(static_cast<protozero::pbf_tag_type>(type), value);
      }

      static void add_bool(protozero::pbf_writer& writer, Field type, bool value)
      {
        writer.add_bool(static_cast<protozero::pbf_tag_type>(type), value);
      }

      static void add_uint32(protozero::pbf_writer& writer, Field type, uint32_t value)
      {
        writer.add_uint32(static_cast<protozero::pbf_tag_type>(type), value);
      }

      static void add_uint64(protozero::pbf_writer& writer, Field type, uint64_t value)
      {
        writer.add_uint64(static_cast<protozero::pbf_tag_type>(type), value);
      }

      static void add_bytes(protozero::pbf_writer& writer, Field type, const char* data, size_t len)
      {
        writer.add_bytes(static_cast<protozero::pbf_tag_type>(type), data, len);
      }

      static void add_string(protozero::pbf_writer& writer, Field type, const std::string& str)
      {
        writer.add_string(static_cast<protozero::pbf_tag_type>(type), str);
      }


      std::string& d_buffer;
      protozero::pbf_writer d_message;
      protozero::pbf_writer d_response;
    };
  };
};
