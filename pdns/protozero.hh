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

#include "config.h"

#include "iputils.hh"
#include "gettime.hh"
#include "uuid-utils.hh"

#ifndef DISABLE_PROTOBUF

#include <protozero/pbf_writer.hpp>

namespace pdns
{
namespace ProtoZero
{
  class Message
  {
  public:
    enum class MetaValueField : protozero::pbf_tag_type
    {
      stringVal = 1,
      intVal = 2
    };
    enum class HTTPVersion : protozero::pbf_tag_type
    {
      HTTP1 = 1,
      HTTP2 = 2,
      HTTP3 = 3
    };
    enum class MetaField : protozero::pbf_tag_type
    {
      key = 1,
      value = 2
    };
    enum class Event : protozero::pbf_tag_type
    {
      ts = 1,
      event = 2,
      start = 3,
      boolVal = 4,
      intVal = 5,
      stringVal = 6,
      bytesVal = 7,
      custom = 8
    };
    enum class MessageType : int32_t
    {
      DNSQueryType = 1,
      DNSResponseType = 2,
      DNSOutgoingQueryType = 3,
      DNSIncomingResponseType = 4
    };
    enum class Field : protozero::pbf_tag_type
    {
      type = 1,
      messageId = 2,
      serverIdentity = 3,
      socketFamily = 4,
      socketProtocol = 5,
      from = 6,
      to = 7,
      inBytes = 8,
      timeSec = 9,
      timeUsec = 10,
      id = 11,
      question = 12,
      response = 13,
      originalRequestorSubnet = 14,
      requestorId = 15,
      initialRequestId = 16,
      deviceId = 17,
      newlyObservedDomain = 18,
      deviceName = 19,
      fromPort = 20,
      toPort = 21,
      meta = 22,
      trace = 23,
      httpVersion = 24,
      workerId = 25,
      packetCacheHit = 26,
      outgoingQueries = 27,
      headerFlags = 28,
      ednsVersion = 29,
      openTelemetryData = 30,
      ede = 31,
      edeText = 32,
      openTelemetryTraceID = 33,
    };
    enum class QuestionField : protozero::pbf_tag_type
    {
      qName = 1,
      qType = 2,
      qClass = 3
    };
    enum class ResponseField : protozero::pbf_tag_type
    {
      rcode = 1,
      rrs = 2,
      appliedPolicy = 3,
      tags = 4,
      queryTimeSec = 5,
      queryTimeUsec = 6,
      appliedPolicyType = 7,
      appliedPolicyTrigger = 8,
      appliedPolicyHit = 9,
      appliedPolicyKind = 10,
      validationState = 11
    };
    enum class RRField : protozero::pbf_tag_type
    {
      name = 1,
      type = 2,
      class_ = 3,
      ttl = 4,
      rdata = 5,
      udr = 6
    };
    enum class TransportProtocol : protozero::pbf_tag_type
    {
      UDP = 1,
      TCP = 2,
      DoT = 3,
      DoH = 4,
      DNSCryptUDP = 5,
      DNSCryptTCP = 6,
      DoQ = 7
    };

    Message(std::string& buffer) :
      d_buffer(buffer), d_message{d_buffer}
    {
    }
    ~Message() = default;
    Message(const Message&) = delete;
    Message(Message&&) = delete;
    Message& operator=(const Message&) = delete;
    Message& operator=(Message&&) = delete;

    void setRequest(const boost::uuids::uuid& uniqueId, const ComboAddress& requestor, const ComboAddress& local, const DNSName& qname, uint16_t qtype, uint16_t qclass, uint16_t qid, TransportProtocol proto, size_t len);
    void setResponse(const DNSName& qname, uint16_t qtype, uint16_t qclass);

    void setType(MessageType mtype)
    {
      add_enum(d_message, Field::type, static_cast<int32_t>(mtype));
    }

    void setHTTPVersion(HTTPVersion version)
    {
      add_enum(d_message, Field::httpVersion, static_cast<int32_t>(version));
    }

    void setMessageIdentity(const boost::uuids::uuid& uniqueId)
    {
      add_bytes(d_message, Field::messageId, reinterpret_cast<const char*>(uniqueId.begin()), uniqueId.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
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

    void setFrom(const ComboAddress& address)
    {
      encodeComboAddress(static_cast<protozero::pbf_tag_type>(Field::from), address);
    }

    void setTo(const ComboAddress& address)
    {
      encodeComboAddress(static_cast<protozero::pbf_tag_type>(Field::to), address);
    }

    void setInBytes(uint64_t len)
    {
      add_uint64(d_message, Field::inBytes, len);
    }

    void setTime()
    {
      timespec timesp{};
      gettime(&timesp, true);

      setTime(timesp.tv_sec, timesp.tv_nsec / 1000);
    }

    void setTime(time_t sec, uint32_t usec)
    {
      // coverity[store_truncates_time_t]
      add_uint32(d_message, Field::timeSec, sec);
      add_uint32(d_message, Field::timeUsec, usec);
    }

    void setId(uint16_t qid)
    {
      add_uint32(d_message, Field::id, ntohs(qid));
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
      for (const auto& str : stringVal) {
        pbf_meta_value.add_string(static_cast<protozero::pbf_tag_type>(MetaValueField::stringVal), str);
      }
      for (const auto& val : intVal) {
        pbf_meta_value.add_uint64(static_cast<protozero::pbf_tag_type>(MetaValueField::intVal), val);
      }
    }

    void setEDNSSubnet(const Netmask& netmask, uint8_t mask)
    {
      encodeNetmask(static_cast<protozero::pbf_tag_type>(Field::originalRequestorSubnet), netmask, mask);
    }

    void setRequestorId(const std::string& req)
    {
      if (!req.empty()) {
        add_string(d_message, Field::requestorId, req);
      }
    }

    void setInitialRequestID(const boost::uuids::uuid& uniqueId)
    {
      add_bytes(d_message, Field::initialRequestId, reinterpret_cast<const char*>(uniqueId.begin()), uniqueId.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
    }

    void setDeviceId(const std::string& deviceId)
    {
      if (!deviceId.empty()) {
        add_string(d_message, Field::deviceId, deviceId);
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

    void setWorkerId(uint64_t wid)
    {
      add_uint64(d_message, Field::workerId, wid);
    }

    void setPacketCacheHit(bool hit)
    {
      add_bool(d_message, Field::packetCacheHit, hit);
    }

    void setOutgoingQueries(uint32_t num)
    {
      add_uint32(d_message, Field::outgoingQueries, num);
    }

    void setHeaderFlags(uint16_t flags)
    {
      add_uint32(d_message, Field::headerFlags, flags);
    }

    void setEDNSVersion(uint32_t version)
    {
      add_uint32(d_message, Field::ednsVersion, version);
    }

    void setOpenTelemetryData(const std::string& data)
    {
      if (!data.empty()) {
        add_string(d_message, Field::openTelemetryData, data);
      }
    }

    void setEDE(const uint16_t ede)
    {
      add_uint32(d_message, Field::ede, ede);
    }

    void setEDEText(const std::string edeText)
    {
      if (!edeText.empty()) {
        add_string(d_message, Field::edeText, edeText);
      }
    }

    void setOpenTelemetryTraceID(const std::array<uint8_t, 16>& traceID)
    {
      add_bytes(d_message, Field::openTelemetryTraceID, reinterpret_cast<const char*>(traceID.data()), traceID.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
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

    void addRRsFromPacket(const char* packet, size_t len, bool includeCNAME = false);
    void addRR(const DNSName& name, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& blob);

  protected:
    void encodeComboAddress(protozero::pbf_tag_type type, const ComboAddress& address);
    void encodeNetmask(protozero::pbf_tag_type type, const Netmask& subnet, uint8_t mask);
    static void encodeDNSName(protozero::pbf_writer& pbf, std::string& buffer, protozero::pbf_tag_type type, const DNSName& name);

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

    // NOLINTBEGIN(cppcoreguidelines-non-private-member-variables-in-classes)
    std::string& d_buffer;
    protozero::pbf_writer d_message;
    protozero::pbf_writer d_response;
    // NOLINTEND(cppcoreguidelines-non-private-member-variables-in-classes)
  };
};
};

#endif /* DISABLE_PROTOBUF */
