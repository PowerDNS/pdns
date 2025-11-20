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

#include "protozero.hh"

#include "filterpo.hh"
#include "rec-eventtrace.hh"
#include "validate.hh"

namespace pdns
{
namespace ProtoZero
{
  class RecMessage : public Message
  {
  public:
    RecMessage() :
      Message(d_msgbuf)
    {
      d_response = protozero::pbf_writer(d_rspbuf);
    }

    RecMessage(std::string& buffer) :
      Message(buffer)
    {
      d_response = protozero::pbf_writer(buffer);
    }

    // Start a new messagebuf, containing separate data for the response part
    RecMessage(std::string::size_type sz1, std::string::size_type sz2) :
      RecMessage()
    {
      reserve(sz1, sz2);
    }

    // Construct a Message with (partially) constructed content
    RecMessage(const std::string& buf1, const std::string& buf2, std::string::size_type sz1, std::string::size_type sz2) :
      Message(d_msgbuf),
      d_msgbuf{buf1},
      d_rspbuf{buf2}
    {
      d_message = protozero::pbf_writer(d_msgbuf);
      d_response = protozero::pbf_writer(d_rspbuf);
      reserve(sz1, sz2);
    }
    RecMessage(const Message&) = delete;
    RecMessage(Message&&) = delete;
    RecMessage& operator=(const Message&) = delete;
    RecMessage& operator=(Message&&) = delete;

    void reserve(std::string::size_type sz1, std::string::size_type sz2)
    {
      // We expect to grow the buffers, in the end the d_message will contain the (grown) d_response
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

    [[nodiscard]] size_t size() const
    {
      return d_msgbuf.size() + d_rspbuf.size();
    }

    std::string&& finishAndMoveBuf()
    {
      if (!d_rspbuf.empty()) {
        d_message.add_message(static_cast<protozero::pbf_tag_type>(Field::response), d_rspbuf);
      }
      return std::move(d_msgbuf);
    }

    void addEvents(const RecEventTrace& trace);

    // DNSResponse related fields below

    void addRR(const DNSRecord& record, const std::set<uint16_t>& exportTypes, std::optional<bool> udr);

    void setAppliedPolicyType(const DNSFilterEngine::PolicyType type)
    {
      uint32_t p;

      switch (type) {
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
      d_response.add_uint32(static_cast<protozero::pbf_tag_type>(ResponseField::appliedPolicyType), p);
    }

    void setAppliedPolicyTrigger(const DNSName& trigger)
    {
      encodeDNSName(d_response, d_rspbuf, static_cast<protozero::pbf_tag_type>(ResponseField::appliedPolicyTrigger), trigger);
    }

    void setAppliedPolicyHit(const std::string& hit)
    {
      d_response.add_string(static_cast<protozero::pbf_tag_type>(ResponseField::appliedPolicyHit), hit);
    }

    void setAppliedPolicyKind(const DNSFilterEngine::PolicyKind kind)
    {
      uint32_t k;

      switch (kind) {
      case DNSFilterEngine::PolicyKind::NoAction:
        k = 1;
        break;
      case DNSFilterEngine::PolicyKind::Drop:
        k = 2;
        break;
      case DNSFilterEngine::PolicyKind::NXDOMAIN:
        k = 3;
        break;
      case DNSFilterEngine::PolicyKind::NODATA:
        k = 4;
        break;
      case DNSFilterEngine::PolicyKind::Truncate:
        k = 5;
        break;
      case DNSFilterEngine::PolicyKind::Custom:
        k = 6;
        break;
      default:
        throw std::runtime_error("Unsupported protobuf policy kind");
      }
      d_response.add_uint32(static_cast<protozero::pbf_tag_type>(ResponseField::appliedPolicyKind), k);
    }

    void setValidationState(const vState state)
    {
      uint32_t s;

      switch (state) {
      case vState::Indeterminate:
        s = 1;
        break;
      case vState::Insecure:
        s = 2;
        break;
      case vState::Secure:
        s = 3;
        break;
      case vState::BogusNoValidDNSKEY:
        s = 4;
        break;
      case vState::BogusInvalidDenial:
        s = 5;
        break;
      case vState::BogusUnableToGetDSs:
        s = 6;
        break;
      case vState::BogusUnableToGetDNSKEYs:
        s = 7;
        break;
      case vState::BogusSelfSignedDS:
        s = 8;
        break;
      case vState::BogusNoRRSIG:
        s = 9;
        break;
      case vState::BogusNoValidRRSIG:
        s = 10;
        break;
      case vState::BogusMissingNegativeIndication:
        s = 11;
        break;
      case vState::BogusSignatureNotYetValid:
        s = 12;
        break;
      case vState::BogusSignatureExpired:
        s = 13;
        break;
      case vState::BogusUnsupportedDNSKEYAlgo:
        s = 14;
        break;
      case vState::BogusUnsupportedDSDigestType:
        s = 15;
        break;
      case vState::BogusNoZoneKeyBitSet:
        s = 16;
        break;
      case vState::BogusRevokedDNSKEY:
        s = 17;
        break;
      case vState::BogusInvalidDNSKEYProtocol:
        s = 18;
        break;
      default:
        throw std::runtime_error("Unsupported protobuf validation state");
      }
      d_response.add_uint32(static_cast<protozero::pbf_tag_type>(ResponseField::validationState), s);
    }

#ifdef NOD_ENABLED
    void clearUDR(std::string&);
#endif

  private:
    std::string d_msgbuf;
    std::string d_rspbuf;

#ifdef NOD_ENABLED
    vector<std::string::size_type> offsets;
#endif
  };
};
};
