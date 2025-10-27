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
#define CATCH_CONFIG_MAIN
#include <memory>
#include <catch2/catch_config.hpp>
#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-xsk.hh"
#include "dnsdist-tcp.hh"

// NOTE: This file contains waaaaaay too many mocked things to make bench-dnsdist-action-rcode.cc
// link. In the future, all these functions and declarations should go away and be put into their
// own hh/cc files.

RecursiveLockGuarded<LuaContext> g_lua{LuaContext()};
shared_ptr<BPFFilter> g_defaultBPFFilter{nullptr};
Rings g_rings;
string g_outputBuffer;

void handleResponseSent([[maybe_unused]] const InternalQueryState& ids, [[maybe_unused]] double udiff, [[maybe_unused]] const ComboAddress& client, [[maybe_unused]] const ComboAddress& backend, [[maybe_unused]] unsigned int size, [[maybe_unused]] const dnsheader& cleartextDH, [[maybe_unused]] dnsdist::Protocol protocol, [[maybe_unused]] bool fromBackend)
{
}

void handleResponseSent([[maybe_unused]] const DNSName& qname, [[maybe_unused]] const QType& qtype, [[maybe_unused]] double udiff, [[maybe_unused]] const ComboAddress& client, [[maybe_unused]] const ComboAddress& backend, [[maybe_unused]] unsigned int size, [[maybe_unused]] const dnsheader& cleartextDH, [[maybe_unused]] dnsdist::Protocol outgoingProtocol, [[maybe_unused]] dnsdist::Protocol incomingProtocol, [[maybe_unused]] bool fromBackend)
{
}

bool processResponse([[maybe_unused]] PacketBuffer& response, [[maybe_unused]] DNSResponse& dnsResponse, [[maybe_unused]] bool muted)
{
  return false;
}

void doExitNicely(int exitCode);
void doExitNicely([[maybe_unused]] int exitCode) {
};

ProcessQueryResult processQuery([[maybe_unused]] DNSQuestion& dnsQuestion, [[maybe_unused]] std::shared_ptr<DownstreamState>& selectedBackend)
{
  return ProcessQueryResult::Drop;
};

bool processRulesResult([[maybe_unused]] const DNSAction::Action& action, [[maybe_unused]] DNSQuestion& dnsQuestion, [[maybe_unused]] std::string& ruleresult, [[maybe_unused]] bool& drop)
{
  return false;
}

ProcessQueryResult processQueryAfterRules([[maybe_unused]] DNSQuestion& dnsQuestion, [[maybe_unused]] std::shared_ptr<DownstreamState>& outgoingBackend)
{
  return ProcessQueryResult::Drop;
}

bool processResponseAfterRules([[maybe_unused]] PacketBuffer& response, [[maybe_unused]] DNSResponse& dnsResponse, [[maybe_unused]] bool muted)
{
  return false;
}

bool applyRulesToResponse([[maybe_unused]] const std::vector<dnsdist::rules::ResponseRuleAction>& respRuleActions, [[maybe_unused]] DNSResponse& dnsResponse)
{
  (void)respRuleActions;
  (void)dnsResponse;
  return true;
}

bool handleTimeoutResponseRules([[maybe_unused]] const std::vector<dnsdist::rules::ResponseRuleAction>& rules, [[maybe_unused]] InternalQueryState& ids, [[maybe_unused]] const std::shared_ptr<DownstreamState>& d_ds, [[maybe_unused]] const std::shared_ptr<TCPQuerySender>& sender)
{
  return false;
}

void handleServerStateChange([[maybe_unused]] const string& nameWithAddr, [[maybe_unused]] bool newResult)
{
}

bool sendUDPResponse([[maybe_unused]] int origFD, [[maybe_unused]] const PacketBuffer& response, [[maybe_unused]] const int delayMsec, [[maybe_unused]] const ComboAddress& origDest, [[maybe_unused]] const ComboAddress& origRemote)
{
  return false;
}

bool assignOutgoingUDPQueryToBackend([[maybe_unused]] std::shared_ptr<DownstreamState>& downstream, [[maybe_unused]] uint16_t queryID, [[maybe_unused]] DNSQuestion& dnsQuestion, [[maybe_unused]] PacketBuffer& query, [[maybe_unused]] bool actuallySend)
{
  return true;
}

#ifdef HAVE_XSK
namespace dnsdist::xsk
{
bool XskProcessQuery([[maybe_unused]] ClientState& clientState, [[maybe_unused]] XskPacket& packet)
{
  return false;
}
}
#endif /* HAVE_XSK */

bool processResponderPacket([[maybe_unused]] std::shared_ptr<DownstreamState>& dss, [[maybe_unused]] PacketBuffer& response, [[maybe_unused]] InternalQueryState&& ids)
{
  return false;
}

// NOLINTNEXTLINE(performance-unnecessary-value-param): this is a stub, the real one is not that simple and the performance does not matter
void responderThread([[maybe_unused]] std::shared_ptr<DownstreamState> dss)
{
}

bool checkQueryHeaders([[maybe_unused]] const struct dnsheader& dnsHeader, [[maybe_unused]] ClientState& clientState)
{
  return true;
}

bool checkDNSCryptQuery([[maybe_unused]] const ClientState& clientState, [[maybe_unused]] PacketBuffer& query, [[maybe_unused]] std::unique_ptr<DNSCryptQuery>& dnsCryptQuery, [[maybe_unused]] time_t now, [[maybe_unused]] bool tcp)
{
  return false;
}

bool responseContentMatches([[maybe_unused]] const PacketBuffer& response, [[maybe_unused]] const DNSName& qname, [[maybe_unused]] const uint16_t qtype, [[maybe_unused]] const uint16_t qclass, [[maybe_unused]] const std::shared_ptr<DownstreamState>& remote, [[maybe_unused]] bool allowEmptyResponse)
{
  return false;
}

class UDPTCPCrossQuerySender : public TCPQuerySender
{
public:
  UDPTCPCrossQuerySender() = default;
  UDPTCPCrossQuerySender(const UDPTCPCrossQuerySender&) = delete;
  UDPTCPCrossQuerySender& operator=(const UDPTCPCrossQuerySender&) = delete;
  UDPTCPCrossQuerySender(UDPTCPCrossQuerySender&&) = default;
  UDPTCPCrossQuerySender& operator=(UDPTCPCrossQuerySender&&) = default;
  ~UDPTCPCrossQuerySender() override = default;

  [[nodiscard]] bool active() const override
  {
    return true;
  }

  void handleResponse([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
  }

  void handleXFRResponse([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
  }

  void notifyIOError([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
  }
};

class UDPCrossProtocolQuery : public CrossProtocolQuery
{
public:
  UDPCrossProtocolQuery() = default;
  UDPCrossProtocolQuery(PacketBuffer&& buffer_, InternalQueryState&& ids_, std::shared_ptr<DownstreamState> backend) :
    CrossProtocolQuery(InternalQuery(std::move(buffer_), std::move(ids_)), backend)
  {
  }
  UDPCrossProtocolQuery(const UDPCrossProtocolQuery&) = delete;
  UDPCrossProtocolQuery& operator=(const UDPCrossProtocolQuery&) = delete;
  UDPCrossProtocolQuery(UDPCrossProtocolQuery&&) = delete;
  UDPCrossProtocolQuery& operator=(UDPCrossProtocolQuery&&) = delete;
  ~UDPCrossProtocolQuery() override = default;

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    return s_sender;
  }

private:
  static std::shared_ptr<UDPTCPCrossQuerySender> s_sender;
};

std::shared_ptr<UDPTCPCrossQuerySender> UDPCrossProtocolQuery::s_sender = std::make_shared<UDPTCPCrossQuerySender>();

std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion);
std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ([[maybe_unused]] DNSQuestion& dnsQuestion)
{
  return std::make_unique<UDPCrossProtocolQuery>();
}
