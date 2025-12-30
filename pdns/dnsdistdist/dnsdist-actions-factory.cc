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
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

#include "dnsdist-actions-factory.hh"

#include "config.h"
#include "dnsdist-configuration.hh"
#include "dnsdist.hh"
#include "dnsdist-async.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-edns.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-mac-address.hh"
#include "dnsdist-protobuf.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-kvs.hh"
#include "dnsdist-rule-chains.hh"
#include "dnsdist-self-answers.hh"
#include "dnsdist-snmp.hh"

#include "dnstap.hh"
#include "dnswriter.hh"
#include "dolog.hh"
#include "ednsoptions.hh"
#include "fstrm_logger.hh"
#include "ipcipher.hh"
#include "dnsdist-ipcrypt2.hh"
#include "iputils.hh"
#include "protozero-trace.hh"
#include "qtype.hh"
#include "remote_logger.hh"
#include "svc-records.hh"
#include "threadname.hh"

namespace dnsdist::actions
{
class DropAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)dnsquestion;
    (void)ruleresult;
    return Action::Drop;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "drop";
  }
};

class AllowAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)dnsquestion;
    (void)ruleresult;
    return Action::Allow;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "allow";
  }
};

class NoneAction : public DNSAction
{
public:
  // this action does not stop the processing
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)dnsquestion;
    (void)ruleresult;
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "no op";
  }
};

class QPSAction : public DNSAction
{
public:
  QPSAction(int limit) :
    d_qps(QPSLimiter(limit, limit))
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)dnsquestion;
    (void)ruleresult;
    if (d_qps.lock()->check()) {
      return Action::None;
    }
    return Action::Drop;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "qps limit to " + std::to_string(d_qps.lock()->getRate());
  }

private:
  mutable LockGuarded<QPSLimiter> d_qps;
};

class DelayAction : public DNSAction
{
public:
  DelayAction(int msec) :
    d_msec(msec)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)dnsquestion;
    *ruleresult = std::to_string(d_msec);
    return Action::Delay;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "delay by " + std::to_string(d_msec) + " ms";
  }

private:
  int d_msec;
};

class TeeAction : public DNSAction
{
public:
  // this action does not stop the processing
  TeeAction(const ComboAddress& rca, const std::optional<ComboAddress>& lca, bool addECS = false, bool addProxyProtocol = false);
  TeeAction(TeeAction& other) = delete;
  TeeAction(TeeAction&& other) = delete;
  TeeAction& operator=(TeeAction& other) = delete;
  TeeAction& operator=(TeeAction&& other) = delete;
  ~TeeAction() override;
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override;
  [[nodiscard]] std::string toString() const override;
  std::map<std::string, double> getStats() const override;

private:
  void worker();

  ComboAddress d_remote;
  std::thread d_worker;
  Socket d_socket;
  mutable std::atomic<unsigned long> d_senderrors{0};
  unsigned long d_recverrors{0};
  mutable std::atomic<unsigned long> d_queries{0};
  stat_t d_responses{0};
  stat_t d_nxdomains{0};
  stat_t d_servfails{0};
  stat_t d_refuseds{0};
  stat_t d_formerrs{0};
  stat_t d_notimps{0};
  stat_t d_noerrors{0};
  mutable stat_t d_tcpdrops{0};
  stat_t d_otherrcode{0};
  std::atomic<bool> d_pleaseQuit{false};
  bool d_addECS{false};
  bool d_addProxyProtocol{false};
};

TeeAction::TeeAction(const ComboAddress& rca, const std::optional<ComboAddress>& lca, bool addECS, bool addProxyProtocol) :
  d_remote(rca), d_socket(d_remote.sin4.sin_family, SOCK_DGRAM, 0), d_addECS(addECS), d_addProxyProtocol(addProxyProtocol)
{
  if (lca) {
    d_socket.bind(*lca, false);
  }
  d_socket.connect(d_remote);
  d_socket.setNonBlocking();
  d_worker = std::thread([this]() {
    worker();
  });
}

TeeAction::~TeeAction()
{
  d_pleaseQuit = true;
  close(d_socket.releaseHandle());
  d_worker.join();
}

DNSAction::Action TeeAction::operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const
{
  (void)ruleresult;
  if (dnsquestion->overTCP()) {
    d_tcpdrops++;
    return DNSAction::Action::None;
  }

  d_queries++;

  PacketBuffer query;
  if (d_addECS) {
    query = dnsquestion->getData();
    bool ednsAdded = false;
    bool ecsAdded = false;

    std::string newECSOption;
    generateECSOption(dnsquestion->ecs ? dnsquestion->ecs->getNetwork() : dnsquestion->ids.origRemote, newECSOption, dnsquestion->ecs ? dnsquestion->ecs->getBits() : dnsquestion->ecsPrefixLength);

    if (!handleEDNSClientSubnet(query, dnsquestion->getMaximumSize(), dnsquestion->ids.qname.wirelength(), ednsAdded, ecsAdded, dnsquestion->ecsOverride, newECSOption)) {
      return DNSAction::Action::None;
    }
  }

  if (d_addProxyProtocol) {
    auto proxyPayload = getProxyProtocolPayload(*dnsquestion);
    if (query.empty()) {
      query = dnsquestion->getData();
    }
    if (!addProxyProtocol(query, proxyPayload)) {
      return DNSAction::Action::None;
    }
  }

  {
    const PacketBuffer& payload = query.empty() ? dnsquestion->getData() : query;
    auto res = send(d_socket.getHandle(), payload.data(), payload.size(), 0);

    if (res <= 0) {
      d_senderrors++;
    }
  }

  return DNSAction::Action::None;
}

std::string TeeAction::toString() const
{
  return "tee to " + d_remote.toStringWithPort();
}

std::map<std::string, double> TeeAction::getStats() const
{
  return {{"queries", d_queries},
          {"responses", d_responses},
          {"recv-errors", d_recverrors},
          {"send-errors", d_senderrors},
          {"noerrors", d_noerrors},
          {"nxdomains", d_nxdomains},
          {"refuseds", d_refuseds},
          {"servfails", d_servfails},
          {"other-rcode", d_otherrcode},
          {"tcp-drops", d_tcpdrops}};
}

void TeeAction::worker()
{
  setThreadName("dnsdist/TeeWork");
  std::array<char, dnsdist::configuration::s_udpIncomingBufferSize> packet{};
  ssize_t res = 0;
  const dnsheader_aligned dnsheader(packet.data());
  for (;;) {
    res = waitForData(d_socket.getHandle(), 0, 250);
    if (d_pleaseQuit) {
      break;
    }

    if (res < 0) {
      usleep(250000);
      continue;
    }
    if (res == 0) {
      continue;
    }
    res = recv(d_socket.getHandle(), packet.data(), packet.size(), 0);
    if (static_cast<size_t>(res) <= sizeof(struct dnsheader)) {
      d_recverrors++;
    }
    else {
      d_responses++;
    }

    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions): rcode is unsigned, RCode::rcodes_ as well
    if (dnsheader->rcode == RCode::NoError) {
      d_noerrors++;
    }
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions): rcode is unsigned, RCode::rcodes_ as well
    else if (dnsheader->rcode == RCode::ServFail) {
      d_servfails++;
    }
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions): rcode is unsigned, RCode::rcodes_ as well
    else if (dnsheader->rcode == RCode::NXDomain) {
      d_nxdomains++;
    }
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions): rcode is unsigned, RCode::rcodes_ as well
    else if (dnsheader->rcode == RCode::Refused) {
      d_refuseds++;
    }
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions): rcode is unsigned, RCode::rcodes_ as well
    else if (dnsheader->rcode == RCode::FormErr) {
      d_formerrs++;
    }
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions): rcode is unsigned, RCode::rcodes_ as well
    else if (dnsheader->rcode == RCode::NotImp) {
      d_notimps++;
    }
  }
}

class PoolAction : public DNSAction
{
public:
  PoolAction(std::string pool, bool stopProcessing) :
    d_pool(std::move(pool)), d_stopProcessing(stopProcessing) {}

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    if (d_stopProcessing) {
      /* we need to do it that way to keep compatiblity with custom Lua actions returning DNSAction.Pool, 'poolname' */
      *ruleresult = d_pool;
      return Action::Pool;
    }
    dnsquestion->ids.poolName = d_pool;
    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "to pool " + d_pool;
  }

private:
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const std::string d_pool;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const bool d_stopProcessing;
};

class QPSPoolAction : public DNSAction
{
public:
  QPSPoolAction(unsigned int limit, std::string pool, bool stopProcessing) :
    d_qps(QPSLimiter(limit, limit)), d_pool(std::move(pool)), d_stopProcessing(stopProcessing) {}
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (d_qps.lock()->check()) {
      if (d_stopProcessing) {
        /* we need to do it that way to keep compatiblity with custom Lua actions returning DNSAction.Pool, 'poolname' */
        *ruleresult = d_pool;
        return Action::Pool;
      }
      dnsquestion->ids.poolName = d_pool;
    }
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "max " + std::to_string(d_qps.lock()->getRate()) + " to pool " + d_pool;
  }

private:
  mutable LockGuarded<QPSLimiter> d_qps;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const std::string d_pool;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const bool d_stopProcessing;
};

class RCodeAction : public DNSAction
{
public:
  RCodeAction(uint8_t rcode, const dnsdist::ResponseConfig& responseConfig) :
    d_responseConfig(responseConfig), d_rcode(rcode) {}
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsdist::self_answers::removeRecordsAndSetRCode(*dnsquestion, d_rcode);
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
      setResponseHeadersFromConfig(header, d_responseConfig);
      return true;
    });
    return Action::HeaderModify;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set rcode " + std::to_string(d_rcode);
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  uint8_t d_rcode;
};

class ERCodeAction : public DNSAction
{
public:
  ERCodeAction(uint8_t rcode, dnsdist::ResponseConfig responseConfig) :
    d_responseConfig(responseConfig), d_rcode(rcode)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsdist::self_answers::removeRecordsAndSetRCode(*dnsquestion, (d_rcode & 0xF));
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
      setResponseHeadersFromConfig(header, d_responseConfig);
      return true;
    });
    dnsquestion->ednsRCode = ((d_rcode & 0xFFF0) >> 4);
    return Action::HeaderModify;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set ercode " + ERCode::to_s(d_rcode);
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  uint8_t d_rcode;
};

class SpoofSVCAction : public DNSAction
{
public:
  SpoofSVCAction(const std::vector<SVCRecordParameters>& parameters, const dnsdist::ResponseConfig& responseConfig) :
    d_responseConfig(responseConfig)
  {
    d_payloads.reserve(parameters.size());

    for (const auto& param : parameters) {
      std::vector<uint8_t> payload;
      if (!generateSVCPayload(payload, param)) {
        throw std::runtime_error("Unable to generate a valid SVC record from the supplied parameters");
      }

      d_payloads.push_back(std::move(payload));

      for (const auto& hint : param.ipv4hints) {
        d_additionals4.insert({param.target, ComboAddress(hint)});
      }

      for (const auto& hint : param.ipv6hints) {
        d_additionals6.insert({param.target, ComboAddress(hint)});
      }
    }
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (!dnsdist::svc::generateSVCResponse(*dnsquestion, d_payloads, d_additionals4, d_additionals6, d_responseConfig)) {
      return Action::None;
    }

    return Action::HeaderModify;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "spoof SVC record ";
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  std::vector<std::vector<uint8_t>> d_payloads;
  std::set<std::pair<DNSName, ComboAddress>> d_additionals4;
  std::set<std::pair<DNSName, ComboAddress>> d_additionals6;
};

class TCAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)dnsquestion;
    (void)ruleresult;
    return Action::Truncate;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "tc=1 answer";
  }
};

class TCResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* dnsResponse, std::string* ruleresult) const override
  {
    (void)dnsResponse;
    (void)ruleresult;
    return Action::Truncate;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "tc=1 answer";
  }
};

class LuaAction : public DNSAction
{
public:
  LuaAction(LuaActionFunction func) :
    d_func(std::move(func))
  {}

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    try {
      DNSAction::Action result{};
      {
        auto lock = g_lua.lock();
        auto ret = d_func(dnsquestion);
        if (ruleresult != nullptr) {
          if (std::optional<std::string> rule = std::get<1>(ret)) {
            *ruleresult = *rule;
          }
          else {
            // default to empty string
            ruleresult->clear();
          }
        }
        result = static_cast<Action>(std::get<0>(ret));
      }
      dnsdist::handleQueuedAsynchronousEvents();
      return result;
    }
    catch (const std::exception& e) {
      SLOG(warnlog("LuaAction failed inside Lua, returning ServFail: %s", e.what()),
           dnsquestion->getLogger()->error(Logr::Warning, e.what(), "LuaAction failed inside Lua, returning ServFail"));
    }
    catch (...) {
      SLOG(warnlog("LuaAction failed inside Lua, returning ServFail: [unknown exception]"),
           dnsquestion->getLogger()->error(Logr::Warning, "[unknown exception]", "LuaAction failed inside Lua, returning ServFail"));
    }
    return DNSAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua script";
  }

private:
  LuaActionFunction d_func;
};

class LuaResponseAction : public DNSResponseAction
{
public:
  LuaResponseAction(LuaResponseActionFunction func) :
    d_func(std::move(func))
  {}
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    try {
      DNSResponseAction::Action result{};
      {
        auto lock = g_lua.lock();
        auto ret = d_func(response);
        if (ruleresult != nullptr) {
          if (std::optional<std::string> rule = std::get<1>(ret)) {
            *ruleresult = *rule;
          }
          else {
            // default to empty string
            ruleresult->clear();
          }
        }
        result = static_cast<Action>(std::get<0>(ret));
      }
      dnsdist::handleQueuedAsynchronousEvents();
      return result;
    }
    catch (const std::exception& e) {
      SLOG(warnlog("LuaResponseAction failed inside Lua, returning ServFail: %s", e.what()),
           response->getLogger()->error(Logr::Warning, e.what(), "LuaResponseAction failed inside Lua, returning ServFail"));
    }
    catch (...) {
      SLOG(warnlog("LuaResponseAction failed inside Lua, returning ServFail: [unknown exception]"),
           response->getLogger()->error(Logr::Warning, "[unknown exception]", "LuaResponseAction failed inside Lua, returning ServFail"));
    }
    return DNSResponseAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua response script";
  }

private:
  LuaResponseActionFunction d_func;
};

class LuaFFIAction : public DNSAction
{
public:
  LuaFFIAction(LuaActionFFIFunction func) :
    d_func(std::move(func))
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    dnsdist_ffi_dnsquestion_t dqffi(dnsquestion);
    try {
      DNSAction::Action result{};
      {
        auto lock = g_lua.lock();
        auto ret = d_func(&dqffi);
        if (ruleresult != nullptr) {
          if (dqffi.result) {
            *ruleresult = *dqffi.result;
          }
          else {
            // default to empty string
            ruleresult->clear();
          }
        }
        result = static_cast<DNSAction::Action>(ret);
      }
      dnsdist::handleQueuedAsynchronousEvents();
      return result;
    }
    catch (const std::exception& e) {
      SLOG(warnlog("LuaFFIAction failed inside Lua, returning ServFail: %s", e.what()),
           dnsquestion->getLogger()->error(Logr::Warning, e.what(), "LuaFFIAction failed inside Lua, returning ServFail"));
    }
    catch (...) {
      SLOG(warnlog("LuaFFIAction failed inside Lua, returning ServFail: [unknown exception]"),
           dnsquestion->getLogger()->error(Logr::Warning, "[unknown exception]", "LuaFFIAction failed inside Lua, returning ServFail"));
    }
    return DNSAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua FFI script";
  }

private:
  LuaActionFFIFunction d_func;
};

class LuaFFIPerThreadAction : public DNSAction
{
public:
  LuaFFIPerThreadAction(std::string code) :
    d_functionCode(std::move(code)), d_functionID(s_functionsCounter++)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    try {
      auto& state = t_perThreadStates[d_functionID];
      if (!state.d_initialized) {
        setupLuaFFIPerThreadContext(state.d_luaContext);
        /* mark the state as initialized first so if there is a syntax error
           we only try to execute the code once */
        state.d_initialized = true;
        state.d_func = state.d_luaContext.executeCode<LuaActionFFIFunction>(d_functionCode);
      }

      if (!state.d_func) {
        /* the function was not properly initialized */
        return DNSAction::Action::None;
      }

      dnsdist_ffi_dnsquestion_t dqffi(dnsquestion);
      auto ret = state.d_func(&dqffi);
      if (ruleresult != nullptr) {
        if (dqffi.result) {
          *ruleresult = *dqffi.result;
        }
        else {
          // default to empty string
          ruleresult->clear();
        }
      }
      dnsdist::handleQueuedAsynchronousEvents();
      return static_cast<DNSAction::Action>(ret);
    }
    catch (const std::exception& e) {
      SLOG(warnlog("LuaFFIPerthreadAction failed inside Lua, returning ServFail: %s", e.what()),
           dnsquestion->getLogger()->error(Logr::Warning, e.what(), "LuaFFIPerthreadAction failed inside Lua, returning ServFail"));
    }
    catch (...) {
      SLOG(warnlog("LuaFFIPerthreadAction failed inside Lua, returning ServFail: [unknown exception]"),
           dnsquestion->getLogger()->error(Logr::Warning, "[unknown exception]", "LuaFFIPerthreadAction failed inside Lua, returning ServFail"));
    }
    return DNSAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua FFI per-thread script";
  }

private:
  struct PerThreadState
  {
    LuaContext d_luaContext;
    LuaActionFFIFunction d_func;
    bool d_initialized{false};
  };
  static std::atomic<uint64_t> s_functionsCounter;
  static thread_local std::map<uint64_t, PerThreadState> t_perThreadStates;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const std::string d_functionCode;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const uint64_t d_functionID;
};

std::atomic<uint64_t> LuaFFIPerThreadAction::s_functionsCounter = 0;
thread_local std::map<uint64_t, LuaFFIPerThreadAction::PerThreadState> LuaFFIPerThreadAction::t_perThreadStates;

class LuaFFIResponseAction : public DNSResponseAction
{
public:
  LuaFFIResponseAction(LuaResponseActionFFIFunction func) :
    d_func(std::move(func))
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    dnsdist_ffi_dnsresponse_t ffiResponse(response);
    try {
      DNSResponseAction::Action result{};
      {
        auto lock = g_lua.lock();
        auto ret = d_func(&ffiResponse);
        if (ruleresult != nullptr) {
          if (ffiResponse.result) {
            *ruleresult = *ffiResponse.result;
          }
          else {
            // default to empty string
            ruleresult->clear();
          }
        }
        result = static_cast<DNSResponseAction::Action>(ret);
      }
      dnsdist::handleQueuedAsynchronousEvents();
      return result;
    }
    catch (const std::exception& e) {
      SLOG(warnlog("LuaFFIResponseAction failed inside Lua, returning ServFail: %s", e.what()),
           response->getLogger()->error(Logr::Warning, e.what(), "LuaFFIResponseAction failed inside Lua, returning ServFail"));
    }
    catch (...) {
      SLOG(warnlog("LuaFFIResponseAction failed inside Lua, returning ServFail: [unknown exception]"),
           response->getLogger()->error(Logr::Warning, "[unknown exception]", "LuaFFIResponseAction failed inside Lua, returning ServFail"));
    }
    return DNSResponseAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua FFI script";
  }

private:
  LuaResponseActionFFIFunction d_func;
};

class LuaFFIPerThreadResponseAction : public DNSResponseAction
{
public:
  LuaFFIPerThreadResponseAction(std::string code) :
    d_functionCode(std::move(code)), d_functionID(s_functionsCounter++)
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    try {
      auto& state = t_perThreadStates[d_functionID];
      if (!state.d_initialized) {
        setupLuaFFIPerThreadContext(state.d_luaContext);
        /* mark the state as initialized first so if there is a syntax error
           we only try to execute the code once */
        state.d_initialized = true;
        state.d_func = state.d_luaContext.executeCode<LuaResponseActionFFIFunction>(d_functionCode);
      }

      if (!state.d_func) {
        /* the function was not properly initialized */
        return DNSResponseAction::Action::None;
      }

      dnsdist_ffi_dnsresponse_t ffiResponse(response);
      auto ret = state.d_func(&ffiResponse);
      if (ruleresult != nullptr) {
        if (ffiResponse.result) {
          *ruleresult = *ffiResponse.result;
        }
        else {
          // default to empty string
          ruleresult->clear();
        }
      }
      dnsdist::handleQueuedAsynchronousEvents();
      return static_cast<DNSResponseAction::Action>(ret);
    }
    catch (const std::exception& e) {
      SLOG(warnlog("LuaFFIPerThreadResponseAction failed inside Lua, returning ServFail: %s", e.what()),
           response->getLogger()->error(Logr::Warning, e.what(), "LuaFFIPerThreadResponseAction failed inside Lua, returning ServFail"));
    }
    catch (...) {
      SLOG(warnlog("LuaFFIPerThreadResponseAction failed inside Lua, returning ServFail: [unknown exception]"),
           response->getLogger()->error(Logr::Warning, "[unknown exception]", "LuaFFIPerThreadResponseAction failed inside Lua, returning ServFail"));
    }
    return DNSResponseAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua FFI per-thread script";
  }

private:
  struct PerThreadState
  {
    LuaContext d_luaContext;
    LuaResponseActionFFIFunction d_func;
    bool d_initialized{false};
  };

  static std::atomic<uint64_t> s_functionsCounter;
  static thread_local std::map<uint64_t, PerThreadState> t_perThreadStates;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const std::string d_functionCode;
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  const uint64_t d_functionID;
};

std::atomic<uint64_t> LuaFFIPerThreadResponseAction::s_functionsCounter = 0;
thread_local std::map<uint64_t, LuaFFIPerThreadResponseAction::PerThreadState> LuaFFIPerThreadResponseAction::t_perThreadStates;

class SpoofAction : public DNSAction
{
public:
  SpoofAction(const vector<ComboAddress>& addrs, const dnsdist::ResponseConfig& responseConfig) :
    d_responseConfig(responseConfig), d_addrs(addrs)
  {
    for (const auto& addr : d_addrs) {
      if (addr.isIPv4()) {
        d_types.insert(QType::A);
      }
      else if (addr.isIPv6()) {
        d_types.insert(QType::AAAA);
      }
    }

    if (!d_addrs.empty()) {
      d_types.insert(QType::ANY);
    }
  }

  SpoofAction(DNSName cname, const dnsdist::ResponseConfig& responseConfig) :
    d_responseConfig(responseConfig), d_cname(std::move(cname))
  {
  }

  SpoofAction(PacketBuffer rawresponse) :
    d_raw(std::move(rawresponse))
  {
  }

  SpoofAction(const vector<std::string>& raws, std::optional<uint16_t> typeForAny, const dnsdist::ResponseConfig& responseConfig) :
    d_responseConfig(responseConfig), d_rawResponses(raws), d_rawTypeForAny(typeForAny)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, string* ruleresult) const override;

  string toString() const override
  {
    string ret = "spoof in ";
    if (!d_cname.empty()) {
      ret += d_cname.toString() + " ";
    }
    if (!d_rawResponses.empty()) {
      ret += "raw bytes ";
    }
    else {
      for (const auto& addr : d_addrs) {
        ret += addr.toString() + " ";
      }
    }
    return ret;
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  std::vector<ComboAddress> d_addrs;
  std::unordered_set<uint16_t> d_types;
  std::vector<std::string> d_rawResponses;
  PacketBuffer d_raw;
  DNSName d_cname;
  std::optional<uint16_t> d_rawTypeForAny;
};

DNSAction::Action SpoofAction::operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const
{
  (void)ruleresult;
  uint16_t qtype = dnsquestion->ids.qtype;
  // do we even have a response?
  if (d_cname.empty() && d_rawResponses.empty() &&
      // make sure pre-forged response is greater than sizeof(dnsheader)
      (d_raw.size() < sizeof(dnsheader)) && d_types.count(qtype) == 0) {
    return Action::None;
  }

  if (d_raw.size() >= sizeof(dnsheader)) {
    dnsdist::self_answers::generateAnswerFromRawPacket(*dnsquestion, d_raw);
    return Action::HeaderModify;
  }

  if (!d_cname.empty()) {
    if (dnsdist::self_answers::generateAnswerFromCNAME(*dnsquestion, d_cname, d_responseConfig)) {
      return Action::HeaderModify;
    }
  }
  else if (!d_rawResponses.empty()) {
    if (dnsdist::self_answers::generateAnswerFromRDataEntries(*dnsquestion, d_rawResponses, d_rawTypeForAny, d_responseConfig)) {
      return Action::HeaderModify;
    }
  }
  else {
    if (dnsdist::self_answers::generateAnswerFromIPAddresses(*dnsquestion, d_addrs, d_responseConfig)) {
      return Action::HeaderModify;
    }
  }

  return Action::None;
}

class SetMacAddrAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetMacAddrAction(uint16_t code) :
    d_code(code)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsdist::MacAddress mac{};
    int res = dnsdist::MacAddressesCache::get(dnsquestion->ids.origRemote, mac.data(), mac.size());
    if (res != 0) {
      return Action::None;
    }

    std::string optRData;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    generateEDNSOption(d_code, reinterpret_cast<const char*>(mac.data()), optRData);

    if (dnsquestion->getHeader()->arcount > 0) {
      bool ednsAdded = false;
      bool optionAdded = false;
      PacketBuffer newContent;
      newContent.reserve(dnsquestion->getData().size());

      if (!slowRewriteEDNSOptionInQueryWithRecords(dnsquestion->getData(), newContent, ednsAdded, d_code, optionAdded, true, false, optRData)) {
        return Action::None;
      }

      if (newContent.size() > dnsquestion->getMaximumSize()) {
        return Action::None;
      }

      dnsquestion->getMutableData() = std::move(newContent);
      if (!dnsquestion->ids.ednsAdded && ednsAdded) {
        dnsquestion->ids.ednsAdded = true;
      }

      return Action::None;
    }

    auto& data = dnsquestion->getMutableData();
    if (generateOptRR(optRData, data, dnsquestion->getMaximumSize(), dnsdist::configuration::s_EdnsUDPPayloadSize, 0, false)) {
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [](dnsheader& header) {
        header.arcount = htons(1);
        return true;
      });
      // make sure that any EDNS sent by the backend is removed before forwarding the response to the client
      dnsquestion->ids.ednsAdded = true;
    }

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "add EDNS MAC (code=" + std::to_string(d_code) + ")";
  }

private:
  uint16_t d_code{3};
};

class SetEDNSOptionAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetEDNSOptionAction(uint16_t code, std::string data) :
    d_code(code), d_data(std::move(data))
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    setEDNSOption(*dnsquestion, d_code, d_data, true);
    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "add EDNS Option (code=" + std::to_string(d_code) + ")";
  }

private:
  uint16_t d_code;
  std::string d_data;
};

class SetEDNSOptionResponseAction : public DNSResponseAction
{
public:
  // this action does not stop the processing
  SetEDNSOptionResponseAction(uint16_t code, std::string data) :
    d_code(code), d_data(std::move(data))
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* response, [[maybe_unused]] std::string* ruleresult) const override
  {
    setEDNSOption(*response, d_code, d_data, false);
    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "add EDNS Option to response (code=" + std::to_string(d_code) + ")";
  }

private:
  uint16_t d_code;
  std::string d_data;
};

class SetNoRecurseAction : public DNSAction
{
public:
  // this action does not stop the processing
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [](dnsheader& header) {
      header.rd = false;
      return true;
    });
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set rd=0";
  }
};

class LogAction : public DNSAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  LogAction() = default;

  LogAction(const std::string& str, bool binary = true, bool append = false, bool buffered = true, bool verboseOnly = true, bool includeTimestamp = false) :
    d_fname(str), d_binary(binary), d_verboseOnly(verboseOnly), d_includeTimestamp(includeTimestamp), d_append(append), d_buffered(buffered)
  {
    if (str.empty()) {
      return;
    }

    if (!reopenLogFile()) {
      throw std::runtime_error("Unable to open file '" + str + "' for logging: " + stringerror());
    }
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    auto filepointer = std::atomic_load_explicit(&d_fp, std::memory_order_acquire);
    if (!filepointer) {
      if (!d_verboseOnly || dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose) {
        if (d_includeTimestamp) {
          SLOG(infolog("[%u.%u] Packet from %s for %s %s with id %d", static_cast<unsigned long long>(dnsquestion->getQueryRealTime().tv_sec), static_cast<unsigned long>(dnsquestion->getQueryRealTime().tv_nsec), dnsquestion->ids.origRemote.toStringWithPort(), dnsquestion->ids.qname.toString(), QType(dnsquestion->ids.qtype).toString(), dnsquestion->getHeader()->id),
               dnsquestion->getLogger()->info(Logr::Info, "Logging packet", "dns.question.real_time_sec", Logging::Loggable(dnsquestion->getQueryRealTime().tv_sec), "dns.question.real_time_nsec", Logging::Loggable(dnsquestion->getQueryRealTime().tv_nsec)));
        }
        else {
          SLOG(infolog("Packet from %s for %s %s with id %d", dnsquestion->ids.origRemote.toStringWithPort(), dnsquestion->ids.qname.toString(), QType(dnsquestion->ids.qtype).toString(), dnsquestion->getHeader()->id),
               dnsquestion->getLogger()->info(Logr::Info, "Logging packet"));
        }
      }
    }
    else {
      if (d_binary) {
        const auto& out = dnsquestion->ids.qname.getStorage();
        if (d_includeTimestamp) {
          auto tv_sec = static_cast<uint64_t>(dnsquestion->getQueryRealTime().tv_sec);
          auto tv_nsec = static_cast<uint32_t>(dnsquestion->getQueryRealTime().tv_nsec);
          fwrite(&tv_sec, sizeof(tv_sec), 1, filepointer.get());
          fwrite(&tv_nsec, sizeof(tv_nsec), 1, filepointer.get());
        }
        uint16_t queryId = dnsquestion->getHeader()->id;
        fwrite(&queryId, sizeof(queryId), 1, filepointer.get());
        fwrite(out.c_str(), 1, out.size(), filepointer.get());
        fwrite(&dnsquestion->ids.qtype, sizeof(dnsquestion->ids.qtype), 1, filepointer.get());
        fwrite(&dnsquestion->ids.origRemote.sin4.sin_family, sizeof(dnsquestion->ids.origRemote.sin4.sin_family), 1, filepointer.get());
        if (dnsquestion->ids.origRemote.sin4.sin_family == AF_INET) {
          fwrite(&dnsquestion->ids.origRemote.sin4.sin_addr.s_addr, sizeof(dnsquestion->ids.origRemote.sin4.sin_addr.s_addr), 1, filepointer.get());
        }
        else if (dnsquestion->ids.origRemote.sin4.sin_family == AF_INET6) {
          fwrite(&dnsquestion->ids.origRemote.sin6.sin6_addr.s6_addr, sizeof(dnsquestion->ids.origRemote.sin6.sin6_addr.s6_addr), 1, filepointer.get());
        }
        fwrite(&dnsquestion->ids.origRemote.sin4.sin_port, sizeof(dnsquestion->ids.origRemote.sin4.sin_port), 1, filepointer.get());
      }
      else {
        if (d_includeTimestamp) {
          fprintf(filepointer.get(), "[%llu.%lu] Packet from %s for %s %s with id %u\n", static_cast<unsigned long long>(dnsquestion->getQueryRealTime().tv_sec), static_cast<unsigned long>(dnsquestion->getQueryRealTime().tv_nsec), dnsquestion->ids.origRemote.toStringWithPort().c_str(), dnsquestion->ids.qname.toString().c_str(), QType(dnsquestion->ids.qtype).toString().c_str(), dnsquestion->getHeader()->id);
        }
        else {
          fprintf(filepointer.get(), "Packet from %s for %s %s with id %u\n", dnsquestion->ids.origRemote.toStringWithPort().c_str(), dnsquestion->ids.qname.toString().c_str(), QType(dnsquestion->ids.qtype).toString().c_str(), dnsquestion->getHeader()->id);
        }
      }
    }
    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    if (!d_fname.empty()) {
      return "log to " + d_fname;
    }
    return "log";
  }

  void reload() override
  {
    if (!reopenLogFile()) {
      int savederrno = errno;
      SLOG(warnlog("Unable to open file '%s' for logging: %s", d_fname, stringerror(savederrno)),
           dnsdist::logging::getTopLogger()->error(Logr::Warning, savederrno, "Unable to open file for logging", "path", Logging::Loggable(d_fname)));
    }
  }

private:
  bool reopenLogFile()
  {
    // we are using a naked pointer here because we don't want fclose to be called
    // with a nullptr, which would happen if we constructor a shared_ptr with fclose
    // as a custom deleter and nullptr as a FILE*
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    auto* nfp = fopen(d_fname.c_str(), d_append ? "a+" : "w");
    if (nfp == nullptr) {
      /* don't fall on our sword when reopening */
      return false;
    }

    auto filepointer = std::shared_ptr<FILE>(nfp, fclose);
    nfp = nullptr;

    if (!d_buffered) {
      setbuf(filepointer.get(), nullptr);
    }

    std::atomic_store_explicit(&d_fp, std::move(filepointer), std::memory_order_release);
    return true;
  }

  std::string d_fname;
  std::shared_ptr<FILE> d_fp{nullptr};
  bool d_binary{true};
  bool d_verboseOnly{true};
  bool d_includeTimestamp{false};
  bool d_append{false};
  bool d_buffered{true};
};

class LogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  LogResponseAction() = default;

  LogResponseAction(const std::string& str, bool append = false, bool buffered = true, bool verboseOnly = true, bool includeTimestamp = false) :
    d_fname(str), d_verboseOnly(verboseOnly), d_includeTimestamp(includeTimestamp), d_append(append), d_buffered(buffered)
  {
    if (str.empty()) {
      return;
    }

    if (!reopenLogFile()) {
      throw std::runtime_error("Unable to open file '" + str + "' for logging: " + stringerror());
    }
  }

  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    auto filepointer = std::atomic_load_explicit(&d_fp, std::memory_order_acquire);
    if (!filepointer) {
      if (!d_verboseOnly || dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose) {
        if (d_includeTimestamp) {
          SLOG(infolog("[%u.%u] Answer to %s for %s %s (%s) with id %u", static_cast<unsigned long long>(response->getQueryRealTime().tv_sec), static_cast<unsigned long>(response->getQueryRealTime().tv_nsec), response->ids.origRemote.toStringWithPort(), response->ids.qname.toString(), QType(response->ids.qtype).toString(), RCode::to_s(response->getHeader()->rcode), response->getHeader()->id),
               response->getLogger()->info(Logr::Info, "Logging response packet", "dns.question.real_time_sec", Logging::Loggable(response->getQueryRealTime().tv_sec), "dns.question.real_time_nsec", Logging::Loggable(response->getQueryRealTime().tv_nsec)));
        }
        else {
          SLOG(infolog("Answer to %s for %s %s (%s) with id %u", response->ids.origRemote.toStringWithPort(), response->ids.qname.toString(), QType(response->ids.qtype).toString(), RCode::to_s(response->getHeader()->rcode), response->getHeader()->id),
               response->getLogger()->info("Logging response packet"));
        }
      }
    }
    else {
      if (d_includeTimestamp) {
        fprintf(filepointer.get(), "[%llu.%lu] Answer to %s for %s %s (%s) with id %u\n", static_cast<unsigned long long>(response->getQueryRealTime().tv_sec), static_cast<unsigned long>(response->getQueryRealTime().tv_nsec), response->ids.origRemote.toStringWithPort().c_str(), response->ids.qname.toString().c_str(), QType(response->ids.qtype).toString().c_str(), RCode::to_s(response->getHeader()->rcode).c_str(), response->getHeader()->id);
      }
      else {
        fprintf(filepointer.get(), "Answer to %s for %s %s (%s) with id %u\n", response->ids.origRemote.toStringWithPort().c_str(), response->ids.qname.toString().c_str(), QType(response->ids.qtype).toString().c_str(), RCode::to_s(response->getHeader()->rcode).c_str(), response->getHeader()->id);
      }
    }
    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    if (!d_fname.empty()) {
      return "log to " + d_fname;
    }
    return "log";
  }

  void reload() override
  {
    if (!reopenLogFile()) {
      int savederrno = errno;
      SLOG(warnlog("Unable to open file '%s' for logging: %s", d_fname, stringerror(savederrno)),
           dnsdist::logging::getTopLogger()->error(Logr::Warning, savederrno, "Unable to open file for logging", "path", Logging::Loggable(d_fname)));
    }
  }

private:
  bool reopenLogFile()
  {
    // we are using a naked pointer here because we don't want fclose to be called
    // with a nullptr, which would happen if we constructor a shared_ptr with fclose
    // as a custom deleter and nullptr as a FILE*
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    auto* nfp = fopen(d_fname.c_str(), d_append ? "a+" : "w");
    if (nfp == nullptr) {
      /* don't fall on our sword when reopening */
      return false;
    }

    auto filepointer = std::shared_ptr<FILE>(nfp, fclose);
    nfp = nullptr;

    if (!d_buffered) {
      setbuf(filepointer.get(), nullptr);
    }

    std::atomic_store_explicit(&d_fp, std::move(filepointer), std::memory_order_release);
    return true;
  }

  std::string d_fname;
  std::shared_ptr<FILE> d_fp{nullptr};
  bool d_verboseOnly{true};
  bool d_includeTimestamp{false};
  bool d_append{false};
  bool d_buffered{true};
};

class SetDisableValidationAction : public DNSAction
{
public:
  // this action does not stop the processing
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [](dnsheader& header) {
      header.cd = true;
      return true;
    });
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set cd=1";
  }
};

class SetSkipCacheAction : public DNSAction
{
public:
  // this action does not stop the processing
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsquestion->ids.skipCache = true;
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "skip cache";
  }
};

class SetSkipCacheResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    response->ids.skipCache = true;
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "skip cache";
  }
};

class SetTempFailureCacheTTLAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetTempFailureCacheTTLAction(uint32_t ttl) :
    d_ttl(ttl)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsquestion->ids.tempFailureTTL = d_ttl;
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set tempfailure cache ttl to " + std::to_string(d_ttl);
  }

private:
  uint32_t d_ttl;
};

class SetECSPrefixLengthAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetECSPrefixLengthAction(uint16_t v4Length, uint16_t v6Length) :
    d_v4PrefixLength(v4Length), d_v6PrefixLength(v6Length)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsquestion->ecsPrefixLength = dnsquestion->ids.origRemote.sin4.sin_family == AF_INET ? d_v4PrefixLength : d_v6PrefixLength;
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set ECS prefix length to " + std::to_string(d_v4PrefixLength) + "/" + std::to_string(d_v6PrefixLength);
  }

private:
  uint16_t d_v4PrefixLength;
  uint16_t d_v6PrefixLength;
};

class SetECSOverrideAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetECSOverrideAction(bool ecsOverride) :
    d_ecsOverride(ecsOverride)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsquestion->ecsOverride = d_ecsOverride;
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set ECS override to " + std::to_string(static_cast<int>(d_ecsOverride));
  }

private:
  bool d_ecsOverride;
};

class SetDisableECSAction : public DNSAction
{
public:
  // this action does not stop the processing
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsquestion->useECS = false;
    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "disable ECS";
  }
};

class SetECSAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetECSAction(const Netmask& v4Netmask) :
    d_v4(v4Netmask), d_hasV6(false)
  {
  }

  SetECSAction(const Netmask& v4Netmask, const Netmask& v6Netmask) :
    d_v4(v4Netmask), d_v6(v6Netmask), d_hasV6(true)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (d_hasV6) {
      dnsquestion->ecs = std::make_unique<Netmask>(dnsquestion->ids.origRemote.isIPv4() ? d_v4 : d_v6);
    }
    else {
      dnsquestion->ecs = std::make_unique<Netmask>(d_v4);
    }

    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    std::string result = "set ECS to " + d_v4.toString();
    if (d_hasV6) {
      result += " / " + d_v6.toString();
    }
    return result;
  }

private:
  Netmask d_v4;
  Netmask d_v6;
  bool d_hasV6;
};

#ifndef DISABLE_PROTOBUF
static std::tuple<DnstapMessage::ProtocolType, std::optional<DnstapMessage::HttpProtocolType>> ProtocolToDNSTap(dnsdist::Protocol protocol)
{
  if (protocol == dnsdist::Protocol::DoUDP) {
    return {DnstapMessage::ProtocolType::DoUDP, std::nullopt};
  }
  if (protocol == dnsdist::Protocol::DoTCP) {
    return {DnstapMessage::ProtocolType::DoTCP, std::nullopt};
  }
  if (protocol == dnsdist::Protocol::DoT) {
    return {DnstapMessage::ProtocolType::DoT, std::nullopt};
  }
  if (protocol == dnsdist::Protocol::DoH) {
    return {DnstapMessage::ProtocolType::DoH, DnstapMessage::HttpProtocolType::HTTP2};
  }
  if (protocol == dnsdist::Protocol::DoH3) {
    return {DnstapMessage::ProtocolType::DoH, DnstapMessage::HttpProtocolType::HTTP3};
  }
  if (protocol == dnsdist::Protocol::DNSCryptUDP) {
    return {DnstapMessage::ProtocolType::DNSCryptUDP, std::nullopt};
  }
  if (protocol == dnsdist::Protocol::DNSCryptTCP) {
    return {DnstapMessage::ProtocolType::DNSCryptTCP, std::nullopt};
  }
  if (protocol == dnsdist::Protocol::DoQ) {
    return {DnstapMessage::ProtocolType::DoQ, std::nullopt};
  }
  throw std::runtime_error("Unhandled protocol for dnstap: " + protocol.toPrettyString());
}

static void remoteLoggerQueueData(RemoteLoggerInterface& remoteLogger, const std::string& data)
{
  auto ret = remoteLogger.queueData(data);

  switch (ret) {
  case RemoteLoggerInterface::Result::Queued:
    break;
  case RemoteLoggerInterface::Result::PipeFull: {
    VERBOSESLOG(infolog("%s: %s", remoteLogger.name(), RemoteLoggerInterface::toErrorString(ret)),
                dnsdist::logging::getTopLogger()->error(Logr::Info, RemoteLoggerInterface::toErrorString(ret), "Remote logger pipe full event", "remote_logger_name", Logging::Loggable(remoteLogger.name())));
    break;
  }
  case RemoteLoggerInterface::Result::TooLarge: {
    SLOG(warnlog("%s: %s", remoteLogger.name(), RemoteLoggerInterface::toErrorString(ret)),
         dnsdist::logging::getTopLogger()->error(Logr::Warning, RemoteLoggerInterface::toErrorString(ret), "Remote logger too large event", "remote_logger_name", Logging::Loggable(remoteLogger.name())));
    break;
  }
  case RemoteLoggerInterface::Result::OtherError:
    SLOG(warnlog("%s: %s", remoteLogger.name(), RemoteLoggerInterface::toErrorString(ret)),
         dnsdist::logging::getTopLogger()->error(Logr::Warning, RemoteLoggerInterface::toErrorString(ret), "Remote logger error event", "remote_logger_name", Logging::Loggable(remoteLogger.name())));
  }
}

class DnstapLogAction : public DNSAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  DnstapLogAction(std::string identity, std::shared_ptr<RemoteLoggerInterface>& logger, std::optional<std::function<void(DNSQuestion*, DnstapMessage*)>> alterFunc) :
    d_identity(std::move(identity)), d_logger(logger), d_alterFunc(std::move(alterFunc))
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    static thread_local std::string data;
    data.clear();

    auto [protocol, httpProtocol] = ProtocolToDNSTap(dnsquestion->getProtocol());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DnstapMessage message(std::move(data), !dnsquestion->getHeader()->qr ? DnstapMessage::MessageType::client_query : DnstapMessage::MessageType::client_response, d_identity, &dnsquestion->ids.origRemote, &dnsquestion->ids.origDest, protocol, reinterpret_cast<const char*>(dnsquestion->getData().data()), dnsquestion->getData().size(), &dnsquestion->getQueryRealTime(), nullptr, DNSName(), httpProtocol);
    {
      if (d_alterFunc) {
        auto lock = g_lua.lock();
        (*d_alterFunc)(dnsquestion, &message);
      }
    }

    data = message.getBuffer();
    remoteLoggerQueueData(*d_logger, data);

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "remote log as dnstap to " + (d_logger ? d_logger->toString() : "");
  }

private:
  std::string d_identity;
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  std::optional<std::function<void(DNSQuestion*, DnstapMessage*)>> d_alterFunc;
};

namespace
{
  void addMetaDataToProtobuf(DNSDistProtoBufMessage& message, const DNSQuestion& dnsquestion, const std::vector<std::pair<std::string, ProtoBufMetaKey>>& metas)
  {
    for (const auto& [name, meta] : metas) {
      message.addMeta(name, meta.getValues(dnsquestion), {});
    }
  }

  void addTagsToProtobuf(DNSDistProtoBufMessage& message, const DNSQuestion& dnsquestion, const std::unordered_set<std::string>& allowed)
  {
    if (!dnsquestion.ids.qTag) {
      return;
    }

    for (const auto& [key, value] : *dnsquestion.ids.qTag) {
      if (!allowed.empty() && allowed.count(key) == 0) {
        continue;
      }

      if (value.empty()) {
        message.addTag(key);
      }
      else {
        auto tag = key;
        tag.append(":");
        tag.append(value);
        message.addTag(tag);
      }
    }
  }

  void addExtendedDNSErrorToProtobuf(DNSDistProtoBufMessage& message, const DNSResponse& response, const std::string& metaKey)
  {
    auto [infoCode, extraText] = dnsdist::edns::getExtendedDNSError(response.getData());
    if (!infoCode) {
      return;
    }

    if (extraText) {
      message.addMeta(metaKey, {*extraText}, {*infoCode});
    }
    else {
      message.addMeta(metaKey, {}, {*infoCode});
    }
  }
}

class RemoteLogAction : public DNSAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  RemoteLogAction(RemoteLogActionConfiguration& config) :
    d_tagsToExport(std::move(config.tagsToExport)), d_metas(std::move(config.metas)), d_logger(config.logger), d_alterFunc(std::move(config.alterQueryFunc)), d_serverID(config.serverID), d_ipEncryptKey(config.ipEncryptKey), d_ipEncryptMethod(config.ipEncryptMethod), d_useServerID(config.useServerID)
  {
    if (!d_ipEncryptKey.empty() && d_ipEncryptMethod == "ipcrypt-pfx") {
      d_ipcrypt2 = pdns::ipcrypt2::IPCrypt2(pdns::ipcrypt2::IPCryptMethod::pfx, d_ipEncryptKey);
    }
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (!dnsquestion->ids.d_protoBufData) {
      dnsquestion->ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    if (!dnsquestion->ids.d_protoBufData->uniqueId) {
      dnsquestion->ids.d_protoBufData->uniqueId = getUniqueID();
    }

    DNSDistProtoBufMessage message(*dnsquestion);
    if (d_useServerID) {
      message.setServerIdentity(dnsdist::configuration::getCurrentRuntimeConfiguration().d_server_id);
    }
    else if (!d_serverID.empty()) {
      message.setServerIdentity(d_serverID);
    }

#ifdef HAVE_IPCIPHER
    if (!d_ipEncryptKey.empty() && d_ipEncryptMethod == "legacy") {
      message.setRequestor(encryptCA(dnsquestion->ids.origRemote, d_ipEncryptKey));
    }
#endif /* HAVE_IPCIPHER */
    if (d_ipcrypt2) {
      auto encryptedAddress = d_ipcrypt2->encrypt(dnsquestion->ids.origRemote);
      encryptedAddress.setPort(dnsquestion->ids.origRemote.getPort());
      message.setRequestor(encryptedAddress);
    }

    if (d_tagsToExport) {
      addTagsToProtobuf(message, *dnsquestion, *d_tagsToExport);
    }

    addMetaDataToProtobuf(message, *dnsquestion, d_metas);

    if (d_alterFunc) {
      auto lock = g_lua.lock();
      (*d_alterFunc)(dnsquestion, &message);
    }

    static thread_local std::string data;
    data.clear();
    message.serialize(data);
    if (!dnsquestion->ids.d_rawProtobufContent.empty()) {
      data.insert(data.end(), dnsquestion->ids.d_rawProtobufContent.begin(), dnsquestion->ids.d_rawProtobufContent.end());
    }
    remoteLoggerQueueData(*d_logger, data);

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "remote log to " + (d_logger ? d_logger->toString() : "");
  }

private:
  std::optional<std::unordered_set<std::string>> d_tagsToExport;
  std::vector<std::pair<std::string, ProtoBufMetaKey>> d_metas;
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  std::optional<std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)>> d_alterFunc;
  std::string d_serverID;
  std::string d_ipEncryptKey;
  std::string d_ipEncryptMethod;
  std::optional<pdns::ipcrypt2::IPCrypt2> d_ipcrypt2{std::nullopt};
  bool d_useServerID;
};
#endif /* DISABLE_PROTOBUF */

#ifndef DISABLE_PROTOBUF
class SetTraceAction : public DNSAction
{
public:
  SetTraceAction(SetTraceActionConfiguration& config) :
    d_loggers(config.remote_loggers), d_incomingTraceIDOptionCode(config.trace_edns_option), d_value{config.value}, d_useIncomingTraceID(config.use_incoming_traceid), d_stripIncomingTraceID(config.strip_incoming_traceid) {};

  DNSAction::Action operator()([[maybe_unused]] DNSQuestion* dnsquestion, [[maybe_unused]] std::string* ruleresult) const override
  {
    auto tracer = dnsquestion->ids.getTracer();
    if (tracer == nullptr) {
      VERBOSESLOG(infolog("SetTraceAction called, but OpenTelemetry tracing is globally disabled. Did you forget to call setOpenTelemetryTracing?"),
                  dnsquestion->getLogger()->info(Logr::Info, "SetTraceAction called, but OpenTelemetry tracing is globally disabled. Did you forget to call setOpenTelemetryTracing?"));
      return Action::None;
    }

    dnsquestion->ids.tracingEnabled = d_value;

    if (!d_value) {
      // Tracing has been turned off or should not be enabled, clean up
      dnsquestion->ids.ottraceLoggers.clear();
      return Action::None;
    }

    dnsquestion->ids.ottraceLoggers = d_loggers;
    tracer->setRootSpanAttribute("query.qname", AnyValue{dnsquestion->ids.qname.toStringNoDot()});
    tracer->setRootSpanAttribute("query.qtype", AnyValue{QType(dnsquestion->ids.qtype).toString()});
    tracer->setRootSpanAttribute("query.remote.address", AnyValue{dnsquestion->ids.origRemote.toString()});
    tracer->setRootSpanAttribute("query.remote.port", AnyValue{dnsquestion->ids.origRemote.getPort()});

    if (!d_useIncomingTraceID && !d_stripIncomingTraceID) {
      // No need to check EDNS
      return Action::None;
    }

    // We need to check if EDNS Options exist
    if (dnsquestion->ednsOptions == nullptr && !parseEDNSOptions(*dnsquestion)) {
      // Maybe parsed, but no EDNS found
      return Action::None;
    }
    if (dnsquestion->ednsOptions == nullptr) {
      // Parsing failed, log a warning and return
      VERBOSESLOG(infolog("parsing EDNS options failed while looking for OpenTelemetry Trace ID"),
                  dnsquestion->getLogger()->info(Logr::Info, "Parsing EDNS options failed while looking for OpenTelemetry Trace ID"));
      return Action::None;
    }

    if (d_useIncomingTraceID) {
      pdns::trace::TraceID traceID;
      pdns::trace::SpanID spanID;
      if (pdns::trace::extractOTraceIDs(*(dnsquestion->ednsOptions), EDNSOptionCode::EDNSOptionCodeEnum(d_incomingTraceIDOptionCode), traceID, spanID)) {
        tracer->setTraceID(traceID);
        if (spanID != pdns::trace::s_emptySpanID) {
          tracer->setRootSpanID(spanID);
        }
      }
    }

    if (d_stripIncomingTraceID) {
      uint16_t optStart;
      size_t optLen;
      bool last;

      if (locateEDNSOptRR(dnsquestion->getData(), &optStart, &optLen, &last) != 0) {
        // Can't find the EDNS OPT RR, can't happen
        return Action::None;
      }

      if (!last) {
        VERBOSESLOG(infolog("SetTraceAction: EDNS options is not the last RR in the packet, not removing TRACEPARENT"),
                    dnsquestion->getLogger()->info(Logr::Info, "SetTraceAction: EDNS options is not the last RR in the packet, not removing TRACEPARENT"));
        return Action::None;
      }

      size_t existingOptLen = optLen;
      removeEDNSOptionFromOPT(reinterpret_cast<char*>(&dnsquestion->getMutableData().at(optStart)), &optLen, d_incomingTraceIDOptionCode);
      dnsquestion->getMutableData().resize(dnsquestion->getData().size() - (existingOptLen - optLen));
      // Ensure the EDNS Option View is not out of date
      dnsquestion->ednsOptions.reset();
    }

    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return string((d_value ? "en" : "dis")) + string("able OpenTelemetry Tracing");
  }

private:
  std::vector<std::shared_ptr<RemoteLoggerInterface>> d_loggers;
  short unsigned int d_incomingTraceIDOptionCode;

  bool d_value;
  bool d_useIncomingTraceID;
  bool d_stripIncomingTraceID;
};
#endif

class SNMPTrapAction : public DNSAction
{
public:
  // this action does not stop the processing
  SNMPTrapAction(std::string reason) :
    d_reason(std::move(reason))
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (g_snmpAgent != nullptr && dnsdist::configuration::getImmutableConfiguration().d_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(*dnsquestion, d_reason);
    }

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "send SNMP trap";
  }

private:
  std::string d_reason;
};

class SetTagAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetTagAction(std::string tag, std::string value) :
    d_tag(std::move(tag)), d_value(std::move(value))
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsquestion->setTag(d_tag, d_value);

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set tag '" + d_tag + "' to value '" + d_value + "'";
  }

private:
  std::string d_tag;
  std::string d_value;
};

#ifndef DISABLE_PROTOBUF
class DnstapLogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  DnstapLogResponseAction(std::string identity, std::shared_ptr<RemoteLoggerInterface>& logger, std::optional<std::function<void(DNSResponse*, DnstapMessage*)>> alterFunc) :
    d_identity(std::move(identity)), d_logger(logger), d_alterFunc(std::move(alterFunc))
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    static thread_local std::string data;
    struct timespec now = {};
    gettime(&now, true);
    data.clear();

    auto [protocol, httpProtocol] = ProtocolToDNSTap(response->getProtocol());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DnstapMessage message(std::move(data), DnstapMessage::MessageType::client_response, d_identity, &response->ids.origRemote, &response->ids.origDest, protocol, reinterpret_cast<const char*>(response->getData().data()), response->getData().size(), &response->getQueryRealTime(), &now, DNSName(), httpProtocol);
    {
      if (d_alterFunc) {
        auto lock = g_lua.lock();
        (*d_alterFunc)(response, &message);
      }
    }

    data = message.getBuffer();
    remoteLoggerQueueData(*d_logger, data);

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "log response as dnstap to " + (d_logger ? d_logger->toString() : "");
  }

private:
  std::string d_identity;
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  std::optional<std::function<void(DNSResponse*, DnstapMessage*)>> d_alterFunc;
};

class RemoteLogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  RemoteLogResponseAction(RemoteLogActionConfiguration& config) :
    d_tagsToExport(std::move(config.tagsToExport)), d_metas(std::move(config.metas)), d_logger(config.logger), d_alterFunc(std::move(config.alterResponseFunc)), d_serverID(config.serverID), d_ipEncryptKey(config.ipEncryptKey), d_ipEncryptMethod(config.ipEncryptMethod), d_exportExtendedErrorsToMeta(std::move(config.exportExtendedErrorsToMeta)), d_includeCNAME(config.includeCNAME), d_useServerID(config.useServerID), d_delay(config.delay)
  {
    if (!d_ipEncryptKey.empty() && d_ipEncryptMethod == "ipcrypt-pfx") {
      d_ipcrypt2 = pdns::ipcrypt2::IPCrypt2(pdns::ipcrypt2::IPCryptMethod::pfx, d_ipEncryptKey);
    }
  }
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (!response->ids.d_protoBufData) {
      response->ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    if (!response->ids.d_protoBufData->uniqueId) {
      response->ids.d_protoBufData->uniqueId = getUniqueID();
    }

    DNSDistProtoBufMessage message(*response, d_includeCNAME);
    if (d_useServerID) {
      message.setServerIdentity(dnsdist::configuration::getCurrentRuntimeConfiguration().d_server_id);
    }
    else if (!d_serverID.empty()) {
      message.setServerIdentity(d_serverID);
    }

#ifdef HAVE_IPCIPHER
    if (!d_ipEncryptKey.empty() && d_ipEncryptMethod == "legacy") {
      message.setRequestor(encryptCA(response->ids.origRemote, d_ipEncryptKey));
    }
#endif /* HAVE_IPCIPHER */
    if (d_ipcrypt2) {
      auto encryptedAddress = d_ipcrypt2->encrypt(response->ids.origRemote);
      encryptedAddress.setPort(response->ids.origRemote.getPort());
      message.setRequestor(encryptedAddress);
    }

    if (d_tagsToExport) {
      addTagsToProtobuf(message, *response, *d_tagsToExport);
    }

    addMetaDataToProtobuf(message, *response, d_metas);

    if (d_exportExtendedErrorsToMeta) {
      addExtendedDNSErrorToProtobuf(message, *response, *d_exportExtendedErrorsToMeta);
    }

    if (d_alterFunc) {
      auto lock = g_lua.lock();
      (*d_alterFunc)(response, &message);
    }

    static thread_local std::string data;
    data.clear();
    message.serialize(data, !d_delay);

    if (!response->ids.d_rawProtobufContent.empty()) {
      data.insert(data.end(), response->ids.d_rawProtobufContent.begin(), response->ids.d_rawProtobufContent.end());
    }

    if (d_delay) {
      response->ids.delayedResponseMsgs.emplace_back(data, std::shared_ptr<RemoteLoggerInterface>(d_logger));
    }
    else {
      d_logger->queueData(data);
    }

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "remote log response to " + (d_logger ? d_logger->toString() : "");
  }

private:
  std::optional<std::unordered_set<std::string>> d_tagsToExport;
  std::vector<std::pair<std::string, ProtoBufMetaKey>> d_metas;
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  std::optional<std::function<void(DNSResponse*, DNSDistProtoBufMessage*)>> d_alterFunc;
  std::string d_serverID;
  std::string d_ipEncryptKey;
  std::string d_ipEncryptMethod;
  std::optional<pdns::ipcrypt2::IPCrypt2> d_ipcrypt2{std::nullopt};
  std::optional<std::string> d_exportExtendedErrorsToMeta{std::nullopt};
  bool d_includeCNAME;
  bool d_useServerID{false};
  bool d_delay{false};
};

#endif /* DISABLE_PROTOBUF */

class DropResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)response;
    (void)ruleresult;
    return Action::Drop;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "drop";
  }
};

class AllowResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)response;
    (void)ruleresult;
    return Action::Allow;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "allow";
  }
};

class DelayResponseAction : public DNSResponseAction
{
public:
  DelayResponseAction(int msec) :
    d_msec(msec)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)response;
    *ruleresult = std::to_string(d_msec);
    return Action::Delay;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "delay by " + std::to_string(d_msec) + " ms";
  }

private:
  int d_msec;
};

class SNMPTrapResponseAction : public DNSResponseAction
{
public:
  // this action does not stop the processing
  SNMPTrapResponseAction(std::string reason) :
    d_reason(std::move(reason))
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (g_snmpAgent != nullptr && dnsdist::configuration::getImmutableConfiguration().d_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(*response, d_reason);
    }

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "send SNMP trap";
  }

private:
  std::string d_reason;
};

class SetTagResponseAction : public DNSResponseAction
{
public:
  // this action does not stop the processing
  SetTagResponseAction(std::string tag, std::string value) :
    d_tag(std::move(tag)), d_value(std::move(value))
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    response->setTag(d_tag, d_value);

    return Action::None;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set tag '" + d_tag + "' to value '" + d_value + "'";
  }

private:
  std::string d_tag;
  std::string d_value;
};

class ClearRecordTypesResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  ClearRecordTypesResponseAction(std::unordered_set<QType> qtypes) :
    d_qtypes(std::move(qtypes))
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (!d_qtypes.empty()) {
      clearDNSPacketRecordTypes(response->getMutableData(), d_qtypes);
    }
    return DNSResponseAction::Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "clear record types";
  }

private:
  std::unordered_set<QType> d_qtypes;
};

class ContinueAction : public DNSAction
{
public:
  // this action does not stop the processing
  ContinueAction(std::shared_ptr<DNSAction>& action) :
    d_action(action)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (d_action) {
      /* call the action */
      auto action = (*d_action)(dnsquestion, ruleresult);
      bool drop = false;
      /* apply the changes if needed (pool selection, flags, etc */
      processRulesResult(action, *dnsquestion, *ruleresult, drop);
    }

    /* but ignore the resulting action no matter what */
    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    if (d_action) {
      return "continue after: " + (d_action ? d_action->toString() : "");
    }
    return "no op";
  }

private:
  std::shared_ptr<DNSAction> d_action;
};

#if defined(HAVE_DNS_OVER_HTTPS) || defined(HAVE_DNS_OVER_HTTP3)
class HTTPStatusAction : public DNSAction
{
public:
  HTTPStatusAction(uint16_t code, PacketBuffer body, std::string contentType, const dnsdist::ResponseConfig& responseConfig) :
    d_responseConfig(responseConfig), d_body(std::move(body)), d_contentType(std::move(contentType)), d_code(code)
  {
  }

  DNSAction::Action operator()([[maybe_unused]] DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
#if defined(HAVE_DNS_OVER_HTTPS)
    if (dnsquestion->ids.du) {
      dnsquestion->ids.du->setHTTPResponse(d_code, PacketBuffer(d_body), d_contentType);
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
        header.qr = true; // for good measure
        setResponseHeadersFromConfig(header, d_responseConfig);
        return true;
      });
      return Action::HeaderModify;
    }
#endif /* HAVE_DNS_OVER_HTTPS */
#if defined(HAVE_DNS_OVER_HTTP3)
    if (dnsquestion->ids.doh3u) {
      dnsquestion->ids.doh3u->setHTTPResponse(d_code, PacketBuffer(d_body), d_contentType);
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
        header.qr = true; // for good measure
        setResponseHeadersFromConfig(header, d_responseConfig);
        return true;
      });
      return Action::HeaderModify;
    }
#endif /* HAVE_DNS_OVER_HTTP3 */
    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "return an HTTP status of " + std::to_string(d_code);
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  PacketBuffer d_body;
  std::string d_contentType;
  int d_code;
};
#endif /* HAVE_DNS_OVER_HTTPS || HAVE_DNS_OVER_HTTP3 */

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
class KeyValueStoreLookupAction : public DNSAction
{
public:
  // this action does not stop the processing
  KeyValueStoreLookupAction(std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, std::string destinationTag) :
    d_kvs(kvs), d_key(lookupKey), d_tag(std::move(destinationTag))
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    std::vector<std::string> keys = d_key->getKeys(*dnsquestion);
    std::string result;
    for (const auto& key : keys) {
      if (d_kvs->getValue(key, result)) {
        break;
      }
    }

    dnsquestion->setTag(d_tag, std::move(result));

    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "lookup key-value store based on '" + d_key->toString() + "' and set the result in tag '" + d_tag + "'";
  }

private:
  std::shared_ptr<KeyValueStore> d_kvs;
  std::shared_ptr<KeyValueLookupKey> d_key;
  std::string d_tag;
};

class KeyValueStoreRangeLookupAction : public DNSAction
{
public:
  // this action does not stop the processing
  KeyValueStoreRangeLookupAction(std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, std::string destinationTag) :
    d_kvs(kvs), d_key(lookupKey), d_tag(std::move(destinationTag))
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    std::vector<std::string> keys = d_key->getKeys(*dnsquestion);
    std::string result;
    for (const auto& key : keys) {
      if (d_kvs->getRangeValue(key, result)) {
        break;
      }
    }

    dnsquestion->setTag(d_tag, std::move(result));

    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "do a range-based lookup in key-value store based on '" + d_key->toString() + "' and set the result in tag '" + d_tag + "'";
  }

private:
  std::shared_ptr<KeyValueStore> d_kvs;
  std::shared_ptr<KeyValueLookupKey> d_key;
  std::string d_tag;
};
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */

class SetMaxReturnedTTLAction : public DNSAction
{
public:
  SetMaxReturnedTTLAction(uint32_t cap) :
    d_cap(cap)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsquestion->ids.ttlCap = d_cap;
    return DNSAction::Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "cap the TTL of the returned response to " + std::to_string(d_cap);
  }

private:
  uint32_t d_cap;
};

class SetMaxReturnedTTLResponseAction : public DNSResponseAction
{
public:
  SetMaxReturnedTTLResponseAction(uint32_t cap) :
    d_cap(cap)
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    response->ids.ttlCap = d_cap;
    return DNSResponseAction::Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "cap the TTL of the returned response to " + std::to_string(d_cap);
  }

private:
  uint32_t d_cap;
};

class NegativeAndSOAAction : public DNSAction
{
public:
  NegativeAndSOAAction(bool nxd, DNSName zone, uint32_t ttl, DNSName mname, DNSName rname, dnsdist::actions::SOAParams params, bool soaInAuthoritySection, dnsdist::ResponseConfig responseConfig) :
    d_responseConfig(responseConfig), d_zone(std::move(zone)), d_mname(std::move(mname)), d_rname(std::move(rname)), d_ttl(ttl), d_params(params), d_nxd(nxd), d_soaInAuthoritySection(soaInAuthoritySection)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (!setNegativeAndAdditionalSOA(*dnsquestion, d_nxd, d_zone, d_ttl, d_mname, d_rname, d_params.serial, d_params.refresh, d_params.retry, d_params.expire, d_params.minimum, d_soaInAuthoritySection)) {
      return Action::None;
    }

    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
      setResponseHeadersFromConfig(header, d_responseConfig);
      return true;
    });

    return Action::Allow;
  }

  [[nodiscard]] std::string toString() const override
  {
    return std::string(d_nxd ? "NXD" : "NODATA") + " with SOA";
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  DNSName d_zone;
  DNSName d_mname;
  DNSName d_rname;
  uint32_t d_ttl;
  dnsdist::actions::SOAParams d_params;
  bool d_nxd;
  bool d_soaInAuthoritySection;
};

class SetProxyProtocolValuesAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetProxyProtocolValuesAction(const std::vector<std::pair<uint8_t, std::string>>& values)
  {
    d_values.reserve(values.size());
    for (const auto& value : values) {
      d_values.push_back({value.second, value.first});
    }
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (!dnsquestion->proxyProtocolValues) {
      dnsquestion->proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>();
    }

    *(dnsquestion->proxyProtocolValues) = d_values;

    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "set Proxy-Protocol values";
  }

private:
  std::vector<ProxyProtocolValue> d_values;
};

class SetAdditionalProxyProtocolValueAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetAdditionalProxyProtocolValueAction(uint8_t type, std::string value) :
    d_value(std::move(value)), d_type(type)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (!dnsquestion->proxyProtocolValues) {
      dnsquestion->proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>();
    }

    dnsquestion->proxyProtocolValues->push_back({d_value, d_type});

    return Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "add a Proxy-Protocol value of type " + std::to_string(d_type);
  }

private:
  std::string d_value;
  uint8_t d_type;
};

class SetReducedTTLResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  SetReducedTTLResponseAction(uint8_t percentage) :
    d_ratio(percentage / 100.0)
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    (void)ruleresult;
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    auto visitor = [&](uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl) {
      (void)section;
      (void)qclass;
      (void)qtype;
      return ttl * d_ratio;
    };
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    editDNSPacketTTL(reinterpret_cast<char*>(response->getMutableData().data()), response->getData().size(), visitor);
    return DNSResponseAction::Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "reduce ttl to " + std::to_string(d_ratio * 100) + " percent of its value";
  }

private:
  double d_ratio{1.0};
};

class SetExtendedDNSErrorAction : public DNSAction
{
public:
  // this action does not stop the processing
  SetExtendedDNSErrorAction(uint16_t infoCode, const std::string& extraText, bool clearExistingEntries)
  {
    d_ede.error.infoCode = infoCode;
    d_ede.error.extraText = extraText;
    d_ede.clearExisting = clearExistingEntries;
  }

  DNSAction::Action operator()(DNSQuestion* dnsQuestion, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (d_ede.clearExisting) {
      dnsQuestion->ids.d_extendedErrors = std::make_unique<std::vector<edns::SetExtendedDNSErrorOperation>>(std::initializer_list<edns::SetExtendedDNSErrorOperation>({d_ede}));
    }
    else {
      if (!dnsQuestion->ids.d_extendedErrors) {
        dnsQuestion->ids.d_extendedErrors = std::make_unique<std::vector<edns::SetExtendedDNSErrorOperation>>(std::initializer_list<edns::SetExtendedDNSErrorOperation>({d_ede}));
      }
      else {
        dnsQuestion->ids.d_extendedErrors->emplace_back(d_ede);
      }
    }

    return DNSAction::Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "set EDNS Extended DNS Error to " + std::to_string(d_ede.error.infoCode) + (d_ede.error.extraText.empty() ? std::string() : std::string(": \"") + d_ede.error.extraText + std::string("\""));
  }

private:
  edns::SetExtendedDNSErrorOperation d_ede;
};

class SetExtendedDNSErrorResponseAction : public DNSResponseAction
{
public:
  // this action does not stop the processing
  SetExtendedDNSErrorResponseAction(uint16_t infoCode, const std::string& extraText, bool clearExistingEntries)
  {
    d_ede.error.infoCode = infoCode;
    d_ede.error.extraText = extraText;
    d_ede.clearExisting = clearExistingEntries;
  }

  DNSResponseAction::Action operator()(DNSResponse* dnsResponse, std::string* ruleresult) const override
  {
    (void)ruleresult;
    if (d_ede.clearExisting) {
      dnsResponse->ids.d_extendedErrors = std::make_unique<std::vector<edns::SetExtendedDNSErrorOperation>>(std::initializer_list<edns::SetExtendedDNSErrorOperation>({d_ede}));
    }
    else {
      if (!dnsResponse->ids.d_extendedErrors) {
        dnsResponse->ids.d_extendedErrors = std::make_unique<std::vector<edns::SetExtendedDNSErrorOperation>>(std::initializer_list<edns::SetExtendedDNSErrorOperation>({d_ede}));
      }
      else {
        dnsResponse->ids.d_extendedErrors->emplace_back(d_ede);
      }
    }

    return DNSResponseAction::Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "set EDNS Extended DNS Error to " + std::to_string(d_ede.error.infoCode) + (d_ede.error.extraText.empty() ? std::string() : std::string(": \"") + d_ede.error.extraText + std::string("\""));
  }

private:
  edns::SetExtendedDNSErrorOperation d_ede;
};

class LimitTTLResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  LimitTTLResponseAction(uint32_t min, uint32_t max = std::numeric_limits<uint32_t>::max(), std::unordered_set<QType> types = {}) :
    d_types(std::move(types)), d_min(min), d_max(max)
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* dnsResponse, std::string* ruleresult) const override
  {
    (void)ruleresult;
    dnsdist::PacketMangling::restrictDNSPacketTTLs(dnsResponse->getMutableData(), d_min, d_max, d_types);
    return DNSResponseAction::Action::None;
  }

  std::string toString() const override
  {
    std::string result = "limit ttl (" + std::to_string(d_min) + " <= ttl <= " + std::to_string(d_max);
    if (!d_types.empty()) {
      bool first = true;
      result += ", types in [";
      for (const auto& type : d_types) {
        if (first) {
          first = false;
        }
        else {
          result += " ";
        }
        result += type.toString();
      }
      result += "]";
    }
    result += +")";
    return result;
  }

private:
  std::unordered_set<QType> d_types;
  uint32_t d_min{0};
  uint32_t d_max{std::numeric_limits<uint32_t>::max()};
};

std::shared_ptr<DNSAction> getLuaAction(dnsdist::actions::LuaActionFunction function)
{
  return std::shared_ptr<DNSAction>(new LuaAction(std::move(function)));
}

std::shared_ptr<DNSAction> getLuaFFIAction(dnsdist::actions::LuaActionFFIFunction function)
{
  return std::shared_ptr<DNSAction>(new LuaFFIAction(std::move(function)));
}

std::shared_ptr<DNSResponseAction> getLuaResponseAction(dnsdist::actions::LuaResponseActionFunction function)
{
  return std::shared_ptr<DNSResponseAction>(new LuaResponseAction(std::move(function)));
}

std::shared_ptr<DNSResponseAction> getLuaFFIResponseAction(dnsdist::actions::LuaResponseActionFFIFunction function)
{
  return std::shared_ptr<DNSResponseAction>(new LuaFFIResponseAction(std::move(function)));
}

#ifndef DISABLE_PROTOBUF
std::shared_ptr<DNSAction> getSetTraceAction(SetTraceActionConfiguration& config)
{
  return std::shared_ptr<DNSAction>(new SetTraceAction(config));
}

std::shared_ptr<DNSAction> getRemoteLogAction(RemoteLogActionConfiguration& config)
{
  return std::shared_ptr<DNSAction>(new RemoteLogAction(config));
}

std::shared_ptr<DNSResponseAction> getRemoteLogResponseAction(RemoteLogActionConfiguration& config)
{
  return std::shared_ptr<DNSResponseAction>(new RemoteLogResponseAction(config));
}

std::shared_ptr<DNSAction> getDnstapLogAction(const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, std::optional<DnstapAlterFunction> alterFunc)
{
  return std::shared_ptr<DNSAction>(new DnstapLogAction(identity, logger, std::move(alterFunc)));
}

std::shared_ptr<DNSResponseAction> getDnstapLogResponseAction(const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, std::optional<DnstapAlterResponseFunction> alterFunc)
{
  return std::shared_ptr<DNSResponseAction>(new DnstapLogResponseAction(identity, logger, std::move(alterFunc)));
}
#endif /* DISABLE_PROTOBUF */

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
std::shared_ptr<DNSAction> getKeyValueStoreLookupAction(std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag)
{
  return std::shared_ptr<DNSAction>(new KeyValueStoreLookupAction(kvs, lookupKey, destinationTag));
}

std::shared_ptr<DNSAction> getKeyValueStoreRangeLookupAction(std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag)
{
  return std::shared_ptr<DNSAction>(new KeyValueStoreRangeLookupAction(kvs, lookupKey, destinationTag));
}
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */

std::shared_ptr<DNSAction> getHTTPStatusAction([[maybe_unused]] uint16_t status, [[maybe_unused]] PacketBuffer&& body, [[maybe_unused]] const std::string& contentType, [[maybe_unused]] const dnsdist::ResponseConfig& responseConfig)
{
#if defined(HAVE_DNS_OVER_HTTPS)
  return std::shared_ptr<DNSAction>(new HTTPStatusAction(status, std::move(body), contentType, responseConfig));
#else
  throw std::runtime_error("Unsupported HTTPStatus action");
#endif
}

std::shared_ptr<DNSResponseAction> getLimitTTLResponseAction(uint32_t min, uint32_t max, std::unordered_set<QType> types)
{
  return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(min, max, std::move(types)));
}

std::shared_ptr<DNSResponseAction> getMinTTLResponseAction(uint32_t min)
{
  return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(min));
}

std::shared_ptr<DNSResponseAction> getClearRecordTypesResponseAction(std::unordered_set<QType> types)
{
  return std::shared_ptr<DNSResponseAction>(new ClearRecordTypesResponseAction(std::move(types)));
}

std::shared_ptr<DNSAction> getContinueAction(std::shared_ptr<DNSAction> action)
{
  return std::shared_ptr<DNSAction>(new ContinueAction(action));
}

std::shared_ptr<DNSAction> getNegativeAndSOAAction(bool nxd, const DNSName& zone, uint32_t ttl, const DNSName& mname, const DNSName& rname, const SOAParams& params, bool soaInAuthority, dnsdist::ResponseConfig responseConfig)
{
  return std::shared_ptr<DNSAction>(new NegativeAndSOAAction(nxd, zone, ttl, mname, rname, params, soaInAuthority, responseConfig));
}

std::shared_ptr<DNSAction> getRCodeAction(uint8_t rcode, const dnsdist::ResponseConfig& responseConfig)
{
  return std::shared_ptr<DNSAction>(new RCodeAction(rcode, responseConfig));
}

std::shared_ptr<DNSAction> getERCodeAction(uint8_t rcode, const dnsdist::ResponseConfig& responseConfig)
{
  return std::shared_ptr<DNSAction>(new ERCodeAction(rcode, responseConfig));
}

std::shared_ptr<DNSAction> getSetECSAction(const std::string& ipv4)
{
  return std::shared_ptr<DNSAction>(new SetECSAction(Netmask(ipv4)));
}

std::shared_ptr<DNSAction> getSetECSAction(const std::string& ipv4, const std::string& ipv6)
{
  return std::shared_ptr<DNSAction>(new SetECSAction(Netmask(ipv4), Netmask(ipv6)));
}

std::shared_ptr<DNSAction> getSpoofAction(const std::vector<ComboAddress>& addresses, const dnsdist::ResponseConfig& config)
{
  return std::shared_ptr<DNSAction>(new SpoofAction(addresses, config));
}

std::shared_ptr<DNSAction> getSpoofAction(const std::vector<std::string>& rawRDatas, std::optional<uint16_t> qtypeForAny, const dnsdist::ResponseConfig& config)
{
  return std::shared_ptr<DNSAction>(new SpoofAction(rawRDatas, qtypeForAny, config));
}

std::shared_ptr<DNSAction> getSpoofAction(const DNSName& cname, const dnsdist::ResponseConfig& config)
{
  return std::shared_ptr<DNSAction>(new SpoofAction(cname, config));
}

std::shared_ptr<DNSAction> getSpoofAction(const PacketBuffer& packet)
{
  return std::shared_ptr<DNSAction>(new SpoofAction(packet));
}

std::shared_ptr<DNSAction> getSpoofSVCAction(const std::vector<SVCRecordParameters>& parameters, const dnsdist::ResponseConfig& responseConfig)
{
  return std::shared_ptr<DNSAction>(new SpoofSVCAction(parameters, responseConfig));
}

std::shared_ptr<DNSAction> getSetMaxReturnedTTLAction(uint32_t max)
{
  return std::shared_ptr<DNSAction>(new SetMaxReturnedTTLAction(max));
}

std::shared_ptr<DNSResponseAction> getSetMaxReturnedTTLResponseAction(uint32_t max)
{
  return std::shared_ptr<DNSResponseAction>(new SetMaxReturnedTTLResponseAction(max));
}

std::shared_ptr<DNSResponseAction> getSetMaxTTLResponseAction(uint32_t max)
{
  return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(0, max));
}

std::shared_ptr<DNSAction> getSetProxyProtocolValuesAction(const std::vector<std::pair<uint8_t, std::string>>& values)
{
  return std::shared_ptr<DNSAction>(new SetProxyProtocolValuesAction(values));
}

std::shared_ptr<DNSAction> getTeeAction(const ComboAddress& rca, std::optional<ComboAddress> lca, bool addECS, bool addProxyProtocol)
{
  return std::shared_ptr<DNSAction>(new TeeAction(rca, lca, addECS, addProxyProtocol));
}

#include "dnsdist-actions-factory-generated-body.hh"
#include "dnsdist-response-actions-factory-generated-body.hh"
}
