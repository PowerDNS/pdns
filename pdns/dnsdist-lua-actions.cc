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
#include "config.h"
#include "threadname.hh"
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
#include "dnsdist-svc.hh"

#include "dnstap.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "fstrm_logger.hh"
#include "remote_logger.hh"
#include "svc-records.hh"

#include <boost/optional/optional_io.hpp>

#include "ipcipher.hh"

class DropAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
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
  TeeAction(const ComboAddress& rca, const boost::optional<ComboAddress>& lca, bool addECS = false, bool addProxyProtocol = false);
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

TeeAction::TeeAction(const ComboAddress& rca, const boost::optional<ComboAddress>& lca, bool addECS, bool addProxyProtocol) :
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
  std::array<char, s_udpIncomingBufferSize> packet{};
  ssize_t res = 0;
  const dnsheader_aligned dnsheader(packet.data());
  for (;;) {
    res = waitForData(d_socket.getHandle(), 0, 250000);
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
  RCodeAction(uint8_t rcode) :
    d_rcode(rcode) {}
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
      header.rcode = d_rcode;
      header.qr = true; // for good measure
      setResponseHeadersFromConfig(header, d_responseConfig);
      return true;
    });
    return Action::HeaderModify;
  }
  [[nodiscard]] std::string toString() const override
  {
    return "set rcode " + std::to_string(d_rcode);
  }
  [[nodiscard]] dnsdist::ResponseConfig& getResponseConfig()
  {
    return d_responseConfig;
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  uint8_t d_rcode;
};

class ERCodeAction : public DNSAction
{
public:
  ERCodeAction(uint8_t rcode) :
    d_rcode(rcode) {}
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
      header.rcode = (d_rcode & 0xF);
      header.qr = true; // for good measure
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
  [[nodiscard]] dnsdist::ResponseConfig& getResponseConfig()
  {
    return d_responseConfig;
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  uint8_t d_rcode;
};

class SpoofSVCAction : public DNSAction
{
public:
  SpoofSVCAction(const LuaArray<SVCRecordParameters>& parameters)
  {
    d_payloads.reserve(parameters.size());

    for (const auto& param : parameters) {
      std::vector<uint8_t> payload;
      if (!generateSVCPayload(payload, param.second)) {
        throw std::runtime_error("Unable to generate a valid SVC record from the supplied parameters");
      }

      d_payloads.push_back(std::move(payload));

      for (const auto& hint : param.second.ipv4hints) {
        d_additionals4.insert({param.second.target, ComboAddress(hint)});
      }

      for (const auto& hint : param.second.ipv6hints) {
        d_additionals6.insert({param.second.target, ComboAddress(hint)});
      }
    }
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    if (!dnsdist::svc::generateSVCResponse(*dnsquestion, d_payloads, d_additionals4, d_additionals6, d_responseConfig)) {
      return Action::None;
    }

    return Action::HeaderModify;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "spoof SVC record ";
  }

  [[nodiscard]] dnsdist::ResponseConfig& getResponseConfig()
  {
    return d_responseConfig;
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  std::vector<std::vector<uint8_t>> d_payloads{};
  std::set<std::pair<DNSName, ComboAddress>> d_additionals4{};
  std::set<std::pair<DNSName, ComboAddress>> d_additionals6{};
};

class TCAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
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
  using func_t = std::function<std::tuple<int, boost::optional<string>>(DNSQuestion* dnsquestion)>;
  LuaAction(LuaAction::func_t func) :
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
          if (boost::optional<std::string> rule = std::get<1>(ret)) {
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
      warnlog("LuaAction failed inside Lua, returning ServFail: %s", e.what());
    }
    catch (...) {
      warnlog("LuaAction failed inside Lua, returning ServFail: [unknown exception]");
    }
    return DNSAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua script";
  }

private:
  func_t d_func;
};

class LuaResponseAction : public DNSResponseAction
{
public:
  using func_t = std::function<std::tuple<int, boost::optional<string>>(DNSResponse* response)>;
  LuaResponseAction(LuaResponseAction::func_t func) :
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
          if (boost::optional<std::string> rule = std::get<1>(ret)) {
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
      warnlog("LuaResponseAction failed inside Lua, returning ServFail: %s", e.what());
    }
    catch (...) {
      warnlog("LuaResponseAction failed inside Lua, returning ServFail: [unknown exception]");
    }
    return DNSResponseAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua response script";
  }

private:
  func_t d_func;
};

class LuaFFIAction : public DNSAction
{
public:
  using func_t = std::function<int(dnsdist_ffi_dnsquestion_t* dnsquestion)>;

  LuaFFIAction(LuaFFIAction::func_t func) :
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
      warnlog("LuaFFIAction failed inside Lua, returning ServFail: %s", e.what());
    }
    catch (...) {
      warnlog("LuaFFIAction failed inside Lua, returning ServFail: [unknown exception]");
    }
    return DNSAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua FFI script";
  }

private:
  func_t d_func;
};

class LuaFFIPerThreadAction : public DNSAction
{
public:
  using func_t = std::function<int(dnsdist_ffi_dnsquestion_t* dnsquestion)>;

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
        state.d_func = state.d_luaContext.executeCode<func_t>(d_functionCode);
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
      warnlog("LuaFFIPerThreadAction failed inside Lua, returning ServFail: %s", e.what());
    }
    catch (...) {
      warnlog("LuaFFIPerthreadAction failed inside Lua, returning ServFail: [unknown exception]");
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
    func_t d_func;
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
  using func_t = std::function<int(dnsdist_ffi_dnsresponse_t* dnsquestion)>;

  LuaFFIResponseAction(LuaFFIResponseAction::func_t func) :
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
      warnlog("LuaFFIResponseAction failed inside Lua, returning ServFail: %s", e.what());
    }
    catch (...) {
      warnlog("LuaFFIResponseAction failed inside Lua, returning ServFail: [unknown exception]");
    }
    return DNSResponseAction::Action::ServFail;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "Lua FFI script";
  }

private:
  func_t d_func;
};

class LuaFFIPerThreadResponseAction : public DNSResponseAction
{
public:
  using func_t = std::function<int(dnsdist_ffi_dnsresponse_t* response)>;

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
        state.d_func = state.d_luaContext.executeCode<func_t>(d_functionCode);
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
      warnlog("LuaFFIPerThreadResponseAction failed inside Lua, returning ServFail: %s", e.what());
    }
    catch (...) {
      warnlog("LuaFFIPerthreadResponseAction failed inside Lua, returning ServFail: [unknown exception]");
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
    func_t d_func;
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

thread_local std::default_random_engine SpoofAction::t_randomEngine;

DNSAction::Action SpoofAction::operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const
{
  uint16_t qtype = dnsquestion->ids.qtype;
  // do we even have a response?
  if (d_cname.empty() && d_rawResponses.empty() &&
      // make sure pre-forged response is greater than sizeof(dnsheader)
      (d_raw.size() < sizeof(dnsheader)) && d_types.count(qtype) == 0) {
    return Action::None;
  }

  if (d_raw.size() >= sizeof(dnsheader)) {
    auto questionId = dnsquestion->getHeader()->id;
    dnsquestion->getMutableData() = d_raw;
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [questionId](dnsheader& header) {
      header.id = questionId;
      return true;
    });
    return Action::HeaderModify;
  }
  std::vector<ComboAddress> addrs = {};
  std::vector<std::string> rawResponses = {};
  unsigned int totrdatalen = 0;
  size_t numberOfRecords = 0;
  if (!d_cname.empty()) {
    qtype = QType::CNAME;
    totrdatalen += d_cname.getStorage().size();
    numberOfRecords = 1;
  }
  else if (!d_rawResponses.empty()) {
    rawResponses.reserve(d_rawResponses.size());
    for (const auto& rawResponse : d_rawResponses) {
      totrdatalen += rawResponse.size();
      rawResponses.push_back(rawResponse);
      ++numberOfRecords;
    }
    if (rawResponses.size() > 1) {
      shuffle(rawResponses.begin(), rawResponses.end(), t_randomEngine);
    }
  }
  else {
    for (const auto& addr : d_addrs) {
      if (qtype != QType::ANY && ((addr.sin4.sin_family == AF_INET && qtype != QType::A) || (addr.sin4.sin_family == AF_INET6 && qtype != QType::AAAA))) {
        continue;
      }
      totrdatalen += addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr);
      addrs.push_back(addr);
      ++numberOfRecords;
    }
  }

  if (addrs.size() > 1) {
    shuffle(addrs.begin(), addrs.end(), t_randomEngine);
  }

  unsigned int qnameWireLength = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName ignore(reinterpret_cast<const char*>(dnsquestion->getData().data()), dnsquestion->getData().size(), sizeof(dnsheader), false, nullptr, nullptr, &qnameWireLength);

  if (dnsquestion->getMaximumSize() < (sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totrdatalen)) {
    return Action::None;
  }

  bool dnssecOK = false;
  bool hadEDNS = false;
  if (g_addEDNSToSelfGeneratedResponses && queryHasEDNS(*dnsquestion)) {
    hadEDNS = true;
    dnssecOK = ((getEDNSZ(*dnsquestion) & EDNS_HEADER_FLAG_DO) != 0);
  }

  auto& data = dnsquestion->getMutableData();
  data.resize(sizeof(dnsheader) + qnameWireLength + 4 + numberOfRecords * 12 /* recordstart */ + totrdatalen); // there goes your EDNS
  uint8_t* dest = &(data.at(sizeof(dnsheader) + qnameWireLength + 4));

  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
    header.qr = true; // for good measure
    setResponseHeadersFromConfig(header, d_responseConfig);
    header.ancount = 0;
    header.arcount = 0; // for now, forget about your EDNS, we're marching over it
    return true;
  });

  uint32_t ttl = htonl(d_responseConfig.ttl);
  uint16_t qclass = htons(dnsquestion->ids.qclass);
  std::array<unsigned char, 12> recordstart = {
    0xc0, 0x0c, // compressed name
    0, 0, // QTYPE
    0, 0, // QCLASS
    0, 0, 0, 0, // TTL
    0, 0 // rdata length
  };
  static_assert(recordstart.size() == 12, "sizeof(recordstart) must be equal to 12, otherwise the above check is invalid");
  memcpy(&recordstart[4], &qclass, sizeof(qclass));
  memcpy(&recordstart[6], &ttl, sizeof(ttl));

  if (qtype == QType::CNAME) {
    const auto& wireData = d_cname.getStorage(); // Note! This doesn't do compression!
    uint16_t rdataLen = htons(wireData.length());
    qtype = htons(qtype);
    memcpy(&recordstart[2], &qtype, sizeof(qtype));
    memcpy(&recordstart[10], &rdataLen, sizeof(rdataLen));

    memcpy(dest, recordstart.data(), recordstart.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    dest += recordstart.size();
    memcpy(dest, wireData.c_str(), wireData.length());
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [](dnsheader& header) {
      header.ancount++;
      return true;
    });
  }
  else if (!rawResponses.empty()) {
    if (qtype == QType::ANY && d_rawTypeForAny) {
      qtype = *d_rawTypeForAny;
    }
    qtype = htons(qtype);
    for (const auto& rawResponse : rawResponses) {
      uint16_t rdataLen = htons(rawResponse.size());
      memcpy(&recordstart[2], &qtype, sizeof(qtype));
      memcpy(&recordstart[10], &rdataLen, sizeof(rdataLen));

      memcpy(dest, recordstart.data(), sizeof(recordstart));
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      dest += recordstart.size();

      memcpy(dest, rawResponse.c_str(), rawResponse.size());
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      dest += rawResponse.size();

      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [](dnsheader& header) {
        header.ancount++;
        return true;
      });
    }
  }
  else {
    for (const auto& addr : addrs) {
      uint16_t rdataLen = htons(addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr));
      qtype = htons(addr.sin4.sin_family == AF_INET ? QType::A : QType::AAAA);
      memcpy(&recordstart[2], &qtype, sizeof(qtype));
      memcpy(&recordstart[10], &rdataLen, sizeof(rdataLen));

      memcpy(dest, recordstart.data(), recordstart.size());
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      dest += sizeof(recordstart);

      memcpy(dest,
             // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
             addr.sin4.sin_family == AF_INET ? reinterpret_cast<const void*>(&addr.sin4.sin_addr.s_addr) : reinterpret_cast<const void*>(&addr.sin6.sin6_addr.s6_addr),
             addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr));
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      dest += (addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr));
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [](dnsheader& header) {
        header.ancount++;
        return true;
      });
    }
  }

  auto finalANCount = dnsquestion->getHeader()->ancount;
  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [finalANCount](dnsheader& header) {
    header.ancount = htons(finalANCount);
    return true;
  });

  if (hadEDNS) {
    addEDNS(dnsquestion->getMutableData(), dnsquestion->getMaximumSize(), dnssecOK, g_PayloadSizeSelfGenAnswers, 0);
  }

  return Action::HeaderModify;
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

      if (!slowRewriteEDNSOptionInQueryWithRecords(dnsquestion->getData(), newContent, ednsAdded, d_code, optionAdded, true, optRData)) {
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
    if (generateOptRR(optRData, data, dnsquestion->getMaximumSize(), g_EdnsUDPPayloadSize, 0, false)) {
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
    setEDNSOption(*dnsquestion, d_code, d_data);
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

  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    setEDNSOption(*response, d_code, d_data);
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

class SetNoRecurseAction : public DNSAction
{
public:
  // this action does not stop the processing
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
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
    auto filepointer = std::atomic_load_explicit(&d_fp, std::memory_order_acquire);
    if (!filepointer) {
      if (!d_verboseOnly || g_verbose) {
        if (d_includeTimestamp) {
          infolog("[%u.%u] Packet from %s for %s %s with id %d", static_cast<unsigned long long>(dnsquestion->getQueryRealTime().tv_sec), static_cast<unsigned long>(dnsquestion->getQueryRealTime().tv_nsec), dnsquestion->ids.origRemote.toStringWithPort(), dnsquestion->ids.qname.toString(), QType(dnsquestion->ids.qtype).toString(), dnsquestion->getHeader()->id);
        }
        else {
          infolog("Packet from %s for %s %s with id %d", dnsquestion->ids.origRemote.toStringWithPort(), dnsquestion->ids.qname.toString(), QType(dnsquestion->ids.qtype).toString(), dnsquestion->getHeader()->id);
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
      warnlog("Unable to open file '%s' for logging: %s", d_fname, stringerror());
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
    auto filepointer = std::atomic_load_explicit(&d_fp, std::memory_order_acquire);
    if (!filepointer) {
      if (!d_verboseOnly || g_verbose) {
        if (d_includeTimestamp) {
          infolog("[%u.%u] Answer to %s for %s %s (%s) with id %u", static_cast<unsigned long long>(response->getQueryRealTime().tv_sec), static_cast<unsigned long>(response->getQueryRealTime().tv_nsec), response->ids.origRemote.toStringWithPort(), response->ids.qname.toString(), QType(response->ids.qtype).toString(), RCode::to_s(response->getHeader()->rcode), response->getHeader()->id);
        }
        else {
          infolog("Answer to %s for %s %s (%s) with id %u", response->ids.origRemote.toStringWithPort(), response->ids.qname.toString(), QType(response->ids.qtype).toString(), RCode::to_s(response->getHeader()->rcode), response->getHeader()->id);
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
      warnlog("Unable to open file '%s' for logging: %s", d_fname, stringerror());
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
static DnstapMessage::ProtocolType ProtocolToDNSTap(dnsdist::Protocol protocol)
{
  if (protocol == dnsdist::Protocol::DoUDP) {
    return DnstapMessage::ProtocolType::DoUDP;
  }
  if (protocol == dnsdist::Protocol::DoTCP) {
    return DnstapMessage::ProtocolType::DoTCP;
  }
  if (protocol == dnsdist::Protocol::DoT) {
    return DnstapMessage::ProtocolType::DoT;
  }
  if (protocol == dnsdist::Protocol::DoH || protocol == dnsdist::Protocol::DoH3) {
    return DnstapMessage::ProtocolType::DoH;
  }
  if (protocol == dnsdist::Protocol::DNSCryptUDP) {
    return DnstapMessage::ProtocolType::DNSCryptUDP;
  }
  if (protocol == dnsdist::Protocol::DNSCryptTCP) {
    return DnstapMessage::ProtocolType::DNSCryptTCP;
  }
  if (protocol == dnsdist::Protocol::DoQ) {
    return DnstapMessage::ProtocolType::DoQ;
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
    vinfolog("%s: %s", remoteLogger.name(), RemoteLoggerInterface::toErrorString(ret));
    break;
  }
  case RemoteLoggerInterface::Result::TooLarge: {
    warnlog("%s: %s", remoteLogger.name(), RemoteLoggerInterface::toErrorString(ret));
    break;
  }
  case RemoteLoggerInterface::Result::OtherError:
    warnlog("%s: %s", remoteLogger.name(), RemoteLoggerInterface::toErrorString(ret));
  }
}

class DnstapLogAction : public DNSAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  DnstapLogAction(std::string identity, std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(DNSQuestion*, DnstapMessage*)>> alterFunc) :
    d_identity(std::move(identity)), d_logger(logger), d_alterFunc(std::move(alterFunc))
  {
  }
  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    static thread_local std::string data;
    data.clear();

    DnstapMessage::ProtocolType protocol = ProtocolToDNSTap(dnsquestion->getProtocol());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DnstapMessage message(std::move(data), !dnsquestion->getHeader()->qr ? DnstapMessage::MessageType::client_query : DnstapMessage::MessageType::client_response, d_identity, &dnsquestion->ids.origRemote, &dnsquestion->ids.origDest, protocol, reinterpret_cast<const char*>(dnsquestion->getData().data()), dnsquestion->getData().size(), &dnsquestion->getQueryRealTime(), nullptr);
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
  boost::optional<std::function<void(DNSQuestion*, DnstapMessage*)>> d_alterFunc;
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

struct RemoteLogActionConfiguration
{
  std::vector<std::pair<std::string, ProtoBufMetaKey>> metas;
  std::optional<std::unordered_set<std::string>> tagsToExport{std::nullopt};
  boost::optional<std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)>> alterQueryFunc{boost::none};
  boost::optional<std::function<void(DNSResponse*, DNSDistProtoBufMessage*)>> alterResponseFunc{boost::none};
  std::shared_ptr<RemoteLoggerInterface> logger;
  std::string serverID;
  std::string ipEncryptKey;
  std::optional<std::string> exportExtendedErrorsToMeta{std::nullopt};
  bool includeCNAME{false};
};

class RemoteLogAction : public DNSAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  RemoteLogAction(RemoteLogActionConfiguration& config) :
    d_tagsToExport(std::move(config.tagsToExport)), d_metas(std::move(config.metas)), d_logger(config.logger), d_alterFunc(std::move(config.alterQueryFunc)), d_serverID(config.serverID), d_ipEncryptKey(config.ipEncryptKey)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    if (!dnsquestion->ids.d_protoBufData) {
      dnsquestion->ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    if (!dnsquestion->ids.d_protoBufData->uniqueId) {
      dnsquestion->ids.d_protoBufData->uniqueId = getUniqueID();
    }

    DNSDistProtoBufMessage message(*dnsquestion);
    if (!d_serverID.empty()) {
      message.setServerIdentity(d_serverID);
    }

#if HAVE_IPCIPHER
    if (!d_ipEncryptKey.empty()) {
      message.setRequestor(encryptCA(dnsquestion->ids.origRemote, d_ipEncryptKey));
    }
#endif /* HAVE_IPCIPHER */

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
  boost::optional<std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)>> d_alterFunc;
  std::string d_serverID;
  std::string d_ipEncryptKey;
};

#endif /* DISABLE_PROTOBUF */

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
    if (g_snmpAgent != nullptr && g_snmpTrapsEnabled) {
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
  DnstapLogResponseAction(std::string identity, std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(DNSResponse*, DnstapMessage*)>> alterFunc) :
    d_identity(std::move(identity)), d_logger(logger), d_alterFunc(std::move(alterFunc))
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    static thread_local std::string data;
    struct timespec now = {};
    gettime(&now, true);
    data.clear();

    DnstapMessage::ProtocolType protocol = ProtocolToDNSTap(response->getProtocol());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DnstapMessage message(std::move(data), DnstapMessage::MessageType::client_response, d_identity, &response->ids.origRemote, &response->ids.origDest, protocol, reinterpret_cast<const char*>(response->getData().data()), response->getData().size(), &response->getQueryRealTime(), &now);
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
  boost::optional<std::function<void(DNSResponse*, DnstapMessage*)>> d_alterFunc;
};

class RemoteLogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  // this action does not stop the processing
  RemoteLogResponseAction(RemoteLogActionConfiguration& config) :
    d_tagsToExport(std::move(config.tagsToExport)), d_metas(std::move(config.metas)), d_logger(config.logger), d_alterFunc(std::move(config.alterResponseFunc)), d_serverID(config.serverID), d_ipEncryptKey(config.ipEncryptKey), d_exportExtendedErrorsToMeta(std::move(config.exportExtendedErrorsToMeta)), d_includeCNAME(config.includeCNAME)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
    if (!response->ids.d_protoBufData) {
      response->ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    if (!response->ids.d_protoBufData->uniqueId) {
      response->ids.d_protoBufData->uniqueId = getUniqueID();
    }

    DNSDistProtoBufMessage message(*response, d_includeCNAME);
    if (!d_serverID.empty()) {
      message.setServerIdentity(d_serverID);
    }

#if HAVE_IPCIPHER
    if (!d_ipEncryptKey.empty()) {
      message.setRequestor(encryptCA(response->ids.origRemote, d_ipEncryptKey));
    }
#endif /* HAVE_IPCIPHER */

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
    message.serialize(data);
    d_logger->queueData(data);

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
  boost::optional<std::function<void(DNSResponse*, DNSDistProtoBufMessage*)>> d_alterFunc;
  std::string d_serverID;
  std::string d_ipEncryptKey;
  std::optional<std::string> d_exportExtendedErrorsToMeta{std::nullopt};
  bool d_includeCNAME;
};
#endif /* DISABLE_PROTOBUF */

class DropResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
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

#ifdef HAVE_NET_SNMP
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
    if (g_snmpAgent && g_snmpTrapsEnabled) {
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
#endif /* HAVE_NET_SNMP */

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
  std::unordered_set<QType> d_qtypes{};
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

#ifdef HAVE_DNS_OVER_HTTPS
class HTTPStatusAction : public DNSAction
{
public:
  HTTPStatusAction(int code, PacketBuffer body, std::string contentType) :
    d_body(std::move(body)), d_contentType(std::move(contentType)), d_code(code)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
    if (!dnsquestion->ids.du) {
      return Action::None;
    }

    dnsquestion->ids.du->setHTTPResponse(d_code, PacketBuffer(d_body), d_contentType);
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsquestion->getMutableData(), [this](dnsheader& header) {
      header.qr = true; // for good measure
      setResponseHeadersFromConfig(header, d_responseConfig);
      return true;
    });
    return Action::HeaderModify;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "return an HTTP status of " + std::to_string(d_code);
  }

  [[nodiscard]] dnsdist::ResponseConfig& getResponseConfig()
  {
    return d_responseConfig;
  }

private:
  dnsdist::ResponseConfig d_responseConfig;
  PacketBuffer d_body;
  std::string d_contentType;
  int d_code;
};
#endif /* HAVE_DNS_OVER_HTTPS */

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

class MaxReturnedTTLAction : public DNSAction
{
public:
  MaxReturnedTTLAction(uint32_t cap) :
    d_cap(cap)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
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

class MaxReturnedTTLResponseAction : public DNSResponseAction
{
public:
  MaxReturnedTTLResponseAction(uint32_t cap) :
    d_cap(cap)
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* response, std::string* ruleresult) const override
  {
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
  struct SOAParams
  {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
  };

  NegativeAndSOAAction(bool nxd, DNSName zone, uint32_t ttl, DNSName mname, DNSName rname, SOAParams params, bool soaInAuthoritySection) :
    d_zone(std::move(zone)), d_mname(std::move(mname)), d_rname(std::move(rname)), d_ttl(ttl), d_params(params), d_nxd(nxd), d_soaInAuthoritySection(soaInAuthoritySection)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dnsquestion, std::string* ruleresult) const override
  {
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
    return std::string(d_nxd ? "NXD " : "NODATA") + " with SOA";
  }
  [[nodiscard]] dnsdist::ResponseConfig& getResponseConfig()
  {
    return d_responseConfig;
  }

private:
  dnsdist::ResponseConfig d_responseConfig;

  DNSName d_zone;
  DNSName d_mname;
  DNSName d_rname;
  uint32_t d_ttl;
  SOAParams d_params;
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
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    auto visitor = [&](uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl) {
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
  SetExtendedDNSErrorAction(uint16_t infoCode, const std::string& extraText)
  {
    d_ede.infoCode = infoCode;
    d_ede.extraText = extraText;
  }

  DNSAction::Action operator()(DNSQuestion* dnsQuestion, std::string* ruleresult) const override
  {
    dnsQuestion->ids.d_extendedError = std::make_unique<EDNSExtendedError>(d_ede);

    return DNSAction::Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "set EDNS Extended DNS Error to " + std::to_string(d_ede.infoCode) + (d_ede.extraText.empty() ? std::string() : std::string(": \"") + d_ede.extraText + std::string("\""));
  }

private:
  EDNSExtendedError d_ede;
};

class SetExtendedDNSErrorResponseAction : public DNSResponseAction
{
public:
  // this action does not stop the processing
  SetExtendedDNSErrorResponseAction(uint16_t infoCode, const std::string& extraText)
  {
    d_ede.infoCode = infoCode;
    d_ede.extraText = extraText;
  }

  DNSResponseAction::Action operator()(DNSResponse* dnsResponse, std::string* ruleresult) const override
  {
    dnsResponse->ids.d_extendedError = std::make_unique<EDNSExtendedError>(d_ede);

    return DNSResponseAction::Action::None;
  }

  [[nodiscard]] std::string toString() const override
  {
    return "set EDNS Extended DNS Error to " + std::to_string(d_ede.infoCode) + (d_ede.extraText.empty() ? std::string() : std::string(": \"") + d_ede.extraText + std::string("\""));
  }

private:
  EDNSExtendedError d_ede;
};

template <typename T, typename ActionT>
static void addAction(GlobalStateHolder<vector<T>>* someRuleActions, const luadnsrule_t& var, const std::shared_ptr<ActionT>& action, boost::optional<luaruleparams_t>& params)
{
  setLuaSideEffect();

  std::string name;
  boost::uuids::uuid uuid{};
  uint64_t creationOrder = 0;
  parseRuleParams(params, uuid, name, creationOrder);
  checkAllParametersConsumed("addAction", params);

  auto rule = makeRule(var, "addAction");
  someRuleActions->modify([&rule, &action, &uuid, creationOrder, &name](vector<T>& ruleactions) {
    ruleactions.push_back({std::move(rule), std::move(action), std::move(name), uuid, creationOrder});
  });
}

using responseParams_t = std::unordered_map<std::string, boost::variant<bool, uint32_t>>;

static void parseResponseConfig(boost::optional<responseParams_t>& vars, dnsdist::ResponseConfig& config)
{
  getOptionalValue<uint32_t>(vars, "ttl", config.ttl);
  getOptionalValue<bool>(vars, "aa", config.setAA);
  getOptionalValue<bool>(vars, "ad", config.setAD);
  getOptionalValue<bool>(vars, "ra", config.setRA);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
void setupLuaActions(LuaContext& luaCtx)
{
  luaCtx.writeFunction("newRuleAction", [](const luadnsrule_t& dnsrule, std::shared_ptr<DNSAction> action, boost::optional<luaruleparams_t> params) {
    boost::uuids::uuid uuid{};
    uint64_t creationOrder = 0;
    std::string name;
    parseRuleParams(params, uuid, name, creationOrder);
    checkAllParametersConsumed("newRuleAction", params);

    auto rule = makeRule(dnsrule, "newRuleAction");
    DNSDistRuleAction ruleaction({std::move(rule), std::move(action), std::move(name), uuid, creationOrder});
    return std::make_shared<DNSDistRuleAction>(ruleaction);
  });

  luaCtx.writeFunction("addAction", [](const luadnsrule_t& var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
    if (era.type() != typeid(std::shared_ptr<DNSAction>)) {
      throw std::runtime_error("addAction() can only be called with query-related actions, not response-related ones. Are you looking for addResponseAction()?");
    }

    addAction(&g_ruleactions, var, boost::get<std::shared_ptr<DNSAction>>(era), params);
  });

  luaCtx.writeFunction("addResponseAction", [](const luadnsrule_t& var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
    if (era.type() != typeid(std::shared_ptr<DNSResponseAction>)) {
      throw std::runtime_error("addResponseAction() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
    }

    addAction(&g_respruleactions, var, boost::get<std::shared_ptr<DNSResponseAction>>(era), params);
  });

  luaCtx.writeFunction("addCacheHitResponseAction", [](const luadnsrule_t& var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
    if (era.type() != typeid(std::shared_ptr<DNSResponseAction>)) {
      throw std::runtime_error("addCacheHitResponseAction() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
    }

    addAction(&g_cachehitrespruleactions, var, boost::get<std::shared_ptr<DNSResponseAction>>(era), params);
  });

  luaCtx.writeFunction("addCacheInsertedResponseAction", [](const luadnsrule_t& var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
    if (era.type() != typeid(std::shared_ptr<DNSResponseAction>)) {
      throw std::runtime_error("addCacheInsertedResponseAction() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
    }

    addAction(&g_cacheInsertedRespRuleActions, var, boost::get<std::shared_ptr<DNSResponseAction>>(era), params);
  });

  luaCtx.writeFunction("addSelfAnsweredResponseAction", [](const luadnsrule_t& var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
    if (era.type() != typeid(std::shared_ptr<DNSResponseAction>)) {
      throw std::runtime_error("addSelfAnsweredResponseAction() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
    }

    addAction(&g_selfansweredrespruleactions, var, boost::get<std::shared_ptr<DNSResponseAction>>(era), params);
  });

  luaCtx.registerFunction<void (DNSAction::*)() const>("printStats", [](const DNSAction& action) {
    setLuaNoSideEffect();
    auto stats = action.getStats();
    for (const auto& stat : stats) {
      g_outputBuffer += stat.first + "\t";
      double integral = 0;
      if (std::modf(stat.second, &integral) == 0.0 && stat.second < static_cast<double>(std::numeric_limits<uint64_t>::max())) {
        g_outputBuffer += std::to_string(static_cast<uint64_t>(stat.second)) + "\n";
      }
      else {
        g_outputBuffer += std::to_string(stat.second) + "\n";
      }
    }
  });

  luaCtx.writeFunction("getAction", [](unsigned int num) {
    setLuaNoSideEffect();
    boost::optional<std::shared_ptr<DNSAction>> ret;
    auto ruleactions = g_ruleactions.getCopy();
    if (num < ruleactions.size()) {
      ret = ruleactions[num].d_action;
    }
    return ret;
  });

  luaCtx.registerFunction("getStats", &DNSAction::getStats);
  luaCtx.registerFunction("reload", &DNSAction::reload);
  luaCtx.registerFunction("reload", &DNSResponseAction::reload);

  luaCtx.writeFunction("LuaAction", [](LuaAction::func_t func) {
    setLuaSideEffect();
    return std::shared_ptr<DNSAction>(new LuaAction(std::move(func)));
  });

  luaCtx.writeFunction("LuaFFIAction", [](LuaFFIAction::func_t func) {
    setLuaSideEffect();
    return std::shared_ptr<DNSAction>(new LuaFFIAction(std::move(func)));
  });

  luaCtx.writeFunction("LuaFFIPerThreadAction", [](const std::string& code) {
    setLuaSideEffect();
    return std::shared_ptr<DNSAction>(new LuaFFIPerThreadAction(code));
  });

  luaCtx.writeFunction("SetNoRecurseAction", []() {
    return std::shared_ptr<DNSAction>(new SetNoRecurseAction);
  });

  luaCtx.writeFunction("SetMacAddrAction", [](int code) {
    return std::shared_ptr<DNSAction>(new SetMacAddrAction(code));
  });

  luaCtx.writeFunction("SetEDNSOptionAction", [](int code, const std::string& data) {
    return std::shared_ptr<DNSAction>(new SetEDNSOptionAction(code, data));
  });

  luaCtx.writeFunction("SetEDNSOptionResponseAction", [](int code, const std::string& data) {
    return std::shared_ptr<DNSResponseAction>(new SetEDNSOptionResponseAction(code, data));
  });

  luaCtx.writeFunction("PoolAction", [](const std::string& poolname, boost::optional<bool> stopProcessing) {
    return std::shared_ptr<DNSAction>(new PoolAction(poolname, stopProcessing ? *stopProcessing : true));
  });

  luaCtx.writeFunction("QPSAction", [](int limit) {
    return std::shared_ptr<DNSAction>(new QPSAction(limit));
  });

  luaCtx.writeFunction("QPSPoolAction", [](int limit, const std::string& poolname, boost::optional<bool> stopProcessing) {
    return std::shared_ptr<DNSAction>(new QPSPoolAction(limit, poolname, stopProcessing ? *stopProcessing : true));
  });

  luaCtx.writeFunction("SpoofAction", [](LuaTypeOrArrayOf<std::string> inp, boost::optional<responseParams_t> vars) {
    vector<ComboAddress> addrs;
    if (auto* ipaddr = boost::get<std::string>(&inp)) {
      addrs.emplace_back(*ipaddr);
    }
    else {
      const auto& ipsArray = boost::get<LuaArray<std::string>>(inp);
      for (const auto& ipAddr : ipsArray) {
        addrs.emplace_back(ipAddr.second);
      }
    }

    auto ret = std::shared_ptr<DNSAction>(new SpoofAction(addrs));
    auto spoofaction = std::dynamic_pointer_cast<SpoofAction>(ret);
    parseResponseConfig(vars, spoofaction->getResponseConfig());
    checkAllParametersConsumed("SpoofAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SpoofSVCAction", [](const LuaArray<SVCRecordParameters>& parameters, boost::optional<responseParams_t> vars) {
    auto ret = std::shared_ptr<DNSAction>(new SpoofSVCAction(parameters));
    auto spoofaction = std::dynamic_pointer_cast<SpoofSVCAction>(ret);
    parseResponseConfig(vars, spoofaction->getResponseConfig());
    return ret;
  });

  luaCtx.writeFunction("SpoofCNAMEAction", [](const std::string& cname, boost::optional<responseParams_t> vars) {
    auto ret = std::shared_ptr<DNSAction>(new SpoofAction(DNSName(cname)));
    auto spoofaction = std::dynamic_pointer_cast<SpoofAction>(ret);
    parseResponseConfig(vars, spoofaction->getResponseConfig());
    checkAllParametersConsumed("SpoofCNAMEAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SpoofRawAction", [](LuaTypeOrArrayOf<std::string> inp, boost::optional<responseParams_t> vars) {
    vector<string> raws;
    if (const auto* str = boost::get<std::string>(&inp)) {
      raws.push_back(*str);
    }
    else {
      const auto& vect = boost::get<LuaArray<std::string>>(inp);
      for (const auto& raw : vect) {
        raws.push_back(raw.second);
      }
    }
    uint32_t qtypeForAny{0};
    getOptionalValue<uint32_t>(vars, "typeForAny", qtypeForAny);
    if (qtypeForAny > std::numeric_limits<uint16_t>::max()) {
      qtypeForAny = 0;
    }
    std::optional<uint16_t> qtypeForAnyParam;
    if (qtypeForAny > 0) {
      qtypeForAnyParam = static_cast<uint16_t>(qtypeForAny);
    }
    auto ret = std::shared_ptr<DNSAction>(new SpoofAction(raws, qtypeForAnyParam));
    auto spoofaction = std::dynamic_pointer_cast<SpoofAction>(ret);
    parseResponseConfig(vars, spoofaction->getResponseConfig());
    checkAllParametersConsumed("SpoofRawAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SpoofPacketAction", [](const std::string& response, size_t len) {
    if (len < sizeof(dnsheader)) {
      throw std::runtime_error(std::string("SpoofPacketAction: given packet len is too small"));
    }
    auto ret = std::shared_ptr<DNSAction>(new SpoofAction(response.c_str(), len));
    return ret;
  });

  luaCtx.writeFunction("DropAction", []() {
    return std::shared_ptr<DNSAction>(new DropAction);
  });

  luaCtx.writeFunction("AllowAction", []() {
    return std::shared_ptr<DNSAction>(new AllowAction);
  });

  luaCtx.writeFunction("NoneAction", []() {
    return std::shared_ptr<DNSAction>(new NoneAction);
  });

  luaCtx.writeFunction("DelayAction", [](int msec) {
    return std::shared_ptr<DNSAction>(new DelayAction(msec));
  });

  luaCtx.writeFunction("TCAction", []() {
    return std::shared_ptr<DNSAction>(new TCAction);
  });

  luaCtx.writeFunction("TCResponseAction", []() {
    return std::shared_ptr<DNSResponseAction>(new TCResponseAction);
  });

  luaCtx.writeFunction("SetDisableValidationAction", []() {
    return std::shared_ptr<DNSAction>(new SetDisableValidationAction);
  });

  luaCtx.writeFunction("LogAction", [](boost::optional<std::string> fname, boost::optional<bool> binary, boost::optional<bool> append, boost::optional<bool> buffered, boost::optional<bool> verboseOnly, boost::optional<bool> includeTimestamp) {
    return std::shared_ptr<DNSAction>(new LogAction(fname ? *fname : "", binary ? *binary : true, append ? *append : false, buffered ? *buffered : false, verboseOnly ? *verboseOnly : true, includeTimestamp ? *includeTimestamp : false));
  });

  luaCtx.writeFunction("LogResponseAction", [](boost::optional<std::string> fname, boost::optional<bool> append, boost::optional<bool> buffered, boost::optional<bool> verboseOnly, boost::optional<bool> includeTimestamp) {
    return std::shared_ptr<DNSResponseAction>(new LogResponseAction(fname ? *fname : "", append ? *append : false, buffered ? *buffered : false, verboseOnly ? *verboseOnly : true, includeTimestamp ? *includeTimestamp : false));
  });

  luaCtx.writeFunction("LimitTTLResponseAction", [](uint32_t min, uint32_t max, boost::optional<LuaArray<uint16_t>> types) {
    std::unordered_set<QType> capTypes;
    if (types) {
      capTypes.reserve(types->size());
      for (const auto& [idx, type] : *types) {
        capTypes.insert(QType(type));
      }
    }
    return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(min, max, capTypes));
  });

  luaCtx.writeFunction("SetMinTTLResponseAction", [](uint32_t min) {
    return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(min));
  });

  luaCtx.writeFunction("SetMaxTTLResponseAction", [](uint32_t max) {
    return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(0, max));
  });

  luaCtx.writeFunction("SetMaxReturnedTTLAction", [](uint32_t max) {
    return std::shared_ptr<DNSAction>(new MaxReturnedTTLAction(max));
  });

  luaCtx.writeFunction("SetMaxReturnedTTLResponseAction", [](uint32_t max) {
    return std::shared_ptr<DNSResponseAction>(new MaxReturnedTTLResponseAction(max));
  });

  luaCtx.writeFunction("SetReducedTTLResponseAction", [](uint8_t percentage) {
    if (percentage > 100) {
      throw std::runtime_error(std::string("SetReducedTTLResponseAction takes a percentage between 0 and 100."));
    }
    return std::shared_ptr<DNSResponseAction>(new SetReducedTTLResponseAction(percentage));
  });

  luaCtx.writeFunction("ClearRecordTypesResponseAction", [](LuaTypeOrArrayOf<int> types) {
    std::unordered_set<QType> qtypes{};
    if (types.type() == typeid(int)) {
      qtypes.insert(boost::get<int>(types));
    }
    else if (types.type() == typeid(LuaArray<int>)) {
      const auto& typesArray = boost::get<LuaArray<int>>(types);
      for (const auto& tpair : typesArray) {
        qtypes.insert(tpair.second);
      }
    }
    return std::shared_ptr<DNSResponseAction>(new ClearRecordTypesResponseAction(std::move(qtypes)));
  });

  luaCtx.writeFunction("RCodeAction", [](uint8_t rcode, boost::optional<responseParams_t> vars) {
    auto ret = std::shared_ptr<DNSAction>(new RCodeAction(rcode));
    auto rca = std::dynamic_pointer_cast<RCodeAction>(ret);
    parseResponseConfig(vars, rca->getResponseConfig());
    checkAllParametersConsumed("RCodeAction", vars);
    return ret;
  });

  luaCtx.writeFunction("ERCodeAction", [](uint8_t rcode, boost::optional<responseParams_t> vars) {
    auto ret = std::shared_ptr<DNSAction>(new ERCodeAction(rcode));
    auto erca = std::dynamic_pointer_cast<ERCodeAction>(ret);
    parseResponseConfig(vars, erca->getResponseConfig());
    checkAllParametersConsumed("ERCodeAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SetSkipCacheAction", []() {
    return std::shared_ptr<DNSAction>(new SetSkipCacheAction);
  });

  luaCtx.writeFunction("SetSkipCacheResponseAction", []() {
    return std::shared_ptr<DNSResponseAction>(new SetSkipCacheResponseAction);
  });

  luaCtx.writeFunction("SetTempFailureCacheTTLAction", [](int maxTTL) {
    return std::shared_ptr<DNSAction>(new SetTempFailureCacheTTLAction(maxTTL));
  });

  luaCtx.writeFunction("DropResponseAction", []() {
    return std::shared_ptr<DNSResponseAction>(new DropResponseAction);
  });

  luaCtx.writeFunction("AllowResponseAction", []() {
    return std::shared_ptr<DNSResponseAction>(new AllowResponseAction);
  });

  luaCtx.writeFunction("DelayResponseAction", [](int msec) {
    return std::shared_ptr<DNSResponseAction>(new DelayResponseAction(msec));
  });

  luaCtx.writeFunction("LuaResponseAction", [](LuaResponseAction::func_t func) {
    setLuaSideEffect();
    return std::shared_ptr<DNSResponseAction>(new LuaResponseAction(std::move(func)));
  });

  luaCtx.writeFunction("LuaFFIResponseAction", [](LuaFFIResponseAction::func_t func) {
    setLuaSideEffect();
    return std::shared_ptr<DNSResponseAction>(new LuaFFIResponseAction(std::move(func)));
  });

  luaCtx.writeFunction("LuaFFIPerThreadResponseAction", [](const std::string& code) {
    setLuaSideEffect();
    return std::shared_ptr<DNSResponseAction>(new LuaFFIPerThreadResponseAction(code));
  });

#ifndef DISABLE_PROTOBUF
  luaCtx.writeFunction("RemoteLogAction", [](std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)>> alterFunc, boost::optional<LuaAssociativeTable<std::string>> vars, boost::optional<LuaAssociativeTable<std::string>> metas) {
    if (logger) {
      // avoids potentially-evaluated-expression warning with clang.
      RemoteLoggerInterface& remoteLoggerRef = *logger;
      if (typeid(remoteLoggerRef) != typeid(RemoteLogger)) {
        // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
        throw std::runtime_error(std::string("RemoteLogAction only takes RemoteLogger. For other types, please look at DnstapLogAction."));
      }
    }

    std::string tags;
    RemoteLogActionConfiguration config;
    config.logger = std::move(logger);
    config.alterQueryFunc = std::move(alterFunc);
    getOptionalValue<std::string>(vars, "serverID", config.serverID);
    getOptionalValue<std::string>(vars, "ipEncryptKey", config.ipEncryptKey);
    getOptionalValue<std::string>(vars, "exportTags", tags);

    if (metas) {
      for (const auto& [key, value] : *metas) {
        config.metas.emplace_back(key, ProtoBufMetaKey(value));
      }
    }

    if (!tags.empty()) {
      config.tagsToExport = std::unordered_set<std::string>();
      if (tags != "*") {
        std::vector<std::string> tokens;
        stringtok(tokens, tags, ",");
        for (auto& token : tokens) {
          config.tagsToExport->insert(std::move(token));
        }
      }
    }

    checkAllParametersConsumed("RemoteLogAction", vars);

    return std::shared_ptr<DNSAction>(new RemoteLogAction(config));
  });

  luaCtx.writeFunction("RemoteLogResponseAction", [](std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSResponse*, DNSDistProtoBufMessage*)>> alterFunc, boost::optional<bool> includeCNAME, boost::optional<LuaAssociativeTable<std::string>> vars, boost::optional<LuaAssociativeTable<std::string>> metas) {
    if (logger) {
      // avoids potentially-evaluated-expression warning with clang.
      RemoteLoggerInterface& remoteLoggerRef = *logger;
      if (typeid(remoteLoggerRef) != typeid(RemoteLogger)) {
        // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
        throw std::runtime_error("RemoteLogResponseAction only takes RemoteLogger. For other types, please look at DnstapLogResponseAction.");
      }
    }

    std::string tags;
    RemoteLogActionConfiguration config;
    config.logger = std::move(logger);
    config.alterResponseFunc = std::move(alterFunc);
    config.includeCNAME = includeCNAME ? *includeCNAME : false;
    getOptionalValue<std::string>(vars, "serverID", config.serverID);
    getOptionalValue<std::string>(vars, "ipEncryptKey", config.ipEncryptKey);
    getOptionalValue<std::string>(vars, "exportTags", tags);
    getOptionalValue<std::string>(vars, "exportExtendedErrorsToMeta", config.exportExtendedErrorsToMeta);

    if (metas) {
      for (const auto& [key, value] : *metas) {
        config.metas.emplace_back(key, ProtoBufMetaKey(value));
      }
    }

    if (!tags.empty()) {
      config.tagsToExport = std::unordered_set<std::string>();
      if (tags != "*") {
        std::vector<std::string> tokens;
        stringtok(tokens, tags, ",");
        for (auto& token : tokens) {
          config.tagsToExport->insert(std::move(token));
        }
      }
    }

    checkAllParametersConsumed("RemoteLogResponseAction", vars);

    return std::shared_ptr<DNSResponseAction>(new RemoteLogResponseAction(config));
  });

  luaCtx.writeFunction("DnstapLogAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSQuestion*, DnstapMessage*)>> alterFunc) {
    return std::shared_ptr<DNSAction>(new DnstapLogAction(identity, logger, std::move(alterFunc)));
  });

  luaCtx.writeFunction("DnstapLogResponseAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSResponse*, DnstapMessage*)>> alterFunc) {
    return std::shared_ptr<DNSResponseAction>(new DnstapLogResponseAction(identity, logger, std::move(alterFunc)));
  });
#endif /* DISABLE_PROTOBUF */

  luaCtx.writeFunction("TeeAction", [](const std::string& remote, boost::optional<bool> addECS, boost::optional<std::string> local, boost::optional<bool> addProxyProtocol) {
    boost::optional<ComboAddress> localAddr{boost::none};
    if (local) {
      localAddr = ComboAddress(*local, 0);
    }

    return std::shared_ptr<DNSAction>(new TeeAction(ComboAddress(remote, 53), localAddr, addECS ? *addECS : false, addProxyProtocol ? *addProxyProtocol : false));
  });

  luaCtx.writeFunction("SetECSPrefixLengthAction", [](uint16_t v4PrefixLength, uint16_t v6PrefixLength) {
    return std::shared_ptr<DNSAction>(new SetECSPrefixLengthAction(v4PrefixLength, v6PrefixLength));
  });

  luaCtx.writeFunction("SetECSOverrideAction", [](bool ecsOverride) {
    return std::shared_ptr<DNSAction>(new SetECSOverrideAction(ecsOverride));
  });

  luaCtx.writeFunction("SetDisableECSAction", []() {
    return std::shared_ptr<DNSAction>(new SetDisableECSAction());
  });

  luaCtx.writeFunction("SetECSAction", [](const std::string& v4Netmask, boost::optional<std::string> v6Netmask) {
    if (v6Netmask) {
      return std::shared_ptr<DNSAction>(new SetECSAction(Netmask(v4Netmask), Netmask(*v6Netmask)));
    }
    return std::shared_ptr<DNSAction>(new SetECSAction(Netmask(v4Netmask)));
  });

#ifdef HAVE_NET_SNMP
  luaCtx.writeFunction("SNMPTrapAction", [](boost::optional<std::string> reason) {
    return std::shared_ptr<DNSAction>(new SNMPTrapAction(reason ? *reason : ""));
  });

  luaCtx.writeFunction("SNMPTrapResponseAction", [](boost::optional<std::string> reason) {
    return std::shared_ptr<DNSResponseAction>(new SNMPTrapResponseAction(reason ? *reason : ""));
  });
#endif /* HAVE_NET_SNMP */

  luaCtx.writeFunction("SetTagAction", [](const std::string& tag, const std::string& value) {
    return std::shared_ptr<DNSAction>(new SetTagAction(tag, value));
  });

  luaCtx.writeFunction("SetTagResponseAction", [](const std::string& tag, const std::string& value) {
    return std::shared_ptr<DNSResponseAction>(new SetTagResponseAction(tag, value));
  });

  luaCtx.writeFunction("ContinueAction", [](std::shared_ptr<DNSAction> action) {
    return std::shared_ptr<DNSAction>(new ContinueAction(action));
  });

#ifdef HAVE_DNS_OVER_HTTPS
  luaCtx.writeFunction("HTTPStatusAction", [](uint16_t status, std::string body, boost::optional<std::string> contentType, boost::optional<responseParams_t> vars) {
    auto ret = std::shared_ptr<DNSAction>(new HTTPStatusAction(status, PacketBuffer(body.begin(), body.end()), contentType ? *contentType : ""));
    auto hsa = std::dynamic_pointer_cast<HTTPStatusAction>(ret);
    parseResponseConfig(vars, hsa->getResponseConfig());
    checkAllParametersConsumed("HTTPStatusAction", vars);
    return ret;
  });
#endif /* HAVE_DNS_OVER_HTTPS */

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  luaCtx.writeFunction("KeyValueStoreLookupAction", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag) {
    return std::shared_ptr<DNSAction>(new KeyValueStoreLookupAction(kvs, lookupKey, destinationTag));
  });

  luaCtx.writeFunction("KeyValueStoreRangeLookupAction", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag) {
    return std::shared_ptr<DNSAction>(new KeyValueStoreRangeLookupAction(kvs, lookupKey, destinationTag));
  });
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */

  luaCtx.writeFunction("NegativeAndSOAAction", [](bool nxd, const std::string& zone, uint32_t ttl, const std::string& mname, const std::string& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum, boost::optional<responseParams_t> vars) {
    bool soaInAuthoritySection = false;
    getOptionalValue<bool>(vars, "soaInAuthoritySection", soaInAuthoritySection);
    NegativeAndSOAAction::SOAParams params{
      .serial = serial,
      .refresh = refresh,
      .retry = retry,
      .expire = expire,
      .minimum = minimum};
    auto ret = std::shared_ptr<DNSAction>(new NegativeAndSOAAction(nxd, DNSName(zone), ttl, DNSName(mname), DNSName(rname), params, soaInAuthoritySection));
    auto action = std::dynamic_pointer_cast<NegativeAndSOAAction>(ret);
    parseResponseConfig(vars, action->getResponseConfig());
    checkAllParametersConsumed("NegativeAndSOAAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SetProxyProtocolValuesAction", [](const std::vector<std::pair<uint8_t, std::string>>& values) {
    return std::shared_ptr<DNSAction>(new SetProxyProtocolValuesAction(values));
  });

  luaCtx.writeFunction("SetAdditionalProxyProtocolValueAction", [](uint8_t type, const std::string& value) {
    return std::shared_ptr<DNSAction>(new SetAdditionalProxyProtocolValueAction(type, value));
  });

  luaCtx.writeFunction("SetExtendedDNSErrorAction", [](uint16_t infoCode, boost::optional<std::string> extraText) {
    return std::shared_ptr<DNSAction>(new SetExtendedDNSErrorAction(infoCode, extraText ? *extraText : ""));
  });

  luaCtx.writeFunction("SetExtendedDNSErrorResponseAction", [](uint16_t infoCode, boost::optional<std::string> extraText) {
    return std::shared_ptr<DNSResponseAction>(new SetExtendedDNSErrorResponseAction(infoCode, extraText ? *extraText : ""));
  });
}
