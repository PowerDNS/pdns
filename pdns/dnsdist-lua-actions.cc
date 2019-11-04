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
#include "dnsdist-ecs.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-protobuf.hh"
#include "dnsdist-kvs.hh"

#include "dolog.hh"
#include "dnstap.hh"
#include "ednsoptions.hh"
#include "fstrm_logger.hh"
#include "remote_logger.hh"

#include <boost/optional/optional_io.hpp>

#ifdef HAVE_LIBCRYPTO
#include "ipcipher.hh"
#endif /* HAVE_LIBCRYPTO */

class DropAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    return Action::Drop;
  }
  std::string toString() const override
  {
    return "drop";
  }
};

class AllowAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    return Action::Allow;
  }
  std::string toString() const override
  {
    return "allow";
  }
};

class NoneAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    return Action::None;
  }
  std::string toString() const override
  {
    return "no op";
  }
};

class QPSAction : public DNSAction
{
public:
  QPSAction(int limit) : d_qps(limit, limit)
  {}
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if(d_qps.check())
      return Action::None;
    else
      return Action::Drop;
  }
  std::string toString() const override
  {
    return "qps limit to "+std::to_string(d_qps.getRate());
  }
private:
  QPSLimiter d_qps;
};

class DelayAction : public DNSAction
{
public:
  DelayAction(int msec) : d_msec(msec)
  {}
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    *ruleresult=std::to_string(d_msec);
    return Action::Delay;
  }
  std::string toString() const override
  {
    return "delay by "+std::to_string(d_msec)+ " msec";
  }
private:
  int d_msec;
};


class TeeAction : public DNSAction
{
public:
  TeeAction(const ComboAddress& ca, bool addECS=false);
  ~TeeAction() override;
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override;
  std::string toString() const override;
  std::map<std::string, double> getStats() const override;

private:
  ComboAddress d_remote;
  std::thread d_worker;
  void worker();

  int d_fd;
  mutable std::atomic<unsigned long> d_senderrors{0};
  unsigned long d_recverrors{0};
  mutable std::atomic<unsigned long> d_queries{0};
  unsigned long d_responses{0};
  unsigned long d_nxdomains{0};
  unsigned long d_servfails{0};
  unsigned long d_refuseds{0};
  unsigned long d_formerrs{0};
  unsigned long d_notimps{0};
  unsigned long d_noerrors{0};
  mutable unsigned long d_tcpdrops{0};
  unsigned long d_otherrcode{0};
  std::atomic<bool> d_pleaseQuit{false};
  bool d_addECS{false};
};

TeeAction::TeeAction(const ComboAddress& ca, bool addECS) : d_remote(ca), d_addECS(addECS)
{
  d_fd=SSocket(d_remote.sin4.sin_family, SOCK_DGRAM, 0);
  SConnect(d_fd, d_remote);
  setNonBlocking(d_fd);
  d_worker=std::thread(std::bind(&TeeAction::worker, this));
}

TeeAction::~TeeAction()
{
  d_pleaseQuit=true;
  close(d_fd);
  d_worker.join();
}

DNSAction::Action TeeAction::operator()(DNSQuestion* dq, std::string* ruleresult) const
{
  if(dq->tcp) {
    d_tcpdrops++;
  }
  else {
    ssize_t res;
    d_queries++;

    if(d_addECS) {
      std::string query;
      uint16_t len = dq->len;
      bool ednsAdded = false;
      bool ecsAdded = false;
      query.reserve(dq->size);
      query.assign((char*) dq->dh, len);

      std::string newECSOption;
      generateECSOption(dq->ecsSet ? dq->ecs.getNetwork() : *dq->remote, newECSOption, dq->ecsSet ? dq->ecs.getBits() :  dq->ecsPrefixLength);

      if (!handleEDNSClientSubnet(const_cast<char*>(query.c_str()), query.capacity(), dq->qname->wirelength(), &len, ednsAdded, ecsAdded, dq->ecsOverride, newECSOption, g_preserveTrailingData)) {
        return DNSAction::Action::None;
      }

      res = send(d_fd, query.c_str(), len, 0);
    }
    else {
      res = send(d_fd, (char*)dq->dh, dq->len, 0);
    }

    if (res <= 0)
      d_senderrors++;
  }
  return DNSAction::Action::None;
}

std::string TeeAction::toString() const
{
  return "tee to "+d_remote.toStringWithPort();
}

std::map<std::string,double> TeeAction::getStats() const
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
          {"tcp-drops", d_tcpdrops}
  };
}

void TeeAction::worker()
{
  setThreadName("dnsdist/TeeWork");
  char packet[1500];
  int res=0;
  struct dnsheader* dh=(struct dnsheader*)packet;
  for(;;) {
    res=waitForData(d_fd, 0, 250000);
    if(d_pleaseQuit)
      break;
    if(res < 0) {
      usleep(250000);
      continue;
    }
    if(res==0)
      continue;
    res=recv(d_fd, packet, sizeof(packet), 0);
    if(res <= (int)sizeof(struct dnsheader))
      d_recverrors++;
    else if(res > 0)
      d_responses++;

    if(dh->rcode == RCode::NoError)
      d_noerrors++;
    else if(dh->rcode == RCode::ServFail)
      d_servfails++;
    else if(dh->rcode == RCode::NXDomain)
      d_nxdomains++;
    else if(dh->rcode == RCode::Refused)
      d_refuseds++;
    else if(dh->rcode == RCode::FormErr)
      d_formerrs++;
    else if(dh->rcode == RCode::NotImp)
      d_notimps++;
  }
}

class PoolAction : public DNSAction
{
public:
  PoolAction(const std::string& pool) : d_pool(pool) {}
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    *ruleresult=d_pool;
    return Action::Pool;
  }
  std::string toString() const override
  {
    return "to pool "+d_pool;
  }

private:
  std::string d_pool;
};


class QPSPoolAction : public DNSAction
{
public:
  QPSPoolAction(unsigned int limit, const std::string& pool) : d_qps(limit, limit), d_pool(pool) {}
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if(d_qps.check()) {
      *ruleresult=d_pool;
      return Action::Pool;
    }
    else
      return Action::None;
  }
  std::string toString() const override
  {
    return "max " +std::to_string(d_qps.getRate())+" to pool "+d_pool;
  }

private:
  QPSLimiter d_qps;
  std::string d_pool;
};

class RCodeAction : public DNSAction
{
public:
  RCodeAction(uint8_t rcode) : d_rcode(rcode) {}
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->dh->rcode = d_rcode;
    dq->dh->qr = true; // for good measure
    setResponseHeadersFromConfig(*dq->dh, d_responseConfig);
    return Action::HeaderModify;
  }
  std::string toString() const override
  {
    return "set rcode "+std::to_string(d_rcode);
  }

  ResponseConfig d_responseConfig;
private:
  uint8_t d_rcode;
};

class ERCodeAction : public DNSAction
{
public:
  ERCodeAction(uint8_t rcode) : d_rcode(rcode) {}
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->dh->rcode = (d_rcode & 0xF);
    dq->ednsRCode = ((d_rcode & 0xFFF0) >> 4);
    dq->dh->qr = true; // for good measure
    setResponseHeadersFromConfig(*dq->dh, d_responseConfig);
    return Action::HeaderModify;
  }
  std::string toString() const override
  {
    return "set ercode "+ERCode::to_s(d_rcode);
  }

  ResponseConfig d_responseConfig;
private:
  uint8_t d_rcode;
};

class TCAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    return Action::Truncate;
  }
  std::string toString() const override
  {
    return "tc=1 answer";
  }
};

class LuaAction : public DNSAction
{
public:
  typedef std::function<std::tuple<int, boost::optional<string> >(DNSQuestion* dq)> func_t;
  LuaAction(const LuaAction::func_t& func) : d_func(func)
  {}

  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    try {
      auto ret = d_func(dq);
      if (ruleresult) {
        if (boost::optional<std::string> rule = std::get<1>(ret)) {
          *ruleresult = *rule;
        }
        else {
          // default to empty string
          ruleresult->clear();
        }
      }
      return static_cast<Action>(std::get<0>(ret));
    } catch (const std::exception &e) {
      warnlog("LuaAction failed inside Lua, returning ServFail: %s", e.what());
    } catch (...) {
      warnlog("LuaAction failed inside Lua, returning ServFail: [unknown exception]");
    }
    return DNSAction::Action::ServFail;
  }

  string toString() const override
  {
    return "Lua script";
  }
private:
  func_t d_func;
};

class LuaResponseAction : public DNSResponseAction
{
public:
  typedef std::function<std::tuple<int, boost::optional<string> >(DNSResponse* dr)> func_t;
  LuaResponseAction(const LuaResponseAction::func_t& func) : d_func(func)
  {}
  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    try {
      auto ret = d_func(dr);
      if(ruleresult) {
        if (boost::optional<std::string> rule = std::get<1>(ret)) {
          *ruleresult = *rule;
        }
        else {
          // default to empty string
          ruleresult->clear();
        }
      }
      return static_cast<Action>(std::get<0>(ret));
    } catch (const std::exception &e) {
      warnlog("LuaResponseAction failed inside Lua, returning ServFail: %s", e.what());
    } catch (...) {
      warnlog("LuaResponseAction failed inside Lua, returning ServFail: [unknown exception]");
    }
    return DNSResponseAction::Action::ServFail;
  }

  string toString() const override
  {
    return "Lua response script";
  }
private:
  func_t d_func;
};

class LuaFFIAction: public DNSAction
{
public:
  typedef std::function<int(dnsdist_ffi_dnsquestion_t* dq)> func_t;

  LuaFFIAction(const LuaFFIAction::func_t& func): d_func(func)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dnsdist_ffi_dnsquestion_t dqffi(dq);
    try {
      std::lock_guard<std::mutex> lock(g_luamutex);

      auto ret = d_func(&dqffi);
      if (ruleresult) {
        if (dqffi.result) {
          *ruleresult = *dqffi.result;
        }
        else {
          // default to empty string
          ruleresult->clear();
        }
      }
      return static_cast<DNSAction::Action>(ret);
    } catch (const std::exception &e) {
      warnlog("LuaFFIAction failed inside Lua, returning ServFail: %s", e.what());
    } catch (...) {
      warnlog("LuaFFIAction failed inside Lua, returning ServFail: [unknown exception]");
    }
    return DNSAction::Action::ServFail;
  }

  string toString() const override
  {
    return "Lua FFI script";
  }
private:
  func_t d_func;
};


class LuaFFIResponseAction: public DNSResponseAction
{
public:
  typedef std::function<int(dnsdist_ffi_dnsquestion_t* dq)> func_t;

  LuaFFIResponseAction(const LuaFFIResponseAction::func_t& func): d_func(func)
  {
  }

  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    DNSQuestion* dq = dynamic_cast<DNSQuestion*>(dr);
    if (dq == nullptr) {
      return DNSResponseAction::Action::ServFail;
    }

    dnsdist_ffi_dnsquestion_t dqffi(dq);
    try {
      std::lock_guard<std::mutex> lock(g_luamutex);

      auto ret = d_func(&dqffi);
      if (ruleresult) {
        if (dqffi.result) {
          *ruleresult = *dqffi.result;
        }
        else {
          // default to empty string
          ruleresult->clear();
        }
      }
      return static_cast<DNSResponseAction::Action>(ret);
    } catch (const std::exception &e) {
      warnlog("LuaFFIResponseAction failed inside Lua, returning ServFail: %s", e.what());
    } catch (...) {
      warnlog("LuaFFIResponseAction failed inside Lua, returning ServFail: [unknown exception]");
    }
    return DNSResponseAction::Action::ServFail;
  }

  string toString() const override
  {
    return "Lua FFI script";
  }
private:
  func_t d_func;
};

DNSAction::Action SpoofAction::operator()(DNSQuestion* dq, std::string* ruleresult) const
{
  uint16_t qtype = dq->qtype;
  // do we even have a response?
  if (d_cname.empty() &&
      d_rawResponse.empty() &&
      d_types.count(qtype) == 0) {
    return Action::None;
  }

  vector<ComboAddress> addrs;
  unsigned int totrdatalen = 0;
  uint16_t numberOfRecords = 0;
  if (!d_cname.empty()) {
    qtype = QType::CNAME;
    totrdatalen += d_cname.toDNSString().size();
    numberOfRecords = 1;
  } else if (!d_rawResponse.empty()) {
    totrdatalen += d_rawResponse.size();
    numberOfRecords = 1;
  }
  else {
    for(const auto& addr : d_addrs) {
      if(qtype != QType::ANY && ((addr.sin4.sin_family == AF_INET && qtype != QType::A) ||
                                 (addr.sin4.sin_family == AF_INET6 && qtype != QType::AAAA))) {
        continue;
      }
      totrdatalen += addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr);
      addrs.push_back(addr);
      ++numberOfRecords;
    }
  }

  if(addrs.size() > 1)
    random_shuffle(addrs.begin(), addrs.end());

  unsigned int consumed=0;
  DNSName ignore((char*)dq->dh, dq->len, sizeof(dnsheader), false, 0, 0, &consumed);

  if (dq->size < (sizeof(dnsheader) + consumed + 4 + numberOfRecords*12 /* recordstart */ + totrdatalen)) {
    return Action::None;
  }

  bool dnssecOK = false;
  bool hadEDNS = false;
  if (g_addEDNSToSelfGeneratedResponses && queryHasEDNS(*dq)) {
    hadEDNS = true;
    dnssecOK = getEDNSZ(*dq) & EDNS_HEADER_FLAG_DO;
  }

  dq->len = sizeof(dnsheader) + consumed + 4; // there goes your EDNS
  char* dest = ((char*)dq->dh) + dq->len;

  dq->dh->qr = true; // for good measure
  setResponseHeadersFromConfig(*dq->dh, d_responseConfig);
  dq->dh->ancount = 0;
  dq->dh->arcount = 0; // for now, forget about your EDNS, we're marching over it

  uint32_t ttl = htonl(d_responseConfig.ttl);
  unsigned char recordstart[] = {0xc0, 0x0c,    // compressed name
                                 0, 0,          // QTYPE
                                 0, QClass::IN,
                                 0, 0, 0, 0,    // TTL
                                 0, 0 };        // rdata length
  static_assert(sizeof(recordstart) == 12, "sizeof(recordstart) must be equal to 12, otherwise the above check is invalid");
  memcpy(&recordstart[6], &ttl, sizeof(ttl));
  bool raw = false;

  if (qtype == QType::CNAME) {
    const std::string wireData = d_cname.toDNSString(); // Note! This doesn't do compression!
    uint16_t rdataLen = htons(wireData.length());
    qtype = htons(qtype);
    memcpy(&recordstart[2], &qtype, sizeof(qtype));
    memcpy(&recordstart[10], &rdataLen, sizeof(rdataLen));

    memcpy(dest, recordstart, sizeof(recordstart));
    dest += sizeof(recordstart);
    memcpy(dest, wireData.c_str(), wireData.length());
    dq->len += wireData.length() + sizeof(recordstart);
    dq->dh->ancount++;
  }
  else if (!d_rawResponse.empty()) {
    uint16_t rdataLen = htons(d_rawResponse.size());
    qtype = htons(qtype);
    memcpy(&recordstart[2], &qtype, sizeof(qtype));
    memcpy(&recordstart[10], &rdataLen, sizeof(rdataLen));

    memcpy(dest, recordstart, sizeof(recordstart));
    dest += sizeof(recordstart);
    memcpy(dest, d_rawResponse.c_str(), d_rawResponse.size());
    dq->len += d_rawResponse.size() + sizeof(recordstart);
    dq->dh->ancount++;
    raw = true;
  }
  else {
    for(const auto& addr : addrs) {
      uint16_t rdataLen = htons(addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr));
      qtype = htons(addr.sin4.sin_family == AF_INET ? QType::A : QType::AAAA);
      memcpy(&recordstart[2], &qtype, sizeof(qtype));
      memcpy(&recordstart[10], &rdataLen, sizeof(rdataLen));

      memcpy(dest, recordstart, sizeof(recordstart));
      dest += sizeof(recordstart);

      memcpy(dest,
             addr.sin4.sin_family == AF_INET ? (void*)&addr.sin4.sin_addr.s_addr : (void*)&addr.sin6.sin6_addr.s6_addr,
             addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr));
      dest += (addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr));
      dq->len += (addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr)) + sizeof(recordstart);
      dq->dh->ancount++;
    }
  }

  dq->dh->ancount = htons(dq->dh->ancount);

  if (hadEDNS && raw == false) {
    addEDNS(dq->dh, dq->len, dq->size, dnssecOK, g_PayloadSizeSelfGenAnswers, 0);
  }

  return Action::HeaderModify;
}

class MacAddrAction : public DNSAction
{
public:
  MacAddrAction(uint16_t code) : d_code(code)
  {}
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if(dq->dh->arcount)
      return Action::None;

    std::string mac = getMACAddress(*dq->remote);
    if(mac.empty())
      return Action::None;

    std::string optRData;
    generateEDNSOption(d_code, mac, optRData);

    std::string res;
    generateOptRR(optRData, res, g_EdnsUDPPayloadSize, 0, false);

    if ((dq->size - dq->len) < res.length())
      return Action::None;

    dq->dh->arcount = htons(1);
    char* dest = ((char*)dq->dh) + dq->len;
    memcpy(dest, res.c_str(), res.length());
    dq->len += res.length();

    return Action::None;
  }
  std::string toString() const override
  {
    return "add EDNS MAC (code="+std::to_string(d_code)+")";
  }
private:
  uint16_t d_code{3};
};

class NoRecurseAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->dh->rd = false;
    return Action::None;
  }
  std::string toString() const override
  {
    return "set rd=0";
  }
};

class LogAction : public DNSAction, public boost::noncopyable
{
public:
  LogAction(): d_fp(nullptr, fclose)
  {
  }

  LogAction(const std::string& str, bool binary=true, bool append=false, bool buffered=true, bool verboseOnly=true, bool includeTimestamp=false): d_fname(str), d_binary(binary), d_verboseOnly(verboseOnly), d_includeTimestamp(includeTimestamp)
  {
    if(str.empty())
      return;
    if(append)
      d_fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(str.c_str(), "a+"), fclose);
    else
      d_fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(str.c_str(), "w"), fclose);
    if(!d_fp)
      throw std::runtime_error("Unable to open file '"+str+"' for logging: "+stringerror());
    if(!buffered)
      setbuf(d_fp.get(), 0);
  }

  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if (!d_fp) {
      if (!d_verboseOnly || g_verbose) {
        if (d_includeTimestamp) {
          infolog("[%u.%u] Packet from %s for %s %s with id %d", static_cast<unsigned long long>(dq->queryTime->tv_sec), static_cast<unsigned long>(dq->queryTime->tv_nsec), dq->remote->toStringWithPort(), dq->qname->toString(), QType(dq->qtype).getName(), dq->dh->id);
        }
        else {
          infolog("Packet from %s for %s %s with id %d", dq->remote->toStringWithPort(), dq->qname->toString(), QType(dq->qtype).getName(), dq->dh->id);
        }
      }
    }
    else {
      if (d_binary) {
        std::string out = dq->qname->toDNSString();
        if (d_includeTimestamp) {
          uint64_t tv_sec = static_cast<uint64_t>(dq->queryTime->tv_sec);
          uint32_t tv_nsec = static_cast<uint32_t>(dq->queryTime->tv_nsec);
          fwrite(&tv_sec, sizeof(tv_sec), 1, d_fp.get());
          fwrite(&tv_nsec, sizeof(tv_nsec), 1, d_fp.get());
        }
        uint16_t id = dq->dh->id;
        fwrite(&id, sizeof(id), 1, d_fp.get());
        fwrite(out.c_str(), 1, out.size(), d_fp.get());
        fwrite(&dq->qtype, sizeof(dq->qtype), 1, d_fp.get());
        fwrite(&dq->remote->sin4.sin_family, sizeof(dq->remote->sin4.sin_family), 1, d_fp.get());
        if (dq->remote->sin4.sin_family == AF_INET) {
          fwrite(&dq->remote->sin4.sin_addr.s_addr, sizeof(dq->remote->sin4.sin_addr.s_addr), 1, d_fp.get());
        }
        else if (dq->remote->sin4.sin_family == AF_INET6) {
          fwrite(&dq->remote->sin6.sin6_addr.s6_addr, sizeof(dq->remote->sin6.sin6_addr.s6_addr), 1, d_fp.get());
        }
        fwrite(&dq->remote->sin4.sin_port, sizeof(dq->remote->sin4.sin_port), 1, d_fp.get());
      }
      else {
        if (d_includeTimestamp) {
          fprintf(d_fp.get(), "[%llu.%lu] Packet from %s for %s %s with id %d\n", static_cast<unsigned long long>(dq->queryTime->tv_sec), static_cast<unsigned long>(dq->queryTime->tv_nsec), dq->remote->toStringWithPort().c_str(), dq->qname->toString().c_str(), QType(dq->qtype).getName().c_str(), dq->dh->id);
        }
        else {
          fprintf(d_fp.get(), "Packet from %s for %s %s with id %d\n", dq->remote->toStringWithPort().c_str(), dq->qname->toString().c_str(), QType(dq->qtype).getName().c_str(), dq->dh->id);
        }
      }
    }
    return Action::None;
  }

  std::string toString() const override
  {
    if (!d_fname.empty()) {
      return "log to " + d_fname;
    }
    return "log";
  }
private:
  std::string d_fname;
  std::unique_ptr<FILE, int(*)(FILE*)> d_fp{nullptr, fclose};
  bool d_binary{true};
  bool d_verboseOnly{true};
  bool d_includeTimestamp{false};
};

class LogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  LogResponseAction(): d_fp(nullptr, fclose)
  {
  }

  LogResponseAction(const std::string& str, bool append=false, bool buffered=true, bool verboseOnly=true, bool includeTimestamp=false): d_fname(str), d_verboseOnly(verboseOnly), d_includeTimestamp(includeTimestamp)
  {
    if(str.empty())
      return;
    if(append)
      d_fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(str.c_str(), "a+"), fclose);
    else
      d_fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(str.c_str(), "w"), fclose);
    if(!d_fp)
      throw std::runtime_error("Unable to open file '"+str+"' for logging: "+stringerror());
    if(!buffered)
      setbuf(d_fp.get(), 0);
  }

  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    if (!d_fp) {
      if (!d_verboseOnly || g_verbose) {
        if (d_includeTimestamp) {
          infolog("[%u.%u] Answer to %s for %s %s (%s) with id %d", static_cast<unsigned long long>(dr->queryTime->tv_sec), static_cast<unsigned long>(dr->queryTime->tv_nsec), dr->remote->toStringWithPort(), dr->qname->toString(), QType(dr->qtype).getName(), RCode::to_s(dr->dh->rcode), dr->dh->id);
        }
        else {
          infolog("Answer to %s for %s %s (%s) with id %d", dr->remote->toStringWithPort(), dr->qname->toString(), QType(dr->qtype).getName(), RCode::to_s(dr->dh->rcode), dr->dh->id);
        }
      }
    }
    else {
      if (d_includeTimestamp) {
        fprintf(d_fp.get(), "[%llu.%lu] Answer to %s for %s %s (%s) with id %d\n", static_cast<unsigned long long>(dr->queryTime->tv_sec), static_cast<unsigned long>(dr->queryTime->tv_nsec), dr->remote->toStringWithPort().c_str(), dr->qname->toString().c_str(), QType(dr->qtype).getName().c_str(), RCode::to_s(dr->dh->rcode).c_str(), dr->dh->id);
      }
      else {
        fprintf(d_fp.get(), "Answer to %s for %s %s (%s) with id %d\n", dr->remote->toStringWithPort().c_str(), dr->qname->toString().c_str(), QType(dr->qtype).getName().c_str(), RCode::to_s(dr->dh->rcode).c_str(), dr->dh->id);
      }
    }
    return Action::None;
  }

  std::string toString() const override
  {
    if (!d_fname.empty()) {
      return "log to " + d_fname;
    }
    return "log";
  }
private:
  std::string d_fname;
  std::unique_ptr<FILE, int(*)(FILE*)> d_fp{nullptr, fclose};
  bool d_verboseOnly{true};
  bool d_includeTimestamp{false};
};


class DisableValidationAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->dh->cd = true;
    return Action::None;
  }
  std::string toString() const override
  {
    return "set cd=1";
  }
};

class SkipCacheAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->skipCache = true;
    return Action::None;
  }
  std::string toString() const override
  {
    return "skip cache";
  }
};

class TempFailureCacheTTLAction : public DNSAction
{
public:
  TempFailureCacheTTLAction(uint32_t ttl) : d_ttl(ttl)
  {}
  TempFailureCacheTTLAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->tempFailureTTL = d_ttl;
    return Action::None;
  }
  std::string toString() const override
  {
    return "set tempfailure cache ttl to "+std::to_string(d_ttl);
  }
private:
  uint32_t d_ttl;
};

class ECSPrefixLengthAction : public DNSAction
{
public:
  ECSPrefixLengthAction(uint16_t v4Length, uint16_t v6Length) : d_v4PrefixLength(v4Length), d_v6PrefixLength(v6Length)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->ecsPrefixLength = dq->remote->sin4.sin_family == AF_INET ? d_v4PrefixLength : d_v6PrefixLength;
    return Action::None;
  }
  std::string toString() const override
  {
    return "set ECS prefix length to " + std::to_string(d_v4PrefixLength) + "/" + std::to_string(d_v6PrefixLength);
  }
private:
  uint16_t d_v4PrefixLength;
  uint16_t d_v6PrefixLength;
};

class ECSOverrideAction : public DNSAction
{
public:
  ECSOverrideAction(bool ecsOverride) : d_ecsOverride(ecsOverride)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->ecsOverride = d_ecsOverride;
    return Action::None;
  }
  std::string toString() const override
  {
    return "set ECS override to " + std::to_string(d_ecsOverride);
  }
private:
  bool d_ecsOverride;
};


class DisableECSAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->useECS = false;
    return Action::None;
  }
  std::string toString() const override
  {
    return "disable ECS";
  }
};

class SetECSAction : public DNSAction
{
public:
  SetECSAction(const Netmask& v4): d_v4(v4), d_hasV6(false)
  {
  }

  SetECSAction(const Netmask& v4, const Netmask& v6): d_v4(v4), d_v6(v6), d_hasV6(true)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    dq->ecsSet = true;

    if (d_hasV6) {
      dq->ecs = dq->remote->isIPv4() ? d_v4 : d_v6;
    }
    else {
      dq->ecs = d_v4;
    }

    return Action::None;
  }

  std::string toString() const override
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


class DnstapLogAction : public DNSAction, public boost::noncopyable
{
public:
  DnstapLogAction(const std::string& identity, std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(DNSQuestion*, DnstapMessage*)> > alterFunc): d_identity(identity), d_logger(logger), d_alterFunc(alterFunc)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    DnstapMessage message(d_identity, dq->remote, dq->local, dq->tcp, reinterpret_cast<const char*>(dq->dh), dq->len, dq->queryTime, nullptr);
    {
      if (d_alterFunc) {
        std::lock_guard<std::mutex> lock(g_luamutex);
        (*d_alterFunc)(dq, &message);
      }
    }
    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  std::string toString() const override
  {
    return "remote log as dnstap to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::string d_identity;
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  boost::optional<std::function<void(DNSQuestion*, DnstapMessage*)> > d_alterFunc;
};

class RemoteLogAction : public DNSAction, public boost::noncopyable
{
public:
  RemoteLogAction(std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)> > alterFunc, const std::string& serverID, const std::string& ipEncryptKey): d_logger(logger), d_alterFunc(alterFunc), d_serverID(serverID), d_ipEncryptKey(ipEncryptKey)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    if (!dq->uniqueId) {
      dq->uniqueId = getUniqueID();
    }

    DNSDistProtoBufMessage message(*dq);
    if (!d_serverID.empty()) {
      message.setServerIdentity(d_serverID);
    }

#if HAVE_LIBCRYPTO
    if (!d_ipEncryptKey.empty())
    {
      message.setRequestor(encryptCA(*dq->remote, d_ipEncryptKey));
    }
#endif /* HAVE_LIBCRYPTO */

    if (d_alterFunc) {
      std::lock_guard<std::mutex> lock(g_luamutex);
      (*d_alterFunc)(dq, &message);
    }

    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  std::string toString() const override
  {
    return "remote log to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  boost::optional<std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)> > d_alterFunc;
  std::string d_serverID;
  std::string d_ipEncryptKey;
};

class SNMPTrapAction : public DNSAction
{
public:
  SNMPTrapAction(const std::string& reason): d_reason(reason)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if (g_snmpAgent && g_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(*dq, d_reason);
    }

    return Action::None;
  }
  std::string toString() const override
  {
    return "send SNMP trap";
  }
private:
  std::string d_reason;
};

class TagAction : public DNSAction
{
public:
  TagAction(const std::string& tag, const std::string& value): d_tag(tag), d_value(value)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if (!dq->qTag) {
      dq->qTag = std::make_shared<QTag>();
    }

    dq->qTag->insert({d_tag, d_value});

    return Action::None;
  }
  std::string toString() const override
  {
    return "set tag '" + d_tag + "' to value '" + d_value + "'";
  }
private:
  std::string d_tag;
  std::string d_value;
};

class DnstapLogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  DnstapLogResponseAction(const std::string& identity, std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(DNSResponse*, DnstapMessage*)> > alterFunc): d_identity(identity), d_logger(logger), d_alterFunc(alterFunc)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    struct timespec now;
    gettime(&now, true);
    DnstapMessage message(d_identity, dr->remote, dr->local, dr->tcp, reinterpret_cast<const char*>(dr->dh), dr->len, dr->queryTime, &now);
    {
      if (d_alterFunc) {
        std::lock_guard<std::mutex> lock(g_luamutex);
        (*d_alterFunc)(dr, &message);
      }
    }
    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  std::string toString() const override
  {
    return "log response as dnstap to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::string d_identity;
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  boost::optional<std::function<void(DNSResponse*, DnstapMessage*)> > d_alterFunc;
};

class RemoteLogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  RemoteLogResponseAction(std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(DNSResponse*, DNSDistProtoBufMessage*)> > alterFunc, const std::string& serverID, const std::string& ipEncryptKey, bool includeCNAME): d_logger(logger), d_alterFunc(alterFunc), d_serverID(serverID), d_ipEncryptKey(ipEncryptKey), d_includeCNAME(includeCNAME)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    if (!dr->uniqueId) {
      dr->uniqueId = getUniqueID();
    }

    DNSDistProtoBufMessage message(*dr, d_includeCNAME);
    if (!d_serverID.empty()) {
      message.setServerIdentity(d_serverID);
    }

#if HAVE_LIBCRYPTO
    if (!d_ipEncryptKey.empty())
    {
      message.setRequestor(encryptCA(*dr->remote, d_ipEncryptKey));
    }
#endif /* HAVE_LIBCRYPTO */

    if (d_alterFunc) {
      std::lock_guard<std::mutex> lock(g_luamutex);
      (*d_alterFunc)(dr, &message);
    }

    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  std::string toString() const override
  {
    return "remote log response to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  boost::optional<std::function<void(DNSResponse*, DNSDistProtoBufMessage*)> > d_alterFunc;
  std::string d_serverID;
  std::string d_ipEncryptKey;
  bool d_includeCNAME;
};

class DropResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    return Action::Drop;
  }
  std::string toString() const override
  {
    return "drop";
  }
};

class AllowResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    return Action::Allow;
  }
  std::string toString() const override
  {
    return "allow";
  }
};

class DelayResponseAction : public DNSResponseAction
{
public:
  DelayResponseAction(int msec) : d_msec(msec)
  {}
  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    *ruleresult=std::to_string(d_msec);
    return Action::Delay;
  }
  std::string toString() const override
  {
    return "delay by "+std::to_string(d_msec)+ " msec";
  }
private:
  int d_msec;
};

class SNMPTrapResponseAction : public DNSResponseAction
{
public:
  SNMPTrapResponseAction(const std::string& reason): d_reason(reason)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    if (g_snmpAgent && g_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(*dr, d_reason);
    }

    return Action::None;
  }
  std::string toString() const override
  {
    return "send SNMP trap";
  }
private:
  std::string d_reason;
};

class TagResponseAction : public DNSResponseAction
{
public:
  TagResponseAction(const std::string& tag, const std::string& value): d_tag(tag), d_value(value)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* dr, std::string* ruleresult) const override
  {
    if (!dr->qTag) {
      dr->qTag = std::make_shared<QTag>();
    }

    dr->qTag->insert({d_tag, d_value});

    return Action::None;
  }
  std::string toString() const override
  {
    return "set tag '" + d_tag + "' to value '" + d_value + "'";
  }
private:
  std::string d_tag;
  std::string d_value;
};

class ContinueAction : public DNSAction
{
public:
  ContinueAction(std::shared_ptr<DNSAction>& action): d_action(action)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if (d_action) {
      /* call the action */
      auto action = (*d_action)(dq, ruleresult);
      bool drop = false;
      /* apply the changes if needed (pool selection, flags, etc */
      processRulesResult(action, *dq, *ruleresult, drop);
    }

    /* but ignore the resulting action no matter what */
    return Action::None;
  }

  std::string toString() const override
  {
    if (d_action) {
      return "continue after: " + (d_action ? d_action->toString() : "");
    }
    else {
      return "no op";
    }
  }

private:
  std::shared_ptr<DNSAction> d_action;
};

#ifdef HAVE_DNS_OVER_HTTPS
class HTTPStatusAction: public DNSAction
{
public:
  HTTPStatusAction(int code, const std::string& body, const std::string& contentType): d_body(body), d_contentType(contentType), d_code(code)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if (!dq->du) {
      return Action::None;
    }

    dq->du->setHTTPResponse(d_code, d_body, d_contentType);
    dq->dh->qr = true; // for good measure
    setResponseHeadersFromConfig(*dq->dh, d_responseConfig);
    return Action::HeaderModify;
  }

  std::string toString() const override
  {
    return "return an HTTP status of " + std::to_string(d_code);
  }

  ResponseConfig d_responseConfig;
private:
  std::string d_body;
  std::string d_contentType;
  int d_code;
};
#endif /* HAVE_DNS_OVER_HTTPS */

class KeyValueStoreLookupAction : public DNSAction
{
public:
  KeyValueStoreLookupAction(std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag): d_kvs(kvs), d_key(lookupKey), d_tag(destinationTag)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    std::vector<std::string> keys = d_key->getKeys(*dq);
    std::string result;
    for (const auto& key : keys) {
      if (d_kvs->getValue(key, result) == true) {
        break;
      }
    }

    if (!dq->qTag) {
      dq->qTag = std::make_shared<QTag>();
    }

    dq->qTag->insert({d_tag, std::move(result)});

    return Action::None;
  }

  std::string toString() const override
  {
    return "lookup key-value store based on '" + d_key->toString() + "' and set the result in tag '" + d_tag + "'";
  }

private:
  std::shared_ptr<KeyValueStore> d_kvs;
  std::shared_ptr<KeyValueLookupKey> d_key;
  std::string d_tag;
};

class SetNegativeAndSOAAction: public DNSAction
{
public:
  SetNegativeAndSOAAction(bool nxd, const DNSName& zone, uint32_t ttl, const DNSName& mname, const DNSName& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum): d_zone(zone), d_mname(mname), d_rname(rname), d_ttl(ttl), d_serial(serial), d_refresh(refresh), d_retry(retry), d_expire(expire), d_minimum(minimum), d_nxd(nxd)
  {
  }

  DNSAction::Action operator()(DNSQuestion* dq, std::string* ruleresult) const override
  {
    if (!setNegativeAndAdditionalSOA(*dq, d_nxd, d_zone, d_ttl, d_mname, d_rname, d_serial, d_refresh, d_retry, d_expire, d_minimum)) {
      return Action::None;
    }

    setResponseHeadersFromConfig(*dq->dh, d_responseConfig);

    return Action::Allow;
  }

  std::string toString() const override
  {
    return std::string(d_nxd ? "NXD " : "NODATA") + " with SOA";
  }

  ResponseConfig d_responseConfig;

private:
  DNSName d_zone;
  DNSName d_mname;
  DNSName d_rname;
  uint32_t d_ttl;
  uint32_t d_serial;
  uint32_t d_refresh;
  uint32_t d_retry;
  uint32_t d_expire;
  uint32_t d_minimum;
  bool d_nxd;
};

template<typename T, typename ActionT>
static void addAction(GlobalStateHolder<vector<T> > *someRulActions, const luadnsrule_t& var, const std::shared_ptr<ActionT>& action, boost::optional<luaruleparams_t>& params) {
  setLuaSideEffect();

  boost::uuids::uuid uuid;
  uint64_t creationOrder;
  parseRuleParams(params, uuid, creationOrder);

  auto rule=makeRule(var);
  someRulActions->modify([&rule, &action, &uuid, creationOrder](vector<T>& rulactions){
      rulactions.push_back({std::move(rule), std::move(action), std::move(uuid), creationOrder});
    });
}

typedef std::unordered_map<std::string, boost::variant<bool, uint32_t> > responseParams_t;

static void parseResponseConfig(boost::optional<responseParams_t> vars, ResponseConfig& config)
{
  if (vars) {
    if (vars->count("ttl")) {
      config.ttl = boost::get<uint32_t>((*vars)["ttl"]);
    }
    if (vars->count("aa")) {
      config.setAA = boost::get<bool>((*vars)["aa"]);
    }
    if (vars->count("ad")) {
      config.setAD = boost::get<bool>((*vars)["ad"]);
    }
    if (vars->count("ra")) {
      config.setRA = boost::get<bool>((*vars)["ra"]);
    }
  }
}

void setResponseHeadersFromConfig(dnsheader& dh, const ResponseConfig& config)
{
  if (config.setAA) {
    dh.aa = *config.setAA;
  }
  if (config.setAD) {
    dh.ad = *config.setAD;
  }
  else {
    dh.ad = false;
  }
  if (config.setRA) {
    dh.ra = *config.setRA;
  }
  else {
    dh.ra = dh.rd; // for good measure
  }
}

void setupLuaActions()
{
  g_lua.writeFunction("newRuleAction", [](luadnsrule_t dnsrule, std::shared_ptr<DNSAction> action, boost::optional<luaruleparams_t> params) {
      boost::uuids::uuid uuid;
      uint64_t creationOrder;
      parseRuleParams(params, uuid, creationOrder);

      auto rule=makeRule(dnsrule);
      DNSDistRuleAction ra({std::move(rule), action, uuid, creationOrder});
      return std::make_shared<DNSDistRuleAction>(ra);
    });

  g_lua.writeFunction("addAction", [](luadnsrule_t var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction> > era, boost::optional<luaruleparams_t> params) {
      if (era.type() != typeid(std::shared_ptr<DNSAction>)) {
        throw std::runtime_error("addAction() can only be called with query-related actions, not response-related ones. Are you looking for addResponseAction()?");
      }

      addAction(&g_rulactions, var, boost::get<std::shared_ptr<DNSAction> >(era), params);
    });

  g_lua.writeFunction("addResponseAction", [](luadnsrule_t var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction> > era, boost::optional<luaruleparams_t> params) {
      if (era.type() != typeid(std::shared_ptr<DNSResponseAction>)) {
        throw std::runtime_error("addResponseAction() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
      }

      addAction(&g_resprulactions, var, boost::get<std::shared_ptr<DNSResponseAction> >(era), params);
    });

  g_lua.writeFunction("addCacheHitResponseAction", [](luadnsrule_t var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
      if (era.type() != typeid(std::shared_ptr<DNSResponseAction>)) {
        throw std::runtime_error("addCacheHitResponseAction() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
      }

      addAction(&g_cachehitresprulactions, var, boost::get<std::shared_ptr<DNSResponseAction> >(era), params);
    });

  g_lua.writeFunction("addSelfAnsweredResponseAction", [](luadnsrule_t var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
      if (era.type() != typeid(std::shared_ptr<DNSResponseAction>)) {
        throw std::runtime_error("addSelfAnsweredResponseAction() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
      }

      addAction(&g_selfansweredresprulactions, var, boost::get<std::shared_ptr<DNSResponseAction> >(era), params);
    });

  g_lua.registerFunction<void(DNSAction::*)()>("printStats", [](const DNSAction& ta) {
      setLuaNoSideEffect();
      auto stats = ta.getStats();
      for(const auto& s : stats) {
        g_outputBuffer+=s.first+"\t";
        if((uint64_t)s.second == s.second)
          g_outputBuffer += std::to_string((uint64_t)s.second)+"\n";
        else
          g_outputBuffer += std::to_string(s.second)+"\n";
      }
    });

  g_lua.writeFunction("getAction", [](unsigned int num) {
      setLuaNoSideEffect();
      boost::optional<std::shared_ptr<DNSAction>> ret;
      auto rulactions = g_rulactions.getCopy();
      if(num < rulactions.size())
        ret=rulactions[num].d_action;
      return ret;
    });

  g_lua.registerFunction("getStats", &DNSAction::getStats);

  g_lua.writeFunction("LuaAction", [](LuaAction::func_t func) {
      setLuaSideEffect();
      return std::shared_ptr<DNSAction>(new LuaAction(func));
    });

  g_lua.writeFunction("LuaFFIAction", [](LuaFFIAction::func_t func) {
      setLuaSideEffect();
      return std::shared_ptr<DNSAction>(new LuaFFIAction(func));
    });

  g_lua.writeFunction("NoRecurseAction", []() {
      return std::shared_ptr<DNSAction>(new NoRecurseAction);
    });

  g_lua.writeFunction("MacAddrAction", [](int code) {
      return std::shared_ptr<DNSAction>(new MacAddrAction(code));
    });

  g_lua.writeFunction("PoolAction", [](const std::string& a) {
      return std::shared_ptr<DNSAction>(new PoolAction(a));
    });

  g_lua.writeFunction("QPSAction", [](int limit) {
      return std::shared_ptr<DNSAction>(new QPSAction(limit));
    });

  g_lua.writeFunction("QPSPoolAction", [](int limit, const std::string& a) {
      return std::shared_ptr<DNSAction>(new QPSPoolAction(limit, a));
    });

  g_lua.writeFunction("SpoofAction", [](boost::variant<std::string,vector<pair<int, std::string>>> inp, boost::optional<std::string> b, boost::optional<responseParams_t> vars) {
      vector<ComboAddress> addrs;
      if(auto s = boost::get<std::string>(&inp))
        addrs.push_back(ComboAddress(*s));
      else {
        const auto& v = boost::get<vector<pair<int,std::string>>>(inp);
        for(const auto& a: v)
          addrs.push_back(ComboAddress(a.second));
      }
      if(b) {
        addrs.push_back(ComboAddress(*b));
      }

      auto ret = std::shared_ptr<DNSAction>(new SpoofAction(addrs));
      auto sa = std::dynamic_pointer_cast<SpoofAction>(ret);
      parseResponseConfig(vars, sa->d_responseConfig);
      return ret;
    });

  g_lua.writeFunction("SpoofCNAMEAction", [](const std::string& a, boost::optional<responseParams_t> vars) {
      auto ret = std::shared_ptr<DNSAction>(new SpoofAction(DNSName(a)));
      auto sa = std::dynamic_pointer_cast<SpoofAction>(ret);
      parseResponseConfig(vars, sa->d_responseConfig);
      return ret;
    });

  g_lua.writeFunction("SpoofRawAction", [](const std::string& raw, boost::optional<responseParams_t> vars) {
      auto ret = std::shared_ptr<DNSAction>(new SpoofAction(raw));
      auto sa = std::dynamic_pointer_cast<SpoofAction>(ret);
      parseResponseConfig(vars, sa->d_responseConfig);
      return ret;
    });

  g_lua.writeFunction("DropAction", []() {
      return std::shared_ptr<DNSAction>(new DropAction);
    });

  g_lua.writeFunction("AllowAction", []() {
      return std::shared_ptr<DNSAction>(new AllowAction);
    });

  g_lua.writeFunction("NoneAction", []() {
      return std::shared_ptr<DNSAction>(new NoneAction);
    });

  g_lua.writeFunction("DelayAction", [](int msec) {
      return std::shared_ptr<DNSAction>(new DelayAction(msec));
    });

  g_lua.writeFunction("TCAction", []() {
      return std::shared_ptr<DNSAction>(new TCAction);
    });

  g_lua.writeFunction("DisableValidationAction", []() {
      return std::shared_ptr<DNSAction>(new DisableValidationAction);
    });

  g_lua.writeFunction("LogAction", [](boost::optional<std::string> fname, boost::optional<bool> binary, boost::optional<bool> append, boost::optional<bool> buffered, boost::optional<bool> verboseOnly, boost::optional<bool> includeTimestamp) {
      return std::shared_ptr<DNSAction>(new LogAction(fname ? *fname : "", binary ? *binary : true, append ? *append : false, buffered ? *buffered : false, verboseOnly ? *verboseOnly : true, includeTimestamp ? *includeTimestamp : false));
    });

  g_lua.writeFunction("LogResponseAction", [](boost::optional<std::string> fname, boost::optional<bool> append, boost::optional<bool> buffered, boost::optional<bool> verboseOnly, boost::optional<bool> includeTimestamp) {
      return std::shared_ptr<DNSResponseAction>(new LogResponseAction(fname ? *fname : "", append ? *append : false, buffered ? *buffered : false, verboseOnly ? *verboseOnly : true, includeTimestamp ? *includeTimestamp : false));
    });

  g_lua.writeFunction("RCodeAction", [](uint8_t rcode, boost::optional<responseParams_t> vars) {
      auto ret = std::shared_ptr<DNSAction>(new RCodeAction(rcode));
      auto rca = std::dynamic_pointer_cast<RCodeAction>(ret);
      parseResponseConfig(vars, rca->d_responseConfig);
      return ret;
    });

  g_lua.writeFunction("ERCodeAction", [](uint8_t rcode, boost::optional<responseParams_t> vars) {
      auto ret = std::shared_ptr<DNSAction>(new ERCodeAction(rcode));
      auto erca = std::dynamic_pointer_cast<ERCodeAction>(ret);
      parseResponseConfig(vars, erca->d_responseConfig);
      return ret;
    });

  g_lua.writeFunction("SkipCacheAction", []() {
      return std::shared_ptr<DNSAction>(new SkipCacheAction);
    });

  g_lua.writeFunction("TempFailureCacheTTLAction", [](int maxTTL) {
      return std::shared_ptr<DNSAction>(new TempFailureCacheTTLAction(maxTTL));
    });

  g_lua.writeFunction("DropResponseAction", []() {
      return std::shared_ptr<DNSResponseAction>(new DropResponseAction);
    });

  g_lua.writeFunction("AllowResponseAction", []() {
      return std::shared_ptr<DNSResponseAction>(new AllowResponseAction);
    });

  g_lua.writeFunction("DelayResponseAction", [](int msec) {
      return std::shared_ptr<DNSResponseAction>(new DelayResponseAction(msec));
    });

  g_lua.writeFunction("LuaResponseAction", [](LuaResponseAction::func_t func) {
      setLuaSideEffect();
      return std::shared_ptr<DNSResponseAction>(new LuaResponseAction(func));
    });

  g_lua.writeFunction("LuaFFIResponseAction", [](LuaFFIResponseAction::func_t func) {
      setLuaSideEffect();
      return std::shared_ptr<DNSResponseAction>(new LuaFFIResponseAction(func));
    });

  g_lua.writeFunction("RemoteLogAction", [](std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)> > alterFunc, boost::optional<std::unordered_map<std::string, std::string>> vars) {
      if (logger) {
        // avoids potentially-evaluated-expression warning with clang.
        RemoteLoggerInterface& rl = *logger.get();
        if (typeid(rl) != typeid(RemoteLogger)) {
          // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
          throw std::runtime_error(std::string("RemoteLogAction only takes RemoteLogger. For other types, please look at DnstapLogAction."));
        }
      }

      std::string serverID;
      std::string ipEncryptKey;
      if (vars) {
        if (vars->count("serverID")) {
          serverID = boost::get<std::string>((*vars)["serverID"]);
        }
        if (vars->count("ipEncryptKey")) {
          ipEncryptKey = boost::get<std::string>((*vars)["ipEncryptKey"]);
        }
      }

#ifdef HAVE_PROTOBUF
      return std::shared_ptr<DNSAction>(new RemoteLogAction(logger, alterFunc, serverID, ipEncryptKey));
#else
      throw std::runtime_error("Protobuf support is required to use RemoteLogAction");
#endif
    });

  g_lua.writeFunction("RemoteLogResponseAction", [](std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSResponse*, DNSDistProtoBufMessage*)> > alterFunc, boost::optional<bool> includeCNAME, boost::optional<std::unordered_map<std::string, std::string>> vars) {
      if (logger) {
        // avoids potentially-evaluated-expression warning with clang.
        RemoteLoggerInterface& rl = *logger.get();
        if (typeid(rl) != typeid(RemoteLogger)) {
          // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
          throw std::runtime_error("RemoteLogResponseAction only takes RemoteLogger. For other types, please look at DnstapLogResponseAction.");
        }
      }

      std::string serverID;
      std::string ipEncryptKey;
      if (vars) {
        if (vars->count("serverID")) {
          serverID = boost::get<std::string>((*vars)["serverID"]);
        }
        if (vars->count("ipEncryptKey")) {
          ipEncryptKey = boost::get<std::string>((*vars)["ipEncryptKey"]);
        }
      }

#ifdef HAVE_PROTOBUF
      return std::shared_ptr<DNSResponseAction>(new RemoteLogResponseAction(logger, alterFunc, serverID, ipEncryptKey, includeCNAME ? *includeCNAME : false));
#else
      throw std::runtime_error("Protobuf support is required to use RemoteLogResponseAction");
#endif
    });

  g_lua.writeFunction("DnstapLogAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSQuestion*, DnstapMessage*)> > alterFunc) {
#ifdef HAVE_PROTOBUF
      return std::shared_ptr<DNSAction>(new DnstapLogAction(identity, logger, alterFunc));
#else
      throw std::runtime_error("Protobuf support is required to use DnstapLogAction");
#endif
    });

  g_lua.writeFunction("DnstapLogResponseAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSResponse*, DnstapMessage*)> > alterFunc) {
#ifdef HAVE_PROTOBUF
      return std::shared_ptr<DNSResponseAction>(new DnstapLogResponseAction(identity, logger, alterFunc));
#else
      throw std::runtime_error("Protobuf support is required to use DnstapLogResponseAction");
#endif
    });

  g_lua.writeFunction("TeeAction", [](const std::string& remote, boost::optional<bool> addECS) {
      return std::shared_ptr<DNSAction>(new TeeAction(ComboAddress(remote, 53), addECS ? *addECS : false));
    });

  g_lua.writeFunction("ECSPrefixLengthAction", [](uint16_t v4PrefixLength, uint16_t v6PrefixLength) {
      return std::shared_ptr<DNSAction>(new ECSPrefixLengthAction(v4PrefixLength, v6PrefixLength));
    });

  g_lua.writeFunction("ECSOverrideAction", [](bool ecsOverride) {
      return std::shared_ptr<DNSAction>(new ECSOverrideAction(ecsOverride));
    });

  g_lua.writeFunction("DisableECSAction", []() {
      return std::shared_ptr<DNSAction>(new DisableECSAction());
    });

  g_lua.writeFunction("SetECSAction", [](const std::string v4, boost::optional<std::string> v6) {
      if (v6) {
        return std::shared_ptr<DNSAction>(new SetECSAction(Netmask(v4), Netmask(*v6)));
      }
      return std::shared_ptr<DNSAction>(new SetECSAction(Netmask(v4)));
    });

  g_lua.writeFunction("SNMPTrapAction", [](boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
      return std::shared_ptr<DNSAction>(new SNMPTrapAction(reason ? *reason : ""));
#else
      throw std::runtime_error("NET SNMP support is required to use SNMPTrapAction()");
#endif /* HAVE_NET_SNMP */
    });

  g_lua.writeFunction("SNMPTrapResponseAction", [](boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
      return std::shared_ptr<DNSResponseAction>(new SNMPTrapResponseAction(reason ? *reason : ""));
#else
      throw std::runtime_error("NET SNMP support is required to use SNMPTrapResponseAction()");
#endif /* HAVE_NET_SNMP */
    });

  g_lua.writeFunction("TagAction", [](std::string tag, std::string value) {
      return std::shared_ptr<DNSAction>(new TagAction(tag, value));
    });

  g_lua.writeFunction("TagResponseAction", [](std::string tag, std::string value) {
      return std::shared_ptr<DNSResponseAction>(new TagResponseAction(tag, value));
    });

  g_lua.writeFunction("ContinueAction", [](std::shared_ptr<DNSAction> action) {
      return std::shared_ptr<DNSAction>(new ContinueAction(action));
    });

#ifdef HAVE_DNS_OVER_HTTPS
  g_lua.writeFunction("HTTPStatusAction", [](uint16_t status, std::string body, boost::optional<std::string> contentType, boost::optional<responseParams_t> vars) {
      auto ret = std::shared_ptr<DNSAction>(new HTTPStatusAction(status, body, contentType ? *contentType : ""));
      auto hsa = std::dynamic_pointer_cast<HTTPStatusAction>(ret);
      parseResponseConfig(vars, hsa->d_responseConfig);
      return ret;
    });
#endif /* HAVE_DNS_OVER_HTTPS */

  g_lua.writeFunction("KeyValueStoreLookupAction", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag) {
      return std::shared_ptr<DNSAction>(new KeyValueStoreLookupAction(kvs, lookupKey, destinationTag));
    });

  g_lua.writeFunction("SetNegativeAndSOAAction", [](bool nxd, const std::string& zone, uint32_t ttl, const std::string& mname, const std::string& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum, boost::optional<responseParams_t> vars) {
      auto ret = std::shared_ptr<DNSAction>(new SetNegativeAndSOAAction(nxd, DNSName(zone), ttl, DNSName(mname), DNSName(rname), serial, refresh, retry, expire, minimum));
      auto action = std::dynamic_pointer_cast<SetNegativeAndSOAAction>(ret);
      parseResponseConfig(vars, action->d_responseConfig);
      return ret;
    });
}
