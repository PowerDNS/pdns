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
#include "threadname.hh"
#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-protobuf.hh"

#include "dolog.hh"
#include "dnstap.hh"
#include "ednsoptions.hh"
#include "fstrm_logger.hh"
#include "remote_logger.hh"
#include "boost/optional/optional_io.hpp"

class DropAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    return Action::Drop;
  }
  string toString() const override
  {
    return "drop";
  }
};

class AllowAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    return Action::Allow;
  }
  string toString() const override
  {
    return "allow";
  }
};

class NoneAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    return Action::None;
  }
  string toString() const override
  {
    return "no op";
  }
};

class QPSAction : public DNSAction
{
public:
  QPSAction(int limit) : d_qps(limit, limit)
  {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if(d_qps.check())
      return Action::None;
    else
      return Action::Drop;
  }
  string toString() const override
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
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    *ruleresult=std::to_string(d_msec);
    return Action::Delay;
  }
  string toString() const override
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
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override;
  string toString() const override;
  std::map<string, double> getStats() const override;

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

DNSAction::Action TeeAction::operator()(DNSQuestion* dq, string* ruleresult) const
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

      string newECSOption;
      generateECSOption(dq->ecsSet ? dq->ecs.getNetwork() : *dq->remote, newECSOption, dq->ecsSet ? dq->ecs.getBits() :  dq->ecsPrefixLength);

      if (!handleEDNSClientSubnet(const_cast<char*>(query.c_str()), query.capacity(), dq->qname->wirelength(), &len, &ednsAdded, &ecsAdded, dq->ecsOverride, newECSOption)) {
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

string TeeAction::toString() const
{
  return "tee to "+d_remote.toStringWithPort();
}

std::map<string,double> TeeAction::getStats() const
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
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    *ruleresult=d_pool;
    return Action::Pool;
  }
  string toString() const override
  {
    return "to pool "+d_pool;
  }

private:
  string d_pool;
};


class QPSPoolAction : public DNSAction
{
public:
  QPSPoolAction(unsigned int limit, const std::string& pool) : d_qps(limit, limit), d_pool(pool) {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if(d_qps.check()) {
      *ruleresult=d_pool;
      return Action::Pool;
    }
    else
      return Action::None;
  }
  string toString() const override
  {
    return "max " +std::to_string(d_qps.getRate())+" to pool "+d_pool;
  }

private:
  QPSLimiter d_qps;
  string d_pool;
};

class RCodeAction : public DNSAction
{
public:
  RCodeAction(uint8_t rcode) : d_rcode(rcode) {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->dh->rcode = d_rcode;
    dq->dh->qr = true; // for good measure
    return Action::HeaderModify;
  }
  string toString() const override
  {
    return "set rcode "+std::to_string(d_rcode);
  }

private:
  uint8_t d_rcode;
};

class TCAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    return Action::Truncate;
  }
  string toString() const override
  {
    return "tc=1 answer";
  }
};

DNSAction::Action LuaAction::operator()(DNSQuestion* dq, string* ruleresult) const
{
  std::lock_guard<std::mutex> lock(g_luamutex);
  try {
    auto ret = d_func(dq);
    if (ruleresult) {
      if (boost::optional<string> rule = std::get<1>(ret)) {
        *ruleresult = *rule;
      }
      else {
        // default to empty string
        ruleresult->clear();
      }
    }
    return (Action)std::get<0>(ret);
  } catch (std::exception &e) {
    warnlog("LuaAction failed inside lua, returning ServFail: %s", e.what());
  } catch (...) {
    warnlog("LuaAction failed inside lua, returning ServFail: [unknown exception]");
  }
  return DNSAction::Action::ServFail;
}

DNSResponseAction::Action LuaResponseAction::operator()(DNSResponse* dr, string* ruleresult) const
{
  std::lock_guard<std::mutex> lock(g_luamutex);
  try {
    auto ret = d_func(dr);
    if(ruleresult) {
      if (boost::optional<string> rule = std::get<1>(ret)) {
        *ruleresult = *rule;
      }
      else {
        // default to empty string
        ruleresult->clear();
      }
    }
    return (Action)std::get<0>(ret);
  } catch (std::exception &e) {
    warnlog("LuaResponseAction failed inside lua, returning ServFail: %s", e.what());
  } catch (...) {
    warnlog("LuaResponseAction failed inside lua, returning ServFail: [unknown exception]");
  }
  return DNSResponseAction::Action::ServFail;
}

DNSAction::Action SpoofAction::operator()(DNSQuestion* dq, string* ruleresult) const
{
  uint16_t qtype = dq->qtype;
  // do we even have a response?
  if(d_cname.empty() && !std::count_if(d_addrs.begin(), d_addrs.end(), [qtype](const ComboAddress& a)
                                       {
                                         return (qtype == QType::ANY || ((a.sin4.sin_family == AF_INET && qtype == QType::A) ||
                                                                         (a.sin4.sin_family == AF_INET6 && qtype == QType::AAAA)));
                                       }))
    return Action::None;

  vector<ComboAddress> addrs;
  unsigned int totrdatalen=0;
  if (!d_cname.empty()) {
    qtype = QType::CNAME;
    totrdatalen += d_cname.toDNSString().size();
  } else {
    for(const auto& addr : d_addrs) {
      if(qtype != QType::ANY && ((addr.sin4.sin_family == AF_INET && qtype != QType::A) ||
                                 (addr.sin4.sin_family == AF_INET6 && qtype != QType::AAAA))) {
        continue;
      }
      totrdatalen += addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr);
      addrs.push_back(addr);
    }
  }

  if(addrs.size() > 1)
    random_shuffle(addrs.begin(), addrs.end());

  unsigned int consumed=0;
  DNSName ignore((char*)dq->dh, dq->len, sizeof(dnsheader), false, 0, 0, &consumed);

  if (dq->size < (sizeof(dnsheader) + consumed + 4 + ((d_cname.empty() ? 0 : 1) + addrs.size())*12 /* recordstart */ + totrdatalen)) {
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
  dq->dh->ra = dq->dh->rd; // for good measure
  dq->dh->ad = false;
  dq->dh->ancount = 0;
  dq->dh->arcount = 0; // for now, forget about your EDNS, we're marching over it

  if(qtype == QType::CNAME) {
    string wireData = d_cname.toDNSString(); // Note! This doesn't do compression!
    const unsigned char recordstart[]={0xc0, 0x0c,    // compressed name
                                       0, (unsigned char) qtype,
                                       0, QClass::IN, // IN
                                       0, 0, 0, 60,   // TTL
                                       0, (unsigned char)wireData.length()};
    static_assert(sizeof(recordstart) == 12, "sizeof(recordstart) must be equal to 12, otherwise the above check is invalid");

    memcpy(dest, recordstart, sizeof(recordstart));
    dest += sizeof(recordstart);
    memcpy(dest, wireData.c_str(), wireData.length());
    dq->len += wireData.length() + sizeof(recordstart);
    dq->dh->ancount++;
  }
  else {
    for(const auto& addr : addrs) {
      unsigned char rdatalen = addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr);
      const unsigned char recordstart[]={0xc0, 0x0c,    // compressed name
                                         0, (unsigned char) (addr.sin4.sin_family == AF_INET ? QType::A : QType::AAAA),
                                         0, QClass::IN, // IN
                                         0, 0, 0, 60,   // TTL
                                         0, rdatalen};
      static_assert(sizeof(recordstart) == 12, "sizeof(recordstart) must be equal to 12, otherwise the above check is invalid");

      memcpy(dest, recordstart, sizeof(recordstart));
      dest += sizeof(recordstart);

      memcpy(dest,
             addr.sin4.sin_family == AF_INET ? (void*)&addr.sin4.sin_addr.s_addr : (void*)&addr.sin6.sin6_addr.s6_addr,
             rdatalen);
      dest += rdatalen;
      dq->len += rdatalen + sizeof(recordstart);
      dq->dh->ancount++;
    }
  }

  dq->dh->ancount = htons(dq->dh->ancount);

  if (hadEDNS) {
    addEDNS(dq->dh, dq->len, dq->size, dnssecOK, g_PayloadSizeSelfGenAnswers);
  }

  return Action::HeaderModify;
}

class MacAddrAction : public DNSAction
{
public:
  MacAddrAction(uint16_t code) : d_code(code)
  {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if(dq->dh->arcount)
      return Action::None;

    string mac = getMACAddress(*dq->remote);
    if(mac.empty())
      return Action::None;

    string optRData;
    generateEDNSOption(d_code, mac, optRData);

    string res;
    generateOptRR(optRData, res, g_EdnsUDPPayloadSize, false);

    if ((dq->size - dq->len) < res.length())
      return Action::None;

    dq->dh->arcount = htons(1);
    char* dest = ((char*)dq->dh) + dq->len;
    memcpy(dest, res.c_str(), res.length());
    dq->len += res.length();

    return Action::None;
  }
  string toString() const override
  {
    return "add EDNS MAC (code="+std::to_string(d_code)+")";
  }
private:
  uint16_t d_code{3};
};

class NoRecurseAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->dh->rd = false;
    return Action::None;
  }
  string toString() const override
  {
    return "set rd=0";
  }
};

class LogAction : public DNSAction, public boost::noncopyable
{
public:
  LogAction() : d_fp(0)
  {
  }
  LogAction(const std::string& str, bool binary=true, bool append=false, bool buffered=true) : d_fname(str), d_binary(binary)
  {
    if(str.empty())
      return;
    if(append)
      d_fp = fopen(str.c_str(), "a+");
    else
      d_fp = fopen(str.c_str(), "w");
    if(!d_fp)
      throw std::runtime_error("Unable to open file '"+str+"' for logging: "+string(strerror(errno)));
    if(!buffered)
      setbuf(d_fp, 0);
  }
  ~LogAction() override
  {
    if(d_fp)
      fclose(d_fp);
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if(!d_fp) {
      vinfolog("Packet from %s for %s %s with id %d", dq->remote->toStringWithPort(), dq->qname->toString(), QType(dq->qtype).getName(), dq->dh->id);
    }
    else {
      if(d_binary) {
        string out = dq->qname->toDNSString();
        fwrite(out.c_str(), 1, out.size(), d_fp);
        fwrite((void*)&dq->qtype, 1, 2, d_fp);
      }
      else {
        fprintf(d_fp, "Packet from %s for %s %s with id %d\n", dq->remote->toStringWithPort().c_str(), dq->qname->toString().c_str(), QType(dq->qtype).getName().c_str(), dq->dh->id);
      }
    }
    return Action::None;
  }
  string toString() const override
  {
    if (!d_fname.empty()) {
      return "log to " + d_fname;
    }
    return "log";
  }
private:
  string d_fname;
  FILE* d_fp{0};
  bool d_binary{true};
};


class DisableValidationAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->dh->cd = true;
    return Action::None;
  }
  string toString() const override
  {
    return "set cd=1";
  }
};

class SkipCacheAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->skipCache = true;
    return Action::None;
  }
  string toString() const override
  {
    return "skip cache";
  }
};

class TempFailureCacheTTLAction : public DNSAction
{
public:
  TempFailureCacheTTLAction(uint32_t ttl) : d_ttl(ttl)
  {}
  TempFailureCacheTTLAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->tempFailureTTL = d_ttl;
    return Action::None;
  }
  string toString() const override
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
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->ecsPrefixLength = dq->remote->sin4.sin_family == AF_INET ? d_v4PrefixLength : d_v6PrefixLength;
    return Action::None;
  }
  string toString() const override
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
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->ecsOverride = d_ecsOverride;
    return Action::None;
  }
  string toString() const override
  {
    return "set ECS override to " + std::to_string(d_ecsOverride);
  }
private:
  bool d_ecsOverride;
};


class DisableECSAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->useECS = false;
    return Action::None;
  }
  string toString() const override
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

  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
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

  string toString() const override
  {
    string result = "set ECS to " + d_v4.toString();
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
  DnstapLogAction(const std::string& identity, std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(const DNSQuestion&, DnstapMessage*)> > alterFunc): d_identity(identity), d_logger(logger), d_alterFunc(alterFunc)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    DnstapMessage message(d_identity, dq->remote, dq->local, dq->tcp, reinterpret_cast<const char*>(dq->dh), dq->len, dq->queryTime, nullptr);
    {
      if (d_alterFunc) {
        std::lock_guard<std::mutex> lock(g_luamutex);
        (*d_alterFunc)(*dq, &message);
      }
    }
    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  string toString() const override
  {
    return "remote log as dnstap to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::string d_identity;
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  boost::optional<std::function<void(const DNSQuestion&, DnstapMessage*)> > d_alterFunc;
};

class RemoteLogAction : public DNSAction, public boost::noncopyable
{
public:
  RemoteLogAction(std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(const DNSQuestion&, DNSDistProtoBufMessage*)> > alterFunc, const std::string& serverID): d_logger(logger), d_alterFunc(alterFunc), d_serverID(serverID)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    if (!dq->uniqueId) {
      dq->uniqueId = t_uuidGenerator();
    }

    DNSDistProtoBufMessage message(*dq);
    if (!d_serverID.empty()) {
      message.setServerIdentity(d_serverID);
    }

    if (d_alterFunc) {
      std::lock_guard<std::mutex> lock(g_luamutex);
      (*d_alterFunc)(*dq, &message);
    }

    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  string toString() const override
  {
    return "remote log to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  boost::optional<std::function<void(const DNSQuestion&, DNSDistProtoBufMessage*)> > d_alterFunc;
  std::string d_serverID;
};

class SNMPTrapAction : public DNSAction
{
public:
  SNMPTrapAction(const std::string& reason): d_reason(reason)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if (g_snmpAgent && g_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(*dq, d_reason);
    }

    return Action::None;
  }
  string toString() const override
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
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if (!dq->qTag) {
      dq->qTag = std::make_shared<QTag>();
    }

    dq->qTag->insert({d_tag, d_value});

    return Action::None;
  }
  string toString() const override
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
  DnstapLogResponseAction(const std::string& identity, std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(const DNSResponse&, DnstapMessage*)> > alterFunc): d_identity(identity), d_logger(logger), d_alterFunc(alterFunc)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    struct timespec now;
    gettime(&now, true);
    DnstapMessage message(d_identity, dr->remote, dr->local, dr->tcp, reinterpret_cast<const char*>(dr->dh), dr->len, dr->queryTime, &now);
    {
      if (d_alterFunc) {
        std::lock_guard<std::mutex> lock(g_luamutex);
        (*d_alterFunc)(*dr, &message);
      }
    }
    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  string toString() const override
  {
    return "log response as dnstap to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::string d_identity;
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  boost::optional<std::function<void(const DNSResponse&, DnstapMessage*)> > d_alterFunc;
};

class RemoteLogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  RemoteLogResponseAction(std::shared_ptr<RemoteLoggerInterface>& logger, boost::optional<std::function<void(const DNSResponse&, DNSDistProtoBufMessage*)> > alterFunc, const std::string& serverID, bool includeCNAME): d_logger(logger), d_alterFunc(alterFunc), d_serverID(serverID), d_includeCNAME(includeCNAME)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    if (!dr->uniqueId) {
      dr->uniqueId = t_uuidGenerator();
    }

    DNSDistProtoBufMessage message(*dr, d_includeCNAME);
    if (!d_serverID.empty()) {
      message.setServerIdentity(d_serverID);
    }

    if (d_alterFunc) {
      std::lock_guard<std::mutex> lock(g_luamutex);
      (*d_alterFunc)(*dr, &message);
    }

    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  string toString() const override
  {
    return "remote log response to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::shared_ptr<RemoteLoggerInterface> d_logger;
  boost::optional<std::function<void(const DNSResponse&, DNSDistProtoBufMessage*)> > d_alterFunc;
  std::string d_serverID;
  bool d_includeCNAME;
};

class DropResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    return Action::Drop;
  }
  string toString() const override
  {
    return "drop";
  }
};

class AllowResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    return Action::Allow;
  }
  string toString() const override
  {
    return "allow";
  }
};

class DelayResponseAction : public DNSResponseAction
{
public:
  DelayResponseAction(int msec) : d_msec(msec)
  {}
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    *ruleresult=std::to_string(d_msec);
    return Action::Delay;
  }
  string toString() const override
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
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    if (g_snmpAgent && g_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(*dr, d_reason);
    }

    return Action::None;
  }
  string toString() const override
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
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    if (!dr->qTag) {
      dr->qTag = std::make_shared<QTag>();
    }

    dr->qTag->insert({d_tag, d_value});

    return Action::None;
  }
  string toString() const override
  {
    return "set tag '" + d_tag + "' to value '" + d_value + "'";
  }
private:
  std::string d_tag;
  std::string d_value;
};

template<typename T, typename ActionT>
static void addAction(GlobalStateHolder<vector<T> > *someRulActions, luadnsrule_t var, std::shared_ptr<ActionT> action, boost::optional<luaruleparams_t> params) {
  setLuaSideEffect();

  boost::uuids::uuid uuid;
  uint64_t creationOrder;
  parseRuleParams(params, uuid, creationOrder);

  auto rule=makeRule(var);
  someRulActions->modify([rule, action, uuid, creationOrder](vector<T>& rulactions){
      rulactions.push_back({rule, action, uuid, creationOrder});
    });
}

void setupLuaActions()
{
  g_lua.writeFunction("newRuleAction", [](luadnsrule_t dnsrule, std::shared_ptr<DNSAction> action, boost::optional<luaruleparams_t> params) {
      boost::uuids::uuid uuid;
      uint64_t creationOrder;
      parseRuleParams(params, uuid, creationOrder);

      auto rule=makeRule(dnsrule);
      DNSDistRuleAction ra({rule, action, uuid, creationOrder});
      return std::make_shared<DNSDistRuleAction>(ra);
    });

  g_lua.writeFunction("addAction", [](luadnsrule_t var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction> > era, boost::optional<luaruleparams_t> params) {
      if (era.type() != typeid(std::shared_ptr<DNSAction>)) {
        throw std::runtime_error("addAction() can only be called with query-related actions, not response-related ones. Are you looking for addResponseAction()?");
      }

      addAction(&g_rulactions, var, boost::get<std::shared_ptr<DNSAction> >(era), params);
    });

  g_lua.writeFunction("addLuaAction", [](luadnsrule_t var, LuaAction::func_t func, boost::optional<luaruleparams_t> params) {
      addAction(&g_rulactions, var, std::make_shared<LuaAction>(func), params);
    });

  g_lua.writeFunction("addLuaResponseAction", [](luadnsrule_t var, LuaResponseAction::func_t func, boost::optional<luaruleparams_t> params) {
      addAction(&g_resprulactions, var, std::make_shared<LuaResponseAction>(func), params);
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

  g_lua.writeFunction("NoRecurseAction", []() {
      return std::shared_ptr<DNSAction>(new NoRecurseAction);
    });

  g_lua.writeFunction("MacAddrAction", [](int code) {
      return std::shared_ptr<DNSAction>(new MacAddrAction(code));
    });

  g_lua.writeFunction("PoolAction", [](const string& a) {
      return std::shared_ptr<DNSAction>(new PoolAction(a));
    });

  g_lua.writeFunction("QPSAction", [](int limit) {
      return std::shared_ptr<DNSAction>(new QPSAction(limit));
    });

  g_lua.writeFunction("QPSPoolAction", [](int limit, const string& a) {
      return std::shared_ptr<DNSAction>(new QPSPoolAction(limit, a));
    });

  g_lua.writeFunction("SpoofAction", [](boost::variant<string,vector<pair<int, string>>> inp, boost::optional<string> b ) {
      vector<ComboAddress> addrs;
      if(auto s = boost::get<string>(&inp))
        addrs.push_back(ComboAddress(*s));
      else {
        const auto& v = boost::get<vector<pair<int,string>>>(inp);
        for(const auto& a: v)
          addrs.push_back(ComboAddress(a.second));
      }
      if(b)
        addrs.push_back(ComboAddress(*b));
      return std::shared_ptr<DNSAction>(new SpoofAction(addrs));
    });

  g_lua.writeFunction("SpoofCNAMEAction", [](const string& a) {
      return std::shared_ptr<DNSAction>(new SpoofAction(a));
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

  g_lua.writeFunction("LogAction", [](const std::string& fname, boost::optional<bool> binary, boost::optional<bool> append, boost::optional<bool> buffered) {
      return std::shared_ptr<DNSAction>(new LogAction(fname, binary ? *binary : true, append ? *append : false, buffered ? *buffered : false));
    });

  g_lua.writeFunction("RCodeAction", [](uint8_t rcode) {
      return std::shared_ptr<DNSAction>(new RCodeAction(rcode));
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

  g_lua.writeFunction("RemoteLogAction", [](std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(const DNSQuestion&, DNSDistProtoBufMessage*)> > alterFunc, boost::optional<std::unordered_map<std::string, std::string>> vars) {
      // avoids potentially-evaluated-expression warning with clang.
      RemoteLoggerInterface& rl = *logger.get();
      if (typeid(rl) != typeid(RemoteLogger)) {
        // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
        throw std::runtime_error(std::string("RemoteLogAction only takes RemoteLogger. For other types, please look at DnstapLogAction."));
      }

      std::string serverID;
      if (vars) {
        if (vars->count("serverID")) {
          serverID = boost::get<std::string>((*vars)["serverID"]);
        }
      }

#ifdef HAVE_PROTOBUF
      return std::shared_ptr<DNSAction>(new RemoteLogAction(logger, alterFunc, serverID));
#else
      throw std::runtime_error("Protobuf support is required to use RemoteLogAction");
#endif
    });

  g_lua.writeFunction("RemoteLogResponseAction", [](std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(const DNSResponse&, DNSDistProtoBufMessage*)> > alterFunc, boost::optional<bool> includeCNAME, boost::optional<std::unordered_map<std::string, std::string>> vars) {
      // avoids potentially-evaluated-expression warning with clang.
      RemoteLoggerInterface& rl = *logger.get();
      if (typeid(rl) != typeid(RemoteLogger)) {
        // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
        throw std::runtime_error("RemoteLogResponseAction only takes RemoteLogger. For other types, please look at DnstapLogResponseAction.");
      }

      std::string serverID;
      if (vars) {
        if (vars->count("serverID")) {
          serverID = boost::get<std::string>((*vars)["serverID"]);
        }
      }

#ifdef HAVE_PROTOBUF
      return std::shared_ptr<DNSResponseAction>(new RemoteLogResponseAction(logger, alterFunc, serverID, includeCNAME ? *includeCNAME : false));
#else
      throw std::runtime_error("Protobuf support is required to use RemoteLogResponseAction");
#endif
    });

  g_lua.writeFunction("DnstapLogAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(const DNSQuestion&, DnstapMessage*)> > alterFunc) {
#ifdef HAVE_PROTOBUF
      return std::shared_ptr<DNSAction>(new DnstapLogAction(identity, logger, alterFunc));
#else
      throw std::runtime_error("Protobuf support is required to use DnstapLogAction");
#endif
    });

  g_lua.writeFunction("DnstapLogResponseAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(const DNSResponse&, DnstapMessage*)> > alterFunc) {
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
}
