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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "packetcache.hh"
#include "utility.hh"
#include "base32.hh"
#include "base64.hh"
#include <string>
#include <sys/types.h>
#include <boost/algorithm/string.hpp>
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "logger.hh"
#include "arguments.hh"
#include "packethandler.hh"
#include "statbag.hh"
#include "resolver.hh"
#include "communicator.hh"
#include "dnsproxy.hh"
#include "version.hh"
#include "auth-main.hh"
#include "trusted-notification-proxy.hh"
#include "gss_context.hh"

#if 0
#undef DLOG
#define DLOG(x) x
#endif

AtomicCounter PacketHandler::s_count;
NetmaskGroup PacketHandler::s_allowNotifyFrom;
set<string> PacketHandler::s_forwardNotify;
bool PacketHandler::s_SVCAutohints{false};

extern string g_programname;

// See https://www.rfc-editor.org/rfc/rfc8078.txt and https://www.rfc-editor.org/errata/eid5049 for details
const std::shared_ptr<CDNSKEYRecordContent> PacketHandler::s_deleteCDNSKEYContent = std::make_shared<CDNSKEYRecordContent>("0 3 0 AA==");
const std::shared_ptr<CDSRecordContent> PacketHandler::s_deleteCDSContent = std::make_shared<CDSRecordContent>("0 0 0 00");

PacketHandler::PacketHandler():B(g_programname), d_dk(&B)
{
  ++s_count;
  d_doDNAME=::arg().mustDo("dname-processing");
  d_doExpandALIAS = ::arg().mustDo("expand-alias");
  d_doResolveAcrossZones = ::arg().mustDo("resolve-across-zones");
  d_logDNSDetails= ::arg().mustDo("log-dns-details");
  string fname= ::arg()["lua-prequery-script"];

  if(fname.empty())
  {
    d_pdl = nullptr;
  }
  else
  {
    d_pdl = std::make_unique<AuthLua4>(::arg()["lua-global-include-dir"]);
    d_pdl->loadFile(fname);
  }
  fname = ::arg()["lua-dnsupdate-policy-script"];
  if (fname.empty())
  {
    d_update_policy_lua = nullptr;
  }
  else
  {
    try {
      d_update_policy_lua = std::make_unique<AuthLua4>();
      d_update_policy_lua->loadFile(fname);
    }
    catch (const std::runtime_error& e) {
      g_log<<Logger::Warning<<"Failed to load update policy - disabling: "<<e.what()<<endl;
      d_update_policy_lua = nullptr;
    }
  }
}

UeberBackend *PacketHandler::getBackend()
{
  return &B;
}

PacketHandler::~PacketHandler()
{
  --s_count;
  DLOG(g_log<<Logger::Error<<"PacketHandler destructor called - "<<s_count<<" left"<<endl);
}

/**
 * This adds CDNSKEY records to the answer packet. Returns true if one was added.
 *
 * @param p          Pointer to the DNSPacket containing the original question
 * @param r          Pointer to the DNSPacket where the records should be inserted into
 * @return           bool that shows if any records were added
**/
bool PacketHandler::addCDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r)
{
  string publishCDNSKEY;
  d_dk.getPublishCDNSKEY(p.qdomain,publishCDNSKEY);
  if (publishCDNSKEY.empty())
    return false;

  DNSZoneRecord rr;
  rr.dr.d_type=QType::CDNSKEY;
  rr.dr.d_ttl=d_sd.minimum;
  rr.dr.d_name=p.qdomain;
  rr.auth=true;

  if (publishCDNSKEY == "0") { // delete DS via CDNSKEY
    rr.dr.setContent(s_deleteCDNSKEYContent);
    r->addRecord(std::move(rr));
    return true;
  }

  bool haveOne=false;
  DNSSECKeeper::keyset_t entryPoints = d_dk.getEntryPoints(p.qdomain);
  for(const auto& value: entryPoints) {
    if (!value.second.published) {
      continue;
    }
    rr.dr.setContent(std::make_shared<DNSKEYRecordContent>(value.first.getDNSKEY()));
    r->addRecord(DNSZoneRecord(rr));
    haveOne=true;
  }

  if(::arg().mustDo("direct-dnskey")) {
    B.lookup(QType(QType::CDNSKEY), p.qdomain, d_sd.domain_id, &p);

    while(B.get(rr)) {
      rr.dr.d_ttl=d_sd.minimum;
      r->addRecord(std::move(rr));
      haveOne=true;
    }
  }
  return haveOne;
}

/**
 * This adds DNSKEY records to the answer packet. Returns true if one was added.
 *
 * @param p          Pointer to the DNSPacket containing the original question
 * @param r          Pointer to the DNSPacket where the records should be inserted into
 * @return           bool that shows if any records were added
**/
bool PacketHandler::addDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r)
{
  DNSZoneRecord rr;
  bool haveOne=false;

  DNSSECKeeper::keyset_t keyset = d_dk.getKeys(p.qdomain);
  for(const auto& value: keyset) {
    if (!value.second.published) {
      continue;
    }
    rr.dr.d_type=QType::DNSKEY;
    rr.dr.d_ttl=d_sd.minimum;
    rr.dr.d_name=p.qdomain;
    rr.dr.setContent(std::make_shared<DNSKEYRecordContent>(value.first.getDNSKEY()));
    rr.auth=true;
    r->addRecord(std::move(rr));
    haveOne=true;
  }

  if(::arg().mustDo("direct-dnskey")) {
    B.lookup(QType(QType::DNSKEY), p.qdomain, d_sd.domain_id, &p);

    while(B.get(rr)) {
      rr.dr.d_ttl=d_sd.minimum;
      r->addRecord(std::move(rr));
      haveOne=true;
    }
  }

  return haveOne;
}

/**
 * This adds CDS records to the answer packet r.
 *
 * @param p   Pointer to the DNSPacket containing the original question.
 * @param r   Pointer to the DNSPacket where the records should be inserted into.
 *            used to determine record TTL.
 * @return    bool that shows if any records were added.
**/
bool PacketHandler::addCDS(DNSPacket& p, std::unique_ptr<DNSPacket>& r)
{
  string publishCDS;
  d_dk.getPublishCDS(p.qdomain, publishCDS);
  if (publishCDS.empty())
    return false;

  vector<string> digestAlgos;
  stringtok(digestAlgos, publishCDS, ", ");

  DNSZoneRecord rr;
  rr.dr.d_type=QType::CDS;
  rr.dr.d_ttl=d_sd.minimum;
  rr.dr.d_name=p.qdomain;
  rr.auth=true;

  if(std::find(digestAlgos.begin(), digestAlgos.end(), "0") != digestAlgos.end()) { // delete DS via CDS
    rr.dr.setContent(s_deleteCDSContent);
    r->addRecord(std::move(rr));
    return true;
  }

  bool haveOne=false;

  DNSSECKeeper::keyset_t keyset = d_dk.getEntryPoints(p.qdomain);

  for(auto const &value : keyset) {
    if (!value.second.published) {
      continue;
    }
    for(auto const &digestAlgo : digestAlgos){
      rr.dr.setContent(std::make_shared<DSRecordContent>(makeDSFromDNSKey(p.qdomain, value.first.getDNSKEY(), pdns::checked_stoi<uint8_t>(digestAlgo))));
      r->addRecord(DNSZoneRecord(rr));
      haveOne=true;
    }
  }

  if(::arg().mustDo("direct-dnskey")) {
    B.lookup(QType(QType::CDS), p.qdomain, d_sd.domain_id, &p);

    while(B.get(rr)) {
      rr.dr.d_ttl=d_sd.minimum;
      r->addRecord(std::move(rr));
      haveOne=true;
    }
  }

  return haveOne;
}

/** This adds NSEC3PARAM records. Returns true if one was added */
bool PacketHandler::addNSEC3PARAM(const DNSPacket& p, std::unique_ptr<DNSPacket>& r)
{
  DNSZoneRecord rr;

  NSEC3PARAMRecordContent ns3prc;
  if(d_dk.getNSEC3PARAM(p.qdomain, &ns3prc)) {
    rr.dr.d_type=QType::NSEC3PARAM;
    rr.dr.d_ttl=d_sd.minimum;
    rr.dr.d_name=p.qdomain;
    ns3prc.d_flags = 0; // the NSEC3PARAM 'flag' is defined to always be zero in RFC5155.
    rr.dr.setContent(std::make_shared<NSEC3PARAMRecordContent>(ns3prc));
    rr.auth = true;
    r->addRecord(std::move(rr));
    return true;
  }
  return false;
}


// This is our chaos class requests handler. Return 1 if content was added, 0 if it wasn't
int PacketHandler::doChaosRequest(const DNSPacket& p, std::unique_ptr<DNSPacket>& r, DNSName &target) const
{
  DNSZoneRecord rr;

  if(p.qtype.getCode()==QType::TXT) {
    static const DNSName versionbind("version.bind."), versionpdns("version.pdns."), idserver("id.server.");
    if (target==versionbind || target==versionpdns) {
      // modes: full, powerdns only, anonymous or custom
      const static string mode=::arg()["version-string"];
      string content;
      if(mode=="full")
        content=fullVersionString();
      else if(mode=="powerdns")
        content="Served by PowerDNS - https://www.powerdns.com/";
      else if(mode=="anonymous") {
        r->setRcode(RCode::ServFail);
        return 0;
      }
      else
        content=mode;
      rr.dr.setContent(DNSRecordContent::make(QType::TXT, 1, "\"" + content + "\""));
    }
    else if (target==idserver) {
      // modes: disabled, hostname or custom
      const static string id=::arg()["server-id"];

      if (id == "disabled") {
        r->setRcode(RCode::Refused);
        return 0;
      }
      string tid=id;
      if(!tid.empty() && tid[0]!='"') { // see #6010 however
        tid = "\"" + tid + "\"";
      }
      rr.dr.setContent(DNSRecordContent::make(QType::TXT, 1, tid));
    }
    else {
      r->setRcode(RCode::Refused);
      return 0;
    }

    rr.dr.d_ttl=5;
    rr.dr.d_name=target;
    rr.dr.d_type=QType::TXT;
    rr.dr.d_class=QClass::CHAOS;
    r->addRecord(std::move(rr));
    return 1;
  }

  r->setRcode(RCode::NotImp);
  return 0;
}

vector<DNSZoneRecord> PacketHandler::getBestReferralNS(DNSPacket& p, const DNSName &target)
{
  vector<DNSZoneRecord> ret;
  DNSZoneRecord rr;
  DNSName subdomain(target);
  do {
    if(subdomain == d_sd.qname) // stop at SOA
      break;
    B.lookup(QType(QType::NS), subdomain, d_sd.domain_id, &p);
    while(B.get(rr)) {
      ret.push_back(rr); // this used to exclude auth NS records for some reason
    }
    if(!ret.empty())
      return ret;
  } while( subdomain.chopOff() );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return ret;
}

void PacketHandler::getBestDNAMESynth(DNSPacket& p, DNSName &target, vector<DNSZoneRecord> &ret)
{
  ret.clear();
  DNSZoneRecord rr;
  DNSName prefix;
  DNSName subdomain(target);
  do {
    DLOG(g_log<<"Attempting DNAME lookup for "<<subdomain<<", d_sd.qname="<<d_sd.qname<<endl);

    B.lookup(QType(QType::DNAME), subdomain, d_sd.domain_id, &p);
    while(B.get(rr)) {
      ret.push_back(rr);  // put in the original
      rr.dr.d_type = QType::CNAME;
      rr.dr.d_name = prefix + rr.dr.d_name;
      rr.dr.setContent(std::make_shared<CNAMERecordContent>(CNAMERecordContent(prefix + getRR<DNAMERecordContent>(rr.dr)->getTarget())));
      rr.auth = false; // don't sign CNAME
      target = getRR<CNAMERecordContent>(rr.dr)->getTarget();
      ret.push_back(rr);
    }
    if(!ret.empty())
      return;
    if(subdomain.countLabels())
      prefix.appendRawLabel(subdomain.getRawLabels()[0]); // XXX DNSName pain this feels wrong
    if(subdomain == d_sd.qname) // stop at SOA
      break;

  } while( subdomain.chopOff() );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return;
}


// Return best matching wildcard or next closer name
bool PacketHandler::getBestWildcard(DNSPacket& p, const DNSName &target, DNSName &wildcard, vector<DNSZoneRecord>* ret)
{
  ret->clear();
  DNSZoneRecord rr;
  DNSName subdomain(target);
  bool haveSomething=false;
  bool haveCNAME = false;

#ifdef HAVE_LUA_RECORDS
  bool doLua=g_doLuaRecord;
  if(!doLua) {
    string val;
    d_dk.getFromMeta(d_sd.qname, "ENABLE-LUA-RECORDS", val);
    doLua = (val=="1");
  }
#endif

  wildcard=subdomain;
  while( subdomain.chopOff() && !haveSomething )  {
    if (subdomain.empty()) {
      B.lookup(QType(QType::ANY), g_wildcarddnsname, d_sd.domain_id, &p);
    } else {
      B.lookup(QType(QType::ANY), g_wildcarddnsname+subdomain, d_sd.domain_id, &p);
    }
    while(B.get(rr)) {
      if (haveCNAME) {
        continue;
      }
#ifdef HAVE_LUA_RECORDS
      if (rr.dr.d_type == QType::LUA && !d_dk.isPresigned(d_sd.qname)) {
        if(!doLua) {
          DLOG(g_log<<"Have a wildcard LUA match, but not doing LUA record for this zone"<<endl);
          continue;
        }

        DLOG(g_log<<"Have a wildcard LUA match"<<endl);

        auto rec=getRR<LUARecordContent>(rr.dr);
        if (!rec) {
          continue;
        }
        if(rec->d_type == QType::CNAME || rec->d_type == p.qtype.getCode() || (p.qtype.getCode() == QType::ANY && rec->d_type != QType::RRSIG)) {
          //    noCache=true;
          DLOG(g_log<<"Executing Lua: '"<<rec->getCode()<<"'"<<endl);
          try {
            auto recvec=luaSynth(rec->getCode(), target, rr, d_sd.qname, p, rec->d_type, s_LUA);
            for (const auto& r : recvec) {
              rr.dr.d_type = rec->d_type; // might be CNAME
              rr.dr.setContent(r);
              rr.scopeMask = p.getRealRemote().getBits(); // this makes sure answer is a specific as your question
              if (rr.dr.d_type == QType::CNAME) {
                haveCNAME = true;
                *ret = {rr};
                break;
              }
              ret->push_back(rr);
            }
          }
          catch (std::exception &e) {
            B.lookupEnd();                 // don't leave DB handle in bad state

            throw;
          }
        }
      }
      else
#endif
      if(rr.dr.d_type != QType::ENT && (rr.dr.d_type == p.qtype.getCode() || rr.dr.d_type == QType::CNAME || (p.qtype.getCode() == QType::ANY && rr.dr.d_type != QType::RRSIG))) {
        if (rr.dr.d_type == QType::CNAME) {
          haveCNAME = true;
          ret->clear();
        }
        ret->push_back(rr);
      }

      wildcard=g_wildcarddnsname+subdomain;
      haveSomething=true;
    }

    if ( subdomain == d_sd.qname || haveSomething ) // stop at SOA or result
      break;

    B.lookup(QType(QType::ANY), subdomain, d_sd.domain_id, &p);
    if (B.get(rr)) {
      DLOG(g_log<<"No wildcard match, ancestor exists"<<endl);
      B.lookupEnd();
      break;
    }
    wildcard=subdomain;
  }

  return haveSomething;
}

DNSName PacketHandler::doAdditionalServiceProcessing(const DNSName &firstTarget, const uint16_t &qtype, std::unique_ptr<DNSPacket>& /* r */, vector<DNSZoneRecord>& extraRecords) {
  DNSName ret = firstTarget;
  size_t ctr = 5; // Max 5 SVCB Aliasforms per query
  bool done = false;
  while (!done && ctr > 0) {
    DNSZoneRecord rr;
    done = true;

    if(!ret.isPartOf(d_sd.qname)) {
      continue;
    }

    B.lookup(QType(qtype), ret, d_sd.domain_id);
    while (B.get(rr)) {
      rr.dr.d_place = DNSResourceRecord::ADDITIONAL;
      switch (qtype) {
        case QType::SVCB: /* fall-through */
        case QType::HTTPS: {
          auto rrc = getRR<SVCBBaseRecordContent>(rr.dr);
          extraRecords.push_back(std::move(rr));
          ret = rrc->getTarget().isRoot() ? ret : rrc->getTarget();
          if (rrc->getPriority() == 0) {
            done = false;
          }
          break;
        }
        default:
          B.lookupEnd();              // don't leave DB handle in bad state

          throw PDNSException("Unknown type (" + QType(qtype).toString() + ") for additional service processing");
      }
    }
    ctr--;
  }
  return ret;
}


// NOLINTNEXTLINE(readability-function-cognitive-complexity)
void PacketHandler::doAdditionalProcessing(DNSPacket& p, std::unique_ptr<DNSPacket>& r)
{
  DNSName content;
  DNSZoneRecord dzr;
  std::unordered_set<DNSName> lookup;
  vector<DNSZoneRecord> extraRecords;
  const auto& rrs = r->getRRS();

  lookup.reserve(rrs.size());
  for(auto& rr : rrs) {
    if(rr.dr.d_place != DNSResourceRecord::ADDITIONAL) {
      content.clear();
      switch(rr.dr.d_type) {
        case QType::NS:
          content=getRR<NSRecordContent>(rr.dr)->getNS();
          break;
        case QType::MX:
          content=getRR<MXRecordContent>(rr.dr)->d_mxname;
          break;
        case QType::SRV:
          content=getRR<SRVRecordContent>(rr.dr)->d_target;
          break;
        case QType::SVCB: /* fall-through */
        case QType::HTTPS: {
          auto rrc = getRR<SVCBBaseRecordContent>(rr.dr);
          content = rrc->getTarget();
          if (content.isRoot()) {
            content = rr.dr.d_name;
          }
          if (rrc->getPriority() == 0) {
            content = doAdditionalServiceProcessing(content, rr.dr.d_type, r, extraRecords);
          }
          break;
        }
        case QType::NAPTR: {
          auto naptrContent = getRR<NAPTRRecordContent>(rr.dr);
          auto flags = naptrContent->getFlags();
          toLowerInPlace(flags);
          if (flags.find('a') != string::npos) {
            content = naptrContent->getReplacement();
            DLOG(g_log<<Logger::Debug<<"adding NAPTR replacement 'a'="<<content<<endl);
          }
          else if (flags.find('s') != string::npos) {
            content = naptrContent->getReplacement();
            DLOG(g_log<<Logger::Debug<<"adding NAPTR replacement 's'="<<content<<endl);
            B.lookup(QType(QType::SRV), content, d_sd.domain_id, &p);
            while(B.get(dzr)) {
              content=getRR<SRVRecordContent>(dzr.dr)->d_target;
              if(content.isPartOf(d_sd.qname)) {
                lookup.emplace(content);
              }
              dzr.dr.d_place=DNSResourceRecord::ADDITIONAL;
              r->addRecord(std::move(dzr));
            }
            content.clear();
          }
          break;
        }
        default:
          continue;
      }
      if(!content.empty() && content.isPartOf(d_sd.qname)) {
        lookup.emplace(content);
      }
    }
  }

  for(auto& rr : extraRecords) {
    r->addRecord(std::move(rr));
  }
  extraRecords.clear();
  // TODO should we have a setting to do this?
  for (auto &rec : r->getServiceRecords()) {
    // Process auto hints
    auto rrc = getRR<SVCBBaseRecordContent>(rec->dr);
    DNSName target = rrc->getTarget().isRoot() ? rec->dr.d_name : rrc->getTarget();

    if (rrc->hasParam(SvcParam::ipv4hint) && rrc->autoHint(SvcParam::ipv4hint)) {
      auto newRRC = rrc->clone();
      if (!newRRC) {
        continue;
      }
      if (s_SVCAutohints) {
        auto hints = getIPAddressFor(target, QType::A);
        if (hints.size() == 0) {
          newRRC->removeParam(SvcParam::ipv4hint);
        } else {
          newRRC->setHints(SvcParam::ipv4hint, hints);
        }
      } else {
        newRRC->removeParam(SvcParam::ipv4hint);
      }
      rrc = newRRC;
      rec->dr.setContent(std::move(newRRC));
    }

    if (rrc->hasParam(SvcParam::ipv6hint) && rrc->autoHint(SvcParam::ipv6hint)) {
      auto newRRC = rrc->clone();
      if (!newRRC) {
        continue;
      }
      if (s_SVCAutohints) {
        auto hints = getIPAddressFor(target, QType::AAAA);
        if (hints.size() == 0) {
          newRRC->removeParam(SvcParam::ipv6hint);
        } else {
          newRRC->setHints(SvcParam::ipv6hint, hints);
        }
      } else {
        newRRC->removeParam(SvcParam::ipv6hint);
      }
      rec->dr.setContent(std::move(newRRC));
    }
  }

  for(const auto& name : lookup) {
    B.lookup(QType(QType::ANY), name, d_sd.domain_id, &p);
    while(B.get(dzr)) {
      if(dzr.dr.d_type == QType::A || dzr.dr.d_type == QType::AAAA) {
        dzr.dr.d_place=DNSResourceRecord::ADDITIONAL;
        r->addRecord(std::move(dzr));
      }
    }
  }
}

vector<ComboAddress> PacketHandler::getIPAddressFor(const DNSName &target, const uint16_t qtype) {
  vector<ComboAddress> ret;
  if (qtype != QType::A && qtype != QType::AAAA) {
    return ret;
  }
  B.lookup(qtype, target, d_sd.domain_id);
  DNSZoneRecord rr;
  while (B.get(rr)) {
    if (qtype == QType::AAAA) {
      auto aaaarrc = getRR<AAAARecordContent>(rr.dr);
      ret.push_back(aaaarrc->getCA());
    } else if (qtype == QType::A) {
      auto arrc = getRR<ARecordContent>(rr.dr);
      ret.push_back(arrc->getCA());
    }
  }
  return ret;
}

void PacketHandler::emitNSEC(std::unique_ptr<DNSPacket>& r, const DNSName& name, const DNSName& next, int mode)
{
  NSECRecordContent nrc;
  nrc.d_next = next;

  nrc.set(QType::NSEC);
  nrc.set(QType::RRSIG);
  if(d_sd.qname == name) {
    nrc.set(QType::SOA); // 1dfd8ad SOA can live outside the records table
    if(!d_dk.isPresigned(d_sd.qname)) {
      auto keyset = d_dk.getKeys(name);
      for(const auto& value: keyset) {
        if (value.second.published) {
          nrc.set(QType::DNSKEY);
          string publishCDNSKEY;
          d_dk.getPublishCDNSKEY(name, publishCDNSKEY);
          if (! publishCDNSKEY.empty())
            nrc.set(QType::CDNSKEY);
          string publishCDS;
          d_dk.getPublishCDS(name, publishCDS);
          if (! publishCDS.empty())
            nrc.set(QType::CDS);
          break;
        }
      }
    }
  }

  DNSZoneRecord rr;
#ifdef HAVE_LUA_RECORDS
  bool first{true};
  bool doLua{false};
#endif

  B.lookup(QType(QType::ANY), name, d_sd.domain_id);
  while(B.get(rr)) {
#ifdef HAVE_LUA_RECORDS
    if (rr.dr.d_type == QType::LUA && first && !d_dk.isPresigned(d_sd.qname)) {
      first = false;
      doLua = g_doLuaRecord;
      if (!doLua) {
        string val;
        d_dk.getFromMeta(d_sd.qname, "ENABLE-LUA-RECORDS", val);
        doLua = (val == "1");
      }
    }

    if (rr.dr.d_type == QType::LUA && doLua) {
      nrc.set(getRR<LUARecordContent>(rr.dr)->d_type);
    }
    else
#endif
      if (d_doExpandALIAS && rr.dr.d_type == QType::ALIAS) {
      // Set the A and AAAA in the NSEC bitmap so aggressive NSEC
      // does not falsely deny the type for this name.
      // This does NOT add the ALIAS to the bitmap, as that record cannot
      // be requested.
      if (!d_dk.isPresigned(d_sd.qname)) {
        nrc.set(QType::A);
        nrc.set(QType::AAAA);
      }
    }
    else if((rr.dr.d_type == QType::DNSKEY || rr.dr.d_type == QType::CDS || rr.dr.d_type == QType::CDNSKEY) && !d_dk.isPresigned(d_sd.qname) && !::arg().mustDo("direct-dnskey")) {
      continue;
    }
    else if(rr.dr.d_type == QType::NS || rr.auth) {
      nrc.set(rr.dr.d_type);
    }
  }

  rr.dr.d_name = name;
  rr.dr.d_ttl = d_sd.getNegativeTTL();
  rr.dr.d_type = QType::NSEC;
  rr.dr.setContent(std::make_shared<NSECRecordContent>(std::move(nrc)));
  rr.dr.d_place = (mode == 5 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;

  r->addRecord(std::move(rr));
}

void PacketHandler::emitNSEC3(std::unique_ptr<DNSPacket>& r, const NSEC3PARAMRecordContent& ns3prc, const DNSName& name, const string& namehash, const string& nexthash, int mode)
{
  NSEC3RecordContent n3rc;
  n3rc.d_algorithm = ns3prc.d_algorithm;
  n3rc.d_flags = ns3prc.d_flags;
  n3rc.d_iterations = ns3prc.d_iterations;
  n3rc.d_salt = ns3prc.d_salt;
  n3rc.d_nexthash = nexthash;

  DNSZoneRecord rr;

  if(!name.empty()) {
    if (d_sd.qname == name) {
      n3rc.set(QType::SOA); // 1dfd8ad SOA can live outside the records table
      n3rc.set(QType::NSEC3PARAM);
      if(!d_dk.isPresigned(d_sd.qname)) {
        auto keyset = d_dk.getKeys(name);
        for(const auto& value: keyset) {
          if (value.second.published) {
            n3rc.set(QType::DNSKEY);
            string publishCDNSKEY;
            d_dk.getPublishCDNSKEY(name, publishCDNSKEY);
            if (! publishCDNSKEY.empty())
              n3rc.set(QType::CDNSKEY);
            string publishCDS;
            d_dk.getPublishCDS(name, publishCDS);
            if (! publishCDS.empty())
              n3rc.set(QType::CDS);
            break;
          }
        }
      }
    }

#ifdef HAVE_LUA_RECORDS
    bool first{true};
    bool doLua{false};
#endif

    B.lookup(QType(QType::ANY), name, d_sd.domain_id);
    while(B.get(rr)) {
#ifdef HAVE_LUA_RECORDS
      if (rr.dr.d_type == QType::LUA && first && !d_dk.isPresigned(d_sd.qname)) {
        first = false;
        doLua = g_doLuaRecord;
        if (!doLua) {
          string val;
          d_dk.getFromMeta(d_sd.qname, "ENABLE-LUA-RECORDS", val);
          doLua = (val == "1");
        }
      }

      if (rr.dr.d_type == QType::LUA && doLua) {
        n3rc.set(getRR<LUARecordContent>(rr.dr)->d_type);
      }
      else
#endif
        if (d_doExpandALIAS && rr.dr.d_type == QType::ALIAS) {
        // Set the A and AAAA in the NSEC3 bitmap so aggressive NSEC
        // does not falsely deny the type for this name.
        // This does NOT add the ALIAS to the bitmap, as that record cannot
        // be requested.
        if (!d_dk.isPresigned(d_sd.qname)) {
          n3rc.set(QType::A);
          n3rc.set(QType::AAAA);
        }
      }
      else if((rr.dr.d_type == QType::DNSKEY || rr.dr.d_type == QType::CDS || rr.dr.d_type == QType::CDNSKEY) && !d_dk.isPresigned(d_sd.qname) && !::arg().mustDo("direct-dnskey")) {
        continue;
      }
      else if(rr.dr.d_type && (rr.dr.d_type == QType::NS || rr.auth)) {
          // skip empty non-terminals
          n3rc.set(rr.dr.d_type);
      }
    }
  }

  const auto numberOfTypesSet = n3rc.numberOfTypesSet();
  if (numberOfTypesSet != 0 && !(numberOfTypesSet == 1 && n3rc.isSet(QType::NS))) {
    n3rc.set(QType::RRSIG);
  }

  rr.dr.d_name = DNSName(toBase32Hex(namehash))+d_sd.qname;
  rr.dr.d_ttl = d_sd.getNegativeTTL();
  rr.dr.d_type=QType::NSEC3;
  rr.dr.setContent(std::make_shared<NSEC3RecordContent>(std::move(n3rc)));
  rr.dr.d_place = (mode == 5 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;

  r->addRecord(std::move(rr));
}

/*
   mode 0 = No Data Responses, QTYPE is not DS
   mode 1 = No Data Responses, QTYPE is DS
   mode 2 = Wildcard No Data Responses
   mode 3 = Wildcard Answer Responses
   mode 4 = Name Error Responses
   mode 5 = Direct NSEC request
*/
void PacketHandler::addNSECX(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, int mode)
{
  NSEC3PARAMRecordContent ns3rc;
  bool narrow = false;
  if(d_dk.getNSEC3PARAM(d_sd.qname, &ns3rc, &narrow))  {
    if (mode != 5) // no direct NSEC3 queries, rfc5155 7.2.8
      addNSEC3(p, r, target, wildcard, ns3rc, narrow, mode);
  }
  else {
    addNSEC(p, r, target, wildcard, mode);
  }
}

bool PacketHandler::getNSEC3Hashes(bool narrow, const std::string& hashed, bool decrement, DNSName& unhashed, std::string& before, std::string& after, int mode)
{
  bool ret;
  if(narrow) { // nsec3-narrow
    ret=true;
    before=hashed;
    if(decrement) {
      decrementHash(before);
      unhashed.clear();
    }
    after=hashed;
    incrementHash(after);
  }
  else {
    DNSName hashedName = DNSName(toBase32Hex(hashed));
    DNSName beforeName, afterName;
    if (!decrement && mode >= 2)
      beforeName = hashedName;
    ret=d_sd.db->getBeforeAndAfterNamesAbsolute(d_sd.domain_id, hashedName, unhashed, beforeName, afterName);
    before=fromBase32Hex(beforeName.toString());
    after=fromBase32Hex(afterName.toString());
  }
  return ret;
}

void PacketHandler::addNSEC3(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, const NSEC3PARAMRecordContent& ns3rc, bool narrow, int mode)
{
  DLOG(g_log<<"addNSEC3() mode="<<mode<<" auth="<<d_sd.qname<<" target="<<target<<" wildcard="<<wildcard<<endl);

  if (d_sd.db == nullptr) {
    if(!B.getSOAUncached(d_sd.qname, d_sd)) {
      DLOG(g_log<<"Could not get SOA for domain");
      return;
    }
  }

  bool doNextcloser = false;
  string before, after, hashed;
  DNSName unhashed, closest;

  if (mode == 2 || mode == 3 || mode == 4) {
    closest=wildcard;
    closest.chopOff();
  } else
    closest=target;

  // add matching NSEC3 RR
  if (mode != 3) {
    unhashed=(mode == 0 || mode == 1 || mode == 5) ? target : closest;
    hashed=hashQNameWithSalt(ns3rc, unhashed);
    DLOG(g_log<<"1 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);

    getNSEC3Hashes(narrow, hashed, false, unhashed, before, after, mode);

    if (((mode == 0 && ns3rc.d_flags) ||  mode == 1) && (hashed != before)) {
      DLOG(g_log<<"No matching NSEC3, do closest (provable) encloser"<<endl);

      bool doBreak = false;
      DNSZoneRecord rr;
      while( closest.chopOff() && (closest != d_sd.qname))  { // stop at SOA
        B.lookup(QType(QType::ANY), closest, d_sd.domain_id, &p);
        while(B.get(rr))
          if (rr.auth)
            doBreak = true;
        if(doBreak)
          break;
      }
      doNextcloser = true;
      unhashed=closest;
      hashed=hashQNameWithSalt(ns3rc, unhashed);
      DLOG(g_log<<"1 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);

      getNSEC3Hashes(narrow, hashed, false, unhashed, before, after);
    }

    if (!after.empty()) {
      DLOG(g_log<<"Done calling for matching, hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
      emitNSEC3(r, ns3rc, unhashed, before, after, mode);
    }
  }

  // add covering NSEC3 RR
  if ((mode >= 2 && mode <= 4) || doNextcloser) {
    DNSName next(target);
    do {
      unhashed=next;
    }
    while( next.chopOff() && !(next==closest));

    hashed=hashQNameWithSalt(ns3rc, unhashed);
    DLOG(g_log<<"2 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);

    getNSEC3Hashes(narrow, hashed, true, unhashed, before, after);
    DLOG(g_log<<"Done calling for covering, hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
    emitNSEC3( r, ns3rc, unhashed, before, after, mode);
  }

  // wildcard denial
  if (mode == 2 || mode == 4) {
    unhashed=g_wildcarddnsname+closest;

    hashed=hashQNameWithSalt(ns3rc, unhashed);
    DLOG(g_log<<"3 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);

    getNSEC3Hashes(narrow, hashed, (mode != 2), unhashed, before, after);
    DLOG(g_log<<"Done calling for '*', hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
    emitNSEC3( r, ns3rc, unhashed, before, after, mode);
  }
}

void PacketHandler::addNSEC(DNSPacket& /* p */, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, int mode)
{
  DLOG(g_log<<"addNSEC() mode="<<mode<<" auth="<<d_sd.qname<<" target="<<target<<" wildcard="<<wildcard<<endl);

  if (d_sd.db == nullptr) {
    if(!B.getSOAUncached(d_sd.qname, d_sd)) {
      DLOG(g_log<<"Could not get SOA for domain"<<endl);
      return;
    }
  }

  DNSName before,after;
  d_sd.db->getBeforeAndAfterNames(d_sd.domain_id, d_sd.qname, target, before, after);
  if (mode != 5 || before == target)
    emitNSEC(r, before, after, mode);

  if (mode == 2 || mode == 4) {
    // wildcard NO-DATA or wildcard denial
    before.clear();
    DNSName closest(wildcard);
    if (mode == 4) {
      closest.chopOff();
      closest.prependRawLabel("*");
    }
    d_sd.db->getBeforeAndAfterNames(d_sd.domain_id, d_sd.qname, closest, before, after);
    emitNSEC(r, before, after, mode);
  }
  return;
}

/* Semantics:

- only one backend owns the SOA of a zone
- only one AXFR per zone at a time - double startTransaction should fail
- backends need to implement transaction semantics


How BindBackend would implement this:
   startTransaction makes a file
   feedRecord sends everything to that file
   commitTransaction moves that file atomically over the regular file, and triggers a reload
   rollbackTransaction removes the file


How PostgreSQLBackend would implement this:
   startTransaction starts a sql transaction, which also deletes all records
   feedRecord is an insert statement
   commitTransaction commits the transaction
   rollbackTransaction aborts it

How MySQLBackend would implement this:
   (good question!)

*/

int PacketHandler::tryAutoPrimary(const DNSPacket& p, const DNSName& tsigkeyname)
{
  if(p.d_tcp)
  {
    // do it right now if the client is TCP
    // rarely happens
    return tryAutoPrimarySynchronous(p, tsigkeyname);
  }
  else
  {
    // queue it if the client is on UDP
    Communicator.addTryAutoPrimaryRequest(p);
    return 0;
  }
}

int PacketHandler::tryAutoPrimarySynchronous(const DNSPacket& p, const DNSName& tsigkeyname)
{
  ComboAddress remote = p.getInnerRemote();
  if(p.hasEDNSSubnet() && pdns::isAddressTrustedNotificationProxy(remote)) {
    remote = p.getRealRemote().getNetwork();
  }
  else {
    remote = p.getInnerRemote();
  }
  remote.setPort(53);

  Resolver::res_t nsset;
  try {
    Resolver resolver;
    uint32_t theirserial;
    resolver.getSoaSerial(remote, p.qdomain, &theirserial);
    resolver.resolve(remote, p.qdomain, QType::NS, &nsset);
  }
  catch(ResolverException &re) {
    g_log<<Logger::Error<<"Error resolving SOA or NS for "<<p.qdomain<<" at: "<< remote <<": "<<re.reason<<endl;
    return RCode::ServFail;
  }

  // check if the returned records are NS records
  bool haveNS=false;
  for(const auto& ns: nsset) {
    if(ns.qtype==QType::NS)
      haveNS=true;
  }

  if(!haveNS) {
    g_log << Logger::Error << "While checking for autoprimary, did not find NS for " << p.qdomain << " at: " << remote << endl;
    return RCode::ServFail;
  }

  string nameserver, account;
  DNSBackend *db;

  if (!::arg().mustDo("allow-unsigned-autoprimary") && tsigkeyname.empty()) {
    g_log << Logger::Error << "Received unsigned NOTIFY for " << p.qdomain << " from potential autoprimary " << remote << ". Refusing." << endl;
    return RCode::Refused;
  }

  if (!B.autoPrimaryBackend(remote.toString(), p.qdomain, nsset, &nameserver, &account, &db)) {
    g_log << Logger::Error << "Unable to find backend willing to host " << p.qdomain << " for potential autoprimary " << remote << ". Remote nameservers: " << endl;
    for(const auto& rr: nsset) {
      if(rr.qtype==QType::NS)
        g_log<<Logger::Error<<rr.content<<endl;
    }
    return RCode::Refused;
  }
  try {
    db->createSecondaryDomain(remote.toString(), p.qdomain, nameserver, account);
    DomainInfo di;
    if (!db->getDomainInfo(p.qdomain, di, false)) {
      g_log << Logger::Error << "Failed to create " << p.qdomain << " for potential autoprimary " << remote << endl;
      return RCode::ServFail;
    }
    g_zoneCache.add(p.qdomain, di.id);
    if (tsigkeyname.empty() == false) {
      vector<string> meta;
      meta.push_back(tsigkeyname.toStringNoDot());
      db->setDomainMetadata(p.qdomain, "AXFR-MASTER-TSIG", meta);
    }
  }
  catch(PDNSException& ae) {
    g_log << Logger::Error << "Database error trying to create " << p.qdomain << " for potential autoprimary " << remote << ": " << ae.reason << endl;
    return RCode::ServFail;
  }
  g_log << Logger::Warning << "Created new secondary zone '" << p.qdomain << "' from autoprimary " << remote << endl;
  return RCode::NoError;
}

int PacketHandler::processNotify(const DNSPacket& p)
{
  /* now what?
     was this notification from an approved address?
     was this notification approved by TSIG?
     We determine our internal SOA id (via UeberBackend)
     We determine the SOA at our (known) primary
     if primary is higher -> do stuff
  */

  g_log<<Logger::Debug<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemoteString()<<endl;

  if(!::arg().mustDo("secondary") && s_forwardNotify.empty()) {
    g_log << Logger::Warning << "Received NOTIFY for " << p.qdomain << " from " << p.getRemoteString() << " but secondary support is disabled in the configuration" << endl;
    return RCode::Refused;
  }

  // Sender verification
  //
  if(!s_allowNotifyFrom.match(p.getInnerRemote()) || p.d_havetsig) {
    if (p.d_havetsig && p.getTSIGKeyname().empty() == false) {
        g_log<<Logger::Notice<<"Received secure NOTIFY for "<<p.qdomain<<" from "<<p.getRemoteString()<<", with TSIG key '"<<p.getTSIGKeyname()<<"'"<<endl;
    } else {
      g_log<<Logger::Warning<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemoteString()<<" but the remote is not providing a TSIG key or in allow-notify-from (Refused)"<<endl;
      return RCode::Refused;
    }
  }

  if ((!::arg().mustDo("allow-unsigned-notify") && !p.d_havetsig) || p.d_havetsig) {
    if (!p.d_havetsig) {
      g_log<<Logger::Warning<<"Received unsigned NOTIFY for "<<p.qdomain<<" from "<<p.getRemoteString()<<" while a TSIG key was required (Refused)"<<endl;
      return RCode::Refused;
    }
    vector<string> meta;
    if (B.getDomainMetadata(p.qdomain,"AXFR-MASTER-TSIG",meta) && meta.size() > 0) {
      DNSName expected{meta[0]};
      if (p.getTSIGKeyname() != expected) {
        g_log<<Logger::Warning<<"Received secure NOTIFY for "<<p.qdomain<<" from "<<p.getRemoteString()<<": expected TSIG key '"<<expected<<"', got '"<<p.getTSIGKeyname()<<"' (Refused)"<<endl;
        return RCode::Refused;
      }
    }
  }

  // Domain verification
  //
  DomainInfo di;
  if(!B.getDomainInfo(p.qdomain, di, false) || !di.backend) {
    if(::arg().mustDo("autosecondary")) {
      g_log << Logger::Warning << "Received NOTIFY for " << p.qdomain << " from " << p.getRemoteString() << " for which we are not authoritative, trying autoprimary" << endl;
      return tryAutoPrimary(p, p.getTSIGKeyname());
    }
    g_log<<Logger::Notice<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemoteString()<<" for which we are not authoritative (Refused)"<<endl;
    return RCode::Refused;
  }

  if(pdns::isAddressTrustedNotificationProxy(p.getInnerRemote())) {
    if (di.primaries.empty()) {
      g_log << Logger::Warning << "Received NOTIFY for " << p.qdomain << " from trusted-notification-proxy " << p.getRemoteString() << ", zone does not have any primaries defined (Refused)" << endl;
      return RCode::Refused;
    }
    g_log<<Logger::Notice<<"Received NOTIFY for "<<p.qdomain<<" from trusted-notification-proxy "<<p.getRemoteString()<<endl;
  }
  else if (::arg().mustDo("primary") && di.isPrimaryType()) {
    g_log << Logger::Warning << "Received NOTIFY for " << p.qdomain << " from " << p.getRemoteString() << " but we are primary (Refused)" << endl;
    return RCode::Refused;
  }
  else if (!di.isPrimary(p.getInnerRemote())) {
    g_log << Logger::Warning << "Received NOTIFY for " << p.qdomain << " from " << p.getRemoteString() << " which is not a primary (Refused)" << endl;
    return RCode::Refused;
  }

  if(!s_forwardNotify.empty()) {
    set<string> forwardNotify(s_forwardNotify);
    for(const auto & j : forwardNotify) {
      g_log<<Logger::Notice<<"Relaying notification of domain "<<p.qdomain<<" from "<<p.getRemoteString()<<" to "<<j<<endl;
      Communicator.notify(p.qdomain,j);
    }
  }

  if(::arg().mustDo("secondary")) {
    g_log<<Logger::Notice<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemoteString()<<" - queueing check"<<endl;
    di.receivedNotify = true;
    Communicator.addSecondaryCheckRequest(di, p.getInnerRemote());
  }
  return 0;
}

static bool validDNSName(const DNSName& name)
{
  if (!g_8bitDNS) {
    return name.has8bitBytes() == false;
  }
  return true;
}

std::unique_ptr<DNSPacket> PacketHandler::question(DNSPacket& p)
{
  std::unique_ptr<DNSPacket> ret{nullptr};

  if(d_pdl)
  {
    ret=d_pdl->prequery(p);
    if(ret)
      return ret;
  }

  if(p.d.rd) {
    static AtomicCounter &rdqueries=*S.getPointer("rd-queries");
    rdqueries++;
  }

  return doQuestion(p);
}


void PacketHandler::makeNXDomain(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard)
{
  DNSZoneRecord rr;
  rr=makeEditedDNSZRFromSOAData(d_dk, d_sd, DNSResourceRecord::AUTHORITY);
  rr.dr.d_ttl=d_sd.getNegativeTTL();
  r->addRecord(std::move(rr));

  if(d_dnssec) {
    addNSECX(p, r, target, wildcard, 4);
  }

  r->setRcode(RCode::NXDomain);
}

void PacketHandler::makeNOError(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, int mode)
{
  DNSZoneRecord rr;
  rr=makeEditedDNSZRFromSOAData(d_dk, d_sd, DNSResourceRecord::AUTHORITY);
  rr.dr.d_ttl=d_sd.getNegativeTTL();
  r->addRecord(std::move(rr));

  if(d_dnssec) {
    addNSECX(p, r, target, wildcard, mode);
  }

  S.inc("noerror-packets");
  S.ringAccount("noerror-queries", p.qdomain, p.qtype);
}


bool PacketHandler::addDSforNS(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& dsname)
{
  //cerr<<"Trying to find a DS for '"<<dsname<<"', domain_id = "<<d_sd.domain_id<<endl;
  B.lookup(QType(QType::DS), dsname, d_sd.domain_id, &p);
  DNSZoneRecord rr;
  bool gotOne=false;
  while(B.get(rr)) {
    gotOne=true;
    rr.dr.d_place = DNSResourceRecord::AUTHORITY;
    r->addRecord(std::move(rr));
  }
  return gotOne;
}

bool PacketHandler::tryReferral(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target, bool retargeted)
{
  vector<DNSZoneRecord> rrset = getBestReferralNS(p, target);
  if(rrset.empty())
    return false;

  DNSName name = rrset.begin()->dr.d_name;
  for(auto& rr: rrset) {
    rr.dr.d_place=DNSResourceRecord::AUTHORITY;
    r->addRecord(std::move(rr));
  }
  if(!retargeted)
    r->setA(false);

  if(d_dk.isSecuredZone(d_sd.qname) && !addDSforNS(p, r, name) && d_dnssec) {
    addNSECX(p, r, name, DNSName(), 1);
  }

  return true;
}

void PacketHandler::completeANYRecords(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target)
{
  addNSECX(p, r, target, DNSName(), 5);
  if(d_sd.qname == p.qdomain) {
    if(!d_dk.isPresigned(d_sd.qname)) {
      addDNSKEY(p, r);
      addCDNSKEY(p, r);
      addCDS(p, r);
    }
    addNSEC3PARAM(p, r);
  }
}

bool PacketHandler::tryDNAME(DNSPacket& p, std::unique_ptr<DNSPacket>& r, DNSName &target)
{
  if(!d_doDNAME)
    return false;
  DLOG(g_log<<Logger::Warning<<"Let's try DNAME.."<<endl);
  vector<DNSZoneRecord> rrset;
  try {
    getBestDNAMESynth(p, target, rrset);
    if(!rrset.empty()) {
      for(size_t i = 0; i < rrset.size(); i++) {
        rrset.at(i).dr.d_place = DNSResourceRecord::ANSWER;
        r->addRecord(std::move(rrset.at(i)));
      }
      return true;
    }
  } catch (const std::range_error &e) {
    // Add the DNAME regardless, but throw to let the caller know we could not
    // synthesize a CNAME
    if(!rrset.empty()) {
      for(size_t i = 0; i < rrset.size(); i++) {
        rrset.at(i).dr.d_place = DNSResourceRecord::ANSWER;
        r->addRecord(std::move(rrset.at(i)));
      }
    }
    throw e;
  }
  return false;
}
bool PacketHandler::tryWildcard(DNSPacket& p, std::unique_ptr<DNSPacket>& r, DNSName &target, DNSName &wildcard, bool& retargeted, bool& nodata)
{
  retargeted = nodata = false;
  DNSName bestmatch;

  vector<DNSZoneRecord> rrset;
  if(!getBestWildcard(p, target, wildcard, &rrset))
    return false;

  if(rrset.empty()) {
    DLOG(g_log<<"Wildcard matched something, but not of the correct type"<<endl);
    nodata=true;
  }
  else {
    bestmatch = target;
    for(auto& rr: rrset) {
      rr.wildcardname = rr.dr.d_name;
      rr.dr.d_name = bestmatch;

      if(rr.dr.d_type == QType::CNAME)  {
        retargeted=true;
        target=getRR<CNAMERecordContent>(rr.dr)->getTarget();
      }

      rr.dr.d_place=DNSResourceRecord::ANSWER;
      r->addRecord(std::move(rr));
    }
  }
  if(d_dnssec && !nodata) {
    addNSECX(p, r, bestmatch, wildcard, 3);
  }

  return true;
}

//! Called by the Distributor to ask a question. Returns 0 in case of an error
// NOLINTNEXTLINE(readability-function-cognitive-complexity): TODO Clean this function up.
std::unique_ptr<DNSPacket> PacketHandler::doQuestion(DNSPacket& p)
{
  DNSZoneRecord rr;

  int retargetcount=0;
  set<DNSName> authSet;

  vector<DNSZoneRecord> rrset;
  bool weDone=false, weRedirected=false, weHaveUnauth=false, doSigs=false;
  DNSName haveAlias;
  uint8_t aliasScopeMask;

  std::unique_ptr<DNSPacket> r{nullptr};
  bool noCache=false;

#ifdef HAVE_LUA_RECORDS
  bool doLua=g_doLuaRecord;
#endif

  if(p.d.qr) { // QR bit from dns packet (thanks RA from N)
    if(d_logDNSDetails)
      g_log<<Logger::Error<<"Received an answer (non-query) packet from "<<p.getRemoteString()<<", dropping"<<endl;
    S.inc("corrupt-packets");
    S.ringAccount("remotes-corrupt", p.getInnerRemote());
    return nullptr;
  }

  if(p.d.tc) { // truncated query. MOADNSParser would silently parse this packet in an incomplete way.
    if(d_logDNSDetails)
      g_log<<Logger::Error<<"Received truncated query packet from "<<p.getRemoteString()<<", dropping"<<endl;
    S.inc("corrupt-packets");
    S.ringAccount("remotes-corrupt", p.getInnerRemote());
    return nullptr;
  }

  if (p.hasEDNS()) {
    if(p.getEDNSVersion() > 0) {
      r = p.replyPacket();

      // PacketWriter::addOpt will take care of setting this correctly in the packet
      r->setEDNSRcode(ERCode::BADVERS);
      return r;
    }
    if (p.hasEDNSCookie()) {
      if (!p.hasWellFormedEDNSCookie()) {
        r = p.replyPacket();
        r->setRcode(RCode::FormErr);
        return r;
      }
      if (!p.hasValidEDNSCookie() && !p.d_tcp) {
        r = p.replyPacket();
        r->setEDNSRcode(ERCode::BADCOOKIE);
        return r;
      }
    }
  }

  if(p.d_havetsig) {
    DNSName tsigkeyname;
    string secret;
    TSIGRecordContent trc;
    if (!checkForCorrectTSIG(p, &tsigkeyname, &secret, &trc)) {
      r=p.replyPacket();  // generate an empty reply packet
      if(d_logDNSDetails)
        g_log<<Logger::Error<<"Received a TSIG signed message with a non-validating key"<<endl;
      // RFC3007 describes that a non-secure message should be sending Refused for DNS Updates
      if (p.d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return r;
    } else {
      getTSIGHashEnum(trc.d_algoName, p.d_tsig_algo);
#ifdef ENABLE_GSS_TSIG
      if (g_doGssTSIG && p.d_tsig_algo == TSIG_GSS) {
        GssContext gssctx(tsigkeyname);
        if (!gssctx.getPeerPrincipal(p.d_peer_principal)) {
          g_log<<Logger::Warning<<"Failed to extract peer principal from GSS context with keyname '"<<tsigkeyname<<"'"<<endl;
        }
      }
#endif
    }
    p.setTSIGDetails(trc, tsigkeyname, secret, trc.d_mac); // this will get copied by replyPacket()
    noCache=true;
  }

  r=p.replyPacket();  // generate an empty reply packet, possibly with TSIG details inside

  if (p.qtype == QType::TKEY) {
    this->tkeyHandler(p, r);
    return r;
  }

  try {

    // XXX FIXME do this in DNSPacket::parse ?

    if(!validDNSName(p.qdomain)) {
      if(d_logDNSDetails)
        g_log<<Logger::Error<<"Received a malformed qdomain from "<<p.getRemoteString()<<", '"<<p.qdomain<<"': sending servfail"<<endl;
      S.inc("corrupt-packets");
      S.ringAccount("remotes-corrupt", p.getInnerRemote());
      S.inc("servfail-packets");
      r->setRcode(RCode::ServFail);
      return r;
    }
    if(p.d.opcode) { // non-zero opcode (again thanks RA!)
      if(p.d.opcode==Opcode::Update) {
        S.inc("dnsupdate-queries");
        int res=processUpdate(p);
        if (res == RCode::Refused)
          S.inc("dnsupdate-refused");
        else if (res != RCode::ServFail)
          S.inc("dnsupdate-answers");
        r->setRcode(res);
        r->setOpcode(Opcode::Update);
        return r;
      }
      else if(p.d.opcode==Opcode::Notify) {
        S.inc("incoming-notifications");
        int res=processNotify(p);
        if(res>=0) {
          r->setRcode(res);
          r->setOpcode(Opcode::Notify);
          return r;
        }
        return nullptr;
      }

      g_log<<Logger::Error<<"Received an unknown opcode "<<p.d.opcode<<" from "<<p.getRemoteString()<<" for "<<p.qdomain<<endl;

      r->setRcode(RCode::NotImp);
      return r;
    }

    // g_log<<Logger::Warning<<"Query for '"<<p.qdomain<<"' "<<p.qtype.toString()<<" from "<<p.getRemoteString()<< " (tcp="<<p.d_tcp<<")"<<endl;

    if(p.qtype.getCode()==QType::IXFR) {
      r->setRcode(RCode::Refused);
      return r;
    }

    DNSName target=p.qdomain;

    // catch chaos qclass requests
    if(p.qclass == QClass::CHAOS) {
      if (doChaosRequest(p,r,target))
        goto sendit;
      else
        return r;
    }

    // we only know about qclass IN (and ANY), send Refused for everything else.
    if(p.qclass != QClass::IN && p.qclass!=QClass::ANY) {
      r->setRcode(RCode::Refused);
      return r;
    }

    // send TC for udp ANY query if any-to-tcp is enabled.
    if(p.qtype.getCode() == QType::ANY && !p.d_tcp && g_anyToTcp) {
      r->d.tc = 1;
      r->commitD();
      return r;
    }

    // for qclass ANY the response should never be authoritative unless the response covers all classes.
    if(p.qclass==QClass::ANY)
      r->setA(false);


  retargeted:;
    if(retargetcount > 10) {    // XXX FIXME, retargetcount++?
      g_log<<Logger::Warning<<"Abort CNAME chain resolution after "<<--retargetcount<<" redirects, sending out servfail. Initial query: '"<<p.qdomain<<"'"<<endl;
      r=p.replyPacket();
      r->setRcode(RCode::ServFail);
      return r;
    }

    if (retargetcount > 0 && !d_doResolveAcrossZones && !target.isPartOf(r->qdomainzone)) {
      // We are following a retarget outside the initial zone (and do not need to check getAuth to know this). Config asked us not to do that.
      // This is a performance optimization, the generic case is checked after getAuth below.
      goto sendit;  // NOLINT(cppcoreguidelines-avoid-goto)
    }

    if(!B.getAuth(target, p.qtype, &d_sd)) {
      DLOG(g_log<<Logger::Error<<"We have no authority over zone '"<<target<<"'"<<endl);
      if(!retargetcount) {
        r->setA(false); // drop AA if we never had a SOA in the first place
        r->setRcode(RCode::Refused); // send REFUSED - but only on empty 'no idea'
      }
      goto sendit;
    }
    DLOG(g_log<<Logger::Error<<"We have authority, zone='"<<d_sd.qname<<"', id="<<d_sd.domain_id<<endl);

    if (retargetcount == 0) {
      r->qdomainzone = d_sd.qname;
    } else if (!d_doResolveAcrossZones && r->qdomainzone != d_sd.qname) {
      // We are following a retarget outside the initial zone. Config asked us not to do that.
      goto sendit;  // NOLINT(cppcoreguidelines-avoid-goto)
    }

    authSet.insert(d_sd.qname);
    d_dnssec=(p.d_dnssecOk && d_dk.isSecuredZone(d_sd.qname));
    doSigs |= d_dnssec;

    if(d_sd.qname==p.qdomain) {
      if(!d_dk.isPresigned(d_sd.qname)) {
        if(p.qtype.getCode() == QType::DNSKEY)
        {
          if(addDNSKEY(p, r))
            goto sendit;
        }
        else if(p.qtype.getCode() == QType::CDNSKEY)
        {
          if(addCDNSKEY(p,r))
            goto sendit;
        }
        else if(p.qtype.getCode() == QType::CDS)
        {
          if(addCDS(p,r))
            goto sendit;
        }
      }
      if(p.qtype.getCode() == QType::NSEC3PARAM)
      {
        if(addNSEC3PARAM(p,r))
          goto sendit;
      }
    }

    if(p.qtype.getCode() == QType::SOA && d_sd.qname==p.qdomain) {
      rr=makeEditedDNSZRFromSOAData(d_dk, d_sd);
      r->addRecord(std::move(rr));
      goto sendit;
    }

    // this TRUMPS a cname!
    if(d_dnssec && p.qtype.getCode() == QType::NSEC && !d_dk.getNSEC3PARAM(d_sd.qname, nullptr)) {
      addNSEC(p, r, target, DNSName(), 5);
      if (!r->isEmpty())
        goto sendit;
    }

    // this TRUMPS a cname!
    if(p.qtype.getCode() == QType::RRSIG) {
      g_log<<Logger::Info<<"Direct RRSIG query for "<<target<<" from "<<p.getRemoteString()<<endl;
      r->setRcode(RCode::Refused);
      goto sendit;
    }

    DLOG(g_log<<"Checking for referrals first, unless this is a DS query"<<endl);
    if(p.qtype.getCode() != QType::DS && tryReferral(p, r, target, retargetcount))
      goto sendit;

    DLOG(g_log<<"Got no referrals, trying ANY"<<endl);

#ifdef HAVE_LUA_RECORDS
    if(!doLua) {
      string val;
      d_dk.getFromMeta(d_sd.qname, "ENABLE-LUA-RECORDS", val);
      doLua = (val=="1");
    }
#endif

    // see what we get..
    B.lookup(QType(QType::ANY), target, d_sd.domain_id, &p);
    rrset.clear();
    haveAlias.clear();
    aliasScopeMask = 0;
    weDone = weRedirected = weHaveUnauth =  false;

    while(B.get(rr)) {
#ifdef HAVE_LUA_RECORDS
      if (rr.dr.d_type == QType::LUA && !d_dk.isPresigned(d_sd.qname)) {
        if(!doLua)
          continue;
        auto rec=getRR<LUARecordContent>(rr.dr);
        if (!rec) {
          continue;
        }
        if(rec->d_type == QType::CNAME || rec->d_type == p.qtype.getCode() || (p.qtype.getCode() == QType::ANY && rec->d_type != QType::RRSIG)) {
          noCache=true;
          try {
            auto recvec=luaSynth(rec->getCode(), target, rr, d_sd.qname, p, rec->d_type, s_LUA);
            if(!recvec.empty()) {
              for (const auto& r_it : recvec) {
                rr.dr.d_type = rec->d_type; // might be CNAME
                rr.dr.setContent(r_it);
                rr.scopeMask = p.getRealRemote().getBits(); // this makes sure answer is a specific as your question
                rrset.push_back(rr);
              }
              if(rec->d_type == QType::CNAME && p.qtype.getCode() != QType::CNAME)
                weRedirected = true;
              else
                weDone = true;
            }
          }
          catch(std::exception &e) {
            B.lookupEnd();              // don't leave DB handle in bad state

            r=p.replyPacket();
            r->setRcode(RCode::ServFail);

            return r;
          }
        }
      }
#endif
      //cerr<<"got content: ["<<rr.content<<"]"<<endl;
      if (!d_dnssec && p.qtype.getCode() == QType::ANY && (rr.dr.d_type == QType:: DNSKEY || rr.dr.d_type == QType::NSEC3PARAM))
        continue; // Don't send dnssec info.
      if (rr.dr.d_type == QType::RRSIG) // RRSIGS are added later any way.
        continue; // TODO: this actually means addRRSig should check if the RRSig is already there

      // cerr<<"Auth: "<<rr.auth<<", "<<(rr.dr.d_type == p.qtype)<<", "<<rr.dr.d_type.toString()<<endl;
      if((p.qtype.getCode() == QType::ANY || rr.dr.d_type == p.qtype.getCode()) && rr.auth)
        weDone=true;
      // the line below fakes 'unauth NS' for delegations for non-DNSSEC backends.
      if((rr.dr.d_type == p.qtype.getCode() && !rr.auth) || (rr.dr.d_type == QType::NS && (!rr.auth || !(d_sd.qname==rr.dr.d_name))))
        weHaveUnauth=true;

      if(rr.dr.d_type == QType::CNAME && p.qtype.getCode() != QType::CNAME)
        weRedirected=true;

      if (DP && rr.dr.d_type == QType::ALIAS && (p.qtype.getCode() == QType::A || p.qtype.getCode() == QType::AAAA || p.qtype.getCode() == QType::ANY) && !d_dk.isPresigned(d_sd.qname)) {
        if (!d_doExpandALIAS) {
          g_log<<Logger::Info<<"ALIAS record found for "<<target<<", but ALIAS expansion is disabled."<<endl;
          continue;
        }
        haveAlias=getRR<ALIASRecordContent>(rr.dr)->getContent();
        aliasScopeMask=rr.scopeMask;
      }

      // Filter out all SOA's and add them in later
      if(rr.dr.d_type == QType::SOA)
        continue;

      rrset.push_back(rr);
    }

    /* Add in SOA if required */
    if(target==d_sd.qname) {
        rr=makeEditedDNSZRFromSOAData(d_dk, d_sd);
        rrset.push_back(rr);
    }


    DLOG(g_log<<"After first ANY query for '"<<target<<"', id="<<d_sd.domain_id<<": weDone="<<weDone<<", weHaveUnauth="<<weHaveUnauth<<", weRedirected="<<weRedirected<<", haveAlias='"<<haveAlias<<"'"<<endl);
    if(p.qtype.getCode() == QType::DS && weHaveUnauth &&  !weDone && !weRedirected) {
      DLOG(g_log<<"Q for DS of a name for which we do have NS, but for which we don't have DS; need to provide an AUTH answer that shows we don't"<<endl);
      makeNOError(p, r, target, DNSName(), 1);
      goto sendit;
    }

    if(!haveAlias.empty() && (!weDone || p.qtype.getCode() == QType::ANY)) {
      DLOG(g_log<<Logger::Warning<<"Found nothing that matched for '"<<target<<"', but did get alias to '"<<haveAlias<<"', referring"<<endl);
      DP->completePacket(r, haveAlias, target, aliasScopeMask);
      return nullptr;
    }


    // referral for DS query
    if(p.qtype.getCode() == QType::DS) {
      DLOG(g_log<<"Qtype is DS"<<endl);
      bool doReferral = true;
      if(d_dk.doesDNSSEC()) {
        for(auto& loopRR: rrset) {
          // In a dnssec capable backend auth=true means, there is no delegation at
          // or above this qname in this zone (for DS queries). Without a delegation,
          // at or above this level, it is pointless to search for referrals.
          if(loopRR.auth) {
            doReferral = false;
            break;
          }
        }
      } else {
        for(auto& loopRR: rrset) {
          // In a non dnssec capable backend auth is always true, so our only option
          // is, always look for referrals. Unless there is a direct match for DS.
          if(loopRR.dr.d_type == QType::DS) {
            doReferral = false;
            break;
          }
        }
      }
      if(doReferral) {
        DLOG(g_log<<"DS query found no direct result, trying referral now"<<endl);
        if(tryReferral(p, r, target, retargetcount))
        {
          DLOG(g_log<<"Got referral for DS query"<<endl);
          goto sendit;
        }
      }
    }


    if(rrset.empty()) {
      DLOG(g_log<<Logger::Warning<<"Found nothing in the by-name ANY, but let's try wildcards.."<<endl);
      bool wereRetargeted(false), nodata(false);
      DNSName wildcard;
      if(tryWildcard(p, r, target, wildcard, wereRetargeted, nodata)) {
        if(wereRetargeted) {
          if(!retargetcount) r->qdomainwild=wildcard;
          retargetcount++;
          goto retargeted;
        }
        if(nodata)
          makeNOError(p, r, target, wildcard, 2);

        goto sendit;
      }
      try {
        if (tryDNAME(p, r, target)) {
          retargetcount++;
          goto retargeted;
        }
      } catch (const std::range_error &e) {
        // We couldn't make a CNAME.....
        r->setRcode(RCode::YXDomain);
        goto sendit;
      }

      if (!(((p.qtype.getCode() == QType::CNAME) || (p.qtype.getCode() == QType::ANY)) && retargetcount > 0))
        makeNXDomain(p, r, target, wildcard);

      goto sendit;
    }

    if(weRedirected) {
      for(auto& loopRR: rrset) {
        if(loopRR.dr.d_type == QType::CNAME) {
          r->addRecord(DNSZoneRecord(loopRR));
          target = getRR<CNAMERecordContent>(loopRR.dr)->getTarget();
          retargetcount++;
          goto retargeted;
        }
      }
    }
    else if(weDone) {
      bool haveRecords = false;
      bool presigned = d_dk.isPresigned(d_sd.qname);
      for(const auto& loopRR: rrset) {
        if (loopRR.dr.d_type == QType::ENT) {
          continue;
        }
        if (loopRR.dr.d_type == QType::ALIAS && d_doExpandALIAS && !presigned) {
          continue;
        }
#ifdef HAVE_LUA_RECORDS
        if (loopRR.dr.d_type == QType::LUA && !presigned) {
          continue;
        }
#endif
        if ((p.qtype.getCode() == QType::ANY || loopRR.dr.d_type == p.qtype.getCode()) && loopRR.auth) {
          r->addRecord(DNSZoneRecord(loopRR));
          haveRecords = true;
        }
      }

      if (haveRecords) {
        if(d_dnssec && p.qtype.getCode() == QType::ANY)
          completeANYRecords(p, r, target);
      }
      else
        makeNOError(p, r, target, DNSName(), 0);

      goto sendit;
    }
    else if(weHaveUnauth) {
      DLOG(g_log<<"Have unauth data, so need to hunt for best NS records"<<endl);
      if(tryReferral(p, r, target, retargetcount))
        goto sendit;
      // check whether this could be fixed easily
      // if (*(rr.dr.d_name.rbegin()) == '.') {
      //      g_log<<Logger::Error<<"Should not get here ("<<p.qdomain<<"|"<<p.qtype.toString()<<"): you have a trailing dot, this could be the problem (or run pdnsutil rectify-zone " <<d_sd.qname<<")"<<endl;
      // } else {
           g_log<<Logger::Error<<"Should not get here ("<<p.qdomain<<"|"<<p.qtype.toString()<<"): please run pdnsutil rectify-zone "<<d_sd.qname<<endl;
      // }
    }
    else {
      DLOG(g_log<<"Have some data, but not the right data"<<endl);
      makeNOError(p, r, target, DNSName(), 0);
    }

  sendit:;
    doAdditionalProcessing(p, r);

    for(const auto& loopRR: r->getRRS()) {
      if(loopRR.scopeMask) {
        noCache=true;
        break;
      }
    }
    if(doSigs)
      addRRSigs(d_dk, B, authSet, r->getRRS(), &p);

    if(PC.enabled() && !noCache && p.couldBeCached())
      PC.insert(p, *r, r->getMinTTL()); // in the packet cache
  }
  catch(const DBException &e) {
    g_log<<Logger::Error<<"Backend reported condition which prevented lookup ("+e.reason+") sending out servfail"<<endl;
    r=p.replyPacket(); // generate an empty reply packet
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries", p.qdomain, p.qtype);
  }
  catch(const PDNSException &e) {
    g_log<<Logger::Error<<"Backend reported permanent error which prevented lookup ("+e.reason+"), aborting"<<endl;
    throw; // we WANT to die at this point
  }
  catch(const std::exception &e) {
    g_log<<Logger::Error<<"Exception building answer packet for "<<p.qdomain<<"/"<<p.qtype.toString()<<" ("<<e.what()<<") sending out servfail"<<endl;
    r=p.replyPacket(); // generate an empty reply packet
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries", p.qdomain, p.qtype);
  }
  return r;

}

bool PacketHandler::checkForCorrectTSIG(const DNSPacket& packet, DNSName* tsigkeyname, string* secret, TSIGRecordContent* tsigContent)
{
  uint16_t tsigPos{0};

  if (!packet.getTSIGDetails(tsigContent, tsigkeyname, &tsigPos)) {
    return false;
  }

  TSIGTriplet tsigTriplet;
  tsigTriplet.name = *tsigkeyname;
  tsigTriplet.algo = tsigContent->d_algoName;
  if (tsigTriplet.algo == DNSName("hmac-md5.sig-alg.reg.int")) {
    tsigTriplet.algo = DNSName("hmac-md5");
  }

  if (tsigTriplet.algo != DNSName("gss-tsig")) {
    string secret64;
    if (!B.getTSIGKey(*tsigkeyname, tsigTriplet.algo, secret64)) {
      g_log << Logger::Error << "Packet for domain '" << packet.qdomain << "' denied: can't find TSIG key with name '" << *tsigkeyname << "' and algorithm '" << tsigTriplet.algo << "'" << endl;
      return false;
    }
    B64Decode(secret64, *secret);
    tsigTriplet.secret = *secret;
  }

  try {
    return packet.validateTSIG(tsigTriplet, *tsigContent, "", tsigContent->d_mac, false);
  }
  catch(const std::runtime_error& err) {
    g_log<<Logger::Error<<"Packet for '"<<packet.qdomain<<"' denied: "<<err.what()<<endl;
    return false;
  }
}
