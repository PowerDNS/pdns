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
#include "common_startup.hh"

#if 0
#undef DLOG
#define DLOG(x) x
#endif 
 
AtomicCounter PacketHandler::s_count;
NetmaskGroup PacketHandler::s_allowNotifyFrom;
set<string> PacketHandler::s_forwardNotify;

extern string s_programname;

PacketHandler::PacketHandler():B(s_programname), d_dk(&B)
{
  ++s_count;
  d_doDNAME=::arg().mustDo("dname-processing");
  d_doExpandALIAS = ::arg().mustDo("expand-alias");
  d_logDNSDetails= ::arg().mustDo("log-dns-details");
  d_doIPv6AdditionalProcessing = ::arg().mustDo("do-ipv6-additional-processing");
  string fname= ::arg()["lua-prequery-script"];
  if(fname.empty())
  {
    d_pdl = NULL;
  }
  else
  {
    d_pdl = std::unique_ptr<AuthLua4>(new AuthLua4());
    d_pdl->loadFile(fname);
  }
  fname = ::arg()["lua-dnsupdate-policy-script"];
  if (fname.empty())
  {
    d_update_policy_lua = NULL;
  }
  else
  {
    d_update_policy_lua = std::unique_ptr<AuthLua4>(new AuthLua4());
    d_update_policy_lua->loadFile(fname);
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
 * @param sd         SOAData of the zone for which CDNSKEY records sets should be added
 * @return           bool that shows if any records were added
**/
bool PacketHandler::addCDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd)
{
  string publishCDNSKEY;
  d_dk.getFromMeta(p.qdomain, "PUBLISH-CDNSKEY", publishCDNSKEY);
  if (publishCDNSKEY != "1")
    return false;

  DNSZoneRecord rr;
  bool haveOne=false;

  DNSSECKeeper::keyset_t entryPoints = d_dk.getEntryPoints(p.qdomain);
  for(const auto& value: entryPoints) {
    rr.dr.d_type=QType::CDNSKEY;
    rr.dr.d_ttl=sd.default_ttl;
    rr.dr.d_name=p.qdomain;
    rr.dr.d_content=std::make_shared<DNSKEYRecordContent>(value.first.getDNSKEY());
    rr.auth=true;
    r->addRecord(rr);
    haveOne=true;
  }

  if(::arg().mustDo("direct-dnskey")) {
    B.lookup(QType(QType::CDNSKEY), p.qdomain, sd.domain_id, &p);

    while(B.get(rr)) {
      rr.dr.d_ttl=sd.default_ttl;
      r->addRecord(rr);
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
 * @param sd         SOAData of the zone for which DNSKEY records sets should be added
 * @return           bool that shows if any records were added
**/
bool PacketHandler::addDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd)
{
  DNSZoneRecord rr;
  bool haveOne=false;

  DNSSECKeeper::keyset_t keyset = d_dk.getKeys(p.qdomain);
  for(const auto& value: keyset) {
    rr.dr.d_type=QType::DNSKEY;
    rr.dr.d_ttl=sd.default_ttl;
    rr.dr.d_name=p.qdomain;
    rr.dr.d_content=std::make_shared<DNSKEYRecordContent>(value.first.getDNSKEY());
    rr.auth=true;
    r->addRecord(rr);
    haveOne=true;
  }

  if(::arg().mustDo("direct-dnskey")) {
    B.lookup(QType(QType::DNSKEY), p.qdomain, sd.domain_id, &p);

    while(B.get(rr)) {
      rr.dr.d_ttl=sd.default_ttl;
      r->addRecord(rr);
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
 * @param sd  SOAData of the zone for which CDS records sets should be added,
 *            used to determine record TTL.
 * @return    bool that shows if any records were added.
**/
bool PacketHandler::addCDS(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd)
{
  string publishCDS;
  d_dk.getFromMeta(p.qdomain, "PUBLISH-CDS", publishCDS);
  if (publishCDS.empty())
    return false;

  vector<string> digestAlgos;
  stringtok(digestAlgos, publishCDS, ", ");

  DNSZoneRecord rr;
  rr.dr.d_type=QType::CDS;
  rr.dr.d_ttl=sd.default_ttl;
  rr.dr.d_name=p.qdomain;
  rr.auth=true;

  bool haveOne=false;

  DNSSECKeeper::keyset_t keyset = d_dk.getEntryPoints(p.qdomain);

  for(auto const &value : keyset) {
    for(auto const &digestAlgo : digestAlgos){
      rr.dr.d_content=std::make_shared<DSRecordContent>(makeDSFromDNSKey(p.qdomain, value.first.getDNSKEY(), pdns_stou(digestAlgo)));
      r->addRecord(rr);
      haveOne=true;
    }
  }

  if(::arg().mustDo("direct-dnskey")) {
    B.lookup(QType(QType::CDS), p.qdomain, sd.domain_id, &p);

    while(B.get(rr)) {
      rr.dr.d_ttl=sd.default_ttl;
      r->addRecord(rr);
      haveOne=true;
    }
  }

  return haveOne;
}

/** This adds NSEC3PARAM records. Returns true if one was added */
bool PacketHandler::addNSEC3PARAM(const DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd)
{
  DNSZoneRecord rr;

  NSEC3PARAMRecordContent ns3prc;
  if(d_dk.getNSEC3PARAM(p.qdomain, &ns3prc)) {
    rr.dr.d_type=QType::NSEC3PARAM;
    rr.dr.d_ttl=sd.default_ttl;
    rr.dr.d_name=p.qdomain;
    ns3prc.d_flags = 0; // the NSEC3PARAM 'flag' is defined to always be zero in RFC5155.
    rr.dr.d_content=std::make_shared<NSEC3PARAMRecordContent>(ns3prc);
    rr.auth = true;
    r->addRecord(rr);
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
      if(mode.empty() || mode=="full")
        content=fullVersionString();
      else if(mode=="powerdns")
        content="Served by PowerDNS - https://www.powerdns.com/";
      else if(mode=="anonymous") {
        r->setRcode(RCode::ServFail);
        return 0;
      }
      else
        content=mode;
      rr.dr.d_content = DNSRecordContent::mastermake(QType::TXT, 1, "\""+content+"\"");
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
      rr.dr.d_content=DNSRecordContent::mastermake(QType::TXT, 1, tid);
    }
    else {
      r->setRcode(RCode::Refused);
      return 0;
    }

    rr.dr.d_ttl=5;
    rr.dr.d_name=target;
    rr.dr.d_type=QType::TXT;
    rr.dr.d_class=QClass::CHAOS;
    r->addRecord(rr);
    return 1;
  }

  r->setRcode(RCode::NotImp);
  return 0;
}

vector<DNSZoneRecord> PacketHandler::getBestReferralNS(DNSPacket& p, const SOAData& sd, const DNSName &target)
{
  vector<DNSZoneRecord> ret;
  DNSZoneRecord rr;
  DNSName subdomain(target);
  do {
    if(subdomain == sd.qname) // stop at SOA
      break;
    B.lookup(QType(QType::NS), subdomain, sd.domain_id, &p);
    while(B.get(rr)) {
      ret.push_back(rr); // this used to exclude auth NS records for some reason
    }
    if(!ret.empty())
      return ret;
  } while( subdomain.chopOff() );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return ret;
}

vector<DNSZoneRecord> PacketHandler::getBestDNAMESynth(DNSPacket& p, const SOAData& sd, DNSName &target)
{
  vector<DNSZoneRecord> ret;
  DNSZoneRecord rr;
  DNSName prefix;
  DNSName subdomain(target);
  do {
    DLOG(g_log<<"Attempting DNAME lookup for "<<subdomain<<", sd.qname="<<sd.qname<<endl);

    B.lookup(QType(QType::DNAME), subdomain, sd.domain_id, &p);
    while(B.get(rr)) {
      ret.push_back(rr);  // put in the original
      rr.dr.d_type = QType::CNAME;
      rr.dr.d_name = prefix + rr.dr.d_name;
      rr.dr.d_content = std::make_shared<CNAMERecordContent>(CNAMERecordContent(prefix + getRR<DNAMERecordContent>(rr.dr)->getTarget()));
      rr.auth = 0; // don't sign CNAME
      target= getRR<CNAMERecordContent>(rr.dr)->getTarget();
      ret.push_back(rr); 
    }
    if(!ret.empty())
      return ret;
    if(subdomain.countLabels())
      prefix.appendRawLabel(subdomain.getRawLabels()[0]); // XXX DNSName pain this feels wrong
    if(subdomain == sd.qname) // stop at SOA
      break;

  } while( subdomain.chopOff() );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return ret;
}


// Return best matching wildcard or next closer name
bool PacketHandler::getBestWildcard(DNSPacket& p, const SOAData& sd, const DNSName &target, DNSName &wildcard, vector<DNSZoneRecord>* ret)
{
  ret->clear();
  DNSZoneRecord rr;
  DNSName subdomain(target);
  bool haveSomething=false;

#ifdef HAVE_LUA_RECORDS
  bool doLua=g_doLuaRecord;
  if(!doLua) {
    string val;
    d_dk.getFromMeta(sd.qname, "ENABLE-LUA-RECORDS", val);
    doLua = (val=="1");
  }
#endif
  
  wildcard=subdomain;
  while( subdomain.chopOff() && !haveSomething )  {
    if (subdomain.empty()) {
      B.lookup(QType(QType::ANY), g_wildcarddnsname, sd.domain_id, &p);
    } else {
      B.lookup(QType(QType::ANY), g_wildcarddnsname+subdomain, sd.domain_id, &p);
    }
    while(B.get(rr)) {
#ifdef HAVE_LUA_RECORDS
      if(rr.dr.d_type == QType::LUA) {
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
          auto recvec=luaSynth(rec->getCode(), target, sd.qname, sd.domain_id, p, rec->d_type);
          for(const auto& r : recvec) {
            rr.dr.d_type = rec->d_type; // might be CNAME
            rr.dr.d_content = r;
            rr.scopeMask = p.getRealRemote().getBits(); // this makes sure answer is a specific as your question
            ret->push_back(rr);
          }
        }
      }
      else
#endif
      if(rr.dr.d_type == p.qtype.getCode() || rr.dr.d_type == QType::CNAME || (p.qtype.getCode() == QType::ANY && rr.dr.d_type != QType::RRSIG)) {
        ret->push_back(rr);
      }

      wildcard=g_wildcarddnsname+subdomain;
      haveSomething=true;
    }

    if ( subdomain == sd.qname || haveSomething ) // stop at SOA or result
      break;

    B.lookup(QType(QType::ANY), subdomain, sd.domain_id, &p);
    if (B.get(rr)) {
      DLOG(g_log<<"No wildcard match, ancestor exists"<<endl);
      while (B.get(rr)) ;
      break;
    }
    wildcard=subdomain;
  }

  return haveSomething;
}

/** dangling is declared true if we were unable to resolve everything */
int PacketHandler::doAdditionalProcessingAndDropAA(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& soadata, bool retargeted)
{
  DNSZoneRecord rr;
  SOAData sd;
  sd.db=0;

  if(p.qtype.getCode()!=QType::AXFR) { // this packet needs additional processing
    // we now have a copy, push_back on packet might reallocate!
    auto& records = r->getRRS();
    vector<DNSZoneRecord> toAdd;

    for(auto i = records.cbegin() ; i!= records.cend(); ++i) {
      if(i->dr.d_place==DNSResourceRecord::ADDITIONAL ||
         !(i->dr.d_type==QType::MX || i->dr.d_type==QType::NS || i->dr.d_type==QType::SRV))
        continue;

      if(r->d.aa && i->dr.d_name.countLabels() && i->dr.d_type==QType::NS && !B.getSOA(i->dr.d_name,sd) && !retargeted) { // drop AA in case of non-SOA-level NS answer, except for root referral
        r->setA(false);
        //        i->d_place=DNSResourceRecord::AUTHORITY; // XXX FIXME
      }

      DNSName lookup;

      if(i->dr.d_type == QType::MX)
        lookup = getRR<MXRecordContent>(i->dr)->d_mxname;
      else if(i->dr.d_type == QType::SRV)
        lookup = getRR<SRVRecordContent>(i->dr)->d_target;
      else if(i->dr.d_type == QType::NS) 
        lookup = getRR<NSRecordContent>(i->dr)->getNS();
      else
        continue;

      B.lookup(QType(d_doIPv6AdditionalProcessing ? QType::ANY : QType::A), lookup, soadata.domain_id, &p);

      while(B.get(rr)) {
        if(rr.dr.d_type != QType::A && rr.dr.d_type!=QType::AAAA)
          continue;
        if(!rr.dr.d_name.isPartOf(soadata.qname)) {
          // FIXME we might still pass on the record if it is occluded and the
          // backend uses a single id for all zones
          continue;
        }
        rr.dr.d_place=DNSResourceRecord::ADDITIONAL;
        toAdd.push_back(rr);
      }
    }
    for(const auto& rec : toAdd)
      r->addRecord(rec);
    
    //records.insert(records.end(), toAdd.cbegin(), toAdd.cend()); // would be faster, but no dedup
  }
  return 1;
}


void PacketHandler::emitNSEC(std::unique_ptr<DNSPacket>& r, const SOAData& sd, const DNSName& name, const DNSName& next, int mode)
{
  NSECRecordContent nrc;
  nrc.d_next = next;

  nrc.set(QType::NSEC);
  nrc.set(QType::RRSIG);
  if(sd.qname == name) {
    nrc.set(QType::SOA); // 1dfd8ad SOA can live outside the records table
    nrc.set(QType::DNSKEY);
    string publishCDNSKEY;
    d_dk.getFromMeta(name, "PUBLISH-CDNSKEY", publishCDNSKEY);
    if (publishCDNSKEY == "1")
      nrc.set(QType::CDNSKEY);
    string publishCDS;
    d_dk.getFromMeta(name, "PUBLISH-CDS", publishCDS);
    if (! publishCDS.empty())
      nrc.set(QType::CDS);
  }

  DNSZoneRecord rr;

  B.lookup(QType(QType::ANY), name, sd.domain_id);
  while(B.get(rr)) {
#ifdef HAVE_LUA_RECORDS   
    if(rr.dr.d_type == QType::LUA)
      nrc.set(getRR<LUARecordContent>(rr.dr)->d_type);
    else
#endif
      if(rr.dr.d_type == QType::NS || rr.auth)
      nrc.set(rr.dr.d_type);
  }

  rr.dr.d_name = name;
  rr.dr.d_ttl = sd.default_ttl;
  rr.dr.d_type = QType::NSEC;
  rr.dr.d_content = std::make_shared<NSECRecordContent>(std::move(nrc));
  rr.dr.d_place = (mode == 5 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;

  r->addRecord(rr);
}

void PacketHandler::emitNSEC3(std::unique_ptr<DNSPacket>& r, const SOAData& sd, const NSEC3PARAMRecordContent& ns3prc, const DNSName& name, const string& namehash, const string& nexthash, int mode)
{
  NSEC3RecordContent n3rc;
  n3rc.d_algorithm = ns3prc.d_algorithm;
  n3rc.d_flags = ns3prc.d_flags;
  n3rc.d_iterations = ns3prc.d_iterations;
  n3rc.d_salt = ns3prc.d_salt;
  n3rc.d_nexthash = nexthash;

  DNSZoneRecord rr;

  if(!name.empty()) {
    if (sd.qname == name) {
      n3rc.set(QType::SOA); // 1dfd8ad SOA can live outside the records table
      n3rc.set(QType::NSEC3PARAM);
      n3rc.set(QType::DNSKEY);
      string publishCDNSKEY;
      d_dk.getFromMeta(name, "PUBLISH-CDNSKEY", publishCDNSKEY);
      if (publishCDNSKEY == "1")
        n3rc.set(QType::CDNSKEY);
      string publishCDS;
      d_dk.getFromMeta(name, "PUBLISH-CDS", publishCDS);
      if (! publishCDS.empty())
        n3rc.set(QType::CDS);
    }

    B.lookup(QType(QType::ANY), name, sd.domain_id);
    while(B.get(rr)) {
#ifdef HAVE_LUA_RECORDS
      if(rr.dr.d_type == QType::LUA)
        n3rc.set(getRR<LUARecordContent>(rr.dr)->d_type);
      else
#endif
        if(rr.dr.d_type && (rr.dr.d_type == QType::NS || rr.auth)) // skip empty non-terminals
        n3rc.set(rr.dr.d_type);
    }
  }

  const auto numberOfTypesSet = n3rc.numberOfTypesSet();
  if (numberOfTypesSet != 0 && !(numberOfTypesSet == 1 && n3rc.isSet(QType::NS))) {
    n3rc.set(QType::RRSIG);
  }

  rr.dr.d_name = DNSName(toBase32Hex(namehash))+sd.qname;
  rr.dr.d_ttl = sd.default_ttl;
  rr.dr.d_type=QType::NSEC3;
  rr.dr.d_content=std::make_shared<NSEC3RecordContent>(std::move(n3rc));
  rr.dr.d_place = (mode == 5 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;

  r->addRecord(rr);
}

/*
   mode 0 = No Data Responses, QTYPE is not DS
   mode 1 = No Data Responses, QTYPE is DS
   mode 2 = Wildcard No Data Responses
   mode 3 = Wildcard Answer Responses
   mode 4 = Name Error Responses
   mode 5 = Direct NSEC request
*/
void PacketHandler::addNSECX(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, const DNSName& auth, int mode)
{
  NSEC3PARAMRecordContent ns3rc;
  bool narrow;
  if(d_dk.getNSEC3PARAM(auth, &ns3rc, &narrow))  {
    if (mode != 5) // no direct NSEC3 queries, rfc5155 7.2.8
      addNSEC3(p, r, target, wildcard, auth, ns3rc, narrow, mode);
  }
  else {
    addNSEC(p, r, target, wildcard, auth, mode);
  }
}

static bool getNSEC3Hashes(bool narrow, DNSBackend* db, int id, const std::string& hashed, bool decrement, DNSName& unhashed, std::string& before, std::string& after, int mode=0)
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
    ret=db->getBeforeAndAfterNamesAbsolute(id, hashedName, unhashed, beforeName, afterName);
    before=fromBase32Hex(beforeName.toString());
    after=fromBase32Hex(afterName.toString());
  }
  return ret;
}

void PacketHandler::addNSEC3(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, const DNSName& auth, const NSEC3PARAMRecordContent& ns3rc, bool narrow, int mode)
{
  DLOG(g_log<<"addNSEC3() mode="<<mode<<" auth="<<auth<<" target="<<target<<" wildcard="<<wildcard<<endl);

  SOAData sd;
  if(!B.getSOAUncached(auth, sd)) {
    DLOG(g_log<<"Could not get SOA for domain");
    return;
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

    getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, false, unhashed, before, after, mode);

    if (((mode == 0 && ns3rc.d_flags) ||  mode == 1) && (hashed != before)) {
      DLOG(g_log<<"No matching NSEC3, do closest (provable) encloser"<<endl);

      bool doBreak = false;
      DNSZoneRecord rr;
      while( closest.chopOff() && (closest != sd.qname))  { // stop at SOA
        B.lookup(QType(QType::ANY), closest, sd.domain_id, &p);
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

      getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, false, unhashed, before, after);
    }

    if (!after.empty()) {
      DLOG(g_log<<"Done calling for matching, hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
      emitNSEC3(r, sd, ns3rc, unhashed, before, after, mode);
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

    getNSEC3Hashes(narrow, sd.db,sd.domain_id,  hashed, true, unhashed, before, after);
    DLOG(g_log<<"Done calling for covering, hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
    emitNSEC3( r, sd, ns3rc, unhashed, before, after, mode);
  }

  // wildcard denial
  if (mode == 2 || mode == 4) {
    unhashed=g_wildcarddnsname+closest;

    hashed=hashQNameWithSalt(ns3rc, unhashed);
    DLOG(g_log<<"3 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);

    getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, (mode != 2), unhashed, before, after);
    DLOG(g_log<<"Done calling for '*', hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
    emitNSEC3( r, sd, ns3rc, unhashed, before, after, mode);
  }
}

void PacketHandler::addNSEC(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, const DNSName& auth, int mode)
{
  DLOG(g_log<<"addNSEC() mode="<<mode<<" auth="<<auth<<" target="<<target<<" wildcard="<<wildcard<<endl);

  SOAData sd;
  if(!B.getSOAUncached(auth, sd)) {
    DLOG(g_log<<"Could not get SOA for domain"<<endl);
    return;
  }

  DNSName before,after;
  sd.db->getBeforeAndAfterNames(sd.domain_id, auth, target, before, after);
  if (mode != 5 || before == target)
    emitNSEC(r, sd, before, after, mode);

  if (mode == 2 || mode == 4) {
    // wildcard NO-DATA or wildcard denial
    before.clear();
    DNSName closest(wildcard);
    if (mode == 4) {
      closest.chopOff();
      closest.prependRawLabel("*");
    }
    sd.db->getBeforeAndAfterNames(sd.domain_id, auth, closest, before, after);
    emitNSEC(r, sd, before, after, mode);
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

int PacketHandler::trySuperMaster(const DNSPacket& p, const DNSName& tsigkeyname)
{
  if(p.d_tcp)
  {
    // do it right now if the client is TCP
    // rarely happens
    return trySuperMasterSynchronous(p, tsigkeyname);
  }
  else
  {
    // queue it if the client is on UDP
    Communicator.addTrySuperMasterRequest(p);
    return 0;
  }
}

int PacketHandler::trySuperMasterSynchronous(const DNSPacket& p, const DNSName& tsigkeyname)
{
  ComboAddress remote = p.getRemote().setPort(53);
  if(p.hasEDNSSubnet() && ::arg().contains("trusted-notification-proxy", remote.toString())) {
    remote = p.getRealRemote().getNetwork();
  }

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
    g_log<<Logger::Error<<"While checking for supermaster, did not find NS for "<<p.qdomain<<" at: "<< remote <<endl;
    return RCode::ServFail;
  }

  string nameserver, account;
  DNSBackend *db;

  if (!::arg().mustDo("allow-unsigned-supermaster") && tsigkeyname.empty()) {
    g_log<<Logger::Error<<"Received unsigned NOTIFY for "<<p.qdomain<<" from potential supermaster "<<remote<<". Refusing."<<endl;
    return RCode::Refused;
  }

  if(!B.superMasterBackend(remote.toString(), p.qdomain, nsset, &nameserver, &account, &db)) {
    g_log<<Logger::Error<<"Unable to find backend willing to host "<<p.qdomain<<" for potential supermaster "<<remote<<". Remote nameservers: "<<endl;
    for(const auto& rr: nsset) {
      if(rr.qtype==QType::NS)
        g_log<<Logger::Error<<rr.content<<endl;
    }
    return RCode::Refused;
  }
  try {
    db->createSlaveDomain(p.getRemote().toString(), p.qdomain, nameserver, account);
    if (tsigkeyname.empty() == false) {
      vector<string> meta;
      meta.push_back(tsigkeyname.toStringNoDot());
      db->setDomainMetadata(p.qdomain, "AXFR-MASTER-TSIG", meta);
    }
  }
  catch(PDNSException& ae) {
    g_log<<Logger::Error<<"Database error trying to create "<<p.qdomain<<" for potential supermaster "<<remote<<": "<<ae.reason<<endl;
    return RCode::ServFail;
  }
  g_log<<Logger::Warning<<"Created new slave zone '"<<p.qdomain<<"' from supermaster "<<remote<<endl;
  return RCode::NoError;
}

int PacketHandler::processNotify(const DNSPacket& p)
{
  /* now what? 
     was this notification from an approved address?
     was this notification approved by TSIG?
     We determine our internal SOA id (via UeberBackend)
     We determine the SOA at our (known) master
     if master is higher -> do stuff
  */

  g_log<<Logger::Debug<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<endl;

  if(!::arg().mustDo("slave") && s_forwardNotify.empty()) {
    g_log<<Logger::Warning<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<" but slave support is disabled in the configuration"<<endl;
    return RCode::Refused;
  }

  // Sender verification
  //
  if(!s_allowNotifyFrom.match((ComboAddress *) &p.d_remote ) || p.d_havetsig) {
    if (p.d_havetsig && p.getTSIGKeyname().empty() == false) {
        g_log<<Logger::Notice<<"Received secure NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<", with TSIG key '"<<p.getTSIGKeyname()<<"'"<<endl;
    } else {
      g_log<<Logger::Warning<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<" but the remote is not providing a TSIG key or in allow-notify-from (Refused)"<<endl;
      return RCode::Refused;
    }
  }

  if ((!::arg().mustDo("allow-unsigned-notify") && !p.d_havetsig) || p.d_havetsig) {
    if (!p.d_havetsig) {
      g_log<<Logger::Warning<<"Received unsigned NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<" while a TSIG key was required (Refused)"<<endl;
      return RCode::Refused;
    }
    vector<string> meta;
    if (B.getDomainMetadata(p.qdomain,"AXFR-MASTER-TSIG",meta) && meta.size() > 0) {
      DNSName expected{meta[0]};
      if (p.getTSIGKeyname() != expected) {
        g_log<<Logger::Warning<<"Received secure NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<": expected TSIG key '"<<expected<<"', got '"<<p.getTSIGKeyname()<<"' (Refused)"<<endl;
        return RCode::Refused;
      }
    }
  }

  // Domain verification
  //
  DomainInfo di;
  if(!B.getDomainInfo(p.qdomain, di, false) || !di.backend) {
    if(::arg().mustDo("superslave")) {
      g_log<<Logger::Warning<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<" for which we are not authoritative, trying supermaster"<<endl;
      return trySuperMaster(p, p.getTSIGKeyname());
    }
    g_log<<Logger::Notice<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<" for which we are not authoritative (Refused)"<<endl;
    return RCode::Refused;
  }

  if(::arg().contains("trusted-notification-proxy", p.getRemote().toString())) {
    g_log<<Logger::Error<<"Received NOTIFY for "<<p.qdomain<<" from trusted-notification-proxy "<< p.getRemote()<<endl;
    if(di.masters.empty()) {
      g_log<<Logger::Error<<"However, "<<p.qdomain<<" does not have any masters defined (Refused)"<<endl;
      return RCode::Refused;
    }
  }
  else if(::arg().mustDo("master") && di.kind == DomainInfo::Master) {
    g_log<<Logger::Warning<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<" but we are master (Refused)"<<endl;
    return RCode::Refused;
  }
  else if(!di.isMaster(p.getRemote())) {
    g_log<<Logger::Warning<<"Received NOTIFY for "<<p.qdomain<<" from "<<p.getRemote()<<" which is not a master (Refused)"<<endl;
    return RCode::Refused;
  }

  if(!s_forwardNotify.empty()) {
    set<string> forwardNotify(s_forwardNotify);
    for(set<string>::const_iterator j=forwardNotify.begin();j!=forwardNotify.end();++j) {
      g_log<<Logger::Notice<<"Relaying notification of domain "<<p.qdomain<<" from "<<p.getRemote()<<" to "<<*j<<endl;
      Communicator.notify(p.qdomain,*j);
    }
  }

  if(::arg().mustDo("slave")) {
    g_log<<Logger::Debug<<"Queueing slave check for "<<p.qdomain<<endl;
    Communicator.addSlaveCheckRequest(di, p.d_remote);
  }
  return 0;
}

static bool validDNSName(const DNSName &name)
{
  if (!g_8bitDNS) {
    string::size_type pos, length;
    char c;
    for(const auto& s : name.getRawLabels()) {
      length=s.length();
      for(pos=0; pos < length; ++pos) {
        c=s[pos];
        if(!((c >= 'a' && c <= 'z') ||
             (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9') ||
             c =='-' || c == '_' || c=='*' || c=='.' || c=='/' || c=='@' || c==' ' || c=='\\' || c==':'))
          return false;
      }
    }
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


void PacketHandler::makeNXDomain(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, const SOAData& sd)
{
  DNSZoneRecord rr;
  rr=makeEditedDNSZRFromSOAData(d_dk, sd, DNSResourceRecord::AUTHORITY);
  rr.dr.d_ttl=min(sd.ttl, sd.default_ttl);
  r->addRecord(rr);

  if(d_dnssec) {
    addNSECX(p, r, target, wildcard, sd.qname, 4);
  }

  r->setRcode(RCode::NXDomain);
}

void PacketHandler::makeNOError(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, const SOAData& sd, int mode)
{
  DNSZoneRecord rr;
  rr=makeEditedDNSZRFromSOAData(d_dk, sd, DNSResourceRecord::AUTHORITY);
  rr.dr.d_ttl=min(sd.ttl, sd.default_ttl);
  r->addRecord(rr);

  if(d_dnssec) {
    addNSECX(p, r, target, wildcard, sd.qname, mode);
  }

  S.ringAccount("noerror-queries", p.qdomain, p.qtype);
}


bool PacketHandler::addDSforNS(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, const DNSName& dsname)
{
  //cerr<<"Trying to find a DS for '"<<dsname<<"', domain_id = "<<sd.domain_id<<endl;
  B.lookup(QType(QType::DS), dsname, sd.domain_id, &p);
  DNSZoneRecord rr;
  bool gotOne=false;
  while(B.get(rr)) {
    gotOne=true;
    rr.dr.d_place = DNSResourceRecord::AUTHORITY;
    r->addRecord(rr);
  }
  return gotOne;
}

bool PacketHandler::tryReferral(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, const DNSName &target, bool retargeted)
{
  vector<DNSZoneRecord> rrset = getBestReferralNS(p, sd, target);
  if(rrset.empty())
    return false;
  
  for(auto& rr: rrset) {
    rr.dr.d_place=DNSResourceRecord::AUTHORITY;
    r->addRecord(rr);
  }
  if(!retargeted)
    r->setA(false);

  if(d_dk.isSecuredZone(sd.qname) && !addDSforNS(p, r, sd, rrset.begin()->dr.d_name) && d_dnssec) {
    addNSECX(p, r, rrset.begin()->dr.d_name, DNSName(), sd.qname, 1);
  }

  return true;
}

void PacketHandler::completeANYRecords(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, const DNSName &target)
{
  addNSECX(p, r, target, DNSName(), sd.qname, 5);
  if(sd.qname == p.qdomain) {
    addDNSKEY(p, r, sd);
    addCDNSKEY(p, r, sd);
    addCDS(p, r, sd);
    addNSEC3PARAM(p, r, sd);
  }
}

bool PacketHandler::tryDNAME(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, DNSName &target)
{
  if(!d_doDNAME)
    return false;
  DLOG(g_log<<Logger::Warning<<"Let's try DNAME.."<<endl);
  vector<DNSZoneRecord> rrset = getBestDNAMESynth(p, sd, target);
  if(!rrset.empty()) {
    for(auto& rr: rrset) {
      rr.dr.d_place = DNSResourceRecord::ANSWER;
      r->addRecord(rr);
    }
    return true;
  }
  return false;
}
bool PacketHandler::tryWildcard(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, DNSName &target, DNSName &wildcard, bool& retargeted, bool& nodata)
{
  retargeted = nodata = false;
  DNSName bestmatch;

  vector<DNSZoneRecord> rrset;
  if(!getBestWildcard(p, sd, target, wildcard, &rrset))
    return false;

  if(rrset.empty()) {
    DLOG(g_log<<"Wildcard matched something, but not of the correct type"<<endl);
    nodata=true;
  }
  else {
    for(auto& rr: rrset) {
      rr.wildcardname = rr.dr.d_name;
      rr.dr.d_name=bestmatch=target;

      if(rr.dr.d_type == QType::CNAME)  {
        retargeted=true;
        target=getRR<CNAMERecordContent>(rr.dr)->getTarget();
      }
  
      rr.dr.d_place=DNSResourceRecord::ANSWER;
      r->addRecord(rr);
    }
  }
  if(d_dnssec && !nodata) {
    addNSECX(p, r, bestmatch, wildcard, sd.qname, 3);
  }

  return true;
}

//! Called by the Distributor to ask a question. Returns 0 in case of an error
std::unique_ptr<DNSPacket> PacketHandler::doQuestion(DNSPacket& p)
{
  DNSZoneRecord rr;
  SOAData sd;

  int retargetcount=0;
  set<DNSName> authSet;

  vector<DNSZoneRecord> rrset;
  bool weDone=0, weRedirected=0, weHaveUnauth=0, doSigs=0;
  DNSName haveAlias;
  uint8_t aliasScopeMask;

  std::unique_ptr<DNSPacket> r{nullptr};
  bool noCache=false;

#ifdef HAVE_LUA_RECORDS
  bool doLua=g_doLuaRecord;
#endif
  
  if(p.d.qr) { // QR bit from dns packet (thanks RA from N)
    if(d_logDNSDetails)
      g_log<<Logger::Error<<"Received an answer (non-query) packet from "<<p.getRemote()<<", dropping"<<endl;
    S.inc("corrupt-packets");
    S.ringAccount("remotes-corrupt", p.d_remote);
    return 0;
  }

  if(p.d.tc) { // truncated query. MOADNSParser would silently parse this packet in an incomplete way.
    if(d_logDNSDetails)
      g_log<<Logger::Error<<"Received truncated query packet from "<<p.getRemote()<<", dropping"<<endl;
    S.inc("corrupt-packets");
    S.ringAccount("remotes-corrupt", p.d_remote);
    return 0;
  }

  if (p.hasEDNS() && p.getEDNSVersion() > 0) {
    r = p.replyPacket();

    // PacketWriter::addOpt will take care of setting this correctly in the packet
    r->setEDNSRcode(ERCode::BADVERS);
    return r;
  }

  if(p.d_havetsig) {
    DNSName keyname;
    string secret;
    TSIGRecordContent trc;
    if(!p.checkForCorrectTSIG(&B, &keyname, &secret, &trc)) {
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
      if (p.d_tsig_algo == TSIG_GSS) {
        GssContext gssctx(keyname);
        if (!gssctx.getPeerPrincipal(p.d_peer_principal)) {
          g_log<<Logger::Warning<<"Failed to extract peer principal from GSS context with keyname '"<<keyname<<"'"<<endl;
        }
      }
    }
    p.setTSIGDetails(trc, keyname, secret, trc.d_mac); // this will get copied by replyPacket()
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
        g_log<<Logger::Error<<"Received a malformed qdomain from "<<p.getRemote()<<", '"<<p.qdomain<<"': sending servfail"<<endl;
      S.inc("corrupt-packets");
      S.ringAccount("remotes-corrupt", p.d_remote);
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
        return 0;
      }
      
      g_log<<Logger::Error<<"Received an unknown opcode "<<p.d.opcode<<" from "<<p.getRemote()<<" for "<<p.qdomain<<endl;

      r->setRcode(RCode::NotImp); 
      return r; 
    }

    // g_log<<Logger::Warning<<"Query for '"<<p.qdomain<<"' "<<p.qtype.getName()<<" from "<<p.getRemote()<< " (tcp="<<p.d_tcp<<")"<<endl;
    
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
    
    if(!B.getAuth(target, p.qtype, &sd)) {
      DLOG(g_log<<Logger::Error<<"We have no authority over zone '"<<target<<"'"<<endl);
      if(!retargetcount) {
        r->setA(false); // drop AA if we never had a SOA in the first place
        r->setRcode(RCode::Refused); // send REFUSED - but only on empty 'no idea'
      }
      goto sendit;
    }
    DLOG(g_log<<Logger::Error<<"We have authority, zone='"<<sd.qname<<"', id="<<sd.domain_id<<endl);

    authSet.insert(sd.qname);
    d_dnssec=(p.d_dnssecOk && d_dk.isSecuredZone(sd.qname));
    doSigs |= d_dnssec;

    if(!retargetcount) r->qdomainzone=sd.qname;

    if(sd.qname==p.qdomain) {
      if(p.qtype.getCode() == QType::DNSKEY)
      {
        if(addDNSKEY(p, r, sd))
          goto sendit;
      }
      else if(p.qtype.getCode() == QType::CDNSKEY)
      {
        if(addCDNSKEY(p,r, sd))
          goto sendit;
      }
      else if(p.qtype.getCode() == QType::CDS)
      {
        if(addCDS(p,r, sd))
          goto sendit;
      }
      else if(d_dnssec && p.qtype.getCode() == QType::NSEC3PARAM)
      {
        if(addNSEC3PARAM(p,r, sd))
          goto sendit;
      }
    }

    if(p.qtype.getCode() == QType::SOA && sd.qname==p.qdomain) {
      rr=makeEditedDNSZRFromSOAData(d_dk, sd);
      r->addRecord(rr);
      goto sendit;
    }

    // this TRUMPS a cname!
    if(d_dnssec && p.qtype.getCode() == QType::NSEC && !d_dk.getNSEC3PARAM(sd.qname, 0)) {
      addNSEC(p, r, target, DNSName(), sd.qname, 5);
      if (!r->isEmpty())
        goto sendit;
    }

    // this TRUMPS a cname!
    if(p.qtype.getCode() == QType::RRSIG) {
      g_log<<Logger::Info<<"Direct RRSIG query for "<<target<<" from "<<p.getRemote()<<endl;
      r->setRcode(RCode::Refused);
      goto sendit;
    }

    DLOG(g_log<<"Checking for referrals first, unless this is a DS query"<<endl);
    if(p.qtype.getCode() != QType::DS && tryReferral(p, r, sd, target, retargetcount))
      goto sendit;

    DLOG(g_log<<"Got no referrals, trying ANY"<<endl);

#ifdef HAVE_LUA_RECORDS
    if(!doLua) {
      string val;
      d_dk.getFromMeta(sd.qname, "ENABLE-LUA-RECORDS", val);
      doLua = (val=="1");
    }
#endif

    // see what we get..
    B.lookup(QType(QType::ANY), target, sd.domain_id, &p);
    rrset.clear();
    haveAlias.trimToLabels(0);
    aliasScopeMask = 0;
    weDone = weRedirected = weHaveUnauth =  false;
    
    while(B.get(rr)) {
#ifdef HAVE_LUA_RECORDS
      if(rr.dr.d_type == QType::LUA) {
        if(!doLua)
          continue;
        auto rec=getRR<LUARecordContent>(rr.dr);
        if (!rec) {
          continue;
        }
        if(rec->d_type == QType::CNAME || rec->d_type == p.qtype.getCode() || (p.qtype.getCode() == QType::ANY && rec->d_type != QType::RRSIG)) {
          noCache=true;
          try {
            auto recvec=luaSynth(rec->getCode(), target, sd.qname, sd.domain_id, p, rec->d_type);
            if(!recvec.empty()) {
              for(const auto& r_it : recvec) {
                rr.dr.d_type = rec->d_type; // might be CNAME
                rr.dr.d_content = r_it;
                rr.scopeMask = p.getRealRemote().getBits(); // this makes sure answer is a specific as your question
                rrset.push_back(rr);
              }
              if(rec->d_type == QType::CNAME && p.qtype.getCode() != QType::CNAME)
                weRedirected = 1;
              else
                weDone = 1;
            }
          }
          catch(std::exception &e) {
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

      // cerr<<"Auth: "<<rr.auth<<", "<<(rr.dr.d_type == p.qtype)<<", "<<rr.dr.d_type.getName()<<endl;
      if((p.qtype.getCode() == QType::ANY || rr.dr.d_type == p.qtype.getCode()) && rr.auth) 
        weDone=1;
      // the line below fakes 'unauth NS' for delegations for non-DNSSEC backends.
      if((rr.dr.d_type == p.qtype.getCode() && !rr.auth) || (rr.dr.d_type == QType::NS && (!rr.auth || !(sd.qname==rr.dr.d_name))))
        weHaveUnauth=1;

      if(rr.dr.d_type == QType::CNAME && p.qtype.getCode() != QType::CNAME) 
        weRedirected=1;

      if(DP && rr.dr.d_type == QType::ALIAS && (p.qtype.getCode() == QType::A || p.qtype.getCode() == QType::AAAA || p.qtype.getCode() == QType::ANY)) {
        if (!d_doExpandALIAS) {
          g_log<<Logger::Info<<"ALIAS record found for "<<target<<", but ALIAS expansion is disabled."<<endl;
          continue;
        }
        haveAlias=getRR<ALIASRecordContent>(rr.dr)->d_content;
        aliasScopeMask=rr.scopeMask;
      }

      // Filter out all SOA's and add them in later
      if(rr.dr.d_type == QType::SOA)
        continue;

      rrset.push_back(rr);
    }

    /* Add in SOA if required */
    if(target==sd.qname) {
        rr=makeEditedDNSZRFromSOAData(d_dk, sd);
        rrset.push_back(rr);
    }


    DLOG(g_log<<"After first ANY query for '"<<target<<"', id="<<sd.domain_id<<": weDone="<<weDone<<", weHaveUnauth="<<weHaveUnauth<<", weRedirected="<<weRedirected<<", haveAlias='"<<haveAlias<<"'"<<endl);
    if(p.qtype.getCode() == QType::DS && weHaveUnauth &&  !weDone && !weRedirected) {
      DLOG(g_log<<"Q for DS of a name for which we do have NS, but for which we don't have DS; need to provide an AUTH answer that shows we don't"<<endl);
      makeNOError(p, r, target, DNSName(), sd, 1);
      goto sendit;
    }

    if(!haveAlias.empty() && (!weDone || p.qtype.getCode() == QType::ANY)) {
      DLOG(g_log<<Logger::Warning<<"Found nothing that matched for '"<<target<<"', but did get alias to '"<<haveAlias<<"', referring"<<endl);
      DP->completePacket(r, haveAlias, target, aliasScopeMask);
      return 0;
    }


    // referral for DS query
    if(p.qtype.getCode() == QType::DS) {
      DLOG(g_log<<"Qtype is DS"<<endl);
      bool doReferral = true;
      if(d_dk.doesDNSSEC()) {
        for(auto& loopRR: rrset) {
          // In a dnssec capable backend auth=true means, there is no delagation at
          // or above this qname in this zone (for DS queries). Without a delegation,
          // at or above this level, it is pointless to search for refferals.
          if(loopRR.auth) {
            doReferral = false;
            break;
          }
        }
      } else {
        for(auto& loopRR: rrset) {
          // In a non dnssec capable backend auth is always true, so our only option
          // is, always look for referals. Unless there is a direct match for DS.
          if(loopRR.dr.d_type == QType::DS) {
            doReferral = false;
            break;
          }
        }
      }
      if(doReferral) {
        DLOG(g_log<<"DS query found no direct result, trying referral now"<<endl);
        if(tryReferral(p, r, sd, target, retargetcount))
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
      if(tryWildcard(p, r, sd, target, wildcard, wereRetargeted, nodata)) {
        if(wereRetargeted) {
          if(!retargetcount) r->qdomainwild=wildcard;
          retargetcount++;
          goto retargeted;
        }
        if(nodata) 
          makeNOError(p, r, target, wildcard, sd, 2);

        goto sendit;
      }
      else if(tryDNAME(p, r, sd, target)) {
	retargetcount++;
	goto retargeted;
      }
      else
      {        
        if (!(((p.qtype.getCode() == QType::CNAME) || (p.qtype.getCode() == QType::ANY)) && retargetcount > 0))
          makeNXDomain(p, r, target, wildcard, sd);
      }
      
      goto sendit;
    }
                                       
    if(weRedirected) {
      for(auto& loopRR: rrset) {
        if(loopRR.dr.d_type == QType::CNAME) {
          r->addRecord(loopRR);
          target = getRR<CNAMERecordContent>(loopRR.dr)->getTarget();
          retargetcount++;
          goto retargeted;
        }
      }
    }
    else if(weDone) {
      bool haveRecords = false;
      for(const auto& loopRR: rrset) {
#ifdef HAVE_LUA_RECORDS
        if(loopRR.dr.d_type == QType::LUA)
            continue;
#endif
        if((p.qtype.getCode() == QType::ANY || loopRR.dr.d_type == p.qtype.getCode()) && loopRR.dr.d_type && loopRR.dr.d_type != QType::ALIAS && loopRR.auth) {
          r->addRecord(loopRR);
          haveRecords = true;
        }
      }

      if (haveRecords) {
        if(d_dnssec && p.qtype.getCode() == QType::ANY)
          completeANYRecords(p, r, sd, target);
      }
      else
        makeNOError(p, r, target, DNSName(), sd, 0);

      goto sendit;
    }
    else if(weHaveUnauth) {
      DLOG(g_log<<"Have unauth data, so need to hunt for best NS records"<<endl);
      if(tryReferral(p, r, sd, target, retargetcount))
        goto sendit;
      // check whether this could be fixed easily
      // if (*(rr.dr.d_name.rbegin()) == '.') {
      //      g_log<<Logger::Error<<"Should not get here ("<<p.qdomain<<"|"<<p.qtype.getCode()<<"): you have a trailing dot, this could be the problem (or run pdnsutil rectify-zone " <<sd.qname<<")"<<endl;
      // } else {
           g_log<<Logger::Error<<"Should not get here ("<<p.qdomain<<"|"<<p.qtype.getCode()<<"): please run pdnsutil rectify-zone "<<sd.qname<<endl;
      // }
    }
    else {
      DLOG(g_log<<"Have some data, but not the right data"<<endl);
      makeNOError(p, r, target, DNSName(), sd, 0);
    }
    
  sendit:;
    if(doAdditionalProcessingAndDropAA(p, r, sd, retargetcount)<0) {
      return 0;
    }

    for(const auto& loopRR: r->getRRS()) {
      if(loopRR.scopeMask) {
        noCache=true;
        break;
      }
    }
    if(doSigs)
      addRRSigs(d_dk, B, authSet, r->getRRS());
      
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
    g_log<<Logger::Error<<"Exception building answer packet for "<<p.qdomain<<"/"<<p.qtype.getName()<<" ("<<e.what()<<") sending out servfail"<<endl;
    r=p.replyPacket(); // generate an empty reply packet
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries", p.qdomain, p.qtype);
  }
  return r; 

}
