/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation;

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "packetcache.hh"
#include "utility.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "base32.hh"
#include <errno.h>
#include "communicator.hh"
#include <set>
#include <boost/utility.hpp>
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "packethandler.hh"
#include "resolver.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include "packetcache.hh"

#include "base64.hh"
#include "inflighter.cc"
#include "lua-auth.hh"
#include "namespaces.hh"
#include "common_startup.hh"
#include <boost/scoped_ptr.hpp>
using boost::scoped_ptr;


void CommunicatorClass::addSuckRequest(const DNSName &domain, const string &master)
{
  Lock l(&d_lock);
  SuckRequest sr;
  sr.domain = domain;
  sr.master = master;
  pair<UniQueue::iterator, bool>  res;

  res=d_suckdomains.push_back(sr);

  if(res.second) {
    d_suck_sem.post();
  }
}

void CommunicatorClass::suck(const DNSName &domain,const string &remote)
{
  L<<Logger::Error<<"Initiating transfer of '"<<domain<<"' from remote '"<<remote<<"'"<<endl;
  UeberBackend B; // fresh UeberBackend

  DomainInfo di;
  di.backend=0;
  bool transaction=false;
  try {
    DNSSECKeeper dk (&B); // reuse our UeberBackend copy for DNSSECKeeper

    if(!B.getDomainInfo(domain, di) || !di.backend) { // di.backend and B are mostly identical
      L<<Logger::Error<<"Can't determine backend for domain '"<<domain<<"'"<<endl;
      return;
    }
    uint32_t domain_id=di.id;

    TSIGTriplet tt;
    if(dk.getTSIGForAccess(domain, remote, &tt.name)) {
      string tsigsecret64;
      if(B.getTSIGKey(tt.name, &tt.algo, &tsigsecret64)) {
        if(B64Decode(tsigsecret64, tt.secret)) {
          L<<Logger::Error<<"Unable to Base-64 decode TSIG key '"<<tt.name<<"' for domain '"<<domain<<"' not found"<<endl;
          return;
        }
      } else {
        L<<Logger::Error<<"TSIG key '"<<tt.name<<"' for domain '"<<domain<<"' not found"<<endl;
        return;
      }
    }


    scoped_ptr<AuthLua> pdl;
    vector<string> scripts;
    if(B.getDomainMetadata(domain, "LUA-AXFR-SCRIPT", scripts) && !scripts.empty()) {
      try {
        pdl.reset(new AuthLua(scripts[0]));
        L<<Logger::Info<<"Loaded Lua script '"<<scripts[0]<<"' to edit the incoming AXFR of '"<<domain<<"'"<<endl;
      }
      catch(std::exception& e) {
        L<<Logger::Error<<"Failed to load Lua editing script '"<<scripts[0]<<"' for incoming AXFR of '"<<domain<<"': "<<e.what()<<endl;
        return;
      }
    }

    vector<string> localaddr;
    ComboAddress laddr;
    if(B.getDomainMetadata(domain, "AXFR-SOURCE", localaddr) && !localaddr.empty()) {
      try {
        laddr = ComboAddress(localaddr[0]);
        L<<Logger::Info<<"AXFR source for domain '"<<domain<<"' set to "<<localaddr[0]<<endl;
      }
      catch(std::exception& e) {
        L<<Logger::Error<<"Failed to load AXFR source '"<<localaddr[0]<<"' for incoming AXFR of '"<<domain<<"': "<<e.what()<<endl;
        return;
      }
    } else {
      laddr.sin4.sin_family = 0;
    }

    bool hadDnssecZone = false;
    bool hadPresigned = false;
    bool hadNSEC3 = false;
    NSEC3PARAMRecordContent ns3pr, hadNs3pr;
    bool isNarrow, hadNarrow=false;

    if(dk.isSecuredZone(domain)) {
      hadDnssecZone=true;
      hadPresigned=dk.isPresigned(domain);
      if (dk.getNSEC3PARAM(domain, &ns3pr, &isNarrow)) {
        hadNSEC3 = true;
        hadNs3pr = ns3pr;
        hadNarrow = isNarrow;
      }
    }

    bool isDnssecZone = false;
    bool isPresigned = false;
    bool isNSEC3 = false;
    bool optOutFlag = false;

    bool first=true;
    bool firstNSEC3=true;
    unsigned int soa_serial = 0;
    set<DNSName> nsset, qnames, secured;
    vector<DNSResourceRecord> rrs;

    ComboAddress raddr(remote, 53);
    AXFRRetriever retriever(raddr, domain, tt, (laddr.sin4.sin_family == 0) ? NULL : &laddr);
    Resolver::res_t recs;
    while(retriever.getChunk(recs)) {
      if(first) {
        L<<Logger::Error<<"AXFR started for '"<<domain<<"'"<<endl;
        first=false;
      }

      for(Resolver::res_t::iterator i=recs.begin();i!=recs.end();++i) {
        if(i->qtype.getCode() == QType::OPT || i->qtype.getCode() == QType::TSIG) // ignore EDNS0 & TSIG
          continue;

        if(!i->qname.isPartOf(domain)) {
          L<<Logger::Error<<"Remote "<<remote<<" tried to sneak in out-of-zone data '"<<i->qname<<"'|"<<i->qtype.getName()<<" during AXFR of zone '"<<domain<<"', ignoring"<<endl;
          continue;
        }

        vector<DNSResourceRecord> out;
        if(!pdl || !pdl->axfrfilter(raddr, domain, *i, out)) {
          out.push_back(*i);
        }

        for(DNSResourceRecord& rr :  out) {
          switch(rr.qtype.getCode()) {
            case QType::NSEC3PARAM: {
              ns3pr = NSEC3PARAMRecordContent(rr.content);
              isDnssecZone = isNSEC3 = true;
              isNarrow = false;
              continue;
            }
            case QType::NSEC3: {
              NSEC3RecordContent ns3rc(rr.content);
              if (firstNSEC3) {
                isDnssecZone = isPresigned = true;
                firstNSEC3 = false;
              } else if (optOutFlag != (ns3rc.d_flags & 1))
                throw PDNSException("Zones with a mixture of Opt-Out NSEC3 RRs and non-Opt-Out NSEC3 RRs are not supported.");
              optOutFlag = ns3rc.d_flags & 1;
              if (ns3rc.d_set.count(QType::NS) && !(rr.qname==domain))
                secured.insert(DNSName(toLower(makeRelative(rr.qname.toString(), domain.toString())))); // XXX DNSName pain
              continue;
            }
            case QType::NSEC: {
              isDnssecZone = isPresigned = true;
              continue;
            }
            case QType::SOA: {
              if(soa_serial != 0)
                continue; //skip the last SOA
              SOAData sd;
              fillSOAData(rr.content,sd);
              soa_serial = sd.serial;
              break;
            }
            case QType::NS: {
              if(rr.qname!=domain)
                nsset.insert(rr.qname);
              break;
            }
            default:
              break;
          }

          qnames.insert(rr.qname);

          rr.domain_id=domain_id;
          rrs.push_back(rr);
        }
      }
    }

    if(isNSEC3) {
      ns3pr.d_flags = optOutFlag ? 1 : 0;
    }


    if(!isPresigned) {
      DNSSECKeeper::keyset_t keys = dk.getKeys(domain);
      if(!keys.empty()) {
        isDnssecZone = true;
        isNSEC3 = hadNSEC3;
        ns3pr = hadNs3pr;
        optOutFlag = (hadNs3pr.d_flags & 1);
        isNarrow = hadNarrow;
      }
    }


    if(isDnssecZone) {
      if(!isNSEC3)
        L<<Logger::Info<<"Adding NSEC ordering information"<<endl;
      else if(!isNarrow)
        L<<Logger::Info<<"Adding NSEC3 hashed ordering information for '"<<domain<<"'"<<endl;
      else
        L<<Logger::Info<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields"<<endl;
    }


    transaction=di.backend->startTransaction(domain, domain_id);
    L<<Logger::Error<<"Transaction started for '"<<domain<<"'"<<endl;

    // update the presigned flag and NSEC3PARAM
    if (isDnssecZone) {
      // update presigned if there was a change
      if (isPresigned && !hadPresigned) {
        // zone is now presigned
        dk.setPresigned(domain);
      } else if (hadPresigned && !isPresigned) {
        // zone is no longer presigned
        dk.unsetPresigned(domain);
      }
      // update NSEC3PARAM
      if (isNSEC3) {
        // zone is NSEC3, only update if there was a change
        if (!hadNSEC3 || (hadNarrow  != isNarrow) ||
            (ns3pr.d_algorithm != hadNs3pr.d_algorithm) ||
            (ns3pr.d_flags != hadNs3pr.d_flags) ||
            (ns3pr.d_iterations != hadNs3pr.d_iterations) ||
            (ns3pr.d_salt != hadNs3pr.d_salt)) {
          dk.setNSEC3PARAM(domain, ns3pr, isNarrow);
        }
      } else if (hadNSEC3 ) {
         // zone is no longer NSEC3
         dk.unsetNSEC3PARAM(domain);
      }
    } else if (hadDnssecZone) {
      // zone is no longer signed
      if (hadPresigned) {
        // remove presigned
        dk.unsetPresigned(domain);
      }
      if (hadNSEC3) {
        // unset NSEC3PARAM
        dk.unsetNSEC3PARAM(domain);
      }
    }

    bool doent=true;
    uint32_t maxent = ::arg().asNum("max-ent-entries");
    string ordername;
    DNSName shorter;
    set<DNSName> rrterm;
    map<DNSName,bool> nonterm;


    for(DNSResourceRecord& rr :  rrs) {

      if(!isPresigned) {
        if (rr.qtype.getCode() == QType::RRSIG)
          continue;
        if(isDnssecZone && rr.qtype.getCode() == QType::DNSKEY && !::arg().mustDo("direct-dnskey"))
          continue;
      }

      // Figure out auth and ents
      rr.auth=true;
      shorter=rr.qname;
      rrterm.clear();
      do {
        if(doent) {
          if (!qnames.count(shorter))
            rrterm.insert(shorter);
        }
        if(nsset.count(shorter) && rr.qtype.getCode() != QType::DS)
          rr.auth=false;

        if (shorter==domain) // stop at apex
          break;
      }while(shorter.chopOff());

      // Insert ents
      if(doent && !rrterm.empty()) {
        bool auth;
        if (!rr.auth && rr.qtype.getCode() == QType::NS) {
          if (isNSEC3)
            ordername=toBase32Hex(hashQNameWithSalt(ns3pr, rr.qname));
          auth=(!isNSEC3 || !optOutFlag || secured.count(DNSName(ordername)));
        } else
          auth=rr.auth;

        for(const auto &nt: rrterm){
          if (!nonterm.count(nt))
              nonterm.insert(pair<DNSName, bool>(nt, auth));
            else if (auth)
              nonterm[nt]=true;
        }

        if(nonterm.size() > maxent) {
          L<<Logger::Error<<"AXFR zone "<<domain<<" has too many empty non terminals."<<endl;
          nonterm.clear();
          doent=false;
        }
      }

      // RRSIG is always auth, even inside a delegation
      if (rr.qtype.getCode() == QType::RRSIG)
        rr.auth=true;

      // Add ordername and insert record
      if (isDnssecZone && rr.qtype.getCode() != QType::RRSIG) {
        if (isNSEC3) {
          // NSEC3
          ordername=toBase32Hex(hashQNameWithSalt(ns3pr, rr.qname));
          if(!isNarrow && (rr.auth || (rr.qtype.getCode() == QType::NS && (!optOutFlag || secured.count(DNSName(ordername)))))) {
            di.backend->feedRecord(rr, &ordername);
          } else
            di.backend->feedRecord(rr);
        } else {
          // NSEC
          if (rr.auth || rr.qtype.getCode() == QType::NS) {
            ordername=toLower(labelReverse(makeRelative(rr.qname.toString(), domain.toString())));
            di.backend->feedRecord(rr, &ordername);
          } else
            di.backend->feedRecord(rr);
        }
      } else
        di.backend->feedRecord(rr);
    }

    // Insert empty non-terminals
    if(doent && !nonterm.empty()) {
      if (isNSEC3) {
        di.backend->feedEnts3(domain_id, domain, nonterm, ns3pr, isNarrow);
      } else
        di.backend->feedEnts(domain_id, nonterm);
    }

    di.backend->commitTransaction();
    transaction = false;
    di.backend->setFresh(domain_id);
    PC.purge(domain.toString()+"$");


    L<<Logger::Error<<"AXFR done for '"<<domain<<"', zone committed with serial number "<<soa_serial<<endl;
    if(::arg().mustDo("slave-renotify"))
      notifyDomain(domain);
  }
  catch(DBException &re) {
    L<<Logger::Error<<"Unable to feed record during incoming AXFR of '" << domain<<"': "<<re.reason<<endl;
    if(di.backend && transaction) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(MOADNSException &re) {
    L<<Logger::Error<<"Unable to parse record during incoming AXFR of '"<<domain<<"' (MOADNSException): "<<re.what()<<endl;
    if(di.backend && transaction) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(std::exception &re) {
    L<<Logger::Error<<"Unable to parse record during incoming AXFR of '"<<domain<<"' (std::exception): "<<re.what()<<endl;
    if(di.backend && transaction) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(ResolverException &re) {
    L<<Logger::Error<<"Unable to AXFR zone '"<<domain<<"' from remote '"<<remote<<"' (resolver): "<<re.reason<<endl;
    if(di.backend && transaction) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(PDNSException &ae) {
    L<<Logger::Error<<"Unable to AXFR zone '"<<domain<<"' from remote '"<<remote<<"' (PDNSException): "<<ae.reason<<endl;
    if(di.backend && transaction) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
}
namespace {
struct QueryInfo
{
  struct timeval query_ttd;
  uint16_t id;
};

struct DomainNotificationInfo
{
  DomainInfo di;
  bool dnssecOk;
  ComboAddress localaddr;
  DNSName tsigkeyname, tsigalgname;
  string tsigsecret;
};
}


struct SlaveSenderReceiver
{
  typedef pair<DNSName, uint16_t> Identifier;

  struct Answer {
    uint32_t theirSerial;
    uint32_t theirInception;
    uint32_t theirExpire;
  };

  map<uint32_t, Answer> d_freshness;

  SlaveSenderReceiver()
  {
  }

  void deliverTimeout(const Identifier& i)
  {
  }

  Identifier send(DomainNotificationInfo& dni)
  {
    random_shuffle(dni.di.masters.begin(), dni.di.masters.end());
    try {
      ComboAddress remote(*dni.di.masters.begin());
      if (dni.localaddr.sin4.sin_family == 0) {
        return make_pair(dni.di.zone,
          d_resolver.sendResolve(ComboAddress(*dni.di.masters.begin(), 53),
            dni.di.zone,
            QType::SOA,
            dni.dnssecOk, dni.tsigkeyname, dni.tsigalgname, dni.tsigsecret)
        );
      } else {
        return make_pair(dni.di.zone,
          d_resolver.sendResolve(ComboAddress(*dni.di.masters.begin(), 53), dni.localaddr,
            dni.di.zone,
            QType::SOA,
            dni.dnssecOk, dni.tsigkeyname, dni.tsigalgname, dni.tsigsecret)
        );
      }
    }
    catch(PDNSException& e) {
      throw runtime_error("While attempting to query freshness of '"+dni.di.zone.toString()+"': "+e.reason);
    }
  }

  bool receive(Identifier& id, Answer& a)
  {
    if(d_resolver.tryGetSOASerial(&id.first, &a.theirSerial, &a.theirInception, &a.theirExpire, &id.second)) {
      return 1;
    }
    return 0;
  }

  void deliverAnswer(DomainNotificationInfo& dni, const Answer& a, unsigned int usec)
  {
    d_freshness[dni.di.id]=a;
  }

  Resolver d_resolver;
};

void CommunicatorClass::addSlaveCheckRequest(const DomainInfo& di, const ComboAddress& remote)
{
  Lock l(&d_lock);
  DomainInfo ours = di;
  ours.backend = 0;
  d_tocheck.insert(ours);
  d_any_sem.post(); // kick the loop!
}

void CommunicatorClass::addTrySuperMasterRequest(DNSPacket *p)
{
  Lock l(&d_lock);
  DNSPacket ours = *p;
  d_potentialsupermasters.push_back(ours);
  d_any_sem.post(); // kick the loop!
}

void CommunicatorClass::slaveRefresh(PacketHandler *P)
{
  // not unless we are slave
  if (!::arg().mustDo("slave")) return;

  UeberBackend *B=P->getBackend();
  vector<DomainInfo> rdomains;
  vector<DomainNotificationInfo> sdomains; // the bool is for 'presigned'
  vector<DNSPacket> trysuperdomains;

  {
    Lock l(&d_lock);
    rdomains.insert(rdomains.end(), d_tocheck.begin(), d_tocheck.end());
    d_tocheck.clear();
    trysuperdomains.insert(trysuperdomains.end(), d_potentialsupermasters.begin(), d_potentialsupermasters.end());
    d_potentialsupermasters.clear();
  }

  for(DNSPacket& dp :  trysuperdomains) {
    // get the TSIG key name
    TSIGRecordContent trc;
    DNSName tsigkeyname;
    string message;
    dp.getTSIGDetails(&trc, &tsigkeyname, &message);
    int res;
    res=P->trySuperMasterSynchronous(&dp, tsigkeyname);
    if(res>=0) {
      DNSPacket *r=dp.replyPacket();
      r->setRcode(res);
      r->setOpcode(Opcode::Notify);
      N->send(r);
      delete r;
    }
  }

  if(rdomains.empty()) // if we have priority domains, check them first
    B->getUnfreshSlaveInfos(&rdomains);

  DNSSECKeeper dk(B); // NOW HEAR THIS! This DK uses our B backend, so no interleaved access!
  {
    Lock l(&d_lock);
    domains_by_name_t& nameindex=boost::multi_index::get<IDTag>(d_suckdomains);

    for(DomainInfo& di :  rdomains) {
      std::vector<std::string> localaddr;
      SuckRequest sr;
      sr.domain=di.zone;
      if(di.masters.empty()) // slave domains w/o masters are ignored
        continue;
      // remove unfresh domains already queued for AXFR, no sense polling them again
      sr.master=*di.masters.begin();
      if(nameindex.count(sr)) {
        continue;
      }
      DomainNotificationInfo dni;
      dni.di=di;
      dni.dnssecOk = dk.isPresigned(di.zone);

      if(dk.getTSIGForAccess(di.zone, sr.master, &dni.tsigkeyname)) {
        string secret64;
        B->getTSIGKey(dni.tsigkeyname, &dni.tsigalgname, &secret64);
        B64Decode(secret64, dni.tsigsecret);
      }

      localaddr.clear();
      // check for AXFR-SOURCE
      if(B->getDomainMetadata(di.zone, "AXFR-SOURCE", localaddr) && !localaddr.empty()) {
        try {
          dni.localaddr = ComboAddress(localaddr[0]);
          L<<Logger::Info<<"Freshness check source (AXFR-SOURCE) for domain '"<<di.zone<<"' set to "<<localaddr[0]<<endl;
        }
        catch(std::exception& e) {
          L<<Logger::Error<<"Failed to load freshness check source '"<<localaddr[0]<<"' for '"<<di.zone<<"': "<<e.what()<<endl;
          return;
        }
      } else {
        dni.localaddr.sin4.sin_family = 0;
      }

      sdomains.push_back(dni);
    }
  }

  if(sdomains.empty())
  {
    if(d_slaveschanged) {
      Lock l(&d_lock);
      L<<Logger::Warning<<"No new unfresh slave domains, "<<d_suckdomains.size()<<" queued for AXFR already"<<endl;
    }
    d_slaveschanged = !rdomains.empty();
    return;
  }
  else {
    Lock l(&d_lock);
    L<<Logger::Warning<<sdomains.size()<<" slave domain"<<(sdomains.size()>1 ? "s" : "")<<" need"<<
      (sdomains.size()>1 ? "" : "s")<<
      " checking, "<<d_suckdomains.size()<<" queued for AXFR"<<endl;
  }

  SlaveSenderReceiver ssr;

  Inflighter<vector<DomainNotificationInfo>, SlaveSenderReceiver> ifl(sdomains, ssr);

  ifl.d_maxInFlight = 200;

  for(;;) {
    try {
      ifl.run();
      break;
    }
    catch(std::exception& e) {
      L<<Logger::Error<<"While checking domain freshness: " << e.what()<<endl;
    }
    catch(PDNSException &re) {
      L<<Logger::Error<<"While checking domain freshness: " << re.reason<<endl;
    }
  }
  L<<Logger::Warning<<"Received serial number updates for "<<ssr.d_freshness.size()<<" zones, had "<<ifl.getTimeouts()<<" timeouts"<<endl;

  typedef DomainNotificationInfo val_t;
  for(val_t& val :  sdomains) {
    DomainInfo& di(val.di);
    // might've come from the packethandler
    if(!di.backend && !B->getDomainInfo(di.zone, di)) {
        L<<Logger::Warning<<"Ignore domain "<< di.zone<<" since it has been removed from our backend"<<endl;
        continue;
    }

    if(!ssr.d_freshness.count(di.id))
      continue;
    uint32_t theirserial = ssr.d_freshness[di.id].theirSerial, ourserial = di.serial;

    if(rfc1982LessThan(theirserial, ourserial) && ourserial != 0) {
      L<<Logger::Error<<"Domain '"<<di.zone<<"' more recent than master, our serial " << ourserial << " > their serial "<< theirserial << endl;
      di.backend->setFresh(di.id);
    }
    else if(theirserial == ourserial) {
      if(!dk.isPresigned(di.zone)) {
        L<<Logger::Info<<"Domain '"<< di.zone<<"' is fresh (not presigned, no RRSIG check)"<<endl;
        di.backend->setFresh(di.id);
      }
      else {
        B->lookup(QType(QType::RRSIG), di.zone); // can't use DK before we are done with this lookup!
        DNSResourceRecord rr;
        uint32_t maxExpire=0, maxInception=0;
        while(B->get(rr)) {
          RRSIGRecordContent rrc(rr.content);
          if(rrc.d_type == QType::SOA) {
            maxInception = std::max(maxInception, rrc.d_siginception);
            maxExpire = std::max(maxExpire, rrc.d_sigexpire);
          }
        }
        if(maxInception == ssr.d_freshness[di.id].theirInception && maxExpire == ssr.d_freshness[di.id].theirExpire) {
          L<<Logger::Info<<"Domain '"<< di.zone<<"' is fresh and apex RRSIGs match"<<endl;
          di.backend->setFresh(di.id);
        }
        else {
          L<<Logger::Warning<<"Domain '"<< di.zone<<"' is fresh, but RRSIGS differ, so DNSSEC stale"<<endl;
          addSuckRequest(di.zone, *di.masters.begin());
        }
      }
    }
    else {
      L<<Logger::Warning<<"Domain '"<< di.zone<<"' is stale, master serial "<<theirserial<<", our serial "<< ourserial <<endl;
      addSuckRequest(di.zone, *di.masters.begin());
    }
  }
}

// stub for PowerDNSLua linking
int directResolve(const std::string& qname, const QType& qtype, int qclass, vector<DNSResourceRecord>& ret)
{
  return -1;
}


