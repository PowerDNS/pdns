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
#include "auth-caches.hh"

#include "base64.hh"
#include "inflighter.cc"
#include "namespaces.hh"
#include "common_startup.hh"

#include "ixfr.hh"

void CommunicatorClass::addSuckRequest(const DNSName &domain, const ComboAddress& master)
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

struct ZoneStatus
{
  bool isDnssecZone{false};
  bool isPresigned{false};
  bool isNSEC3 {false};
  bool optOutFlag {false};
  NSEC3PARAMRecordContent ns3pr;

  bool isNarrow{false};
  unsigned int soa_serial{0};
  set<DNSName> nsset, qnames, secured;
  uint32_t domain_id;
  int numDeltas{0};
};


void CommunicatorClass::ixfrSuck(const DNSName &domain, const TSIGTriplet& tt, const ComboAddress& laddr, const ComboAddress& remote, unique_ptr<AuthLua4>& pdl,
                                 ZoneStatus& zs, vector<DNSRecord>* axfr)
{
  UeberBackend B; // fresh UeberBackend

  DomainInfo di;
  di.backend=0;
  //  bool transaction=false;
  try {
    DNSSECKeeper dk (&B); // reuse our UeberBackend copy for DNSSECKeeper

    bool wrongDomainKind = false;
    // this checks three error conditions, and sets wrongDomainKind if we hit the third & had an error
    if(!B.getDomainInfo(domain, di) || !di.backend || (wrongDomainKind = true, di.kind != DomainInfo::Slave)) { // di.backend and B are mostly identical
      if(wrongDomainKind)
        g_log<<Logger::Error<<"Can't determine backend for domain '"<<domain<<"', not configured as slave"<<endl;
      else
        g_log<<Logger::Error<<"Can't determine backend for domain '"<<domain<<"'"<<endl;
      return;
    }

    soatimes st;
    memset(&st, 0, sizeof(st));
    st.serial=di.serial;

    DNSRecord drsoa;
    drsoa.d_content = std::make_shared<SOARecordContent>(g_rootdnsname, g_rootdnsname, st);
    auto deltas = getIXFRDeltas(remote, domain, drsoa, tt, laddr.sin4.sin_family ? &laddr : 0, ((size_t) ::arg().asNum("xfr-max-received-mbytes")) * 1024 * 1024);
    zs.numDeltas=deltas.size();
    //    cout<<"Got "<<deltas.size()<<" deltas from serial "<<di.serial<<", applying.."<<endl;
    
    for(const auto& d : deltas) {
      const auto& remove = d.first;
      const auto& add = d.second;
      //      cout<<"Delta sizes: "<<remove.size()<<", "<<add.size()<<endl;
      
      if(remove.empty()) { // we got passed an AXFR!
        *axfr = add;
        return;
      }
        

      // our hammer is 'replaceRRSet(domain_id, qname, qt, vector<DNSResourceRecord>& rrset)
      // which thinks in terms of RRSETs
      // however, IXFR does not, and removes and adds *records* (bummer)
      // this means that we must group updates by {qname,qtype}, retrieve the RRSET, apply
      // the add/remove updates, and replaceRRSet the whole thing. 
      
      
      map<pair<DNSName,uint16_t>, pair<vector<DNSRecord>, vector<DNSRecord> > > grouped;
      
      for(const auto& x: remove)
        grouped[{x.d_name, x.d_type}].first.push_back(x);
      for(const auto& x: add)
        grouped[{x.d_name, x.d_type}].second.push_back(x);

      di.backend->startTransaction(domain, -1);
      for(const auto g : grouped) {
        vector<DNSRecord> rrset;
        {
          DNSZoneRecord zrr;
          B.lookup(QType(g.first.second), g.first.first+domain, di.id);
          while(B.get(zrr)) {
            zrr.dr.d_name.makeUsRelative(domain);
            rrset.push_back(zrr.dr);
          }
        }
        // O(N^2)!
        rrset.erase(remove_if(rrset.begin(), rrset.end(), 
                              [&g](const DNSRecord& dr) {
                                return count(g.second.first.cbegin(), 
                                             g.second.first.cend(), dr);
                              }), rrset.end());
        // the DNSRecord== operator compares on name, type, class and lowercase content representation

        for(const auto& x : g.second.second) {
          rrset.push_back(x);
        }

        vector<DNSResourceRecord> replacement;
        for(const auto& dr : rrset) {
          auto rr = DNSResourceRecord::fromWire(dr);
          rr.qname += domain;
          rr.domain_id = di.id;
          if(dr.d_type == QType::SOA) {
            //            cout<<"New SOA: "<<x.d_content->getZoneRepresentation()<<endl;
            auto sr = getRR<SOARecordContent>(dr);
            zs.soa_serial=sr->d_st.serial;
          }
          
          replacement.push_back(rr);
        }

        di.backend->replaceRRSet(di.id, g.first.first+domain, QType(g.first.second), replacement);
      }
      di.backend->commitTransaction();
    }
  }
  catch(std::exception& p) {
    g_log<<Logger::Error<<"Got exception during IXFR: "<<p.what()<<endl;
    throw;
  }
  catch(PDNSException& p) {
    g_log<<Logger::Error<<"Got exception during IXFR: "<<p.reason<<endl;
    throw;
  }  
}


static bool processRecordForZS(const DNSName& domain, bool& firstNSEC3, DNSResourceRecord& rr, ZoneStatus& zs)
{
  switch(rr.qtype.getCode()) {
  case QType::NSEC3PARAM: 
    zs.ns3pr = NSEC3PARAMRecordContent(rr.content);
    zs.isDnssecZone = zs.isNSEC3 = true;
    zs.isNarrow = false;
    return false;
  case QType::NSEC3: {
    NSEC3RecordContent ns3rc(rr.content);
    if (firstNSEC3) {
      zs.isDnssecZone = zs.isPresigned = true;
      firstNSEC3 = false;
    } else if (zs.optOutFlag != (ns3rc.d_flags & 1))
      throw PDNSException("Zones with a mixture of Opt-Out NSEC3 RRs and non-Opt-Out NSEC3 RRs are not supported.");
    zs.optOutFlag = ns3rc.d_flags & 1;
    if (ns3rc.isSet(QType::NS) && !(rr.qname==domain)) {
      DNSName hashPart = rr.qname.makeRelative(domain);
      zs.secured.insert(hashPart);
    }
    return false;
  }
  
  case QType::NSEC: 
    zs.isDnssecZone = zs.isPresigned = true;
    return false;
  
  case QType::NS: 
    if(rr.qname!=domain)
      zs.nsset.insert(rr.qname);
    break;
  }

  zs.qnames.insert(rr.qname);

  rr.domain_id=zs.domain_id;
  return true;
}

/* So this code does a number of things. 
   1) It will AXFR a domain from a master
      The code can retrieve the current serial number in the database itself.
      It may attempt an IXFR
   2) It will filter the zone through a lua *filter* script
   3) The code walks through the zone records do determine DNSSEC status (secured, nsec/nsec3, optout)
   4) It inserts the zone into the database
      With the right 'ordername' fields
   5) It updates the Empty Non Terminals
*/

static vector<DNSResourceRecord> doAxfr(const ComboAddress& raddr, const DNSName& domain, const TSIGTriplet& tt, const ComboAddress& laddr,  unique_ptr<AuthLua4>& pdl, ZoneStatus& zs)
{
  uint16_t axfr_timeout=::arg().asNum("axfr-fetch-timeout");
  vector<DNSResourceRecord> rrs;
  AXFRRetriever retriever(raddr, domain, tt, (laddr.sin4.sin_family == 0) ? NULL : &laddr, ((size_t) ::arg().asNum("xfr-max-received-mbytes")) * 1024 * 1024, axfr_timeout);
  Resolver::res_t recs;
  bool first=true;
  bool firstNSEC3{true};
  bool soa_received {false};
  while(retriever.getChunk(recs, nullptr, axfr_timeout)) {
    if(first) {
      g_log<<Logger::Error<<"AXFR started for '"<<domain<<"'"<<endl;
      first=false;
    }

    for(Resolver::res_t::iterator i=recs.begin();i!=recs.end();++i) {
      i->qname.makeUsLowerCase();
      if(i->qtype.getCode() == QType::OPT || i->qtype.getCode() == QType::TSIG) // ignore EDNS0 & TSIG
        continue;

      if(!i->qname.isPartOf(domain)) {
        g_log<<Logger::Error<<"Remote "<<raddr.toStringWithPort()<<" tried to sneak in out-of-zone data '"<<i->qname<<"'|"<<i->qtype.getName()<<" during AXFR of zone '"<<domain<<"', ignoring"<<endl;
        continue;
      }

      vector<DNSResourceRecord> out;
      if(!pdl || !pdl->axfrfilter(raddr, domain, *i, out)) {
        out.push_back(*i); // if axfrfilter didn't do anything, we put our record in 'out' ourselves
      }

      for(DNSResourceRecord& rr :  out) {
        if(!rr.qname.isPartOf(domain)) {
          g_log<<Logger::Error<<"Lua axfrfilter() filter tried to sneak in out-of-zone data '"<<i->qname<<"'|"<<i->qtype.getName()<<" during AXFR of zone '"<<domain<<"', ignoring"<<endl;
          continue;
        }
        if(!processRecordForZS(domain, firstNSEC3, rr, zs))
          continue;
        if(rr.qtype.getCode() == QType::SOA) {
          if(soa_received)
            continue; //skip the last SOA
          SOAData sd;
          fillSOAData(rr.content,sd);
          zs.soa_serial = sd.serial;
          soa_received = true;
        }

        rrs.push_back(rr);

      }
    }
  }
  return rrs;
}   


void CommunicatorClass::suck(const DNSName &domain, const ComboAddress& remote)
{
  {
    Lock l(&d_lock);
    if(d_inprogress.count(domain)) {
      return; 
    }
    d_inprogress.insert(domain);
  }
  RemoveSentinel rs(domain, this); // this removes us from d_inprogress when we go out of scope

  g_log<<Logger::Error<<"Initiating transfer of '"<<domain<<"' from remote '"<<remote<<"'"<<endl;
  UeberBackend B; // fresh UeberBackend

  DomainInfo di;
  di.backend=0;
  bool transaction=false;
  try {
    DNSSECKeeper dk (&B); // reuse our UeberBackend copy for DNSSECKeeper
    bool wrongDomainKind = false;
    // this checks three error conditions & sets wrongDomainKind if we hit the third
    if(!B.getDomainInfo(domain, di) || !di.backend || (wrongDomainKind = true, di.kind != DomainInfo::Slave)) { // di.backend and B are mostly identical
      if(wrongDomainKind)
        g_log<<Logger::Error<<"Can't determine backend for domain '"<<domain<<"', not configured as slave"<<endl;
      else
        g_log<<Logger::Error<<"Can't determine backend for domain '"<<domain<<"'"<<endl;
      return;
    }
    ZoneStatus zs;
    zs.domain_id=di.id;

    TSIGTriplet tt;
    if(dk.getTSIGForAccess(domain, remote, &tt.name)) {
      string tsigsecret64;
      if(B.getTSIGKey(tt.name, &tt.algo, &tsigsecret64)) {
        if(B64Decode(tsigsecret64, tt.secret)) {
          g_log<<Logger::Error<<"Unable to Base-64 decode TSIG key '"<<tt.name<<"' for domain '"<<domain<<"' not found"<<endl;
          return;
        }
      } else {
        g_log<<Logger::Error<<"TSIG key '"<<tt.name<<"' for domain '"<<domain<<"' not found"<<endl;
        return;
      }
    }


    unique_ptr<AuthLua4> pdl{nullptr};
    vector<string> scripts;
    string script=::arg()["lua-axfr-script"];
    if(B.getDomainMetadata(domain, "LUA-AXFR-SCRIPT", scripts) && !scripts.empty()) {
      if (pdns_iequals(scripts[0], "NONE")) {
        script.clear();
      } else {
        script=scripts[0];
      }
    }
    if(!script.empty()){
      try {
        pdl = make_unique<AuthLua4>();
        pdl->loadFile(script);
        g_log<<Logger::Info<<"Loaded Lua script '"<<script<<"' to edit the incoming AXFR of '"<<domain<<"'"<<endl;
      }
      catch(std::exception& e) {
        g_log<<Logger::Error<<"Failed to load Lua editing script '"<<script<<"' for incoming AXFR of '"<<domain<<"': "<<e.what()<<endl;
        return;
      }
    }

    vector<string> localaddr;
    ComboAddress laddr;

    if(B.getDomainMetadata(domain, "AXFR-SOURCE", localaddr) && !localaddr.empty()) {
      try {
        laddr = ComboAddress(localaddr[0]);
        g_log<<Logger::Info<<"AXFR source for domain '"<<domain<<"' set to "<<localaddr[0]<<endl;
      }
      catch(std::exception& e) {
        g_log<<Logger::Error<<"Failed to load AXFR source '"<<localaddr[0]<<"' for incoming AXFR of '"<<domain<<"': "<<e.what()<<endl;
        return;
      }
    } else {
      if(remote.sin4.sin_family == AF_INET && !::arg()["query-local-address"].empty()) {
        laddr = ComboAddress(::arg()["query-local-address"]);
      } else if(remote.sin4.sin_family == AF_INET6 && !::arg()["query-local-address6"].empty()) {
        laddr = ComboAddress(::arg()["query-local-address6"]);
      } else {
        bool isv6 = remote.sin4.sin_family == AF_INET6;
        g_log<<Logger::Error<<"Unable to AXFR, destination address is IPv" << (isv6 ? "6" : "4") << ", but query-local-address"<< (isv6 ? "6" : "") << " is unset!"<<endl;
        return;
      }
    }

    bool hadDnssecZone = false;
    bool hadPresigned = false;
    bool hadNSEC3 = false;
    NSEC3PARAMRecordContent hadNs3pr;
    bool hadNarrow=false;


    vector<DNSResourceRecord> rrs;
    if(dk.isSecuredZone(domain)) {
      hadDnssecZone=true;
      hadPresigned=dk.isPresigned(domain);
      if (dk.getNSEC3PARAM(domain, &zs.ns3pr, &zs.isNarrow)) {
        hadNSEC3 = true;
        hadNs3pr = zs.ns3pr;
        hadNarrow = zs.isNarrow;
      }
    }
    else if(di.serial) {
      vector<string> meta;
      B.getDomainMetadata(domain, "IXFR", meta);
      if(!meta.empty() && meta[0]=="1") {
        vector<DNSRecord> axfr;
        g_log<<Logger::Warning<<"Starting IXFR of '"<<domain<<"' from remote "<<remote<<endl;
        ixfrSuck(domain, tt, laddr, remote, pdl, zs, &axfr);
        if(!axfr.empty()) {
          g_log<<Logger::Warning<<"IXFR of '"<<domain<<"' from remote '"<<remote<<"' turned into an AXFR"<<endl;
          bool firstNSEC3=true;
          rrs.reserve(axfr.size());
          for(const auto& dr : axfr) {
            auto rr = DNSResourceRecord::fromWire(dr);
            (rr.qname += domain).makeUsLowerCase();
            rr.domain_id = zs.domain_id;
            if(!processRecordForZS(domain, firstNSEC3, rr, zs))
              continue;
            if(dr.d_type == QType::SOA) {
              auto sd = getRR<SOARecordContent>(dr);
              zs.soa_serial = sd->d_st.serial;
            }
            rrs.push_back(rr);
          }
        }
        else {
          g_log<<Logger::Warning<<"Done with IXFR of '"<<domain<<"' from remote '"<<remote<<"', got "<<zs.numDeltas<<" delta"<<addS(zs.numDeltas)<<", serial now "<<zs.soa_serial<<endl;
          purgeAuthCaches(domain.toString()+"$");
          return;
        }
      }
    }

    if(rrs.empty()) {
      g_log<<Logger::Warning<<"Starting AXFR of '"<<domain<<"' from remote "<<remote<<endl;
      rrs = doAxfr(remote, domain, tt, laddr, pdl, zs);
      g_log<<Logger::Warning<<"AXFR of '"<<domain<<"' from remote "<<remote<<" done"<<endl;
    }
 
    if(zs.isNSEC3) {
      zs.ns3pr.d_flags = zs.optOutFlag ? 1 : 0;
    }

    if(!zs.isPresigned) {
      DNSSECKeeper::keyset_t keys = dk.getKeys(domain);
      if(!keys.empty()) {
        zs.isDnssecZone = true;
        zs.isNSEC3 = hadNSEC3;
        zs.ns3pr = hadNs3pr;
        zs.optOutFlag = (hadNs3pr.d_flags & 1);
        zs.isNarrow = hadNarrow;
      }
    }

    if(zs.isDnssecZone) {
      if(!zs.isNSEC3)
        g_log<<Logger::Info<<"Adding NSEC ordering information"<<endl;
      else if(!zs.isNarrow)
        g_log<<Logger::Info<<"Adding NSEC3 hashed ordering information for '"<<domain<<"'"<<endl;
      else
        g_log<<Logger::Info<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields"<<endl;
    }


    transaction=di.backend->startTransaction(domain, zs.domain_id);
    g_log<<Logger::Error<<"Backend transaction started for '"<<domain<<"' storage"<<endl;

    // update the presigned flag and NSEC3PARAM
    if (zs.isDnssecZone) {
      // update presigned if there was a change
      if (zs.isPresigned && !hadPresigned) {
        // zone is now presigned
        dk.setPresigned(domain);
      } else if (hadPresigned && !zs.isPresigned) {
        // zone is no longer presigned
        dk.unsetPresigned(domain);
      }
      // update NSEC3PARAM
      if (zs.isNSEC3) {
        // zone is NSEC3, only update if there was a change
        if (!hadNSEC3 || (hadNarrow  != zs.isNarrow) ||
            (zs.ns3pr.d_algorithm != hadNs3pr.d_algorithm) ||
            (zs.ns3pr.d_flags != hadNs3pr.d_flags) ||
            (zs.ns3pr.d_iterations != hadNs3pr.d_iterations) ||
            (zs.ns3pr.d_salt != hadNs3pr.d_salt)) {
          dk.setNSEC3PARAM(domain, zs.ns3pr, zs.isNarrow);
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
    DNSName shorter, ordername;
    set<DNSName> rrterm;
    map<DNSName,bool> nonterm;


    for(DNSResourceRecord& rr :  rrs) {
      if(!zs.isPresigned) {
        if (rr.qtype.getCode() == QType::RRSIG)
          continue;
        if(zs.isDnssecZone && rr.qtype.getCode() == QType::DNSKEY && !::arg().mustDo("direct-dnskey"))
          continue;
      }

      // Figure out auth and ents
      rr.auth=true;
      shorter=rr.qname;
      rrterm.clear();
      do {
        if(doent) {
          if (!zs.qnames.count(shorter))
            rrterm.insert(shorter);
        }
        if(zs.nsset.count(shorter) && rr.qtype.getCode() != QType::DS)
          rr.auth=false;

        if (shorter==domain) // stop at apex
          break;
      }while(shorter.chopOff());

      // Insert ents
      if(doent && !rrterm.empty()) {
        bool auth;
        if (!rr.auth && rr.qtype.getCode() == QType::NS) {
          if (zs.isNSEC3)
            ordername=DNSName(toBase32Hex(hashQNameWithSalt(zs.ns3pr, rr.qname)));
          auth=(!zs.isNSEC3 || !zs.optOutFlag || zs.secured.count(ordername));
        } else
          auth=rr.auth;

        for(const auto &nt: rrterm){
          if (!nonterm.count(nt))
              nonterm.insert(pair<DNSName, bool>(nt, auth));
            else if (auth)
              nonterm[nt]=true;
        }

        if(nonterm.size() > maxent) {
          g_log<<Logger::Error<<"AXFR zone "<<domain<<" has too many empty non terminals."<<endl;
          nonterm.clear();
          doent=false;
        }
      }

      // RRSIG is always auth, even inside a delegation
      if (rr.qtype.getCode() == QType::RRSIG)
        rr.auth=true;

      // Add ordername and insert record
      if (zs.isDnssecZone && rr.qtype.getCode() != QType::RRSIG) {
        if (zs.isNSEC3) {
          // NSEC3
          ordername=DNSName(toBase32Hex(hashQNameWithSalt(zs.ns3pr, rr.qname)));
          if(!zs.isNarrow && (rr.auth || (rr.qtype.getCode() == QType::NS && (!zs.optOutFlag || zs.secured.count(ordername))))) {
            di.backend->feedRecord(rr, ordername, true);
          } else
            di.backend->feedRecord(rr, DNSName());
        } else {
          // NSEC
          if (rr.auth || rr.qtype.getCode() == QType::NS) {
            ordername=rr.qname.makeRelative(domain);
            di.backend->feedRecord(rr, ordername);
          } else
            di.backend->feedRecord(rr, DNSName());
        }
      } else
        di.backend->feedRecord(rr, DNSName());
    }

    // Insert empty non-terminals
    if(doent && !nonterm.empty()) {
      if (zs.isNSEC3) {
        di.backend->feedEnts3(zs.domain_id, domain, nonterm, zs.ns3pr, zs.isNarrow);
      } else
        di.backend->feedEnts(zs.domain_id, nonterm);
    }

    di.backend->commitTransaction();
    transaction = false;
    di.backend->setFresh(zs.domain_id);
    purgeAuthCaches(domain.toString()+"$");

    g_log<<Logger::Error<<"AXFR done for '"<<domain<<"', zone committed with serial number "<<zs.soa_serial<<endl;

    // Send slave re-notifications
    bool notify;
    vector<string> meta;
    if(B.getDomainMetadata(domain, "SLAVE-RENOTIFY", meta ) && !meta.empty()) {
      notify=(meta.front() == "1");
    } else {
      notify=(::arg().mustDo("slave-renotify"));
    }
    if(notify) {
      notifyDomain(domain, &B);
    }

  }
  catch(DBException &re) {
    g_log<<Logger::Error<<"Unable to feed record during incoming AXFR of '" << domain<<"': "<<re.reason<<endl;
    if(di.backend && transaction) {
      g_log<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(const MOADNSException &mde) {
    g_log<<Logger::Error<<"Unable to parse record during incoming AXFR of '"<<domain<<"' (MOADNSException): "<<mde.what()<<endl;
    if(di.backend && transaction) {
      g_log<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(std::exception &re) {
    g_log<<Logger::Error<<"Unable to parse record during incoming AXFR of '"<<domain<<"' (std::exception): "<<re.what()<<endl;
    if(di.backend && transaction) {
      g_log<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(ResolverException &re) {
    {
      Lock l(&d_lock);
      // The AXFR probably failed due to a problem on the master server. If SOA-checks against this master
      // still succeed, we would constantly try to AXFR the zone. To avoid this, we add the zone to the list of
      // failed slave-checks. This will suspend slave-checks (and subsequent AXFR) for this zone for some time.
      uint64_t newCount = 1;
      time_t now = time(0);
      const auto failedEntry = d_failedSlaveRefresh.find(domain);
      if (failedEntry != d_failedSlaveRefresh.end())
        newCount = d_failedSlaveRefresh[domain].first + 1;
      time_t nextCheck = now + std::min(newCount * d_tickinterval, (uint64_t)::arg().asNum("soa-retry-default"));
      d_failedSlaveRefresh[domain] = {newCount, nextCheck};
      g_log<<Logger::Error<<"Unable to AXFR zone '"<<domain<<"' from remote '"<<remote<<"' (resolver): "<<re.reason<<" (This was the "<<(newCount == 1 ? "first" : std::to_string(newCount) + "th")<<" time. Excluding zone from slave-checks until "<<nextCheck<<")"<<endl;
    }
    if(di.backend && transaction) {
      g_log<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(PDNSException &ae) {
    g_log<<Logger::Error<<"Unable to AXFR zone '"<<domain<<"' from remote '"<<remote<<"' (PDNSException): "<<ae.reason<<endl;
    if(di.backend && transaction) {
      g_log<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
}
namespace {
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
  typedef std::tuple<DNSName, ComboAddress, uint16_t> Identifier;

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
      return std::make_tuple(dni.di.zone,
                             *dni.di.masters.begin(),
                             d_resolver.sendResolve(*dni.di.masters.begin(),
                                                    dni.localaddr,
                                                    dni.di.zone,
                                                    QType::SOA,
                                                    nullptr,
                                                    dni.dnssecOk, dni.tsigkeyname, dni.tsigalgname, dni.tsigsecret)
        );
    }
    catch(PDNSException& e) {
      throw runtime_error("While attempting to query freshness of '"+dni.di.zone.toLogString()+"': "+e.reason);
    }
  }

  bool receive(Identifier& id, Answer& a)
  {
    if(d_resolver.tryGetSOASerial(&(std::get<0>(id)), &(std::get<1>(id)), &a.theirSerial, &a.theirInception, &a.theirExpire, &(std::get<2>(id)))) {
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

  // When adding a check, if the remote addr from which notification was
  // received is a master, clear all other masters so we can be sure the
  // query goes to that one.
  for (const auto& master : di.masters) {
    if (ComboAddress::addressOnlyEqual()(remote, master)) {
      ours.masters.clear();
      ours.masters.push_back(master);
      break;
    }
  }
  d_tocheck.erase(di);
  d_tocheck.insert(ours);
  d_any_sem.post(); // kick the loop!
}

void CommunicatorClass::addTrySuperMasterRequest(const DNSPacket& p)
{
  Lock l(&d_lock);
  DNSPacket ours = p;
  if(d_potentialsupermasters.insert(ours).second)
    d_any_sem.post(); // kick the loop!
}

void CommunicatorClass::slaveRefresh(PacketHandler *P)
{
  // not unless we are slave
  if (!::arg().mustDo("slave")) return;

  UeberBackend *B=P->getBackend();
  vector<DomainInfo> rdomains;
  vector<DomainNotificationInfo> sdomains;
  set<DNSPacket, cmp> trysuperdomains;
  {
    Lock l(&d_lock);
    set<DomainInfo> requeue;
    for(const auto& di: d_tocheck) {
      if(d_inprogress.count(di.zone)) {
        g_log<<Logger::Debug<<"Got NOTIFY for "<<di.zone<<" while AXFR in progress, requeueing SOA check"<<endl;
        requeue.insert(di);
      }
      else {
        // We received a NOTIFY for a zone. This means at least one of the zone's master server is working.
        // Therefore we delete the zone from the list of failed slave-checks to allow immediate checking.
        const auto wasFailedDomain = d_failedSlaveRefresh.find(di.zone);
        if (wasFailedDomain != d_failedSlaveRefresh.end()) {
          g_log<<Logger::Debug<<"Got NOTIFY for "<<di.zone<<", removing zone from list of failed slave-checks and going to check SOA serial"<<endl;
          d_failedSlaveRefresh.erase(di.zone);
        } else {
          g_log<<Logger::Debug<<"Got NOTIFY for "<<di.zone<<", going to check SOA serial"<<endl;
        }
        rdomains.push_back(di);
      }
    }
    d_tocheck.swap(requeue);

    trysuperdomains = d_potentialsupermasters;
    d_potentialsupermasters.clear();
  }

  for(const DNSPacket& dp :  trysuperdomains) {
    // get the TSIG key name
    TSIGRecordContent trc;
    DNSName tsigkeyname;
    dp.getTSIGDetails(&trc, &tsigkeyname);
    P->trySuperMasterSynchronous(dp, tsigkeyname); // FIXME could use some error loging
  }
  if(rdomains.empty()) { // if we have priority domains, check them first
    B->getUnfreshSlaveInfos(&rdomains);
  }
  DNSSECKeeper dk(B); // NOW HEAR THIS! This DK uses our B backend, so no interleaved access!
  {
    Lock l(&d_lock);
    domains_by_name_t& nameindex=boost::multi_index::get<IDTag>(d_suckdomains);
    time_t now = time(0);

    for(DomainInfo& di :  rdomains) {
      const auto failed = d_failedSlaveRefresh.find(di.zone);
      if (failed != d_failedSlaveRefresh.end() && now < failed->second.second ) {
        // If the domain has failed before and the time before the next check has not expired, skip this domain
        g_log<<Logger::Debug<<"Zone '"<<di.zone<<"' is on the list of failed SOA checks. Skipping SOA checks until "<< failed->second.second<<endl;
        continue;
      }
      std::vector<std::string> localaddr;
      SuckRequest sr;
      sr.domain=di.zone;
      if(di.masters.empty()) // slave domains w/o masters are ignored
        continue;
      // remove unfresh domains already queued for AXFR, no sense polling them again
      sr.master=*di.masters.begin();
      if(nameindex.count(sr)) {  // this does NOT however protect us against AXFRs already in progress!
        continue;
      }
      if(d_inprogress.count(sr.domain)) // this does
        continue;

      DomainNotificationInfo dni;
      dni.di=di;
      dni.dnssecOk = dk.doesDNSSEC();

      if(dk.getTSIGForAccess(di.zone, sr.master, &dni.tsigkeyname)) {
        string secret64;
        if(!B->getTSIGKey(dni.tsigkeyname, &dni.tsigalgname, &secret64)) {
          g_log<<Logger::Error<<"TSIG key '"<<dni.tsigkeyname<<"' for domain '"<<di.zone<<"' not found, can not AXFR."<<endl;
          continue;
        }
        if (B64Decode(secret64, dni.tsigsecret) == -1) {
          g_log<<Logger::Error<<"Unable to Base-64 decode TSIG key '"<<dni.tsigkeyname<<"' for domain '"<<di.zone<<"', can not AXFR."<<endl;
          continue;
        }
      }

      localaddr.clear();
      // check for AXFR-SOURCE
      if(B->getDomainMetadata(di.zone, "AXFR-SOURCE", localaddr) && !localaddr.empty()) {
        try {
          dni.localaddr = ComboAddress(localaddr[0]);
          g_log<<Logger::Info<<"Freshness check source (AXFR-SOURCE) for domain '"<<di.zone<<"' set to "<<localaddr[0]<<endl;
        }
        catch(std::exception& e) {
          g_log<<Logger::Error<<"Failed to load freshness check source '"<<localaddr[0]<<"' for '"<<di.zone<<"': "<<e.what()<<endl;
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
      g_log<<Logger::Warning<<"No new unfresh slave domains, "<<d_suckdomains.size()<<" queued for AXFR already, "<<d_inprogress.size()<<" in progress"<<endl;
    }
    d_slaveschanged = !rdomains.empty();
    return;
  }
  else {
    Lock l(&d_lock);
    g_log<<Logger::Warning<<sdomains.size()<<" slave domain"<<(sdomains.size()>1 ? "s" : "")<<" need"<<
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
      g_log<<Logger::Error<<"While checking domain freshness: " << e.what()<<endl;
    }
    catch(PDNSException &re) {
      g_log<<Logger::Error<<"While checking domain freshness: " << re.reason<<endl;
    }
  }
  g_log<<Logger::Warning<<"Received serial number updates for "<<ssr.d_freshness.size()<<" zone"<<addS(ssr.d_freshness.size())<<", had "<<ifl.getTimeouts()<<" timeout"<<addS(ifl.getTimeouts())<<endl;

  typedef DomainNotificationInfo val_t;
  time_t now = time(0);
  for(val_t& val :  sdomains) {
    DomainInfo& di(val.di);
    DomainInfo tempdi;
    // might've come from the packethandler
    // Please do not overwrite received DI just to make sure it exists in backend.
    if(!di.backend) {
      if (!B->getDomainInfo(di.zone, tempdi)) {
        g_log<<Logger::Warning<<"Ignore domain "<< di.zone<<" since it has been removed from our backend"<<endl;
        continue;
      }
      // Backend for di still doesn't exist and this might cause us to
      // SEGFAULT on the setFresh command later on
      di.backend = tempdi.backend;
    }

    if(!ssr.d_freshness.count(di.id)) { // If we don't have an answer for the domain
      uint64_t newCount = 1;
      Lock l(&d_lock);
      const auto failedEntry = d_failedSlaveRefresh.find(di.zone);
      if (failedEntry != d_failedSlaveRefresh.end())
        newCount = d_failedSlaveRefresh[di.zone].first + 1;
      time_t nextCheck = now + std::min(newCount * d_tickinterval, (uint64_t)::arg().asNum("soa-retry-default"));
      d_failedSlaveRefresh[di.zone] = {newCount, nextCheck};
      if (newCount == 1) {
        g_log<<Logger::Warning<<"Unable to retrieve SOA for "<<di.zone<<
          ", this was the first time. NOTE: For every subsequent failed SOA check the domain will be suspended from freshness checks for 'num-errors x "<<
          d_tickinterval<<" seconds', with a maximum of "<<(uint64_t)::arg().asNum("soa-retry-default")<<" seconds. Skipping SOA checks until "<<nextCheck<<endl;
      } else if (newCount % 10 == 0) {
        g_log<<Logger::Warning<<"Unable to retrieve SOA for "<<di.zone<<", this was the "<<std::to_string(newCount)<<"th time. Skipping SOA checks until "<<nextCheck<<endl;
      }
      continue;
    }

    {
      Lock l(&d_lock);
      const auto wasFailedDomain = d_failedSlaveRefresh.find(di.zone);
      if (wasFailedDomain != d_failedSlaveRefresh.end())
        d_failedSlaveRefresh.erase(di.zone);
    }

    bool hasSOA = false;
    SOAData sd;
    try{
      hasSOA = B->getSOA(di.zone, sd);
    }
    catch(...) {}

    uint32_t theirserial = ssr.d_freshness[di.id].theirSerial, ourserial = sd.serial;

    if(rfc1982LessThan(theirserial, ourserial) && ourserial != 0 && !::arg().mustDo("axfr-lower-serial"))  {
      g_log<<Logger::Error<<"Domain '"<<di.zone<<"' more recent than master, our serial " << ourserial << " > their serial "<< theirserial << endl;
      di.backend->setFresh(di.id);
    }
    else if(hasSOA && theirserial == ourserial) {
      uint32_t maxExpire=0, maxInception=0;
      if(dk.isPresigned(di.zone)) {
        B->lookup(QType(QType::RRSIG), di.zone, di.id); // can't use DK before we are done with this lookup!
        DNSZoneRecord zr;
        while(B->get(zr)) {
          auto rrsig = getRR<RRSIGRecordContent>(zr.dr);
          if(rrsig->d_type == QType::SOA) {
            maxInception = std::max(maxInception, rrsig->d_siginception);
            maxExpire = std::max(maxExpire, rrsig->d_sigexpire);
          }
        }
      }
      if(! maxInception && ! ssr.d_freshness[di.id].theirInception) {
        g_log<<Logger::Info<<"Domain '"<< di.zone<<"' is fresh (no DNSSEC), serial is "<<ourserial<<endl;
        di.backend->setFresh(di.id);
      }
      else if(maxInception == ssr.d_freshness[di.id].theirInception && maxExpire == ssr.d_freshness[di.id].theirExpire) {
        g_log<<Logger::Info<<"Domain '"<< di.zone<<"' is fresh and SOA RRSIGs match, serial is "<<ourserial<<endl;
        di.backend->setFresh(di.id);
      }
      else if(maxExpire >= now && ! ssr.d_freshness[di.id].theirInception ) {
        g_log<<Logger::Info<<"Domain '"<< di.zone<<"' is fresh, master is no longer signed but (some) signatures are still vallid, serial is "<<ourserial<<endl;
        di.backend->setFresh(di.id);
      }
      else if(maxInception && ! ssr.d_freshness[di.id].theirInception ) {
        g_log<<Logger::Warning<<"Domain '"<< di.zone<<"' is stale, master is no longer signed and all signatures have expired, serial is "<<ourserial<<endl;
        addSuckRequest(di.zone, *di.masters.begin());
      }
      else if(dk.doesDNSSEC() && ! maxInception && ssr.d_freshness[di.id].theirInception) {
        g_log<<Logger::Warning<<"Domain '"<< di.zone<<"' is stale, master has signed, serial is "<<ourserial<<endl;
        addSuckRequest(di.zone, *di.masters.begin());
      }
      else {
        g_log<<Logger::Warning<<"Domain '"<< di.zone<<"' is fresh, but RRSIGs differ, so DNSSEC is stale, serial is "<<ourserial<<endl;
        addSuckRequest(di.zone, *di.masters.begin());
      }
    }
    else {
      if(hasSOA) {
        g_log<<Logger::Warning<<"Domain '"<< di.zone<<"' is stale, master serial "<<theirserial<<", our serial "<< ourserial <<endl;
      }
      else {
        g_log<<Logger::Warning<<"Domain '"<< di.zone<<"' is empty, master serial "<<theirserial<<endl;
      }
      addSuckRequest(di.zone, *di.masters.begin());
    }
  }
}
