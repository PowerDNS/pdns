/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2015  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation

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
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include "lua-recursor.hh"
#include "utility.hh"
#include "syncres.hh"
#include <iostream>
#include <map>
#include "dnsrecords.hh"
#include <algorithm>
#include <set>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <deque>
#include "logger.hh"
#include "misc.hh"
#include "arguments.hh"
#include "lwres.hh"
#include "recursor_cache.hh"
#include "dnsparser.hh"
#include "dns_random.hh"
#include "lock.hh"
#include "cachecleaner.hh"

__thread SyncRes::StaticStorage* t_sstorage;

unsigned int SyncRes::s_maxnegttl;
unsigned int SyncRes::s_maxcachettl;
unsigned int SyncRes::s_packetcachettl;
unsigned int SyncRes::s_packetcacheservfailttl;
unsigned int SyncRes::s_serverdownmaxfails;
unsigned int SyncRes::s_serverdownthrottletime;
uint64_t SyncRes::s_queries;
uint64_t SyncRes::s_outgoingtimeouts;
uint64_t SyncRes::s_outgoing4timeouts;
uint64_t SyncRes::s_outgoing6timeouts;
uint64_t SyncRes::s_outqueries;
uint64_t SyncRes::s_tcpoutqueries;
uint64_t SyncRes::s_throttledqueries;
uint64_t SyncRes::s_dontqueries;
uint64_t SyncRes::s_nodelegated;
uint64_t SyncRes::s_unreachables;
unsigned int SyncRes::s_minimumTTL;
bool SyncRes::s_doIPv6;
bool SyncRes::s_nopacketcache;
bool SyncRes::s_rootNXTrust;
unsigned int SyncRes::s_maxqperq;
unsigned int SyncRes::s_maxtotusec;
string SyncRes::s_serverID;
SyncRes::LogMode SyncRes::s_lm;

#define LOG(x) if(d_lm == Log) { L <<Logger::Warning << x; } else if(d_lm == Store) { d_trace << x; }

bool SyncRes::s_noEDNS;

void accountAuthLatency(int usec, int family)
{
  if(family == AF_INET) {
    if(usec < 1000)
      g_stats.auth4Answers0_1++;
    else if(usec < 10000)
      g_stats.auth4Answers1_10++;
    else if(usec < 100000)
      g_stats.auth4Answers10_100++;
    else if(usec < 1000000)
      g_stats.auth4Answers100_1000++;
    else
      g_stats.auth4AnswersSlow++;
  } else  {
    if(usec < 1000)
      g_stats.auth6Answers0_1++;
    else if(usec < 10000)
      g_stats.auth6Answers1_10++;
    else if(usec < 100000)
      g_stats.auth6Answers10_100++;
    else if(usec < 1000000)
      g_stats.auth6Answers100_1000++;
    else
      g_stats.auth6AnswersSlow++;
  }

}

SyncRes::SyncRes(const struct timeval& now) :  d_outqueries(0), d_tcpoutqueries(0), d_throttledqueries(0), d_timeouts(0), d_unreachables(0),
					       d_totUsec(0), d_doDNSSEC(false), d_now(now),
					       d_cacheonly(false), d_nocache(false), d_doEDNS0(false), d_lm(s_lm)
                                                 
{ 
  if(!t_sstorage) {
    t_sstorage = new StaticStorage();
  }
}

/** everything begins here - this is the entry point just after receiving a packet */
int SyncRes::beginResolve(const DNSName &qname, const QType &qtype, uint16_t qclass, vector<DNSRecord>&ret)
{
  s_queries++;

  if( (qtype.getCode() == QType::AXFR))
    return -1;

  static const DNSName arpa("1.0.0.127.in-addr.arpa."), localhost("localhost."), 
    versionbind("version.bind."), idserver("id.server."), versionpdns("version.pdns.");

  if( (qtype.getCode()==QType::PTR && qname==arpa) ||
      (qtype.getCode()==QType::A && qname==localhost)) {
    ret.clear();
    DNSRecord dr;
    dr.d_name=qname;
    dr.d_place = DNSRecord::Answer;
    dr.d_type=qtype.getCode();
    dr.d_class=QClass::IN;
    dr.d_ttl=86400;
    if(qtype.getCode()==QType::PTR)
      dr.d_content=shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::PTR, 1, "localhost."));
    else
      dr.d_content=shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::A, 1, "127.0.0.1"));
    ret.push_back(dr);
    return 0;
  }

  if(qclass==QClass::CHAOS && qtype.getCode()==QType::TXT &&
        (qname==versionbind || qname==idserver || qname==versionpdns )
     ) {
    ret.clear();
    DNSRecord dr;
    dr.d_name=qname;
    dr.d_type=qtype.getCode();
    dr.d_class=qclass;
    dr.d_ttl=86400;
    dr.d_place = DNSRecord::Answer;
    if(qname==versionbind  || qname==versionpdns)
      dr.d_content=shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::TXT, 3, "\""+::arg()["version-string"]+"\""));
    else
      dr.d_content=shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::TXT, 3, "\""+s_serverID+"\""));

    ret.push_back(dr);
    return 0;
  }

  if(qclass==QClass::ANY)
    qclass=QClass::IN;
  else if(qclass!=QClass::IN)
    return -1;

  set<GetBestNSAnswer> beenthere;
  int res=doResolve(qname, qtype, ret, 0, beenthere);
  return res;
}

//! This is the 'out of band resolver', in other words, the authoritative server
bool SyncRes::doOOBResolve(const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, int depth, int& res)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  LOG(prefix<<qname.toString()<<": checking auth storage for '"<<qname.toString()<<"|"<<qtype.getName()<<"'"<<endl);
  DNSName authdomain(qname);

  domainmap_t::const_iterator iter=getBestAuthZone(&authdomain);
  if(iter==t_sstorage->domainmap->end()) {
    LOG(prefix<<qname.toString()<<": auth storage has no zone for this query!"<<endl);
    return false;
  }
  LOG(prefix<<qname.toString()<<": auth storage has data, zone='"<<authdomain.toString()<<"'"<<endl);
  pair<AuthDomain::records_t::const_iterator, AuthDomain::records_t::const_iterator> range;

  range=iter->second.d_records.equal_range(tie(qname)); // partial lookup

  ret.clear();
  AuthDomain::records_t::const_iterator ziter;
  bool somedata=false;
  for(ziter=range.first; ziter!=range.second; ++ziter) {
    somedata=true;
    if(qtype.getCode()==QType::ANY || ziter->d_type==qtype.getCode() || ziter->d_type==QType::CNAME)  // let rest of nameserver do the legwork on this one
      ret.push_back(*ziter);
  }
  if(!ret.empty()) {
    LOG(prefix<<qname.toString()<<": exact match in zone '"<<authdomain.toString()<<"'"<<endl);
    res=0;
    return true;
  }
  if(somedata) {
    LOG(prefix<<qname.toString()<<": found record in '"<<authdomain.toString()<<"', but nothing of the right type, sending SOA"<<endl);
    ziter=iter->second.d_records.find(boost::make_tuple(authdomain, QType::SOA));
    if(ziter!=iter->second.d_records.end()) {
      DNSRecord dr=*ziter;
      dr.d_place=DNSRecord::Nameserver;
      ret.push_back(dr);
    }
    else
      LOG(prefix<<qname.toString()<<": can't find SOA record '"<<authdomain.toString()<<"' in our zone!"<<endl);
    res=RCode::NoError;
    return true;
  }

  LOG(prefix<<qname.toString()<<": nothing found so far in '"<<authdomain.toString()<<"', trying wildcards"<<endl);
  DNSName wcarddomain(qname);
  while(wcarddomain != iter->first && wcarddomain.chopOff()) {
    LOG(prefix<<qname.toString()<<": trying '*."+wcarddomain.toString()+"' in "<<authdomain.toString()<<endl);
    range=iter->second.d_records.equal_range(boost::make_tuple(DNSName("*")+wcarddomain));
    if(range.first==range.second)
      continue;

    for(ziter=range.first; ziter!=range.second; ++ziter) {
      DNSRecord dr=*ziter;
      if(dr.d_type == qtype.getCode() || qtype.getCode() == QType::ANY) {
        dr.d_name = qname;
        dr.d_place=DNSRecord::Answer;
        ret.push_back(dr);
      }
    }
    LOG(prefix<<qname.toString()<<": in '"<<authdomain.toString()<<"', had wildcard match on '*."+wcarddomain.toString()+"'"<<endl);
    res=RCode::NoError;
    return true;
  }

  DNSName nsdomain(qname);

  while(nsdomain.chopOff() && nsdomain != iter->first) {
    range=iter->second.d_records.equal_range(boost::make_tuple(nsdomain,QType::NS));
    if(range.first==range.second)
      continue;

    for(ziter=range.first; ziter!=range.second; ++ziter) {
      DNSRecord dr=*ziter;
      dr.d_place=DNSRecord::Nameserver;
      ret.push_back(dr);
    }
  }
  if(ret.empty()) {
    LOG(prefix<<qname.toString()<<": no NS match in zone '"<<authdomain.toString()<<"' either, handing out SOA"<<endl);
    ziter=iter->second.d_records.find(boost::make_tuple(authdomain, QType::SOA));
    if(ziter!=iter->second.d_records.end()) {
      DNSRecord dr=*ziter;
      dr.d_place=DNSRecord::Nameserver;
      ret.push_back(dr);
    }
    else {
      LOG(prefix<<qname.toString()<<": can't find SOA record '"<<authdomain.toString()<<"' in our zone!"<<endl);
    }
    res=RCode::NXDomain;
  }
  else
    res=0;

  return true;
}

void SyncRes::doEDNSDumpAndClose(int fd)
{
  FILE* fp=fdopen(fd, "w");
  fprintf(fp,"IP Address\tMode\tMode last updated at\n");
  for(const auto& eds : t_sstorage->ednsstatus) {
    fprintf(fp, "%s\t%d\t%s", eds.first.toString().c_str(), (int)eds.second.mode, ctime(&eds.second.modeSetAt));
  }

  fclose(fp);
}

int SyncRes::asyncresolveWrapper(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, struct timeval* now, LWResult* res)
{
  /* what is your QUEST?
     the goal is to get as many remotes as possible on the highest level of EDNS support
     The levels are:

     0) UNKNOWN Unknown state 
     1) EDNS: Honors EDNS0
     2) EDNSIGNORANT: Ignores EDNS0, gives replies without EDNS0
     3) NOEDNS: Generates FORMERR on EDNS queries

     Everybody starts out assumed to be '0'.
     If '0', send out EDNS0
        If you FORMERR us, go to '3', 
        If no EDNS in response, go to '2'
     If '1', send out EDNS0
        If FORMERR, downgrade to 3
     If '2', keep on including EDNS0, see what happens
        Same behaviour as 0 
     If '3', send bare queries
  */

  g_stats.noEdnsOutQueries++;
  
  SyncRes::EDNSStatus* ednsstatus;
  ednsstatus = &t_sstorage->ednsstatus[ip]; // does this include port? 

  if(ednsstatus->modeSetAt && ednsstatus->modeSetAt + 3600 < d_now.tv_sec) {
    *ednsstatus=SyncRes::EDNSStatus();
    //    cerr<<"Resetting EDNS Status for "<<ip.toString()<<endl);
  }

  SyncRes::EDNSStatus::EDNSMode& mode=ednsstatus->mode;
  SyncRes::EDNSStatus::EDNSMode oldmode = mode;
  int EDNSLevel=0;

  int ret;
  for(int tries = 0; tries < 3; ++tries) {
    //    cerr<<"Remote '"<<ip.toString()<<"' currently in mode "<<mode<<endl;
    
    if(mode==EDNSStatus::UNKNOWN || mode==EDNSStatus::EDNSOK || mode==EDNSStatus::EDNSIGNORANT)
      EDNSLevel = 1;
    else if(mode==EDNSStatus::NOEDNS) {
      g_stats.noEdnsOutQueries++;
      EDNSLevel = 0;
    }
    
    ret=asyncresolve(ip, domain, type, doTCP, sendRDQuery, EDNSLevel, now, res);

    if(ret == 0 || ret < 0) {
      //      cerr<< (ret < 0 ? "Transport error" : "Timeout")<<" for query to "<<ip.toString()<<" for '"<<domain.toString()<<"' (ret="<<ret<<"), no change in mode"<<endl;
      return ret;
    }
    else if(mode==EDNSStatus::UNKNOWN || mode==EDNSStatus::EDNSOK || mode == EDNSStatus::EDNSIGNORANT ) {
      if(res->d_rcode == RCode::FormErr || res->d_rcode == RCode::NotImp)  {
	//	cerr<<"Downgrading to NOEDNS because of "<<RCode::to_s(res->d_rcode)<<" for query to "<<ip.toString()<<" for '"<<domain.toString()<<"'"<<endl;
        mode = EDNSStatus::NOEDNS;
        continue;
      }
      else if(!res->d_haveEDNS) {
        if(mode != EDNSStatus::EDNSIGNORANT) {
          mode = EDNSStatus::EDNSIGNORANT;
	  //	  cerr<<"We find that "<<ip.toString()<<" is an EDNS-ignorer for '"<<domain.toString()<<"', moving to mode 3"<<endl;
	}
      }
      else {
	mode = EDNSStatus::EDNSOK;
	//	cerr<<"We find that "<<ip.toString()<<" is EDNS OK!"<<endl;
      }
      
    }
    if(oldmode != mode)
      ednsstatus->modeSetAt=d_now.tv_sec;
    //    cerr<<"Result: ret="<<ret<<", EDNS-level: "<<EDNSLevel<<", haveEDNS: "<<res->d_haveEDNS<<", new mode: "<<mode<<endl;  
    return ret;
  }
  return ret;
}

int SyncRes::doResolve(const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, int depth, set<GetBestNSAnswer>& beenthere)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  int res=0;
  if(!(d_nocache && qtype.getCode()==QType::NS && qname.isRoot())) {
    if(d_cacheonly) { // very limited OOB support
      LWResult lwr;
      LOG(prefix<<qname.toString()<<": Recursion not requested for '"<<qname.toString()<<"|"<<qtype.getName()<<"', peeking at auth/forward zones"<<endl);
      DNSName authname(qname);
      domainmap_t::const_iterator iter=getBestAuthZone(&authname);
      if(iter != t_sstorage->domainmap->end()) {
        const vector<ComboAddress>& servers = iter->second.d_servers;
        if(servers.empty()) {
          ret.clear();
          doOOBResolve(qname, qtype, ret, depth, res);
          return res;
        }
        else {
          const ComboAddress remoteIP = servers.front();
          LOG(prefix<<qname.toString()<<": forwarding query to hardcoded nameserver '"<< remoteIP.toStringWithPort()<<"' for zone '"<<authname.toString()<<"'"<<endl);

          res=asyncresolveWrapper(remoteIP, qname, qtype.getCode(), false, false, &d_now, &lwr);
          // filter out the good stuff from lwr.result()

	  for(const auto& rec : lwr.d_records) {
            if(rec.d_place == DNSRecord::Answer)
              ret.push_back(rec);
          }
          return res;
        }
      }
    }

    if(doCNAMECacheCheck(qname,qtype,ret,depth,res)) // will reroute us if needed
      return res;

    if(doCacheCheck(qname,qtype,ret,depth,res)) // we done
      return res;
  }

  if(d_cacheonly)
    return 0;

  LOG(prefix<<qname.toString()<<": No cache hit for '"<<qname.toString()<<"|"<<qtype.getName()<<"', trying to find an appropriate NS record"<<endl);

  DNSName subdomain(qname);

  set<DNSName> nsset;
  bool flawedNSSet=false;

  // the two retries allow getBestNSNamesFromCache&co to reprime the root
  // hints, in case they ever go missing
  for(int tries=0;tries<2 && nsset.empty();++tries) {
    subdomain=getBestNSNamesFromCache(subdomain, qtype, nsset, &flawedNSSet, depth, beenthere); //  pass beenthere to both occasions
  }

  if(!(res=doResolveAt(nsset, subdomain, flawedNSSet, qname, qtype, ret, depth, beenthere)))
    return 0;

  LOG(prefix<<qname.toString()<<": failed (res="<<res<<")"<<endl);
  ;
  return res<0 ? RCode::ServFail : res;
}

#if 0
// for testing purposes
static bool ipv6First(const ComboAddress& a, const ComboAddress& b)
{
  return !(a.sin4.sin_family < a.sin4.sin_family);
}
#endif

/** This function explicitly goes out for A or AAAA addresses
*/
vector<ComboAddress> SyncRes::getAddrs(const DNSName &qname, int depth, set<GetBestNSAnswer>& beenthere)
{
  typedef vector<DNSRecord> res_t;
  res_t res;

  typedef vector<ComboAddress> ret_t;
  ret_t ret;

  QType type;

  for(int j=1; j<2+s_doIPv6; j++)
  {
    bool done=false;
    switch(j) {
      case 0:
        type = QType::ANY;
        break;
      case 1:
        type = QType::A;
        break;
      case 2:
        type = QType::AAAA;
        break;
    }

    if(!doResolve(qname, type, res,depth+1, beenthere) && !res.empty()) {  // this consults cache, OR goes out
      for(res_t::const_iterator i=res.begin(); i!= res.end(); ++i) {
        if(i->d_type == QType::A || i->d_type == QType::AAAA) {
	  if(auto rec = std::dynamic_pointer_cast<ARecordContent>(i->d_content))
	    ret.push_back(rec->getCA(53));
	  else if(auto rec = std::dynamic_pointer_cast<AAAARecordContent>(i->d_content))
	    ret.push_back(rec->getCA(53));
          done=true;
        }
      }
    }
    if(done) {
      if(j==1 && s_doIPv6) { // we got an A record, see if we have some AAAA lying around
	vector<DNSRecord> cset;
	if(t_RC->get(d_now.tv_sec, qname, QType(QType::AAAA), &cset) > 0) {
	  for(auto k=cset.cbegin();k!=cset.cend();++k) {
	    if(k->d_ttl > (unsigned int)d_now.tv_sec ) {
	      ComboAddress ca=std::dynamic_pointer_cast<AAAARecordContent>(k->d_content)->getCA(53);
	      ret.push_back(ca);
	    }
	  }
	}
      }
      break;
    }
  }

  if(ret.size() > 1) {
    random_shuffle(ret.begin(), ret.end(), dns_random);

    // move 'best' address for this nameserver name up front
    nsspeeds_t::iterator best = t_sstorage->nsSpeeds.find(qname);

    if(best != t_sstorage->nsSpeeds.end())
      for(ret_t::iterator i=ret.begin(); i != ret.end(); ++i) {
        if(*i==best->second.d_best) {  // got the fastest one
          if(i!=ret.begin()) {
            *i=*ret.begin();
            *ret.begin()=best->second.d_best;
          }
          break;
        }
      }
  }

  return ret;
}

void SyncRes::getBestNSFromCache(const DNSName &qname, const QType& qtype, vector<DNSRecord>& bestns, bool* flawedNSSet, int depth, set<GetBestNSAnswer>& beenthere)
{
  string prefix;
  DNSName subdomain(qname);
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }
  bestns.clear();
  bool brokeloop;
  do {
    brokeloop=false;
    LOG(prefix<<qname.toString()<<": Checking if we have NS in cache for '"<<subdomain.toString()<<"'"<<endl);
    vector<DNSRecord> ns;
    *flawedNSSet = false;
    if(t_RC->get(d_now.tv_sec, subdomain, QType(QType::NS), &ns) > 0) {
      for(auto k=ns.cbegin();k!=ns.cend(); ++k) {
        if(k->d_ttl > (unsigned int)d_now.tv_sec ) {
          vector<DNSRecord> aset;

          const DNSRecord& dr=*k;
	  auto nrr = std::dynamic_pointer_cast<NSRecordContent>(dr.d_content);
          if(!nrr->getNS().isPartOf(subdomain) || t_RC->get(d_now.tv_sec, nrr->getNS(), s_doIPv6 ? QType(QType::ADDR) : QType(QType::A),
                                                            doLog() ? &aset : 0) > 5) {
            bestns.push_back(dr);
            LOG(prefix<<qname.toString()<<": NS (with ip, or non-glue) in cache for '"<<subdomain.toString()<<"' -> '"<<nrr->getNS()<<"'"<<endl);
            LOG(prefix<<qname.toString()<<": within bailiwick: "<< nrr->getNS().isPartOf(subdomain));
            if(!aset.empty()) {
              LOG(",  in cache, ttl="<<(unsigned int)(((time_t)aset.begin()->d_ttl- d_now.tv_sec ))<<endl);
            }
            else {
              LOG(", not in cache / did not look at cache"<<endl);
            }
          }
          else {
            *flawedNSSet=true;
            LOG(prefix<<qname<<": NS in cache for '"<<subdomain<<"', but needs glue ("<<nrr->getNS()<<") which we miss or is expired"<<endl);
          }
        }
      }
      if(!bestns.empty()) {
        GetBestNSAnswer answer;
        answer.qname=qname;
	answer.qtype=qtype.getCode();
	for(const auto& dr : bestns)
	  answer.bestns.insert(make_pair(dr.d_name, dr.d_content->getZoneRepresentation()));
	// XXX we are passing a DNSName through a string here!

        if(beenthere.count(answer)) {
	  brokeloop=true;
          LOG(prefix<<qname.toString()<<": We have NS in cache for '"<<subdomain.toString()<<"' but part of LOOP (already seen "<<answer.qname.toString()<<")! Trying less specific NS"<<endl);
	  ;
          if(doLog())
            for( set<GetBestNSAnswer>::const_iterator j=beenthere.begin();j!=beenthere.end();++j) {
	      bool neo = !(*j< answer || answer<*j);
	      LOG(prefix<<qname.toString()<<": beenthere"<<(neo?"*":"")<<": "<<j->qname.toString()<<"|"<<DNSRecordContent::NumberToType(j->qtype)<<" ("<<(unsigned int)j->bestns.size()<<")"<<endl);
            }
          bestns.clear();
        }
        else {
	  beenthere.insert(answer);
          LOG(prefix<<qname.toString()<<": We have NS in cache for '"<<subdomain.toString()<<"' (flawedNSSet="<<*flawedNSSet<<")"<<endl);
          return;
        }
      }
    }
    LOG(prefix<<qname.toString()<<": no valid/useful NS in cache for '"<<subdomain.toString()<<"'"<<endl);
    ;
    if(subdomain.isRoot() && !brokeloop) {
      primeHints();
      LOG(prefix<<qname.toString()<<": reprimed the root"<<endl);
    }
  }while(subdomain.chopOff());
}

SyncRes::domainmap_t::const_iterator SyncRes::getBestAuthZone(DNSName* qname)
{
  SyncRes::domainmap_t::const_iterator ret;
  do {
    ret=t_sstorage->domainmap->find(*qname);
    if(ret!=t_sstorage->domainmap->end())
      break;
  }while(qname->chopOff());
  return ret;
}

/** doesn't actually do the work, leaves that to getBestNSFromCache */
DNSName SyncRes::getBestNSNamesFromCache(const DNSName &qname, const QType& qtype, set<DNSName>& nsset, bool* flawedNSSet, int depth, set<GetBestNSAnswer>&beenthere)
{
  DNSName subdomain(qname);
  DNSName authdomain(qname);

  domainmap_t::const_iterator iter=getBestAuthZone(&authdomain);
  if(iter!=t_sstorage->domainmap->end()) {
    if( iter->second.d_servers.empty() )
      nsset.insert(DNSName()); // this gets picked up in doResolveAt, if empty it means "we are auth", otherwise it denotes a forward
    else {
      for(vector<ComboAddress>::const_iterator server=iter->second.d_servers.begin(); server != iter->second.d_servers.end(); ++server)
	//        nsset.insert((iter->second.d_rdForward ? "+" : "-") + server->toStringWithPort()); // add a '+' if the rd bit should be set
      // XXX this doesn't work, nsset can't contain a port number, or a plus etc! DNSNAME PAIN
	abort();
    }

    return authdomain;
  }

  vector<DNSRecord> bestns;
  getBestNSFromCache(subdomain, qtype, bestns, flawedNSSet, depth, beenthere);

  for(auto k=bestns.cbegin() ; k != bestns.cend(); ++k) {
    nsset.insert(std::dynamic_pointer_cast<NSRecordContent>(k->d_content)->getNS());
    if(k==bestns.cbegin())
      subdomain=k->d_name;
  }
  return subdomain;
}

bool SyncRes::doCNAMECacheCheck(const DNSName &qname, const QType &qtype, vector<DNSRecord>& ret, int depth, int &res)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  if((depth>9 && d_outqueries>10 && d_throttledqueries>5) || depth > 15) {
    LOG(prefix<<qname.toString()<<": recursing (CNAME or other indirection) too deep, depth="<<depth<<endl);
    res=RCode::ServFail;
    return true;
  }

  LOG(prefix<<qname.toString()<<": Looking for CNAME cache hit of '"<<(qname.toString()+"|CNAME")<<"'"<<endl);
  vector<DNSRecord> cset;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  if(t_RC->get(d_now.tv_sec, qname,QType(QType::CNAME), &cset, &signatures) > 0) {

    for(auto j=cset.cbegin() ; j != cset.cend() ; ++j) {
      if(j->d_ttl>(unsigned int) d_now.tv_sec) {
        LOG(prefix<<qname.toString()<<": Found cache CNAME hit for '"<< (qname.toString()+"|CNAME") <<"' to '"<<j->d_content->getZoneRepresentation()<<"'"<<endl);
        DNSRecord dr=*j;
        dr.d_ttl-=d_now.tv_sec;
        ret.push_back(dr);

	for(const auto& signature : signatures) {
	  DNSRecord dr;
	  dr.d_type=QType::RRSIG;
	  dr.d_name=qname;
	  dr.d_ttl=j->d_ttl - d_now.tv_sec;
	  dr.d_content=signature;
	  dr.d_place=DNSRecord::Answer;
	  dr.d_class=1;
	  ret.push_back(dr);
	}

        if(!(qtype==QType(QType::CNAME))) { // perhaps they really wanted a CNAME!
          set<GetBestNSAnswer>beenthere;
          res=doResolve(std::dynamic_pointer_cast<CNAMERecordContent>(j->d_content)->getTarget(), qtype, ret, depth+1, beenthere);
        }
        else
          res=0;
        return true;
      }
    }
  }
  LOG(prefix<<qname.toString()<<": No CNAME cache hit of '"<< (qname.toString()+"|CNAME") <<"' found"<<endl);
  return false;
}

static const DNSName getLastLabel(const DNSName& qname)
{
  DNSName ret(qname);
  ret.trimToLabels(1);
  return ret;
}


bool SyncRes::doCacheCheck(const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, int depth, int &res)
{
  bool giveNegative=false;

  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  DNSName sqname(qname);
  QType sqt(qtype);
  uint32_t sttl=0;
  //  cout<<"Lookup for '"<<qname.toString()<<"|"<<qtype.getName()<<"' -> "<<getLastLabel(qname)<<endl;

  pair<negcache_t::const_iterator, negcache_t::const_iterator> range;
  QType qtnull(0);

  if(s_rootNXTrust &&
     (range.first=t_sstorage->negcache.find(tie(getLastLabel(qname), qtnull))) != t_sstorage->negcache.end() &&
      range.first->d_qname.isRoot() && (uint32_t)d_now.tv_sec < range.first->d_ttd ) {
    sttl=range.first->d_ttd - d_now.tv_sec;

    LOG(prefix<<qname.toString()<<": Entire name '"<<qname.toString()<<"', is negatively cached via '"<<range.first->d_name.toString()<<"' & '"<<range.first->d_qname.toString()<<"' for another "<<sttl<<" seconds"<<endl);
    res = RCode::NXDomain;
    sqname=range.first->d_qname;
    sqt=QType::SOA;
    moveCacheItemToBack(t_sstorage->negcache, range.first);

    giveNegative=true;
  }
  else {
    range=t_sstorage->negcache.equal_range(tie(qname));
    negcache_t::iterator ni;
    for(ni=range.first; ni != range.second; ni++) {
      // we have something
      if(ni->d_qtype.getCode() == 0 || ni->d_qtype == qtype) {
	res=0;
	if((uint32_t)d_now.tv_sec < ni->d_ttd) {
	  sttl=ni->d_ttd - d_now.tv_sec;
	  if(ni->d_qtype.getCode()) {
	    LOG(prefix<<qname.toString()<<": "<<qtype.getName()<<" is negatively cached via '"<<ni->d_qname.toString()<<"' for another "<<sttl<<" seconds"<<endl);
	    res = RCode::NoError;
	  }
	  else {
	    LOG(prefix<<qname.toString()<<": Entire name '"<<qname.toString()<<"', is negatively cached via '"<<ni->d_qname.toString()<<"' for another "<<sttl<<" seconds"<<endl);
	    res= RCode::NXDomain;
	  }
	  giveNegative=true;
	  sqname=ni->d_qname;
	  sqt=QType::SOA;
	  moveCacheItemToBack(t_sstorage->negcache, ni);
	  break;
	}
	else {
	  LOG(prefix<<qname.toString()<<": Entire name '"<<qname.toString()<<"' or type was negatively cached, but entry expired"<<endl);
	  moveCacheItemToFront(t_sstorage->negcache, ni);
	}
      }
    }
  }
  vector<DNSRecord> cset;
  bool found=false, expired=false;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  uint32_t ttl=0;
  if(t_RC->get(d_now.tv_sec, sqname, sqt, &cset, d_doDNSSEC ? &signatures : 0) > 0) {
    LOG(prefix<<sqname.toString()<<": Found cache hit for "<<sqt.getName()<<": ");
    for(auto j=cset.cbegin() ; j != cset.cend() ; ++j) {
      LOG(j->d_content->getZoneRepresentation());
      if(j->d_ttl>(unsigned int) d_now.tv_sec) {
        DNSRecord dr=*j;
        ttl = (dr.d_ttl-=d_now.tv_sec);
        if(giveNegative) {
          dr.d_place=DNSRecord::Nameserver;
          dr.d_ttl=sttl;
        }
        ret.push_back(dr);
        LOG("[ttl="<<dr.d_ttl<<"] ");
        found=true;
      }
      else {
        LOG("[expired] ");
        expired=true;
      }
    }

    for(const auto& signature : signatures) {
      DNSRecord dr;
      dr.d_type=QType::RRSIG;
      dr.d_name=sqname;
      dr.d_ttl=ttl; 
      dr.d_content=signature;
      dr.d_place=DNSRecord::Answer;
      dr.d_class=1;
      ret.push_back(dr);
    }
  
    LOG(endl);
    if(found && !expired) {
      if(!giveNegative)
        res=0;
      return true;
    }
    else
      LOG(prefix<<qname.toString()<<": cache had only stale entries"<<endl);
  }

  return false;
}

bool SyncRes::moreSpecificThan(const DNSName& a, const DNSName &b)
{
  return (a.isPartOf(b) && a.countLabels() > b.countLabels());
}

struct speedOrder
{
  speedOrder(map<DNSName,double> &speeds) : d_speeds(speeds) {}
  bool operator()(const DNSName &a, const DNSName &b) const
  {
    return d_speeds[a] < d_speeds[b];
  }
  map<DNSName, double>& d_speeds;
};

inline vector<DNSName> SyncRes::shuffleInSpeedOrder(set<DNSName> &tnameservers, const string &prefix)
{
  vector<DNSName> rnameservers;
  rnameservers.reserve(tnameservers.size());
  for(const auto& tns:tnameservers) {
    rnameservers.push_back(tns);
  }
  map<DNSName, double> speeds;

  for(const auto& val: rnameservers) {
    double speed;
    speed=t_sstorage->nsSpeeds[val].get(&d_now);
    speeds[val]=speed;
  }
  random_shuffle(rnameservers.begin(),rnameservers.end(), dns_random);
  speedOrder so(speeds);
  stable_sort(rnameservers.begin(),rnameservers.end(), so);

  if(doLog()) {
    LOG(prefix<<"Nameservers: ");
    for(vector<DNSName>::const_iterator i=rnameservers.begin();i!=rnameservers.end();++i) {
			if(i!=rnameservers.begin()) {
        LOG(", ");
        if(!((i-rnameservers.begin())%3)) {
          LOG(endl<<prefix<<"             ");
        }
      }
      LOG(i->toString()<<"(" << (boost::format("%0.2f") % (speeds[*i]/1000.0)).str() <<"ms)");
    }
    LOG(endl);
  }
  return rnameservers;
}

struct TCacheComp
{
  bool operator()(const pair<DNSName, QType>& a, const pair<DNSName, QType>& b) const
  {
    return tie(a.first, a.second) < tie(b.first, b.second);
  }
};

static bool magicAddrMatch(const QType& query, const QType& answer)
{
  if(query.getCode() != QType::ADDR)
    return false;
  return answer.getCode() == QType::A || answer.getCode() == QType::AAAA;
}

/** returns -1 in case of no results, rcode otherwise */
int SyncRes::doResolveAt(set<DNSName> nameservers, DNSName auth, bool flawedNSSet, const DNSName &qname, const QType &qtype,
                         vector<DNSRecord>&ret,
                         int depth, set<GetBestNSAnswer>&beenthere)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  LOG(prefix<<qname.toString()<<": Cache consultations done, have "<<(unsigned int)nameservers.size()<<" NS to contact"<<endl);

  for(;;) { // we may get more specific nameservers
    vector<DNSName > rnameservers = shuffleInSpeedOrder(nameservers, doLog() ? (prefix+qname.toString()+": ") : string() );

		for(vector<DNSName >::const_iterator tns=rnameservers.begin();;++tns) {
      if(tns==rnameservers.end()) {
        LOG(prefix<<qname.toString()<<": Failed to resolve via any of the "<<(unsigned int)rnameservers.size()<<" offered NS at level '"<<auth.toString()<<"'"<<endl);
        if(auth!=DNSName() && flawedNSSet) {
          LOG(prefix<<qname.toString()<<": Ageing nameservers for level '"<<auth.toString()<<"', next query might succeed"<<endl);
	  
          if(t_RC->doAgeCache(d_now.tv_sec, auth, QType::NS, 10))
            g_stats.nsSetInvalidations++;
        }
        return -1;
      }
      // this line needs to identify the 'self-resolving' behaviour, but we get it wrong now
      if(qname == *tns && qtype.getCode()==QType::A && rnameservers.size() > (unsigned)(1+1*s_doIPv6)) {
        LOG(prefix<<qname.toString()<<": Not using NS to resolve itself! ("<<(1+tns-rnameservers.begin())<<"/"<<rnameservers.size()<<")"<<endl);
        continue;
      }

      typedef vector<ComboAddress> remoteIPs_t;
      remoteIPs_t remoteIPs;
      remoteIPs_t::const_iterator remoteIP;
      bool doTCP=false;
      int resolveret;
      bool pierceDontQuery=false;
      bool sendRDQuery=false;
      LWResult lwr;
      if(tns->empty()) {
        LOG(prefix<<qname.toString()<<": Domain is out-of-band"<<endl);
        doOOBResolve(qname, qtype, lwr.d_records, depth, lwr.d_rcode);
        lwr.d_tcbit=false;
        lwr.d_aabit=true;
      }
      else {
        LOG(prefix<<qname.toString()<<": Trying to resolve NS '"<<tns->toString()<< "' ("<<1+tns-rnameservers.begin()<<"/"<<(unsigned int)rnameservers.size()<<")"<<endl);
	;

        if(!isCanonical(*tns)) {
          LOG(prefix<<qname.toString()<<": Domain has hardcoded nameserver(s)"<<endl);

          string txtAddr = tns->toString();
          if(!tns->empty()) {
            sendRDQuery = txtAddr[0] == '+';
            txtAddr=txtAddr.c_str()+1;
          }
          ComboAddress addr=parseIPAndPort(txtAddr, 53);

          remoteIPs.push_back(addr);
          pierceDontQuery=true;
        }
        else {
          remoteIPs=getAddrs(*tns, depth+2, beenthere);
          pierceDontQuery=false;
        }

        if(remoteIPs.empty()) {
          LOG(prefix<<qname.toString()<<": Failed to get IP for NS "<<tns->toString()<<", trying next if available"<<endl);
          flawedNSSet=true;
          continue;
        }
        else {

          LOG(prefix<<qname.toString()<<": Resolved '"+auth.toString()+"' NS "<<tns->toString()<<" to: ");
          for(remoteIP = remoteIPs.begin(); remoteIP != remoteIPs.end(); ++remoteIP) {
            if(remoteIP != remoteIPs.begin()) {
              LOG(", ");
            }
            LOG(remoteIP->toString());
          }
          LOG(endl);

        }

        for(remoteIP = remoteIPs.begin(); remoteIP != remoteIPs.end(); ++remoteIP) {
          LOG(prefix<<qname.toString()<<": Trying IP "<< remoteIP->toStringWithPort() <<", asking '"<<qname.toString()<<"|"<<qtype.getName()<<"'"<<endl);
          extern NetmaskGroup* g_dontQuery;

          if(t_sstorage->throttle.shouldThrottle(d_now.tv_sec, boost::make_tuple(*remoteIP, "", 0))) {
            LOG(prefix<<qname.toString()<<": server throttled "<<endl);
            s_throttledqueries++; d_throttledqueries++;
            continue;
          }
          else if(t_sstorage->throttle.shouldThrottle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()))) {
            LOG(prefix<<qname.toString()<<": query throttled "<<endl);
            s_throttledqueries++; d_throttledqueries++;
            continue;
          }
          else if(!pierceDontQuery && g_dontQuery && g_dontQuery->match(&*remoteIP)) {
            LOG(prefix<<qname.toString()<<": not sending query to " << remoteIP->toString() << ", blocked by 'dont-query' setting" << endl);
            s_dontqueries++;
            continue;
          }
          else {
            s_outqueries++; d_outqueries++;
            if(d_outqueries + d_throttledqueries > s_maxqperq) throw ImmediateServFailException("more than "+lexical_cast<string>(s_maxqperq)+" (max-qperq) queries sent while resolving "+qname.toString());
          TryTCP:
            if(doTCP) {
              LOG(prefix<<qname.toString()<<": using TCP with "<< remoteIP->toStringWithPort() <<endl);
              s_tcpoutqueries++; d_tcpoutqueries++;
            }

	    if(s_maxtotusec && d_totUsec > s_maxtotusec)
	      throw ImmediateServFailException("Too much time waiting for "+qname.toString()+"|"+qtype.getName()+", timeouts: "+boost::lexical_cast<string>(d_timeouts) +", throttles: "+boost::lexical_cast<string>(d_throttledqueries) + ", queries: "+lexical_cast<string>(d_outqueries)+", "+lexical_cast<string>(d_totUsec/1000)+"msec");

	    if(d_pdl && d_pdl->preoutquery(*remoteIP, d_requestor, qname, qtype, lwr.d_records, resolveret)) {
	      LOG(prefix<<qname.toString()<<": query handled by Lua"<<endl);
	    }
	    else
	      resolveret=asyncresolveWrapper(*remoteIP, qname,  qtype.getCode(),
                                           doTCP, sendRDQuery, &d_now, &lwr);    // <- we go out on the wire!

            if(resolveret==-3)
	      throw ImmediateServFailException("Query killed by policy");

	    d_totUsec += lwr.d_usec;
	    accountAuthLatency(lwr.d_usec, remoteIP->sin4.sin_family);
	    if(resolveret != 1) {
              if(resolveret==0) {
                LOG(prefix<<qname.toString()<<": timeout resolving after "<<lwr.d_usec/1000.0<<"msec "<< (doTCP ? "over TCP" : "")<<endl);
                d_timeouts++;
                s_outgoingtimeouts++;
		if(remoteIP->sin4.sin_family == AF_INET)
		  s_outgoing4timeouts++;
		else
		  s_outgoing6timeouts++;
              }
              else if(resolveret==-2) {
                LOG(prefix<<qname.toString()<<": hit a local resource limit resolving"<< (doTCP ? " over TCP" : "")<<", probable error: "<<stringerror()<<endl);
                g_stats.resourceLimits++;
              }
              else {
                s_unreachables++; d_unreachables++;
                LOG(prefix<<qname.toString()<<": error resolving"<< (doTCP ? " over TCP" : "") <<", possible error: "<<strerror(errno)<< endl);
              }

              if(resolveret!=-2) { // don't account for resource limits, they are our own fault
		t_sstorage->nsSpeeds[*tns].submit(*remoteIP, 1000000, &d_now); // 1 sec

		// code below makes sure we don't filter COM or the root
                if (s_serverdownmaxfails > 0 && (auth != DNSName(".")) && t_sstorage->fails.incr(*remoteIP) >= s_serverdownmaxfails) {
                  LOG(prefix<<qname.toString()<<": Max fails reached resolving on "<< remoteIP->toString() <<". Going full throttle for 1 minute" <<endl);
                  t_sstorage->throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, "", 0), s_serverdownthrottletime, 10000); // mark server as down
                } else if(resolveret==-1)
                  t_sstorage->throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()), 60, 100); // unreachable, 1 minute or 100 queries
                else
                  t_sstorage->throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()), 10, 5);  // timeout
              }
              continue;
            }

//	    if(d_timeouts + 0.5*d_throttledqueries > 6.0 && d_timeouts > 2) throw ImmediateServFailException("Too much work resolving "+qname+"|"+qtype.getName()+", timeouts: "+boost::lexical_cast<string>(d_timeouts) +", throttles: "+boost::lexical_cast<string>(d_throttledqueries));

            if(lwr.d_rcode==RCode::ServFail || lwr.d_rcode==RCode::Refused) {
              LOG(prefix<<qname.toString()<<": "<<tns->toString()<<" returned a "<< (lwr.d_rcode==RCode::ServFail ? "ServFail" : "Refused") << ", trying sibling IP or NS"<<endl);
              t_sstorage->throttle.throttle(d_now.tv_sec,boost::make_tuple(*remoteIP, qname, qtype.getCode()),60,3); // servfail or refused
              continue;
            }

            if(s_serverdownmaxfails > 0)
              t_sstorage->fails.clear(*remoteIP);

            break;  // this IP address worked!
          wasLame:; // well, it didn't
            LOG(prefix<<qname.toString()<<": status=NS "<<tns->toString()<<" ("<< remoteIP->toString() <<") is lame for '"<<auth.toString()<<"', trying sibling IP or NS"<<endl);
            t_sstorage->throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()), 60, 100); // lame
          }
        }

        if(remoteIP == remoteIPs.end())  // we tried all IP addresses, none worked
          continue;

        if(lwr.d_tcbit) {
          if(!doTCP) {
            doTCP=true;
            LOG(prefix<<qname.toString()<<": truncated bit set, retrying via TCP"<<endl);
            goto TryTCP;
          }
          LOG(prefix<<qname.toString()<<": truncated bit set, over TCP?"<<endl);
          return RCode::ServFail;
        }
        LOG(prefix<<qname.toString()<<": Got "<<(unsigned int)lwr.d_records.size()<<" answers from "<<tns->toString()<<" ("<< remoteIP->toString() <<"), rcode="<<lwr.d_rcode<<" ("<<RCode::to_s(lwr.d_rcode)<<"), aa="<<lwr.d_aabit<<", in "<<lwr.d_usec/1000<<"ms"<<endl);

        /*  // for you IPv6 fanatics :-)
        if(remoteIP->sin4.sin_family==AF_INET6)
          lwr.d_usec/=3;
        */
        //        cout<<"msec: "<<lwr.d_usec/1000.0<<", "<<g_avgLatency/1000.0<<'\n';

        t_sstorage->nsSpeeds[*tns].submit(*remoteIP, lwr.d_usec, &d_now);
      }

      if(s_minimumTTL) {
	for(auto& rec : lwr.d_records) {
	  rec.d_ttl = max(rec.d_ttl, s_minimumTTL);
	}
      }

      struct CachePair
      {
	vector<DNSRecord> records;
	vector<shared_ptr<RRSIGRecordContent>> signatures;
      };
      typedef map<pair<DNSName, QType>, CachePair, TCacheComp > tcache_t;
      tcache_t tcache;

      if(d_doDNSSEC) {
	for(const auto& rec : lwr.d_records) {
	  if(rec.d_type == QType::RRSIG) {
	    auto rrsig = std::dynamic_pointer_cast<RRSIGRecordContent>(rec.d_content);
	    //	    cerr<<"Got an RRSIG for "<<DNSRecordContent::NumberToType(rrsig->d_type)<<" with name '"<<rec.d_name<<"'"<<endl;
	    tcache[make_pair(rec.d_name, QType(rrsig->d_type))].signatures.push_back(rrsig);
	  }
	}
      }

      // reap all answers from this packet that are acceptable
      for(auto& rec : lwr.d_records) {
        if(rec.d_type == QType::OPT) {
          LOG(prefix<<qname.toString()<<": OPT answer '"<<rec.d_name<<"' from '"<<auth.toString()<<"' nameservers" <<endl);
          continue;
        }
        LOG(prefix<<qname.toString()<<": accept answer '"<<rec.d_name<<"|"<<DNSRecordContent::NumberToType(rec.d_type)<<"|"<<rec.d_content->getZoneRepresentation()<<"' from '"<<auth.toString()<<"' nameservers? "<<(int)rec.d_place<<" ");
        if(rec.d_type == QType::ANY) {
          LOG("NO! - we don't accept 'ANY' data"<<endl);
          continue;
        }

        // Check if we are authoritative for a zone in this answer
        if (!t_sstorage->domainmap->empty()) {
          DNSName tmp_qname(rec.d_name);
          auto auth_domain_iter=getBestAuthZone(&tmp_qname);
          if(auth_domain_iter!=t_sstorage->domainmap->end()) {
            if (auth_domain_iter->first != auth) {
              LOG("NO! - we are authoritative for the zone "<<auth_domain_iter->first.toString()<<endl);
              continue;
            } else {
              // ugly...
              LOG("YES! - This answer was retrieved from the local auth store"<<endl);
            }
          }
        }


        if(rec.d_name.isPartOf(auth)) {
          if(lwr.d_aabit && lwr.d_rcode==RCode::NoError && rec.d_place==DNSRecord::Answer && ::arg().contains("delegation-only",auth.toString() /* ugh */)) {
            LOG("NO! Is from delegation-only zone"<<endl);
            s_nodelegated++;
            return RCode::NXDomain;
          }
	  else if(rec.d_type == QType::RRSIG) {
	    LOG("RRSIG - separate"<<endl);
	  }
          else {
            LOG("YES!"<<endl);

            rec.d_ttl=min(s_maxcachettl, rec.d_ttl);

            DNSRecord dr(rec);
            dr.d_place=DNSRecord::Answer;

            dr.d_ttl += d_now.tv_sec;

            tcache[make_pair(rec.d_name,QType(rec.d_type))].records.push_back(dr);
          }
        }
        else
          LOG("NO!"<<endl);
      }

      // supplant
      for(tcache_t::iterator i=tcache.begin();i!=tcache.end();++i) {
        if(i->second.records.size() > 1) {  // need to group the ttl to be the minimum of the RRSET (RFC 2181, 5.2)
          uint32_t lowestTTL=std::numeric_limits<uint32_t>::max();
	  for(auto& record : i->second.records) 
            lowestTTL=min(lowestTTL, record.d_ttl);
          
	  for(auto& record : i->second.records) 
	    *const_cast<uint32_t*>(&record.d_ttl)=lowestTTL; // boom
        }

	//	cout<<"Have "<<i->second.records.size()<<" records and "<<i->second.signatures.size()<<" signatures for "<<i->first.first.toString();
	//	cout<<'|'<<DNSRecordContent::NumberToType(i->first.second.getCode())<<endl;
        t_RC->replace(d_now.tv_sec, i->first.first, i->first.second, i->second.records, i->second.signatures, lwr.d_aabit);
      }
      set<DNSName> nsset;
      LOG(prefix<<qname.toString()<<": determining status after receiving this packet"<<endl);

      bool done=false, realreferral=false, negindic=false, sawDS=false;
      DNSName newauth, soaname;
      DNSName newtarget;

      for(auto& rec : lwr.d_records) {
        if(rec.d_place==DNSRecord::Nameserver && rec.d_type==QType::SOA && 
           lwr.d_rcode==RCode::NXDomain && dottedEndsOn(qname,rec.d_name) && dottedEndsOn(rec.d_name, auth)) {
          LOG(prefix<<qname.toString()<<": got negative caching indication for name '"<<qname.toString()+"' (accept="<<dottedEndsOn(rec.d_name, auth)<<"), newtarget='"<<newtarget.toString()<<"'"<<endl);

          rec.d_ttl = min(rec.d_ttl, s_maxnegttl);
          if(!newtarget.length()) // only add a SOA if we're not going anywhere after this
            ret.push_back(rec);

          NegCacheEntry ne;

          ne.d_qname=rec.d_name;

          ne.d_ttd=d_now.tv_sec + rec.d_ttl;

          ne.d_name=qname;
          ne.d_qtype=QType(0); // this encodes 'whole record'

          replacing_insert(t_sstorage->negcache, ne);
	  if(s_rootNXTrust && auth.isRoot()) {
	    ne.d_name = getLastLabel(ne.d_name);
	    replacing_insert(t_sstorage->negcache, ne);
	  }

          negindic=true;
        }
        else if(rec.d_place==DNSRecord::Answer && rec.d_name == qname && rec.d_type==QType::CNAME && (!(qtype==QType(QType::CNAME)))) {
          ret.push_back(rec);
          newtarget=DNSName(rec.d_content->getZoneRepresentation());
        }
	else if(d_doDNSSEC && (rec.d_type==QType::RRSIG || rec.d_type==QType::NSEC || rec.d_type==QType::NSEC3) && rec.d_place==DNSRecord::Answer){
	  if(rec.d_type != QType::RRSIG || rec.d_name == qname)
	    ret.push_back(rec); // enjoy your DNSSEC
	}
        // for ANY answers we *must* have an authoritative answer, unless we are forwarding recursively
        else if(rec.d_place==DNSRecord::Answer && rec.d_name == qname &&
                (
                 rec.d_type==qtype.getCode() || (lwr.d_aabit && (qtype==QType(QType::ANY) || magicAddrMatch(qtype, QType(rec.d_type)) ) ) || sendRDQuery
                )
               )
          {

	    LOG(prefix<<qname.toString()<<": answer is in: resolved to '"<< rec.d_content->getZoneRepresentation()<<"|"<<DNSRecordContent::NumberToType(rec.d_type)<<"'"<<endl);

          done=true;
          ret.push_back(rec);
        }
        else if(rec.d_place==DNSRecord::Nameserver && qname.isPartOf(rec.d_name) && rec.d_type==QType::NS) {
          if(moreSpecificThan(rec.d_name,auth)) {
            newauth=rec.d_name;
            LOG(prefix<<qname.toString()<<": got NS record '"<<rec.d_name.toString()<<"' -> '"<<rec.d_content->getZoneRepresentation()<<"'"<<endl);
            realreferral=true;
          }
          else {
            LOG(prefix<<qname.toString()<<": got upwards/level NS record '"<<rec.d_name.toString()<<"' -> '"<<rec.d_content->getZoneRepresentation()<<"', had '"<<auth.toString()<<"'"<<endl);
	  }
          nsset.insert(DNSName(rec.d_content->getZoneRepresentation()));
        }
        else if(rec.d_place==DNSRecord::Nameserver && dottedEndsOn(qname,rec.d_name) && rec.d_type==QType::DS) { 
	  LOG(prefix<<qname.toString()<<": got DS record '"<<rec.d_name.toString()<<"' -> '"<<rec.d_content->getZoneRepresentation()<<"'"<<endl);
	  sawDS=true;
	}
        else if(!done && rec.d_place==DNSRecord::Nameserver && dottedEndsOn(qname,rec.d_name) && rec.d_type==QType::SOA && 
           lwr.d_rcode==RCode::NoError) {
          LOG(prefix<<qname.toString()<<": got negative caching indication for '"<< (qname.toString()+"|"+qtype.getName()+"'") <<endl);

          if(!newtarget.empty()) {
            LOG(prefix<<qname.toString()<<": Hang on! Got a redirect to '"<<newtarget.toString()<<"' already"<<endl);
          }
          else {
            rec.d_ttl = min(s_maxnegttl, rec.d_ttl);
            ret.push_back(rec);
            NegCacheEntry ne;
            ne.d_qname=rec.d_name;
            ne.d_ttd=d_now.tv_sec + rec.d_ttl;
            ne.d_name=qname;
            ne.d_qtype=qtype;
            if(qtype.getCode()) {  // prevents us from blacking out a whole domain
              replacing_insert(t_sstorage->negcache, ne);
            }
            negindic=true;
          }
        }
      }

      if(done){
        LOG(prefix<<qname.toString()<<": status=got results, this level of recursion done"<<endl);
        return 0;
      }
      if(!newtarget.empty()) {
        if(newtarget == qname) {
          LOG(prefix<<qname.toString()<<": status=got a CNAME referral to self, returning SERVFAIL"<<endl);
          return RCode::ServFail;
        }
        if(depth > 10) {
          LOG(prefix<<qname.toString()<<": status=got a CNAME referral, but recursing too deep, returning SERVFAIL"<<endl);
          return RCode::ServFail;
        }
        LOG(prefix<<qname.toString()<<": status=got a CNAME referral, starting over with "<<newtarget.toString()<<endl);

        set<GetBestNSAnswer> beenthere2;
        return doResolve(newtarget, qtype, ret, depth + 1, beenthere2);
      }
      if(lwr.d_rcode==RCode::NXDomain) {
        LOG(prefix<<qname.toString()<<": status=NXDOMAIN, we are done "<<(negindic ? "(have negative SOA)" : "")<<endl);
        return RCode::NXDomain;
      }
      if(nsset.empty() && !lwr.d_rcode && (negindic || lwr.d_aabit)) {
        LOG(prefix<<qname.toString()<<": status=noerror, other types may exist, but we are done "<<(negindic ? "(have negative SOA) " : "")<<(lwr.d_aabit ? "(have aa bit) " : "")<<endl);
        return 0;
      }
      else if(realreferral) {
        LOG(prefix<<qname.toString()<<": status=did not resolve, got "<<(unsigned int)nsset.size()<<" NS, looping to them"<<endl);
	if(sawDS) {
	  t_sstorage->dnssecmap[newauth]=true;
	  /*	  for(const auto& e : t_sstorage->dnssecmap)
	    cout<<e.first.toString()<<' ';
	    cout<<endl;*/
	}
        auth=newauth;
        nameservers=nsset;
        break;
      }
      else if(isCanonical(*tns)) { // means: not OOB (I think)
        goto wasLame;
      }
    }
  }
  return -1;
}


// used by PowerDNSLua - note that this neglects to add the packet count & statistics back to pdns_ercursor.cc
int directResolve(const std::string& qname, const QType& qtype, int qclass, vector<DNSRecord>& ret)
{
  struct timeval now;
  gettimeofday(&now, 0);

  SyncRes sr(now);
  int res = sr.beginResolve(DNSName(qname), QType(qtype), qclass, ret); // DNSName conversion XXX
  
  return res;
}
