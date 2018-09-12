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

#include "syncres.hh"
#include "lua-recursor4.hh"
#include "utility.hh"
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
#include "validate.hh"
#include "misc.hh"
#include "arguments.hh"
#include "lwres.hh"
#include "recursor_cache.hh"
#include "dnsparser.hh"
#include "dns_random.hh"
#include "lock.hh"
#include "ednssubnet.hh"
#include "cachecleaner.hh"
#include "rec-lua-conf.hh"
__thread SyncRes::StaticStorage* t_sstorage;

unsigned int SyncRes::s_maxnegttl;
unsigned int SyncRes::s_maxcachettl;
unsigned int SyncRes::s_packetcachettl;
unsigned int SyncRes::s_packetcacheservfailttl;
unsigned int SyncRes::s_serverdownmaxfails;
unsigned int SyncRes::s_serverdownthrottletime;
std::atomic<uint64_t> SyncRes::s_queries;
std::atomic<uint64_t> SyncRes::s_outgoingtimeouts;
std::atomic<uint64_t> SyncRes::s_outgoing4timeouts;
std::atomic<uint64_t> SyncRes::s_outgoing6timeouts;
std::atomic<uint64_t> SyncRes::s_outqueries;
std::atomic<uint64_t> SyncRes::s_tcpoutqueries;
std::atomic<uint64_t> SyncRes::s_throttledqueries;
std::atomic<uint64_t> SyncRes::s_dontqueries;
std::atomic<uint64_t> SyncRes::s_nodelegated;
std::atomic<uint64_t> SyncRes::s_unreachables;
unsigned int SyncRes::s_minimumTTL;
bool SyncRes::s_doIPv6;
bool SyncRes::s_nopacketcache;
bool SyncRes::s_rootNXTrust;
unsigned int SyncRes::s_maxqperq;
unsigned int SyncRes::s_maxtotusec;
unsigned int SyncRes::s_maxdepth;
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
  /* rfc6895 section 3.1 + RRSIG and NSEC3 */
  static const std::set<uint16_t> metaTypes = { QType::AXFR, QType::IXFR, QType::RRSIG, QType::NSEC3, QType::OPT, QType::TSIG, QType::TKEY, QType::MAILA, QType::MAILB };
  s_queries++;
  d_wasVariable=false;
  d_wasOutOfBand=false;

  if( (qtype.getCode() == QType::AXFR))
    return -1;

  static const DNSName arpa("1.0.0.127.in-addr.arpa."), localhost("localhost."), 
    versionbind("version.bind."), idserver("id.server."), versionpdns("version.pdns.");

  if( (qtype.getCode()==QType::PTR && qname==arpa) ||
      (qtype.getCode()==QType::A && qname==localhost)) {
    ret.clear();
    DNSRecord dr;
    dr.d_name=qname;
    dr.d_place = DNSResourceRecord::ANSWER;
    dr.d_type=qtype.getCode();
    dr.d_class=QClass::IN;
    dr.d_ttl=86400;
    if(qtype.getCode()==QType::PTR)
      dr.d_content=shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::PTR, 1, "localhost."));
    else
      dr.d_content=shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::A, 1, "127.0.0.1"));
    ret.push_back(dr);
    d_wasOutOfBand=true;
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
    dr.d_place = DNSResourceRecord::ANSWER;
    if(qname==versionbind  || qname==versionpdns)
      dr.d_content=shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::TXT, 3, "\""+::arg()["version-string"]+"\""));
    else
      dr.d_content=shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(QType::TXT, 3, "\""+s_serverID+"\""));

    ret.push_back(dr);
    d_wasOutOfBand=true;
    return 0;
  }

  if (metaTypes.count(qtype.getCode())) {
    return -1;
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
bool SyncRes::doOOBResolve(const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, unsigned int depth, int& res)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  LOG(prefix<<qname<<": checking auth storage for '"<<qname<<"|"<<qtype.getName()<<"'"<<endl);
  DNSName authdomain(qname);

  domainmap_t::const_iterator iter=getBestAuthZone(&authdomain);
  if(iter==t_sstorage->domainmap->end()) {
    LOG(prefix<<qname<<": auth storage has no zone for this query!"<<endl);
    return false;
  }
  LOG(prefix<<qname<<": auth storage has data, zone='"<<authdomain<<"'"<<endl);
  pair<AuthDomain::records_t::const_iterator, AuthDomain::records_t::const_iterator> range;

  range=iter->second.d_records.equal_range(tie(qname)); // partial lookup

  ret.clear();
  AuthDomain::records_t::const_iterator ziter;
  bool somedata=false;
  for(ziter=range.first; ziter!=range.second; ++ziter) {
    somedata=true;
    if(qtype.getCode()==QType::ANY || ziter->d_type==qtype.getCode() || ziter->d_type==QType::CNAME)  // let rest of nameserver do the legwork on this one
      ret.push_back(*ziter);
    else if(ziter->d_type == QType::NS && ziter->d_name.countLabels() > authdomain.countLabels()) { // we hit a delegation point!
      DNSRecord dr=*ziter;
      dr.d_place=DNSResourceRecord::AUTHORITY;
      ret.push_back(dr);
    }
  }
  if(!ret.empty()) {
    LOG(prefix<<qname<<": exact match in zone '"<<authdomain<<"'"<<endl);
    res=0;
    return true;
  }
  if(somedata) {
    LOG(prefix<<qname<<": found record in '"<<authdomain<<"', but nothing of the right type, sending SOA"<<endl);
    ziter=iter->second.d_records.find(boost::make_tuple(authdomain, QType::SOA));
    if(ziter!=iter->second.d_records.end()) {
      DNSRecord dr=*ziter;
      dr.d_place=DNSResourceRecord::AUTHORITY;
      ret.push_back(dr);
    }
    else
      LOG(prefix<<qname<<": can't find SOA record '"<<authdomain<<"' in our zone!"<<endl);
    res=RCode::NoError;
    return true;
  }

  LOG(prefix<<qname<<": nothing found so far in '"<<authdomain<<"', trying wildcards"<<endl);
  DNSName wcarddomain(qname);
  while(wcarddomain != iter->first && wcarddomain.chopOff()) {
    LOG(prefix<<qname<<": trying '*."<<wcarddomain<<"' in "<<authdomain<<endl);
    range=iter->second.d_records.equal_range(boost::make_tuple(DNSName("*")+wcarddomain));
    if(range.first==range.second)
      continue;

    for(ziter=range.first; ziter!=range.second; ++ziter) {
      DNSRecord dr=*ziter;
      if(dr.d_type == qtype.getCode() || qtype.getCode() == QType::ANY) {
        dr.d_name = qname;
        dr.d_place=DNSResourceRecord::ANSWER;
        ret.push_back(dr);
      }
    }
    LOG(prefix<<qname<<": in '"<<authdomain<<"', had wildcard match on '*."<<wcarddomain<<"'"<<endl);
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
      dr.d_place=DNSResourceRecord::AUTHORITY;
      ret.push_back(dr);
    }
  }
  if(ret.empty()) {
    LOG(prefix<<qname<<": no NS match in zone '"<<authdomain<<"' either, handing out SOA"<<endl);
    ziter=iter->second.d_records.find(boost::make_tuple(authdomain, QType::SOA));
    if(ziter!=iter->second.d_records.end()) {
      DNSRecord dr=*ziter;
      dr.d_place=DNSResourceRecord::AUTHORITY;
      ret.push_back(dr);
    }
    else {
      LOG(prefix<<qname<<": can't find SOA record '"<<authdomain<<"' in our zone!"<<endl);
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
  if (!fp) {
    return;
  }
  fprintf(fp,"IP Address\tMode\tMode last updated at\n");
  for(const auto& eds : t_sstorage->ednsstatus) {
    fprintf(fp, "%s\t%d\t%s", eds.first.toString().c_str(), (int)eds.second.mode, ctime(&eds.second.modeSetAt));
  }

  fclose(fp);
}

/* so here is the story. First we complete the full resolution process for a domain name. And only THEN do we decide
   to also do DNSSEC validation, which leads to new queries. To make this simple, we *always* ask for DNSSEC records
   so that if there are RRSIGs for a name, we'll have them.

   However, some hosts simply can't answer questions which ask for DNSSEC. This can manifest itself as:
   * No answer
   * FormErr
   * Nonsense answer

   The cause of "No answer" may be fragmentation, and it is tempting to probe if smaller answers would get through.
   Another cause of "No answer" may simply be a network condition.
   Nonsense answers are a clearer indication this host won't be able to do DNSSEC evah.

   Previous implementations have suffered from turning off DNSSEC questions for an authoritative server based on timeouts. 
   A clever idea is to only turn off DNSSEC if we know a domain isn't signed anyhow. The problem with that really
   clever idea however is that at this point in PowerDNS, we may simply not know that yet. All the DNSSEC thinking happens 
   elsewhere. It may not have happened yet. 

   For now this means we can't be clever, but will turn off DNSSEC if you reply with FormError or gibberish.
*/

int SyncRes::asyncresolveWrapper(const ComboAddress& ip, bool wantsEDNS, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, struct timeval* now, boost::optional<Netmask>& srcmask, LWResult* res)
{
  /* what is your QUEST?
     the goal is to get as many remotes as possible on the highest level of EDNS support
     The levels are:

     0) UNKNOWN Unknown state 
     1) EDNS: Honors EDNS0
     2) EDNSIGNORANT: Ignores EDNS0, gives replies without EDNS0
     3) NOEDNS: Generates FORMERR/NOTIMP on EDNS queries

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

  SyncRes::EDNSStatus* ednsstatus;
  ednsstatus = &t_sstorage->ednsstatus[ip]; // does this include port? 

  if(ednsstatus->modeSetAt && ednsstatus->modeSetAt + 3600 < d_now.tv_sec) {
    *ednsstatus=SyncRes::EDNSStatus();
    //    cerr<<"Resetting EDNS Status for "<<ip.toString()<<endl);
  }

  SyncRes::EDNSStatus::EDNSMode& mode=ednsstatus->mode;
  SyncRes::EDNSStatus::EDNSMode oldmode = mode;
  int EDNSLevel = 0;
  auto luaconfsLocal = g_luaconfs.getLocal();
  ResolveContext ctx;
#ifdef HAVE_PROTOBUF
  ctx.d_initialRequestId = d_initialRequestId;
#endif

  int ret;
  for(int tries = 0; tries < 3; ++tries) {
    //    cerr<<"Remote '"<<ip.toString()<<"' currently in mode "<<mode<<endl;
    
    if(mode==EDNSStatus::NOEDNS) {
      g_stats.noEdnsOutQueries++;
      if (wantsEDNS) {
        LOG("Remote " + ip.toString() + " does not support EDNS!");
      }
      EDNSLevel = 0; // level != mode
    }
    else if(mode==EDNSStatus::UNKNOWN || mode==EDNSStatus::EDNSOK || mode==EDNSStatus::EDNSIGNORANT)
      EDNSLevel = 1;
    
    DNSName sendQname(domain);
    if (g_lowercaseOutgoing)
      sendQname = sendQname.makeLowerCase();

    ret=asyncresolve(ip, sendQname, type, doTCP, sendRDQuery, EDNSLevel, now, srcmask, ctx, luaconfsLocal->outgoingProtobufServer, res);
    if(ret < 0) {
      return ret; // transport error, nothing to learn here
    }

    if(ret == 0) { // timeout, not doing anything with it now
      return ret;
    }
    else if(mode==EDNSStatus::UNKNOWN || mode==EDNSStatus::EDNSOK || mode == EDNSStatus::EDNSIGNORANT ) {
      if(res->d_rcode == RCode::FormErr || res->d_rcode == RCode::NotImp)  {
	//	cerr<<"Downgrading to NOEDNS because of "<<RCode::to_s(res->d_rcode)<<" for query to "<<ip.toString()<<" for '"<<domain<<"'"<<endl;
        mode = EDNSStatus::NOEDNS;
        continue;
      }
      else if(!res->d_haveEDNS) {
        if(mode != EDNSStatus::EDNSIGNORANT) {
          mode = EDNSStatus::EDNSIGNORANT;
	  //	  cerr<<"We find that "<<ip.toString()<<" is an EDNS-ignorer for '"<<domain<<"', moving to mode 3"<<endl;
	}
      }
      else {
	mode = EDNSStatus::EDNSOK;
	//	cerr<<"We find that "<<ip.toString()<<" is EDNS OK!"<<endl;
      }
      
    }
    if(oldmode != mode || !ednsstatus->modeSetAt)
      ednsstatus->modeSetAt=d_now.tv_sec;
    //    cerr<<"Result: ret="<<ret<<", EDNS-level: "<<EDNSLevel<<", haveEDNS: "<<res->d_haveEDNS<<", new mode: "<<mode<<endl;  
    return ret;
  }
  return ret;
}

int SyncRes::doResolve(const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, unsigned int depth, set<GetBestNSAnswer>& beenthere)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  LOG(prefix<<qname<<": Wants "<< (d_doDNSSEC ? "" : "NO ") << "DNSSEC processing in query for "<<qtype.getName()<<endl);

  if(s_maxdepth && depth > s_maxdepth)
    throw ImmediateServFailException("More than "+std::to_string(s_maxdepth)+" (max-recursion-depth) levels of recursion needed while resolving "+qname.toLogString());

  int res=0;
  if(!(d_nocache && qtype.getCode()==QType::NS && qname.isRoot())) {
    if(d_cacheonly) { // very limited OOB support
      LWResult lwr;
      LOG(prefix<<qname<<": Recursion not requested for '"<<qname<<"|"<<qtype.getName()<<"', peeking at auth/forward zones"<<endl);
      DNSName authname(qname);
      domainmap_t::const_iterator iter=getBestAuthZone(&authname);
      if(iter != t_sstorage->domainmap->end()) {
        const vector<ComboAddress>& servers = iter->second.d_servers;
        if(servers.empty()) {
          ret.clear();
          d_wasOutOfBand = doOOBResolve(qname, qtype, ret, depth, res);
          return res;
        }
        else {
          const ComboAddress remoteIP = servers.front();
          LOG(prefix<<qname<<": forwarding query to hardcoded nameserver '"<< remoteIP.toStringWithPort()<<"' for zone '"<<authname<<"'"<<endl);

          boost::optional<Netmask> nm;
          res=asyncresolveWrapper(remoteIP, d_doDNSSEC, qname, qtype.getCode(), false, false, &d_now, nm, &lwr);
          // filter out the good stuff from lwr.result()
          if (res == 1) {
            for(const auto& rec : lwr.d_records) {
              if(rec.d_place == DNSResourceRecord::ANSWER)
                ret.push_back(rec);
            }
            return 0;
          }
          else {
            return RCode::ServFail;
          }
        }
      }
    }

    if(!d_skipCNAMECheck && doCNAMECacheCheck(qname,qtype,ret,depth,res)) // will reroute us if needed
      return res;

    if(doCacheCheck(qname,qtype,ret,depth,res)) // we done
      return res;
  }

  if(d_cacheonly)
    return 0;

  LOG(prefix<<qname<<": No cache hit for '"<<qname<<"|"<<qtype.getName()<<"', trying to find an appropriate NS record"<<endl);

  DNSName subdomain(qname);
  if(qtype == QType::DS) subdomain.chopOff();

  NsSet nsset;
  bool flawedNSSet=false;

  // the two retries allow getBestNSNamesFromCache&co to reprime the root
  // hints, in case they ever go missing
  for(int tries=0;tries<2 && nsset.empty();++tries) {
    subdomain=getBestNSNamesFromCache(subdomain, qtype, nsset, &flawedNSSet, depth, beenthere); //  pass beenthere to both occasions
  }

  if(!(res=doResolveAt(nsset, subdomain, flawedNSSet, qname, qtype, ret, depth, beenthere)))
    return 0;

  LOG(prefix<<qname<<": failed (res="<<res<<")"<<endl);
  ;

  if (res == -2)
    return res;

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
vector<ComboAddress> SyncRes::getAddrs(const DNSName &qname, unsigned int depth, set<GetBestNSAnswer>& beenthere)
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
	  if(auto rec = getRR<ARecordContent>(*i))
	    ret.push_back(rec->getCA(53));
	  else if(auto aaaarec = getRR<AAAARecordContent>(*i))
	    ret.push_back(aaaarec->getCA(53));
          done=true;
        }
      }
    }
    if(done) {
      if(j==1 && s_doIPv6) { // we got an A record, see if we have some AAAA lying around
	vector<DNSRecord> cset;
	if(t_RC->get(d_now.tv_sec, qname, QType(QType::AAAA), &cset, d_incomingECSFound ? d_incomingECSNetwork : d_requestor) > 0) {
	  for(auto k=cset.cbegin();k!=cset.cend();++k) {
	    if(k->d_ttl > (unsigned int)d_now.tv_sec ) {
	      if (auto drc = getRR<AAAARecordContent>(*k)) {
	        ComboAddress ca=drc->getCA(53);
	        ret.push_back(ca);
	      }
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

void SyncRes::getBestNSFromCache(const DNSName &qname, const QType& qtype, vector<DNSRecord>& bestns, bool* flawedNSSet, unsigned int depth, set<GetBestNSAnswer>& beenthere)
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
    LOG(prefix<<qname<<": Checking if we have NS in cache for '"<<subdomain<<"'"<<endl);
    vector<DNSRecord> ns;
    *flawedNSSet = false;
    if(t_RC->get(d_now.tv_sec, subdomain, QType(QType::NS), &ns, d_incomingECSFound ? d_incomingECSNetwork : d_requestor) > 0) {
      for(auto k=ns.cbegin();k!=ns.cend(); ++k) {
        if(k->d_ttl > (unsigned int)d_now.tv_sec ) {
          vector<DNSRecord> aset;

          const DNSRecord& dr=*k;
	  auto nrr = getRR<NSRecordContent>(dr);
          if(nrr && (!nrr->getNS().isPartOf(subdomain) || t_RC->get(d_now.tv_sec, nrr->getNS(), s_doIPv6 ? QType(QType::ADDR) : QType(QType::A),
                                                                    doLog() ? &aset : 0, d_incomingECSFound ? d_incomingECSNetwork : d_requestor) > 5)) {
            bestns.push_back(dr);
            LOG(prefix<<qname<<": NS (with ip, or non-glue) in cache for '"<<subdomain<<"' -> '"<<nrr->getNS()<<"'"<<endl);
            LOG(prefix<<qname<<": within bailiwick: "<< nrr->getNS().isPartOf(subdomain));
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
	for(const auto& dr : bestns) {
          if (auto nsContent = getRR<NSRecordContent>(dr)) {
            answer.bestns.insert(make_pair(dr.d_name, nsContent->getNS()));
          }
        }

        if(beenthere.count(answer)) {
	  brokeloop=true;
          LOG(prefix<<qname<<": We have NS in cache for '"<<subdomain<<"' but part of LOOP (already seen "<<answer.qname<<")! Trying less specific NS"<<endl);
	  ;
          if(doLog())
            for( set<GetBestNSAnswer>::const_iterator j=beenthere.begin();j!=beenthere.end();++j) {
	      bool neo = !(*j< answer || answer<*j);
	      LOG(prefix<<qname<<": beenthere"<<(neo?"*":"")<<": "<<j->qname<<"|"<<DNSRecordContent::NumberToType(j->qtype)<<" ("<<(unsigned int)j->bestns.size()<<")"<<endl);
            }
          bestns.clear();
        }
        else {
	  beenthere.insert(answer);
          LOG(prefix<<qname<<": We have NS in cache for '"<<subdomain<<"' (flawedNSSet="<<*flawedNSSet<<")"<<endl);
          return;
        }
      }
    }
    LOG(prefix<<qname<<": no valid/useful NS in cache for '"<<subdomain<<"'"<<endl);
    ;
    if(subdomain.isRoot() && !brokeloop) {
      // We lost the root NS records
      primeHints();
      LOG(prefix<<qname<<": reprimed the root"<<endl);
      getRootNS();
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
DNSName SyncRes::getBestNSNamesFromCache(const DNSName &qname, const QType& qtype, NsSet& nsset, bool* flawedNSSet, unsigned int depth, set<GetBestNSAnswer>&beenthere)
{
  DNSName subdomain(qname);
  DNSName authdomain(qname);

  domainmap_t::const_iterator iter=getBestAuthZone(&authdomain);
  if(iter!=t_sstorage->domainmap->end()) {
    if( iter->second.d_servers.empty() )
      // this gets picked up in doResolveAt, the empty DNSName, combined with the
      // empty vector means 'we are auth for this zone'
      nsset.insert({DNSName(), {{}, false}});
    else {
      // Again, picked up in doResolveAt. An empty DNSName, combined with a
      // non-empty vector of ComboAddresses means 'this is a forwarded domain'
      nsset.insert({DNSName(), {iter->second.d_servers, iter->second.d_rdForward}});
    }
    return authdomain;
  }

  vector<DNSRecord> bestns;
  getBestNSFromCache(subdomain, qtype, bestns, flawedNSSet, depth, beenthere);

  for(auto k=bestns.cbegin() ; k != bestns.cend(); ++k) {
    // The actual resolver code will not even look at the ComboAddress or bool
    if (auto nsContent = getRR<NSRecordContent>(*k)) {
      nsset.insert({nsContent->getNS(), {{}, false}});
      if(k==bestns.cbegin())
        subdomain=k->d_name;
    }
  }
  return subdomain;
}

bool SyncRes::doCNAMECacheCheck(const DNSName &qname, const QType &qtype, vector<DNSRecord>& ret, unsigned int depth, int &res)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  if((depth>9 && d_outqueries>10 && d_throttledqueries>5) || depth > 15) {
    LOG(prefix<<qname<<": recursing (CNAME or other indirection) too deep, depth="<<depth<<endl);
    res=RCode::ServFail;
    return true;
  }

  LOG(prefix<<qname<<": Looking for CNAME cache hit of '"<<qname<<"|CNAME"<<"'"<<endl);
  vector<DNSRecord> cset;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  if(t_RC->get(d_now.tv_sec, qname,QType(QType::CNAME), &cset, d_incomingECSFound ? d_incomingECSNetwork : d_requestor, &signatures, &d_wasVariable) > 0) {

    for(auto j=cset.cbegin() ; j != cset.cend() ; ++j) {
      if (j->d_class != QClass::IN) {
        continue;
      }

      if(j->d_ttl>(unsigned int) d_now.tv_sec) {
        LOG(prefix<<qname<<": Found cache CNAME hit for '"<< qname << "|CNAME" <<"' to '"<<j->d_content->getZoneRepresentation()<<"'"<<endl);
        DNSRecord dr=*j;
        dr.d_ttl-=d_now.tv_sec;
        ret.push_back(dr);

	for(const auto& signature : signatures) {
	  DNSRecord sigdr;
	  sigdr.d_type=QType::RRSIG;
	  sigdr.d_name=qname;
	  sigdr.d_ttl=j->d_ttl - d_now.tv_sec;
	  sigdr.d_content=signature;
	  sigdr.d_place=DNSResourceRecord::ANSWER;
	  sigdr.d_class=1;
	  ret.push_back(sigdr);
	}

        if(!(qtype==QType(QType::CNAME))) { // perhaps they really wanted a CNAME!
          set<GetBestNSAnswer>beenthere;
          const auto cnameContent = getRR<CNAMERecordContent>(*j);
          if (cnameContent) {
            res=doResolve(cnameContent->getTarget(), qtype, ret, depth+1, beenthere);
          }
        }
        else
          res=0;
        return true;
      }
    }
  }
  LOG(prefix<<qname<<": No CNAME cache hit of '"<< qname << "|CNAME" <<"' found"<<endl);
  return false;
}

static const DNSName getLastLabel(const DNSName& qname)
{
  DNSName ret(qname);
  ret.trimToLabels(1);
  return ret;
}


bool SyncRes::doCacheCheck(const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, unsigned int depth, int &res)
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
  //  cout<<"Lookup for '"<<qname<<"|"<<qtype.getName()<<"' -> "<<getLastLabel(qname)<<endl;

  pair<negcache_t::const_iterator, negcache_t::const_iterator> range;
  QType qtnull(0);

  DNSName authname(qname);
  bool wasForwardedOrAuth = false;
  bool wasAuth = false;
  domainmap_t::const_iterator iter=getBestAuthZone(&authname);
  if(iter != t_sstorage->domainmap->end()) {
    wasForwardedOrAuth = true;
    const vector<ComboAddress>& servers = iter->second.d_servers;
    if(servers.empty()) {
      wasAuth = true;
    }
  }

  if(s_rootNXTrust &&
     (range.first=t_sstorage->negcache.find(tie(getLastLabel(qname), qtnull))) != t_sstorage->negcache.end() &&
      !(wasForwardedOrAuth && !authname.isRoot()) && // when forwarding, the root may only neg-cache if it was forwarded to.
      range.first->d_qname.isRoot() && (uint32_t)d_now.tv_sec < range.first->d_ttd) {
    sttl=range.first->d_ttd - d_now.tv_sec;

    LOG(prefix<<qname<<": Entire name '"<<qname<<"', is negatively cached via '"<<range.first->d_name<<"' & '"<<range.first->d_qname<<"' for another "<<sttl<<" seconds"<<endl);
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
      if(!(wasForwardedOrAuth && ni->d_qname != authname) && // Only the authname nameserver can neg cache entries
         (ni->d_qtype.getCode() == 0 || ni->d_qtype == qtype)) {
	res=0;
	if((uint32_t)d_now.tv_sec < ni->d_ttd) {
	  sttl=ni->d_ttd - d_now.tv_sec;
	  if(ni->d_qtype.getCode()) {
	    LOG(prefix<<qname<<": "<<qtype.getName()<<" is negatively cached via '"<<ni->d_qname<<"' for another "<<sttl<<" seconds"<<endl);
	    res = RCode::NoError;
	  }
	  else {
	    LOG(prefix<<qname<<": Entire name '"<<qname<<"', is negatively cached via '"<<ni->d_qname<<"' for another "<<sttl<<" seconds"<<endl);
	    res= RCode::NXDomain;
	  }
	  giveNegative=true;
	  sqname=ni->d_qname;
	  sqt=QType::SOA;
          if(d_doDNSSEC) {
            for(const auto& p : ni->d_dnssecProof) {
              for(const auto& rec: p.second.records) 
                ret.push_back(rec);
              for(const auto& rec: p.second.signatures) 
                ret.push_back(rec);
            }
          }
	  moveCacheItemToBack(t_sstorage->negcache, ni);
	  break;
	}
	else {
	  LOG(prefix<<qname<<": Entire name '"<<qname<<"' or type was negatively cached, but entry expired"<<endl);
	  moveCacheItemToFront(t_sstorage->negcache, ni);
	}
      }
    }
  }
  vector<DNSRecord> cset;
  bool found=false, expired=false;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  uint32_t ttl=0;
  if(t_RC->get(d_now.tv_sec, sqname, sqt, &cset, d_incomingECSFound ? d_incomingECSNetwork : d_requestor, d_doDNSSEC ? &signatures : 0, &d_wasVariable) > 0) {
    LOG(prefix<<sqname<<": Found cache hit for "<<sqt.getName()<<": ");
    for(auto j=cset.cbegin() ; j != cset.cend() ; ++j) {

      LOG(j->d_content->getZoneRepresentation());

      if (j->d_class != QClass::IN) {
        continue;
      }

      if(j->d_ttl>(unsigned int) d_now.tv_sec) {
        DNSRecord dr=*j;
        ttl = (dr.d_ttl-=d_now.tv_sec);
        if(giveNegative) {
          dr.d_place=DNSResourceRecord::AUTHORITY;
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
      dr.d_place= giveNegative ? DNSResourceRecord::AUTHORITY : DNSResourceRecord::ANSWER;
      dr.d_class=1;
      ret.push_back(dr);
    }
  
    LOG(endl);
    if(found && !expired) {
      if(!giveNegative)
        res=0;
      d_wasOutOfBand = wasAuth;
      return true;
    }
    else
      LOG(prefix<<qname<<": cache had only stale entries"<<endl);
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

inline vector<DNSName> SyncRes::shuffleInSpeedOrder(NsSet &tnameservers, const string &prefix)
{
  vector<DNSName> rnameservers;
  rnameservers.reserve(tnameservers.size());
  for(const auto& tns:tnameservers) {
    rnameservers.push_back(tns.first);
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
      LOG((i->empty() ? string("<empty>") : i->toString())<<"(" << (boost::format("%0.2f") % (speeds[*i]/1000.0)).str() <<"ms)");
    }
    LOG(endl);
  }
  return rnameservers;
}

static bool magicAddrMatch(const QType& query, const QType& answer)
{
  if(query.getCode() != QType::ADDR)
    return false;
  return answer.getCode() == QType::A || answer.getCode() == QType::AAAA;
}


recsig_t harvestRecords(const vector<DNSRecord>& records, const set<uint16_t>& types)
{
  recsig_t ret;
  for(const auto& rec : records) {
    if(rec.d_type == QType::RRSIG) {
      auto rrs=getRR<RRSIGRecordContent>(rec);
      if(rrs && types.count(rrs->d_type))
	ret[make_pair(rec.d_name, rrs->d_type)].signatures.push_back(rec);
    }
    else if(types.count(rec.d_type))
      ret[make_pair(rec.d_name, rec.d_type)].records.push_back(rec);
  }
  return ret;
}

static void addNXNSECS(vector<DNSRecord>&ret, const vector<DNSRecord>& records)
{
  auto csp = harvestRecords(records, {QType::NSEC, QType::NSEC3, QType::SOA});
  for(const auto& c : csp) {
    if(c.first.second == QType::NSEC || c.first.second == QType::NSEC3 || c.first.second == QType::SOA) {
      if(c.first.second !=QType::SOA) {
	for(const auto& rec : c.second.records)
	  ret.push_back(rec);
      }
      for(const auto& rec : c.second.signatures)
	ret.push_back(rec);
    }
  }
}

/** returns:
 *  -1 in case of no results
 *  -2 when a FilterEngine Policy was hit
 *  rcode otherwise
 */
int SyncRes::doResolveAt(NsSet &nameservers, DNSName auth, bool flawedNSSet, const DNSName &qname, const QType &qtype,
                         vector<DNSRecord>&ret,
                         unsigned int depth, set<GetBestNSAnswer>&beenthere)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  LOG(prefix<<qname<<": Cache consultations done, have "<<(unsigned int)nameservers.size()<<" NS to contact");

  if(d_wantsRPZ) {
    for (auto const &ns : nameservers) {
      d_appliedPolicy = g_luaconfs.getLocal()->dfe.getProcessingPolicy(ns.first, d_discardedPolicies);
      if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
        LOG(", however nameserver "<<ns.first<<" was blocked by RPZ policy '"<<(d_appliedPolicy.d_name ? *d_appliedPolicy.d_name : "")<<"'"<<endl);
        return -2;
      }

      // Traverse all IP addresses for this NS to see if they have an RPN NSIP policy
      for (auto const &address : ns.second.first) {
        d_appliedPolicy = g_luaconfs.getLocal()->dfe.getProcessingPolicy(address, d_discardedPolicies);
        if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
          LOG(", however nameserver "<<ns.first<<" IP address "<<address.toString()<<" was blocked by RPZ policy '"<<(d_appliedPolicy.d_name ? *d_appliedPolicy.d_name : "")<<"'"<<endl);
          return -2;
        }
      }
    }
  }

  LOG(endl);

  for(;;) { // we may get more specific nameservers
    vector<DNSName > rnameservers = shuffleInSpeedOrder(nameservers, doLog() ? (prefix+qname.toString()+": ") : string() );

    for(vector<DNSName >::const_iterator tns=rnameservers.begin();;++tns) {
      if(tns==rnameservers.end()) {
        LOG(prefix<<qname<<": Failed to resolve via any of the "<<(unsigned int)rnameservers.size()<<" offered NS at level '"<<auth<<"'"<<endl);
        if(!auth.isRoot() && flawedNSSet) {
          LOG(prefix<<qname<<": Ageing nameservers for level '"<<auth<<"', next query might succeed"<<endl);

          if(t_RC->doAgeCache(d_now.tv_sec, auth, QType::NS, 10))
            g_stats.nsSetInvalidations++;
        }
        return -1;
      }
      // this line needs to identify the 'self-resolving' behaviour, but we get it wrong now
      if(qname == *tns && qtype.getCode()==QType::A && rnameservers.size() > (unsigned)(1+1*s_doIPv6)) {
        LOG(prefix<<qname<<": Not using NS to resolve itself! ("<<(1+tns-rnameservers.begin())<<"/"<<rnameservers.size()<<")"<<endl);
        continue;
      }

      typedef vector<ComboAddress> remoteIPs_t;
      remoteIPs_t remoteIPs;
      remoteIPs_t::const_iterator remoteIP;
      bool doTCP=false;
      int resolveret;
      bool pierceDontQuery=false;
      bool sendRDQuery=false;
      boost::optional<Netmask> ednsmask;
      LWResult lwr;
      if(tns->empty() && nameservers[*tns].first.empty() ) {
        LOG(prefix<<qname<<": Domain is out-of-band"<<endl);
        d_wasOutOfBand = doOOBResolve(qname, qtype, lwr.d_records, depth, lwr.d_rcode);
        lwr.d_tcbit=false;
        lwr.d_aabit=true;
      }
      else {
        if(!tns->empty()) {
          LOG(prefix<<qname<<": Trying to resolve NS '"<<*tns<< "' ("<<1+tns-rnameservers.begin()<<"/"<<(unsigned int)rnameservers.size()<<")"<<endl);
        }

        if(tns->empty()) {
          LOG(prefix<<qname<<": Domain has hardcoded nameserver");

          remoteIPs = nameservers[*tns].first;
          if(remoteIPs.size() > 1) {
            LOG("s");
          }
          LOG(endl);

          sendRDQuery = nameservers[*tns].second;
          pierceDontQuery=true;
        }
        else {
          remoteIPs=getAddrs(*tns, depth+2, beenthere);
          pierceDontQuery=false;
        }

        if(remoteIPs.empty()) {
          LOG(prefix<<qname<<": Failed to get IP for NS "<<*tns<<", trying next if available"<<endl);
          flawedNSSet=true;
          continue;
        }
        else {
          bool hitPolicy{false};
          LOG(prefix<<qname<<": Resolved '"<<auth<<"' NS "<<*tns<<" to: ");
          for(remoteIP = remoteIPs.begin(); remoteIP != remoteIPs.end(); ++remoteIP) {
            if(remoteIP != remoteIPs.begin()) {
              LOG(", ");
            }
            LOG(remoteIP->toString());
            if (d_wantsRPZ) {
              d_appliedPolicy = g_luaconfs.getLocal()->dfe.getProcessingPolicy(*remoteIP, d_discardedPolicies);
              if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) {
                hitPolicy = true;
                LOG(" (blocked by RPZ policy '"+(d_appliedPolicy.d_name ? *d_appliedPolicy.d_name : "")+"')");
              }
            }
          }
          LOG(endl);
          if (hitPolicy) //implies d_wantsRPZ
            return -2;
        }

        for(remoteIP = remoteIPs.begin(); remoteIP != remoteIPs.end(); ++remoteIP) {
          LOG(prefix<<qname<<": Trying IP "<< remoteIP->toStringWithPort() <<", asking '"<<qname<<"|"<<qtype.getName()<<"'"<<endl);
          extern NetmaskGroup* g_dontQuery;

          if(t_sstorage->throttle.shouldThrottle(d_now.tv_sec, boost::make_tuple(*remoteIP, "", 0))) {
            LOG(prefix<<qname<<": server throttled "<<endl);
            s_throttledqueries++; d_throttledqueries++;
            continue;
          }
          else if(t_sstorage->throttle.shouldThrottle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()))) {
            LOG(prefix<<qname<<": query throttled "<<endl);
            s_throttledqueries++; d_throttledqueries++;
            continue;
          }
          else if(!pierceDontQuery && g_dontQuery && g_dontQuery->match(&*remoteIP)) {
            LOG(prefix<<qname<<": not sending query to " << remoteIP->toString() << ", blocked by 'dont-query' setting" << endl);
            s_dontqueries++;
            continue;
          }
          else {
            s_outqueries++; d_outqueries++;
            if(d_outqueries + d_throttledqueries > s_maxqperq) throw ImmediateServFailException("more than "+std::to_string(s_maxqperq)+" (max-qperq) queries sent while resolving "+qname.toLogString());
          TryTCP:
            if(doTCP) {
              LOG(prefix<<qname<<": using TCP with "<< remoteIP->toStringWithPort() <<endl);
              s_tcpoutqueries++; d_tcpoutqueries++;
            }

	    if(s_maxtotusec && d_totUsec > s_maxtotusec)
	      throw ImmediateServFailException("Too much time waiting for "+qname.toLogString()+"|"+qtype.getName()+", timeouts: "+std::to_string(d_timeouts) +", throttles: "+std::to_string(d_throttledqueries) + ", queries: "+std::to_string(d_outqueries)+", "+std::to_string(d_totUsec/1000)+"msec");

	    if(d_pdl && d_pdl->preoutquery(*remoteIP, d_requestor, qname, qtype, doTCP, lwr.d_records, resolveret)) {
	      LOG(prefix<<qname<<": query handled by Lua"<<endl);
	    }
	    else {
	      ednsmask=getEDNSSubnetMask(d_requestor, qname, *remoteIP, d_incomingECSFound ? d_incomingECS : boost::none);
              if(ednsmask) {
                LOG(prefix<<qname<<": Adding EDNS Client Subnet Mask "<<ednsmask->toString()<<" to query"<<endl);
              }
	      resolveret=asyncresolveWrapper(*remoteIP, d_doDNSSEC, qname,  qtype.getCode(),
					     doTCP, sendRDQuery, &d_now, ednsmask, &lwr);    // <- we go out on the wire!
              if(ednsmask) {
                LOG(prefix<<qname<<": Received EDNS Client Subnet Mask "<<ednsmask->toString()<<" on response"<<endl);
              }


	    }
            if(resolveret==-3)
	      throw ImmediateServFailException("Query killed by policy");

	    d_totUsec += lwr.d_usec;
	    accountAuthLatency(lwr.d_usec, remoteIP->sin4.sin_family);
	    if(resolveret != 1) {
              if(resolveret==0) {
                LOG(prefix<<qname<<": timeout resolving after "<<lwr.d_usec/1000.0<<"msec "<< (doTCP ? "over TCP" : "")<<endl);
                d_timeouts++;
                s_outgoingtimeouts++;
		if(remoteIP->sin4.sin_family == AF_INET)
		  s_outgoing4timeouts++;
		else
		  s_outgoing6timeouts++;
              }
              else if(resolveret==-2) {
                LOG(prefix<<qname<<": hit a local resource limit resolving"<< (doTCP ? " over TCP" : "")<<", probable error: "<<stringerror()<<endl);
                g_stats.resourceLimits++;
              }
              else {
                s_unreachables++; d_unreachables++;
                LOG(prefix<<qname<<": error resolving from "<<remoteIP->toString()<< (doTCP ? " over TCP" : "") <<", possible error: "<<strerror(errno)<< endl);
              }

              if(resolveret!=-2) { // don't account for resource limits, they are our own fault
		t_sstorage->nsSpeeds[*tns].submit(*remoteIP, 1000000, &d_now); // 1 sec

		// code below makes sure we don't filter COM or the root
                if (s_serverdownmaxfails > 0 && (auth != DNSName(".")) && t_sstorage->fails.incr(*remoteIP) >= s_serverdownmaxfails) {
                  LOG(prefix<<qname<<": Max fails reached resolving on "<< remoteIP->toString() <<". Going full throttle for "<< s_serverdownthrottletime <<" seconds" <<endl);
                  t_sstorage->throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, "", 0), s_serverdownthrottletime, 10000); // mark server as down
                } else if(resolveret==-1)
                  t_sstorage->throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()), 60, 100); // unreachable, 1 minute or 100 queries
                else
                  t_sstorage->throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()), 10, 5);  // timeout
              }
              continue;
            }

//	    if(d_timeouts + 0.5*d_throttledqueries > 6.0 && d_timeouts > 2) throw ImmediateServFailException("Too much work resolving "+qname+"|"+qtype.getName()+", timeouts: "+std::to_string(d_timeouts) +", throttles: "+std::to_string(d_throttledqueries));

            if(lwr.d_rcode==RCode::ServFail || lwr.d_rcode==RCode::Refused) {
              LOG(prefix<<qname<<": "<<*tns<<" ("<<remoteIP->toString()<<") returned a "<< (lwr.d_rcode==RCode::ServFail ? "ServFail" : "Refused") << ", trying sibling IP or NS"<<endl);
              t_sstorage->throttle.throttle(d_now.tv_sec,boost::make_tuple(*remoteIP, qname, qtype.getCode()),60,3); // servfail or refused
              continue;
            }

            if(s_serverdownmaxfails > 0)
              t_sstorage->fails.clear(*remoteIP);

            break;  // this IP address worked!
          wasLame:; // well, it didn't
            LOG(prefix<<qname<<": status=NS "<<*tns<<" ("<< remoteIP->toString() <<") is lame for '"<<auth<<"', trying sibling IP or NS"<<endl);
            t_sstorage->throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()), 60, 100); // lame
          }
        }

        if(remoteIP == remoteIPs.end())  // we tried all IP addresses, none worked
          continue;

        if(lwr.d_tcbit) {
          if(!doTCP) {
            doTCP=true;
            LOG(prefix<<qname<<": truncated bit set, retrying via TCP"<<endl);
            goto TryTCP;
          }
          LOG(prefix<<qname<<": truncated bit set, over TCP?"<<endl);
          return RCode::ServFail;
        }
        LOG(prefix<<qname<<": Got "<<(unsigned int)lwr.d_records.size()<<" answers from "<<*tns<<" ("<< remoteIP->toString() <<"), rcode="<<lwr.d_rcode<<" ("<<RCode::to_s(lwr.d_rcode)<<"), aa="<<lwr.d_aabit<<", in "<<lwr.d_usec/1000<<"ms"<<endl);

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
      struct CacheKey
      {
	DNSName name;
	uint16_t type;
	DNSResourceRecord::Place place;
	bool operator<(const CacheKey& rhs) const {
	  return tie(name, type) < tie(rhs.name, rhs.type);
	}
      };
      typedef map<CacheKey, CachePair> tcache_t;
      tcache_t tcache;

      for(const auto& rec : lwr.d_records) {
        if (rec.d_class != QClass::IN) {
          continue;
        }
        if(rec.d_type == QType::RRSIG) {
          auto rrsig = getRR<RRSIGRecordContent>(rec);
          if (rrsig) {
            //	    cerr<<"Got an RRSIG for "<<DNSRecordContent::NumberToType(rrsig->d_type)<<" with name '"<<rec.d_name<<"'"<<endl;
            tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signatures.push_back(rrsig);
          }
        }
      }

      // reap all answers from this packet that are acceptable
      for(auto& rec : lwr.d_records) {
        if(rec.d_type == QType::OPT) {
          LOG(prefix<<qname<<": OPT answer '"<<rec.d_name<<"' from '"<<auth<<"' nameservers" <<endl);
          continue;
        }
        LOG(prefix<<qname<<": accept answer '"<<rec.d_name<<"|"<<DNSRecordContent::NumberToType(rec.d_type)<<"|"<<rec.d_content->getZoneRepresentation()<<"' from '"<<auth<<"' nameservers? "<<(int)rec.d_place<<" ");
        if(rec.d_type == QType::ANY) {
          LOG("NO! - we don't accept 'ANY'-typed data"<<endl);
          continue;
        }

        if(rec.d_class != QClass::IN) {
          LOG("NO! - we don't accept records for any other class than 'IN'"<<endl);
          continue;
        }

        if(rec.d_name.isPartOf(auth)) {
          if(rec.d_type == QType::RRSIG) {
            LOG("RRSIG - separate"<<endl);
          }
          else if(lwr.d_aabit && lwr.d_rcode==RCode::NoError && rec.d_place==DNSResourceRecord::ANSWER && (rec.d_type != QType::DNSKEY || rec.d_name != auth) && g_delegationOnly.count(auth)) {
            LOG("NO! Is from delegation-only zone"<<endl);
            s_nodelegated++;
            return RCode::NXDomain;
          }
          else {
            bool haveLogged = false;
            if (!t_sstorage->domainmap->empty()) {
              // Check if we are authoritative for a zone in this answer
              DNSName tmp_qname(rec.d_name);
              auto auth_domain_iter=getBestAuthZone(&tmp_qname);
              if(auth_domain_iter!=t_sstorage->domainmap->end() &&
                  auth.countLabels() <= auth_domain_iter->first.countLabels()) {
                if (auth_domain_iter->first != auth) {
                  LOG("NO! - we are authoritative for the zone "<<auth_domain_iter->first<<endl);
                  continue;
                } else {
                  LOG("YES! - This answer was ");
                  if (nameservers[*tns].first.empty()) {
                    LOG("retrieved from the local auth store.");
                  } else {
                    LOG("received from a server we forward to.");
                  }
                  haveLogged = true;
                  LOG(endl);
                }
              }
            }
            if (!haveLogged) {
              LOG("YES!"<<endl);
            }

            rec.d_ttl=min(s_maxcachettl, rec.d_ttl);

            DNSRecord dr(rec);
            dr.d_place=DNSResourceRecord::ANSWER;

            dr.d_ttl += d_now.tv_sec;
            tcache[{rec.d_name,rec.d_type,rec.d_place}].records.push_back(dr);
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

//		cout<<"Have "<<i->second.records.size()<<" records and "<<i->second.signatures.size()<<" signatures for "<<i->first.name;
//		cout<<'|'<<DNSRecordContent::NumberToType(i->first.type)<<endl;
        if(i->second.records.empty()) // this happens when we did store signatures, but passed on the records themselves
          continue;
        t_RC->replace(d_now.tv_sec, i->first.name, QType(i->first.type), i->second.records, i->second.signatures, lwr.d_aabit, i->first.place == DNSResourceRecord::ANSWER ? ednsmask : boost::optional<Netmask>());
	if(i->first.place == DNSResourceRecord::ANSWER && ednsmask)
	  d_wasVariable=true;
      }
      set<DNSName> nsset;
      LOG(prefix<<qname<<": determining status after receiving this packet"<<endl);

      bool done=false, realreferral=false, negindic=false, sawDS=false;
      DNSName newauth, soaname;
      DNSName newtarget;

      for(auto& rec : lwr.d_records) {
        if (rec.d_type!=QType::OPT && rec.d_class!=QClass::IN)
          continue;

        if(rec.d_place==DNSResourceRecord::AUTHORITY && rec.d_type==QType::SOA &&
           lwr.d_rcode==RCode::NXDomain && qname.isPartOf(rec.d_name) && rec.d_name.isPartOf(auth)) {
          LOG(prefix<<qname<<": got negative caching indication for name '"<<qname<<"' (accept="<<rec.d_name.isPartOf(auth)<<"), newtarget='"<<newtarget<<"'"<<endl);

          rec.d_ttl = min(rec.d_ttl, s_maxnegttl);
          if(newtarget.empty()) // only add a SOA if we're not going anywhere after this
            ret.push_back(rec);
	  if(!wasVariable()) {
	    NegCacheEntry ne;
	    
	    ne.d_qname=rec.d_name;
	    ne.d_ttd=d_now.tv_sec + rec.d_ttl;
	    ne.d_name=qname;
	    ne.d_qtype=QType(0); // this encodes 'whole record'
	    ne.d_dnssecProof = harvestRecords(lwr.d_records, {QType::NSEC, QType::NSEC3});
	    replacing_insert(t_sstorage->negcache, ne);
	    if(s_rootNXTrust && auth.isRoot()) {
	      ne.d_name = getLastLabel(ne.d_name);
	      replacing_insert(t_sstorage->negcache, ne);
	    }
	  }

          negindic=true;
        }
        else if(rec.d_place==DNSResourceRecord::ANSWER && rec.d_name == qname && rec.d_type==QType::CNAME && (!(qtype==QType(QType::CNAME)))) {
          ret.push_back(rec);
          if (auto content = getRR<CNAMERecordContent>(rec)) {
            newtarget=content->getTarget();
          }
        }
	else if((rec.d_type==QType::RRSIG || rec.d_type==QType::NSEC || rec.d_type==QType::NSEC3) && rec.d_place==DNSResourceRecord::ANSWER){
	  if(rec.d_type != QType::RRSIG || rec.d_name == qname)
	    ret.push_back(rec); // enjoy your DNSSEC
	}
        // for ANY answers we *must* have an authoritative answer, unless we are forwarding recursively
        else if(rec.d_place==DNSResourceRecord::ANSWER && rec.d_name == qname &&
                (
                 rec.d_type==qtype.getCode() || (lwr.d_aabit && (qtype==QType(QType::ANY) || magicAddrMatch(qtype, QType(rec.d_type)) ) ) || sendRDQuery
                )
               )
          {

	    LOG(prefix<<qname<<": answer is in: resolved to '"<< rec.d_content->getZoneRepresentation()<<"|"<<DNSRecordContent::NumberToType(rec.d_type)<<"'"<<endl);

          done=true;
          ret.push_back(rec);
        }
        else if(rec.d_place==DNSResourceRecord::AUTHORITY && qname.isPartOf(rec.d_name) && rec.d_type==QType::NS) {
          if(moreSpecificThan(rec.d_name,auth)) {
            newauth=rec.d_name;
            LOG(prefix<<qname<<": got NS record '"<<rec.d_name<<"' -> '"<<rec.d_content->getZoneRepresentation()<<"'"<<endl);
            realreferral=true;
          }
          else {
            LOG(prefix<<qname<<": got upwards/level NS record '"<<rec.d_name<<"' -> '"<<rec.d_content->getZoneRepresentation()<<"', had '"<<auth<<"'"<<endl);
	  }
          if (auto content = getRR<NSRecordContent>(rec)) {
            nsset.insert(content->getNS());
          }
        }
        else if(rec.d_place==DNSResourceRecord::AUTHORITY && qname.isPartOf(rec.d_name) && rec.d_type==QType::DS) {
	  LOG(prefix<<qname<<": got DS record '"<<rec.d_name<<"' -> '"<<rec.d_content->getZoneRepresentation()<<"'"<<endl);
	  sawDS=true;
	}
        else if(!done && rec.d_place==DNSResourceRecord::AUTHORITY && qname.isPartOf(rec.d_name) && rec.d_type==QType::SOA &&
           lwr.d_rcode==RCode::NoError) {
          LOG(prefix<<qname<<": got negative caching indication for '"<< qname<<"|"<<qtype.getName()<<"'"<<endl);

          if(!newtarget.empty()) {
            LOG(prefix<<qname<<": Hang on! Got a redirect to '"<<newtarget<<"' already"<<endl);
          }
          else {
            rec.d_ttl = min(s_maxnegttl, rec.d_ttl);
            ret.push_back(rec);
	    if(!wasVariable()) {
	      NegCacheEntry ne;
	      ne.d_qname=rec.d_name;
	      ne.d_ttd=d_now.tv_sec + rec.d_ttl;
	      ne.d_name=qname;
	      ne.d_qtype=qtype;
	      ne.d_dnssecProof = harvestRecords(lwr.d_records, {QType::NSEC, QType::NSEC3});
	      if(qtype.getCode()) {  // prevents us from blacking out a whole domain
		replacing_insert(t_sstorage->negcache, ne);
	      }
	    }
            negindic=true;
          }
        }
      }

      if(done){
        LOG(prefix<<qname<<": status=got results, this level of recursion done"<<endl);
        return 0;
      }
      if(!newtarget.empty()) {
        if(newtarget == qname) {
          LOG(prefix<<qname<<": status=got a CNAME referral to self, returning SERVFAIL"<<endl);
          return RCode::ServFail;
        }
        if(depth > 10) {
          LOG(prefix<<qname<<": status=got a CNAME referral, but recursing too deep, returning SERVFAIL"<<endl);
          return RCode::ServFail;
        }
        LOG(prefix<<qname<<": status=got a CNAME referral, starting over with "<<newtarget<<endl);

        set<GetBestNSAnswer> beenthere2;
        return doResolve(newtarget, qtype, ret, depth + 1, beenthere2);
      }
      if(lwr.d_rcode==RCode::NXDomain) {
        LOG(prefix<<qname<<": status=NXDOMAIN, we are done "<<(negindic ? "(have negative SOA)" : "")<<endl);

        if(d_doDNSSEC)
          addNXNSECS(ret, lwr.d_records);

        return RCode::NXDomain;
      }
      if(nsset.empty() && !lwr.d_rcode && (negindic || lwr.d_aabit || sendRDQuery)) {
        LOG(prefix<<qname<<": status=noerror, other types may exist, but we are done "<<(negindic ? "(have negative SOA) " : "")<<(lwr.d_aabit ? "(have aa bit) " : "")<<endl);
        
        if(d_doDNSSEC)
          addNXNSECS(ret, lwr.d_records);
        return 0;
      }
      else if(realreferral) {
        LOG(prefix<<qname<<": status=did not resolve, got "<<(unsigned int)nsset.size()<<" NS, ");
	if(sawDS) {
	  t_sstorage->dnssecmap[newauth]=true;
	  /*	  for(const auto& e : t_sstorage->dnssecmap)
	    cout<<e.first<<' ';
	    cout<<endl;*/
	}
        auth=newauth;

        nameservers.clear();
        for (auto const &nameserver : nsset) {
          if (d_wantsRPZ) {
            d_appliedPolicy = g_luaconfs.getLocal()->dfe.getProcessingPolicy(nameserver, d_discardedPolicies);
            if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
              LOG("however "<<nameserver<<" was blocked by RPZ policy '"<<(d_appliedPolicy.d_name ? *d_appliedPolicy.d_name : "")<<"'"<<endl);
              return -2;
            }
          }
          nameservers.insert({nameserver, {{}, false}});
        }
        LOG("looping to them"<<endl);
        break;
      }
      else if(!tns->empty()) { // means: not OOB, OOB == empty
        goto wasLame;
      }
    }
  }
  return -1;
}


// used by PowerDNSLua - note that this neglects to add the packet count & statistics back to pdns_ercursor.cc
int directResolve(const DNSName& qname, const QType& qtype, int qclass, vector<DNSRecord>& ret)
{
  struct timeval now;
  gettimeofday(&now, 0);

  SyncRes sr(now);
  int res = sr.beginResolve(qname, QType(qtype), qclass, ret); 
  
  return res;
}
