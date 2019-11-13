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

#include "syncres.hh"
#include "arguments.hh"
#include "cachecleaner.hh"
#include "dns_random.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "ednssubnet.hh"
#include "logger.hh"
#include "lua-recursor4.hh"
#include "rec-lua-conf.hh"
#include "dnsseckeeper.hh"
#include "validate-recursor.hh"

thread_local SyncRes::ThreadLocalStorage SyncRes::t_sstorage;

std::unordered_set<DNSName> SyncRes::s_delegationOnly;
std::unique_ptr<NetmaskGroup> SyncRes::s_dontQuery{nullptr};
NetmaskGroup SyncRes::s_ednssubnets;
SuffixMatchNode SyncRes::s_ednsdomains;
EDNSSubnetOpts SyncRes::s_ecsScopeZero;
string SyncRes::s_serverID;
SyncRes::LogMode SyncRes::s_lm;

unsigned int SyncRes::s_maxnegttl;
unsigned int SyncRes::s_maxcachettl;
unsigned int SyncRes::s_maxqperq;
unsigned int SyncRes::s_maxtotusec;
unsigned int SyncRes::s_maxdepth;
unsigned int SyncRes::s_minimumTTL;
unsigned int SyncRes::s_packetcachettl;
unsigned int SyncRes::s_packetcacheservfailttl;
unsigned int SyncRes::s_serverdownmaxfails;
unsigned int SyncRes::s_serverdownthrottletime;
unsigned int SyncRes::s_ecscachelimitttl;
std::atomic<uint64_t> SyncRes::s_authzonequeries;
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
std::atomic<uint64_t> SyncRes::s_ecsqueries;
std::atomic<uint64_t> SyncRes::s_ecsresponses;
uint8_t SyncRes::s_ecsipv4limit;
uint8_t SyncRes::s_ecsipv6limit;
uint8_t SyncRes::s_ecsipv4cachelimit;
uint8_t SyncRes::s_ecsipv6cachelimit;

bool SyncRes::s_doIPv6;
bool SyncRes::s_nopacketcache;
bool SyncRes::s_rootNXTrust;
bool SyncRes::s_noEDNS;

#define LOG(x) if(d_lm == Log) { L <<Logger::Warning << x; } else if(d_lm == Store) { d_trace << x; }

static void accountAuthLatency(int usec, int family)
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


SyncRes::SyncRes(const struct timeval& now) :  d_authzonequeries(0), d_outqueries(0), d_tcpoutqueries(0), d_throttledqueries(0), d_timeouts(0), d_unreachables(0),
					       d_totUsec(0), d_now(now),
					       d_cacheonly(false), d_doDNSSEC(false), d_doEDNS0(false), d_lm(s_lm)
                                                 
{ 
}

/** everything begins here - this is the entry point just after receiving a packet */
int SyncRes::beginResolve(const DNSName &qname, const QType &qtype, uint16_t qclass, vector<DNSRecord>&ret)
{
  vState state = Indeterminate;
  s_queries++;
  d_wasVariable=false;
  d_wasOutOfBand=false;

  if (doSpecialNamesResolve(qname, qtype, qclass, ret)) {
    d_queryValidationState = Insecure; // this could fool our stats into thinking a validation took place
    return 0;                          // so do check before updating counters (we do now)
  }

  auto qtypeCode = qtype.getCode();
  /* rfc6895 section 3.1 */
  if ((qtypeCode >= 128 && qtypeCode <= 254) || qtypeCode == QType::RRSIG || qtypeCode == QType::NSEC3 || qtypeCode == QType::OPT || qtypeCode == 65535) {
    return -1;
  }

  if(qclass==QClass::ANY)
    qclass=QClass::IN;
  else if(qclass!=QClass::IN)
    return -1;

  set<GetBestNSAnswer> beenthere;
  int res=doResolve(qname, qtype, ret, 0, beenthere, state);
  d_queryValidationState = state;

  if (shouldValidate()) {
    if (d_queryValidationState != Indeterminate) {
      g_stats.dnssecValidations++;
    }
    increaseDNSSECStateCounter(d_queryValidationState);
  }

  return res;
}

/*! Handles all special, built-in names
 * Fills ret with an answer and returns true if it handled the query.
 *
 * Handles the following queries (and their ANY variants):
 *
 * - localhost. IN A
 * - localhost. IN AAAA
 * - 1.0.0.127.in-addr.arpa. IN PTR
 * - 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa. IN PTR
 * - version.bind. CH TXT
 * - version.pdns. CH TXT
 * - id.server. CH TXT
 */
bool SyncRes::doSpecialNamesResolve(const DNSName &qname, const QType &qtype, const uint16_t qclass, vector<DNSRecord> &ret)
{
  static const DNSName arpa("1.0.0.127.in-addr.arpa."), ip6_arpa("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."),
    localhost("localhost."), versionbind("version.bind."), idserver("id.server."), versionpdns("version.pdns.");

  bool handled = false;
  vector<pair<QType::typeenum, string> > answers;

  if ((qname == arpa || qname == ip6_arpa) &&
      qclass == QClass::IN) {
    handled = true;
    if (qtype == QType::PTR || qtype == QType::ANY)
      answers.push_back({QType::PTR, "localhost."});
  }

  if (qname == localhost &&
      qclass == QClass::IN) {
    handled = true;
    if (qtype == QType::A || qtype == QType::ANY)
      answers.push_back({QType::A, "127.0.0.1"});
    if (qtype == QType::AAAA || qtype == QType::ANY)
      answers.push_back({QType::AAAA, "::1"});
  }

  if ((qname == versionbind || qname == idserver || qname == versionpdns) &&
      qclass == QClass::CHAOS) {
    handled = true;
    if (qtype == QType::TXT || qtype == QType::ANY) {
      if(qname == versionbind || qname == versionpdns)
        answers.push_back({QType::TXT, "\""+::arg()["version-string"]+"\""});
      else
        answers.push_back({QType::TXT, "\""+s_serverID+"\""});
    }
  }

  if (handled && !answers.empty()) {
    ret.clear();
    d_wasOutOfBand=true;

    DNSRecord dr;
    dr.d_name = qname;
    dr.d_place = DNSResourceRecord::ANSWER;
    dr.d_class = qclass;
    dr.d_ttl = 86400;
    for (const auto& ans : answers) {
      dr.d_type = ans.first;
      dr.d_content = DNSRecordContent::mastermake(ans.first, qclass, ans.second);
      ret.push_back(dr);
    }
  }

  return handled;
}


//! This is the 'out of band resolver', in other words, the authoritative server
void SyncRes::AuthDomain::addSOA(std::vector<DNSRecord>& records) const
{
  SyncRes::AuthDomain::records_t::const_iterator ziter = d_records.find(boost::make_tuple(getName(), QType::SOA));
  if (ziter != d_records.end()) {
    DNSRecord dr = *ziter;
    dr.d_place = DNSResourceRecord::AUTHORITY;
    records.push_back(dr);
  }
  else {
    // cerr<<qname<<": can't find SOA record '"<<getName()<<"' in our zone!"<<endl;
  }
}

int SyncRes::AuthDomain::getRecords(const DNSName& qname, uint16_t qtype, std::vector<DNSRecord>& records) const
{
  int result = RCode::NoError;
  records.clear();

  // partial lookup
  std::pair<records_t::const_iterator,records_t::const_iterator> range = d_records.equal_range(tie(qname));

  SyncRes::AuthDomain::records_t::const_iterator ziter;
  bool somedata = false;

  for(ziter = range.first; ziter != range.second; ++ziter) {
    somedata = true;

    if(qtype == QType::ANY || ziter->d_type == qtype || ziter->d_type == QType::CNAME) {
      // let rest of nameserver do the legwork on this one
      records.push_back(*ziter);
    }
    else if (ziter->d_type == QType::NS && ziter->d_name.countLabels() > getName().countLabels()) {
      // we hit a delegation point!
      DNSRecord dr = *ziter;
      dr.d_place=DNSResourceRecord::AUTHORITY;
      records.push_back(dr);
    }
  }

  if (!records.empty()) {
    /* We have found an exact match, we're done */
    // cerr<<qname<<": exact match in zone '"<<getName()<<"'"<<endl;
    return result;
  }

  if (somedata) {
    /* We have records for that name, but not of the wanted qtype */
    // cerr<<qname<<": found record in '"<<getName()<<"', but nothing of the right type, sending SOA"<<endl;
    addSOA(records);

    return result;
  }

  // cerr<<qname<<": nothing found so far in '"<<getName()<<"', trying wildcards"<<endl;
  DNSName wcarddomain(qname);
  while(wcarddomain != getName() && wcarddomain.chopOff()) {
    // cerr<<qname<<": trying '*."<<wcarddomain<<"' in "<<getName()<<endl;
    range = d_records.equal_range(boost::make_tuple(g_wildcarddnsname + wcarddomain));
    if (range.first==range.second)
      continue;

    for(ziter = range.first; ziter != range.second; ++ziter) {
      DNSRecord dr = *ziter;
      // if we hit a CNAME, just answer that - rest of recursor will do the needful & follow
      if(dr.d_type == qtype || qtype == QType::ANY || dr.d_type == QType::CNAME) {
        dr.d_name = qname;
        dr.d_place = DNSResourceRecord::ANSWER;
        records.push_back(dr);
      }
    }

    if (records.empty()) {
      addSOA(records);
    }

    // cerr<<qname<<": in '"<<getName()<<"', had wildcard match on '*."<<wcarddomain<<"'"<<endl;
    return result;
  }

  /* Nothing for this name, no wildcard, let's see if there is some NS */
  DNSName nsdomain(qname);
  while (nsdomain.chopOff() && nsdomain != getName()) {
    range = d_records.equal_range(boost::make_tuple(nsdomain,QType::NS));
    if(range.first == range.second)
      continue;

    for(ziter = range.first; ziter != range.second; ++ziter) {
      DNSRecord dr = *ziter;
      dr.d_place = DNSResourceRecord::AUTHORITY;
      records.push_back(dr);
    }
  }

  if(records.empty()) {
    // cerr<<qname<<": no NS match in zone '"<<getName()<<"' either, handing out SOA"<<endl;
    addSOA(records);
    result = RCode::NXDomain;
  }

  return result;
}

bool SyncRes::doOOBResolve(const AuthDomain& domain, const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, int& res)
{
  d_authzonequeries++;
  s_authzonequeries++;

  res = domain.getRecords(qname, qtype.getCode(), ret);
  return true;
}

bool SyncRes::doOOBResolve(const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, unsigned int depth, int& res)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  DNSName authdomain(qname);
  domainmap_t::const_iterator iter=getBestAuthZone(&authdomain);
  if(iter==t_sstorage.domainmap->end() || !iter->second.isAuth()) {
    LOG(prefix<<qname<<": auth storage has no zone for this query!"<<endl);
    return false;
  }

  LOG(prefix<<qname<<": auth storage has data, zone='"<<authdomain<<"'"<<endl);
  return doOOBResolve(iter->second, qname, qtype, ret, res);
}

uint64_t SyncRes::doEDNSDump(int fd)
{
  FILE* fp=fdopen(dup(fd), "w");
  if (!fp) {
    return 0;
  }
  uint64_t count = 0;

  fprintf(fp,"; edns from thread follows\n;\n");
  for(const auto& eds : t_sstorage.ednsstatus) {
    count++;
    fprintf(fp, "%s\t%d\t%s", eds.first.toString().c_str(), (int)eds.second.mode, ctime(&eds.second.modeSetAt));
  }
  fclose(fp);
  return count;
}

uint64_t SyncRes::doDumpNSSpeeds(int fd)
{
  FILE* fp=fdopen(dup(fd), "w");
  if(!fp)
    return 0;
  fprintf(fp, "; nsspeed dump from thread follows\n;\n");
  uint64_t count=0;

  for(const auto& i : t_sstorage.nsSpeeds)
  {
    count++;

    // an <empty> can appear hear in case of authoritative (hosted) zones
    fprintf(fp, "%s -> ", i.first.toLogString().c_str());
    for(const auto& j : i.second.d_collection)
    {
      // typedef vector<pair<ComboAddress, DecayingEwma> > collection_t;
      fprintf(fp, "%s/%f ", j.first.toString().c_str(), j.second.peek());
    }
    fprintf(fp, "\n");
  }
  fclose(fp);
  return count;
}

uint64_t SyncRes::doDumpFailedServers(int fd)
{
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(dup(fd), "w"), fclose);
  if(!fp)
    return 0;
  fprintf(fp.get(), "; failed servers dump follows\n");
  fprintf(fp.get(), "; remote IP\tcount\ttimestamp\n");
  uint64_t count=0;

  for(const auto& i : t_sstorage.fails.getMap())
  {
    count++;
    char tmp[26];
    ctime_r(&i.second.last, tmp);
    fprintf(fp.get(), "%s\t%lld\t%s", i.first.toString().c_str(),
            static_cast<long long>(i.second.value), tmp);
  }

  return count;
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

int SyncRes::asyncresolveWrapper(const ComboAddress& ip, bool ednsMANDATORY, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, struct timeval* now, boost::optional<Netmask>& srcmask, LWResult* res, bool* chained) const
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

  SyncRes::EDNSStatus* ednsstatus = &t_sstorage.ednsstatus[ip]; // does this include port? YES

  if (ednsstatus->modeSetAt && ednsstatus->modeSetAt + 3600 < d_now.tv_sec) {
    *ednsstatus = SyncRes::EDNSStatus();
    //    cerr<<"Resetting EDNS Status for "<<ip.toString()<<endl);
  }

  SyncRes::EDNSStatus::EDNSMode *mode = &ednsstatus->mode;
  SyncRes::EDNSStatus::EDNSMode oldmode = *mode;
  int EDNSLevel = 0;
  auto luaconfsLocal = g_luaconfs.getLocal();
  ResolveContext ctx;
#ifdef HAVE_PROTOBUF
  ctx.d_initialRequestId = d_initialRequestId;
#endif

  int ret;
  for(int tries = 0; tries < 3; ++tries) {
    //    cerr<<"Remote '"<<ip.toString()<<"' currently in mode "<<mode<<endl;
    
    if (*mode == EDNSStatus::NOEDNS) {
      g_stats.noEdnsOutQueries++;
      EDNSLevel = 0; // level != mode
    }
    else if (ednsMANDATORY || *mode == EDNSStatus::UNKNOWN || *mode == EDNSStatus::EDNSOK || *mode == EDNSStatus::EDNSIGNORANT)
      EDNSLevel = 1;

    DNSName sendQname(domain);
    if (g_lowercaseOutgoing)
      sendQname.makeUsLowerCase();

    if (d_asyncResolve) {
      ret = d_asyncResolve(ip, sendQname, type, doTCP, sendRDQuery, EDNSLevel, now, srcmask, ctx, luaconfsLocal->outgoingProtobufServer, res, chained);
    }
    else {
      ret=asyncresolve(ip, sendQname, type, doTCP, sendRDQuery, EDNSLevel, now, srcmask, ctx, luaconfsLocal->outgoingProtobufServer, res, chained);
    }
    // ednsstatus might be cleared, so do a new lookup
    ednsstatus = &t_sstorage.ednsstatus[ip]; // does this include port? YES
    mode = &ednsstatus->mode;
    if(ret < 0) {
      return ret; // transport error, nothing to learn here
    }

    if(ret == 0) { // timeout, not doing anything with it now
      return ret;
    }
    else if(*mode==EDNSStatus::UNKNOWN || *mode==EDNSStatus::EDNSOK || *mode == EDNSStatus::EDNSIGNORANT ) {
      /* So, you might be tempted to treat the presence of EDNS in a response as meaning that the
         server does understand EDNS, and thus prevent a downgrade to no EDNS.
         It turns out that you can't because there are a lot of crappy servers out there,
         so you have to treat a FormErr as 'I have no idea what this EDNS thing is' no matter what.
      */
      if(res->d_rcode == RCode::FormErr || res->d_rcode == RCode::NotImp) {
	//	cerr<<"Downgrading to NOEDNS because of "<<RCode::to_s(res->d_rcode)<<" for query to "<<ip.toString()<<" for '"<<domain<<"'"<<endl;
        *mode = EDNSStatus::NOEDNS;
        continue;
      }
      else if(!res->d_haveEDNS) {
        if (*mode != EDNSStatus::EDNSIGNORANT) {
          *mode = EDNSStatus::EDNSIGNORANT;
	  //	  cerr<<"We find that "<<ip.toString()<<" is an EDNS-ignorer for '"<<domain<<"', moving to mode 2"<<endl;
	}
      }
      else {
	*mode = EDNSStatus::EDNSOK;
	//	cerr<<"We find that "<<ip.toString()<<" is EDNS OK!"<<endl;
      }
      
    }
    if (oldmode != *mode || !ednsstatus->modeSetAt)
      ednsstatus->modeSetAt=d_now.tv_sec;
    //    cerr<<"Result: ret="<<ret<<", EDNS-level: "<<EDNSLevel<<", haveEDNS: "<<res->d_haveEDNS<<", new mode: "<<mode<<endl;  
    return ret;
  }
  return ret;
}

/*! This function will check the cache and go out to the internet if the answer is not in cache
 *
 * \param qname The name we need an answer for
 * \param qtype
 * \param ret The vector of DNSRecords we need to fill with the answers
 * \param depth The recursion depth we are in
 * \param beenthere
 * \return DNS RCODE or -1 (Error) or -2 (RPZ hit)
 */
int SyncRes::doResolve(const DNSName &qname, const QType &qtype, vector<DNSRecord>&ret, unsigned int depth, set<GetBestNSAnswer>& beenthere, vState& state)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  LOG(prefix<<qname<<": Wants "<< (d_doDNSSEC ? "" : "NO ") << "DNSSEC processing, "<<(d_requireAuthData ? "" : "NO ")<<"auth data in query for "<<qtype.getName()<<endl);

  state = Indeterminate;

  if(s_maxdepth && depth > s_maxdepth)
    throw ImmediateServFailException("More than "+std::to_string(s_maxdepth)+" (max-recursion-depth) levels of recursion needed while resolving "+qname.toLogString());

  int res=0;

  // This is a difficult way of expressing "this is a normal query", i.e. not getRootNS.
  if(!(d_updatingRootNS && qtype.getCode()==QType::NS && qname.isRoot())) {
    if(d_cacheonly) { // very limited OOB support
      LWResult lwr;
      LOG(prefix<<qname<<": Recursion not requested for '"<<qname<<"|"<<qtype.getName()<<"', peeking at auth/forward zones"<<endl);
      DNSName authname(qname);
      domainmap_t::const_iterator iter=getBestAuthZone(&authname);
      if(iter != t_sstorage.domainmap->end()) {
        if(iter->second.isAuth()) {
          ret.clear();
          d_wasOutOfBand = doOOBResolve(qname, qtype, ret, depth, res);
          return res;
        }
        else {
          const vector<ComboAddress>& servers = iter->second.d_servers;
          const ComboAddress remoteIP = servers.front();
          LOG(prefix<<qname<<": forwarding query to hardcoded nameserver '"<< remoteIP.toStringWithPort()<<"' for zone '"<<authname<<"'"<<endl);

          boost::optional<Netmask> nm;
          bool chained = false;
          res=asyncresolveWrapper(remoteIP, d_doDNSSEC, qname, qtype.getCode(), false, false, &d_now, nm, &lwr, &chained);

          d_totUsec += lwr.d_usec;
          accountAuthLatency(lwr.d_usec, remoteIP.sin4.sin_family);

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

    DNSName authname(qname);
    bool wasForwardedOrAuthZone = false;
    bool wasAuthZone = false;
    bool wasForwardRecurse = false;
    domainmap_t::const_iterator iter = getBestAuthZone(&authname);
    if(iter != t_sstorage.domainmap->end()) {
      const auto& domain = iter->second;
      wasForwardedOrAuthZone = true;

      if (domain.isAuth()) {
        wasAuthZone = true;
      } else if (domain.shouldRecurse()) {
        wasForwardRecurse = true;
      }
    }

    if(!d_skipCNAMECheck && doCNAMECacheCheck(qname, qtype, ret, depth, res, state, wasAuthZone, wasForwardRecurse)) { // will reroute us if needed
      d_wasOutOfBand = wasAuthZone;
      return res;
    }

    if(doCacheCheck(qname, authname, wasForwardedOrAuthZone, wasAuthZone, wasForwardRecurse, qtype, ret, depth, res, state)) {
      // we done
      d_wasOutOfBand = wasAuthZone;
      return res;
    }
  }

  if(d_cacheonly)
    return 0;

  LOG(prefix<<qname<<": No cache hit for '"<<qname<<"|"<<qtype.getName()<<"', trying to find an appropriate NS record"<<endl);

  DNSName subdomain(qname);
  if(qtype == QType::DS) subdomain.chopOff();

  NsSet nsset;
  bool flawedNSSet=false;

  /* we use subdomain here instead of qname because for DS queries we only care about the state of the parent zone */
  computeZoneCuts(subdomain, g_rootdnsname, depth);

  // the two retries allow getBestNSNamesFromCache&co to reprime the root
  // hints, in case they ever go missing
  for(int tries=0;tries<2 && nsset.empty();++tries) {
    subdomain=getBestNSNamesFromCache(subdomain, qtype, nsset, &flawedNSSet, depth, beenthere); //  pass beenthere to both occasions
  }

  state = getValidationStatus(qname, false);

  LOG(prefix<<qname<<": initial validation status for "<<qname<<" is "<<vStates[state]<<endl);

  if(!(res=doResolveAt(nsset, subdomain, flawedNSSet, qname, qtype, ret, depth, beenthere, state)))
    return 0;

  LOG(prefix<<qname<<": failed (res="<<res<<")"<<endl);

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

struct speedOrderCA
{
  speedOrderCA(std::map<ComboAddress,double>& speeds): d_speeds(speeds) {}
  bool operator()(const ComboAddress& a, const ComboAddress& b) const
  {
    return d_speeds[a] < d_speeds[b];
  }
  std::map<ComboAddress, double>& d_speeds;
};

/** This function explicitly goes out for A or AAAA addresses
*/
vector<ComboAddress> SyncRes::getAddrs(const DNSName &qname, unsigned int depth, set<GetBestNSAnswer>& beenthere, bool cacheOnly)
{
  typedef vector<DNSRecord> res_t;
  res_t res;

  typedef vector<ComboAddress> ret_t;
  ret_t ret;

  QType type;
  bool oldCacheOnly = d_cacheonly;
  bool oldRequireAuthData = d_requireAuthData;
  bool oldValidationRequested = d_DNSSECValidationRequested;
  d_requireAuthData = false;
  d_DNSSECValidationRequested = false;
  d_cacheonly = cacheOnly;

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

    vState newState = Indeterminate;
    if(!doResolve(qname, type, res,depth+1, beenthere, newState) && !res.empty()) {  // this consults cache, OR goes out
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
	if(t_RC->get(d_now.tv_sec, qname, QType(QType::AAAA), false, &cset, d_incomingECSFound ? d_incomingECSNetwork : d_requestor) > 0) {
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

  d_requireAuthData = oldRequireAuthData;
  d_DNSSECValidationRequested = oldValidationRequested;
  d_cacheonly = oldCacheOnly;

  /* we need to remove from the nsSpeeds collection the existing IPs
     for this nameserver that are no longer in the set, even if there
     is only one or none at all in the current set.
  */
  map<ComboAddress, double> speeds;
  auto& collection = t_sstorage.nsSpeeds[qname].d_collection;
  for(const auto& val: ret) {
    speeds[val] = collection[val].get(&d_now);
  }

  t_sstorage.nsSpeeds[qname].purge(speeds);

  if(ret.size() > 1) {
    random_shuffle(ret.begin(), ret.end(), dns_random);
    speedOrderCA so(speeds);
    stable_sort(ret.begin(), ret.end(), so);

    if(doLog()) {
      string prefix=d_prefix;
      prefix.append(depth, ' ');
      LOG(prefix<<"Nameserver "<<qname<<" IPs: ");
      bool first = true;
      for(const auto& addr : ret) {
        if (first) {
          first = false;
        }
        else {
          LOG(", ");
        }
        LOG((addr.toString())<<"(" << (boost::format("%0.2f") % (speeds[addr]/1000.0)).str() <<"ms)");
      }
      LOG(endl);
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

    if(t_RC->get(d_now.tv_sec, subdomain, QType(QType::NS), false, &ns, d_incomingECSFound ? d_incomingECSNetwork : d_requestor) > 0) {
      for(auto k=ns.cbegin();k!=ns.cend(); ++k) {
        if(k->d_ttl > (unsigned int)d_now.tv_sec ) {
          vector<DNSRecord> aset;

          const DNSRecord& dr=*k;
	  auto nrr = getRR<NSRecordContent>(dr);
          if(nrr && (!nrr->getNS().isPartOf(subdomain) || t_RC->get(d_now.tv_sec, nrr->getNS(), s_doIPv6 ? QType(QType::ADDR) : QType(QType::A),
                                                                    false, doLog() ? &aset : 0, d_incomingECSFound ? d_incomingECSNetwork : d_requestor) > 5)) {
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

    if(subdomain.isRoot() && !brokeloop) {
      // We lost the root NS records
      primeHints();
      primeRootNSZones(g_dnssecmode != DNSSECMode::Off);
      LOG(prefix<<qname<<": reprimed the root"<<endl);
      /* let's prevent an infinite loop */
      if (!d_updatingRootNS) {
        getRootNS(d_now, d_asyncResolve);
      }
    }
  } while(subdomain.chopOff());
}

SyncRes::domainmap_t::const_iterator SyncRes::getBestAuthZone(DNSName* qname) const
{
  SyncRes::domainmap_t::const_iterator ret;
  do {
    ret=t_sstorage.domainmap->find(*qname);
    if(ret!=t_sstorage.domainmap->end())
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
  if(iter!=t_sstorage.domainmap->end()) {
    if( iter->second.isAuth() )
      // this gets picked up in doResolveAt, the empty DNSName, combined with the
      // empty vector means 'we are auth for this zone'
      nsset.insert({DNSName(), {{}, false}});
    else {
      // Again, picked up in doResolveAt. An empty DNSName, combined with a
      // non-empty vector of ComboAddresses means 'this is a forwarded domain'
      // This is actually picked up in retrieveAddressesForNS called from doResolveAt.
      nsset.insert({DNSName(), {iter->second.d_servers, iter->second.shouldRecurse() }});
    }
    return authdomain;
  }

  vector<DNSRecord> bestns;
  getBestNSFromCache(subdomain, qtype, bestns, flawedNSSet, depth, beenthere);

  for(auto k=bestns.cbegin() ; k != bestns.cend(); ++k) {
    // The actual resolver code will not even look at the ComboAddress or bool
    const auto nsContent = getRR<NSRecordContent>(*k);
    if (nsContent) {
      nsset.insert({nsContent->getNS(), {{}, false}});
      if(k==bestns.cbegin())
        subdomain=k->d_name;
    }
  }
  return subdomain;
}

bool SyncRes::doCNAMECacheCheck(const DNSName &qname, const QType &qtype, vector<DNSRecord>& ret, unsigned int depth, int &res, vState& state, bool wasAuthZone, bool wasForwardRecurse)
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
  vector<std::shared_ptr<DNSRecord>> authorityRecs;
  bool wasAuth;
  /* we don't require auth data for forward-recurse lookups */
  if(t_RC->get(d_now.tv_sec, qname, QType(QType::CNAME), !wasForwardRecurse && d_requireAuthData, &cset, d_incomingECSFound ? d_incomingECSNetwork : d_requestor, d_doDNSSEC ? &signatures : nullptr, d_doDNSSEC ? &authorityRecs : nullptr, &d_wasVariable, &state, &wasAuth) > 0) {

    for(auto j=cset.cbegin() ; j != cset.cend() ; ++j) {
      if (j->d_class != QClass::IN) {
        continue;
      }

      if(j->d_ttl>(unsigned int) d_now.tv_sec) {

        if (!wasAuthZone && shouldValidate() && wasAuth && state == Indeterminate && d_requireAuthData) {
          /* This means we couldn't figure out the state when this entry was cached,
             most likely because we hadn't computed the zone cuts yet. */
          /* make sure they are computed before validating */
          DNSName subdomain(qname);
          /* if we are retrieving a DS, we only care about the state of the parent zone */
          if(qtype == QType::DS)
            subdomain.chopOff();

          computeZoneCuts(subdomain, g_rootdnsname, depth);

          vState recordState = getValidationStatus(qname, false);
          if (recordState == Secure) {
            LOG(prefix<<qname<<": got Indeterminate state from the CNAME cache, validating.."<<endl);
            state = SyncRes::validateRecordsWithSigs(depth, qname, QType(QType::CNAME), qname, cset, signatures);
            if (state != Indeterminate) {
              LOG(prefix<<qname<<": got Indeterminate state from the CNAME cache, new validation result is "<<vStates[state]<<endl);
              t_RC->updateValidationStatus(d_now.tv_sec, qname, QType(QType::CNAME), d_incomingECSFound ? d_incomingECSNetwork : d_requestor, d_requireAuthData, state);
            }
          }
        }

        LOG(prefix<<qname<<": Found cache CNAME hit for '"<< qname << "|CNAME" <<"' to '"<<j->d_content->getZoneRepresentation()<<"', validation state is "<<vStates[state]<<endl);

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
          sigdr.d_class=QClass::IN;
          ret.push_back(sigdr);
        }

        for(const auto& rec : authorityRecs) {
          DNSRecord authDR(*rec);
          authDR.d_ttl=j->d_ttl - d_now.tv_sec;
          ret.push_back(authDR);
        }

        if(qtype != QType::CNAME) { // perhaps they really wanted a CNAME!
          set<GetBestNSAnswer>beenthere;

          vState cnameState = Indeterminate;
          const auto cnameContent = getRR<CNAMERecordContent>(*j);
          if (cnameContent) {
            res=doResolve(cnameContent->getTarget(), qtype, ret, depth+1, beenthere, cnameState);
            LOG(prefix<<qname<<": updating validation state for response to "<<qname<<" from "<<vStates[state]<<" with the state from the CNAME quest: "<<vStates[cnameState]<<endl);
            updateValidationState(state, cnameState);
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

namespace {
struct CacheEntry
{
  vector<DNSRecord> records;
  vector<shared_ptr<RRSIGRecordContent>> signatures;
  uint32_t signaturesTTL{std::numeric_limits<uint32_t>::max()};
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
typedef map<CacheKey, CacheEntry> tcache_t;
}

static void reapRecordsFromNegCacheEntryForValidation(tcache_t& tcache, const vector<DNSRecord>& records)
{
  for (const auto& rec : records) {
    if (rec.d_type == QType::RRSIG) {
      auto rrsig = getRR<RRSIGRecordContent>(rec);
      if (rrsig) {
        tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signatures.push_back(rrsig);
      }
    } else {
      tcache[{rec.d_name,rec.d_type,rec.d_place}].records.push_back(rec);
    }
  }
}

/*!
 * Convience function to push the records from records into ret with a new TTL
 *
 * \param records DNSRecords that need to go into ret
 * \param ttl     The new TTL for these records
 * \param ret     The vector of DNSRecords that should contian the records with the modified TTL
 */
static void addTTLModifiedRecords(const vector<DNSRecord>& records, const uint32_t ttl, vector<DNSRecord>& ret) {
  for (const auto& rec : records) {
    DNSRecord r(rec);
    r.d_ttl = ttl;
    ret.push_back(r);
  }
}

void SyncRes::computeNegCacheValidationStatus(NegCache::NegCacheEntry& ne, const DNSName& qname, const QType& qtype, const int res, vState& state, unsigned int depth)
{
  DNSName subdomain(qname);
  /* if we are retrieving a DS, we only care about the state of the parent zone */
  if(qtype == QType::DS)
    subdomain.chopOff();

  computeZoneCuts(subdomain, g_rootdnsname, depth);

  tcache_t tcache;
  reapRecordsFromNegCacheEntryForValidation(tcache, ne.authoritySOA.records);
  reapRecordsFromNegCacheEntryForValidation(tcache, ne.authoritySOA.signatures);
  reapRecordsFromNegCacheEntryForValidation(tcache, ne.DNSSECRecords.records);
  reapRecordsFromNegCacheEntryForValidation(tcache, ne.DNSSECRecords.signatures);

  for (const auto& entry : tcache) {
    // this happens when we did store signatures, but passed on the records themselves
    if (entry.second.records.empty()) {
      continue;
    }

    const DNSName& owner = entry.first.name;

    vState recordState = getValidationStatus(owner, false);
    if (state == Indeterminate) {
      state = recordState;
    }

    if (recordState == Secure) {
      recordState = SyncRes::validateRecordsWithSigs(depth, qname, qtype, owner, entry.second.records, entry.second.signatures);
    }

    if (recordState != Indeterminate && recordState != state) {
      updateValidationState(state, recordState);
      if (state != Secure) {
        break;
      }
    }
  }

  if (state == Secure) {
    dState expectedState = res == RCode::NXDomain ? NXDOMAIN : NXQTYPE;
    dState denialState = getDenialValidationState(ne, state, expectedState, false);
    updateDenialValidationState(ne, state, denialState, expectedState, qtype == QType::DS);
  }
  if (state != Indeterminate) {
    /* validation succeeded, let's update the cache entry so we don't have to validate again */
    t_sstorage.negcache.updateValidationStatus(ne.d_name, ne.d_qtype, state);
  }
}

bool SyncRes::doCacheCheck(const DNSName &qname, const DNSName& authname, bool wasForwardedOrAuthZone, bool wasAuthZone, bool wasForwardRecurse, const QType &qtype, vector<DNSRecord>&ret, unsigned int depth, int &res, vState& state)
{
  bool giveNegative=false;

  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  // sqname and sqtype are used contain 'higher' names if we have them (e.g. powerdns.com|SOA when we find a negative entry for doesnotexists.powerdns.com|A)
  DNSName sqname(qname);
  QType sqt(qtype);
  uint32_t sttl=0;
  //  cout<<"Lookup for '"<<qname<<"|"<<qtype.getName()<<"' -> "<<getLastLabel(qname)<<endl;
  vState cachedState;
  NegCache::NegCacheEntry ne;

  if(s_rootNXTrust &&
     t_sstorage.negcache.getRootNXTrust(qname, d_now, ne) &&
      ne.d_auth.isRoot() &&
      !(wasForwardedOrAuthZone && !authname.isRoot())) { // when forwarding, the root may only neg-cache if it was forwarded to.
    sttl = ne.d_ttd - d_now.tv_sec;
    LOG(prefix<<qname<<": Entire name '"<<qname<<"', is negatively cached via '"<<ne.d_auth<<"' & '"<<ne.d_name<<"' for another "<<sttl<<" seconds"<<endl);
    res = RCode::NXDomain;
    giveNegative = true;
    cachedState = ne.d_validationState;
  }
  else if (t_sstorage.negcache.get(qname, qtype, d_now, ne) &&
           !(wasForwardedOrAuthZone && ne.d_auth != authname)) { // Only the authname nameserver can neg cache entries

    /* If we are looking for a DS, discard NXD if auth == qname
       and ask for a specific denial instead */
    if (qtype != QType::DS || ne.d_qtype.getCode() || ne.d_auth != qname ||
        t_sstorage.negcache.get(qname, qtype, d_now, ne, true))
    {
      res = 0;
      sttl = ne.d_ttd - d_now.tv_sec;
      giveNegative = true;
      cachedState = ne.d_validationState;
      if(ne.d_qtype.getCode()) {
        LOG(prefix<<qname<<": "<<qtype.getName()<<" is negatively cached via '"<<ne.d_auth<<"' for another "<<sttl<<" seconds"<<endl);
        res = RCode::NoError;
      }
      else {
        LOG(prefix<<qname<<": Entire name '"<<qname<<"', is negatively cached via '"<<ne.d_auth<<"' for another "<<sttl<<" seconds"<<endl);
        res = RCode::NXDomain;
      }
    }
  }

  if (giveNegative) {

    state = cachedState;

    if (!wasAuthZone && shouldValidate() && state == Indeterminate) {
      LOG(prefix<<qname<<": got Indeterminate state for records retrieved from the negative cache, validating.."<<endl);
      computeNegCacheValidationStatus(ne, qname, qtype, res, state, depth);
    }

    // Transplant SOA to the returned packet
    addTTLModifiedRecords(ne.authoritySOA.records, sttl, ret);
    if(d_doDNSSEC) {
      addTTLModifiedRecords(ne.authoritySOA.signatures, sttl, ret);
      addTTLModifiedRecords(ne.DNSSECRecords.records, sttl, ret);
      addTTLModifiedRecords(ne.DNSSECRecords.signatures, sttl, ret);
    }

    LOG(prefix<<qname<<": updating validation state with negative cache content for "<<qname<<" to "<<vStates[state]<<endl);
    return true;
  }

  vector<DNSRecord> cset;
  bool found=false, expired=false;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  vector<std::shared_ptr<DNSRecord>> authorityRecs;
  uint32_t ttl=0;
  bool wasCachedAuth;
  if(t_RC->get(d_now.tv_sec, sqname, sqt, !wasForwardRecurse && d_requireAuthData, &cset, d_incomingECSFound ? d_incomingECSNetwork : d_requestor, d_doDNSSEC ? &signatures : nullptr, d_doDNSSEC ? &authorityRecs : nullptr, &d_wasVariable, &cachedState, &wasCachedAuth) > 0) {

    LOG(prefix<<sqname<<": Found cache hit for "<<sqt.getName()<<": ");

    if (!wasAuthZone && shouldValidate() && wasCachedAuth && cachedState == Indeterminate && d_requireAuthData) {

      /* This means we couldn't figure out the state when this entry was cached,
         most likely because we hadn't computed the zone cuts yet. */
      /* make sure they are computed before validating */
      DNSName subdomain(sqname);
      /* if we are retrieving a DS, we only care about the state of the parent zone */
      if(qtype == QType::DS)
        subdomain.chopOff();

      computeZoneCuts(subdomain, g_rootdnsname, depth);

      vState recordState = getValidationStatus(qname, false);
      if (recordState == Secure) {
        LOG(prefix<<sqname<<": got Indeterminate state from the cache, validating.."<<endl);
        cachedState = SyncRes::validateRecordsWithSigs(depth, sqname, sqt, sqname, cset, signatures);
      }
      else {
        cachedState = recordState;
      }

      if (cachedState != Indeterminate) {
        LOG(prefix<<qname<<": got Indeterminate state from the cache, validation result is "<<vStates[cachedState]<<endl);
        t_RC->updateValidationStatus(d_now.tv_sec, sqname, sqt, d_incomingECSFound ? d_incomingECSNetwork : d_requestor, d_requireAuthData, cachedState);
      }
    }

    for(auto j=cset.cbegin() ; j != cset.cend() ; ++j) {

      LOG(j->d_content->getZoneRepresentation());

      if (j->d_class != QClass::IN) {
        continue;
      }

      if(j->d_ttl>(unsigned int) d_now.tv_sec) {
        DNSRecord dr=*j;
        ttl = (dr.d_ttl-=d_now.tv_sec);
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
      dr.d_place = DNSResourceRecord::ANSWER;
      dr.d_class=QClass::IN;
      ret.push_back(dr);
    }

    for(const auto& rec : authorityRecs) {
      DNSRecord dr(*rec);
      dr.d_ttl=ttl;
      ret.push_back(dr);
    }

    LOG(endl);
    if(found && !expired) {
      if (!giveNegative)
        res=0;
      LOG(prefix<<qname<<": updating validation state with cache content for "<<qname<<" to "<<vStates[cachedState]<<endl);
      state = cachedState;
      return true;
    }
    else
      LOG(prefix<<qname<<": cache had only stale entries"<<endl);
  }

  return false;
}

bool SyncRes::moreSpecificThan(const DNSName& a, const DNSName &b) const
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
  for(const auto& tns: tnameservers) {
    rnameservers.push_back(tns.first);
    if(tns.first.empty()) // this was an authoritative OOB zone, don't pollute the nsSpeeds with that
      return rnameservers;
  }
  map<DNSName, double> speeds;

  for(const auto& val: rnameservers) {
    double speed;
    speed=t_sstorage.nsSpeeds[val].get(&d_now);
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

static uint32_t getRRSIGTTL(const time_t now, const std::shared_ptr<RRSIGRecordContent>& rrsig)
{
  uint32_t res = 0;
  if (now < rrsig->d_sigexpire) {
    res = static_cast<uint32_t>(rrsig->d_sigexpire) - now;
  }
  return res;
}

static const set<uint16_t> nsecTypes = {QType::NSEC, QType::NSEC3};

/* Fills the authoritySOA and DNSSECRecords fields from ne with those found in the records
 *
 * \param records The records to parse for the authority SOA and NSEC(3) records
 * \param ne      The NegCacheEntry to be filled out (will not be cleared, only appended to
 */
static void harvestNXRecords(const vector<DNSRecord>& records, NegCache::NegCacheEntry& ne, const time_t now, uint32_t* lowestTTL) {
  for(const auto& rec : records) {
    if(rec.d_place != DNSResourceRecord::AUTHORITY)
      // RFC 4035 section 3.1.3. indicates that NSEC records MUST be placed in
      // the AUTHORITY section. Section 3.1.1 indicates that that RRSIGs for
      // records MUST be in the same section as the records they cover.
      // Hence, we ignore all records outside of the AUTHORITY section.
      continue;

    if(rec.d_type == QType::RRSIG) {
      auto rrsig = getRR<RRSIGRecordContent>(rec);
      if(rrsig) {
        if(rrsig->d_type == QType::SOA) {
          ne.authoritySOA.signatures.push_back(rec);
          if (lowestTTL && isRRSIGNotExpired(now, rrsig)) {
            *lowestTTL = min(*lowestTTL, rec.d_ttl);
            *lowestTTL = min(*lowestTTL, getRRSIGTTL(now, rrsig));
          }
        }
        if(nsecTypes.count(rrsig->d_type)) {
          ne.DNSSECRecords.signatures.push_back(rec);
          if (lowestTTL && isRRSIGNotExpired(now, rrsig)) {
            *lowestTTL = min(*lowestTTL, rec.d_ttl);
            *lowestTTL = min(*lowestTTL, getRRSIGTTL(now, rrsig));
          }
        }
      }
      continue;
    }
    if(rec.d_type == QType::SOA) {
      ne.authoritySOA.records.push_back(rec);
      if (lowestTTL) {
        *lowestTTL = min(*lowestTTL, rec.d_ttl);
      }
      continue;
    }
    if(nsecTypes.count(rec.d_type)) {
      ne.DNSSECRecords.records.push_back(rec);
      if (lowestTTL) {
        *lowestTTL = min(*lowestTTL, rec.d_ttl);
      }
      continue;
    }
  }
}

static cspmap_t harvestCSPFromNE(const NegCache::NegCacheEntry& ne)
{
  cspmap_t cspmap;
  for(const auto& rec : ne.DNSSECRecords.signatures) {
    if(rec.d_type == QType::RRSIG) {
      auto rrc = getRR<RRSIGRecordContent>(rec);
      if (rrc) {
        cspmap[{rec.d_name,rrc->d_type}].signatures.push_back(rrc);
      }
    }
  }
  for(const auto& rec : ne.DNSSECRecords.records) {
    cspmap[{rec.d_name, rec.d_type}].records.push_back(rec.d_content);
  }
  return cspmap;
}

// TODO remove after processRecords is fixed!
// Adds the RRSIG for the SOA and the NSEC(3) + RRSIGs to ret
static void addNXNSECS(vector<DNSRecord>&ret, const vector<DNSRecord>& records)
{
  NegCache::NegCacheEntry ne;
  harvestNXRecords(records, ne, 0, nullptr);
  ret.insert(ret.end(), ne.authoritySOA.signatures.begin(), ne.authoritySOA.signatures.end());
  ret.insert(ret.end(), ne.DNSSECRecords.records.begin(), ne.DNSSECRecords.records.end());
  ret.insert(ret.end(), ne.DNSSECRecords.signatures.begin(), ne.DNSSECRecords.signatures.end());
}

bool SyncRes::nameserversBlockedByRPZ(const DNSFilterEngine& dfe, const NsSet& nameservers)
{
  if(d_wantsRPZ) {
    for (auto const &ns : nameservers) {
      d_appliedPolicy = dfe.getProcessingPolicy(ns.first, d_discardedPolicies);
      if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
        LOG(", however nameserver "<<ns.first<<" was blocked by RPZ policy '"<<(d_appliedPolicy.d_name ? *d_appliedPolicy.d_name : "")<<"'"<<endl);
        return true;
      }

      // Traverse all IP addresses for this NS to see if they have an RPN NSIP policy
      for (auto const &address : ns.second.first) {
        d_appliedPolicy = dfe.getProcessingPolicy(address, d_discardedPolicies);
        if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
          LOG(", however nameserver "<<ns.first<<" IP address "<<address.toString()<<" was blocked by RPZ policy '"<<(d_appliedPolicy.d_name ? *d_appliedPolicy.d_name : "")<<"'"<<endl);
          return true;
        }
      }
    }
  }
  return false;
}

bool SyncRes::nameserverIPBlockedByRPZ(const DNSFilterEngine& dfe, const ComboAddress& remoteIP)
{
  if (d_wantsRPZ) {
    d_appliedPolicy = dfe.getProcessingPolicy(remoteIP, d_discardedPolicies);
    if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) {
      LOG(" (blocked by RPZ policy '"+(d_appliedPolicy.d_name ? *d_appliedPolicy.d_name : "")+"')");
      return true;
    }
  }
  return false;
}

vector<ComboAddress> SyncRes::retrieveAddressesForNS(const std::string& prefix, const DNSName& qname, vector<DNSName >::const_iterator& tns, const unsigned int depth, set<GetBestNSAnswer>& beenthere, const vector<DNSName >& rnameservers, NsSet& nameservers, bool& sendRDQuery, bool& pierceDontQuery, bool& flawedNSSet, bool cacheOnly)
{
  vector<ComboAddress> result;

  if(!tns->empty()) {
    LOG(prefix<<qname<<": Trying to resolve NS '"<<*tns<< "' ("<<1+tns-rnameservers.begin()<<"/"<<(unsigned int)rnameservers.size()<<")"<<endl);
    result = getAddrs(*tns, depth+2, beenthere, cacheOnly);
    pierceDontQuery=false;
  }
  else {
    LOG(prefix<<qname<<": Domain has hardcoded nameserver");

    result = nameservers[*tns].first;
    if(result.size() > 1) {
      LOG("s");
    }
    LOG(endl);

    sendRDQuery = nameservers[*tns].second;
    pierceDontQuery=true;
  }
  return result;
}

bool SyncRes::throttledOrBlocked(const std::string& prefix, const ComboAddress& remoteIP, const DNSName& qname, const QType& qtype, bool pierceDontQuery)
{
  if(t_sstorage.throttle.shouldThrottle(d_now.tv_sec, boost::make_tuple(remoteIP, "", 0))) {
    LOG(prefix<<qname<<": server throttled "<<endl);
    s_throttledqueries++; d_throttledqueries++;
    return true;
  }
  else if(t_sstorage.throttle.shouldThrottle(d_now.tv_sec, boost::make_tuple(remoteIP, qname, qtype.getCode()))) {
    LOG(prefix<<qname<<": query throttled "<<remoteIP.toString()<<", "<<qname<<"; "<<qtype.getName()<<endl);
    s_throttledqueries++; d_throttledqueries++;
    return true;
  }
  else if(!pierceDontQuery && s_dontQuery && s_dontQuery->match(&remoteIP)) {
    LOG(prefix<<qname<<": not sending query to " << remoteIP.toString() << ", blocked by 'dont-query' setting" << endl);
    s_dontqueries++;
    return true;
  }
  return false;
}

bool SyncRes::validationEnabled() const
{
  return g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate;
}

uint32_t SyncRes::computeLowestTTD(const std::vector<DNSRecord>& records, const std::vector<std::shared_ptr<RRSIGRecordContent> >& signatures, uint32_t signaturesTTL) const
{
  uint32_t lowestTTD = std::numeric_limits<uint32_t>::max();
  for(const auto& record : records)
    lowestTTD = min(lowestTTD, record.d_ttl);

  /* even if it was not requested for that request (Process, and neither AD nor DO set),
     it might be requested at a later time so we need to be careful with the TTL. */
  if (validationEnabled() && !signatures.empty()) {
    /* if we are validating, we don't want to cache records after their signatures expire. */
    /* records TTL are now TTD, let's add 'now' to the signatures lowest TTL */
    lowestTTD = min(lowestTTD, static_cast<uint32_t>(signaturesTTL + d_now.tv_sec));

    for(const auto& sig : signatures) {
      if (isRRSIGNotExpired(d_now.tv_sec, sig)) {
        // we don't decerement d_sigexpire by 'now' because we actually want a TTD, not a TTL */
        lowestTTD = min(lowestTTD, static_cast<uint32_t>(sig->d_sigexpire));
      }
    }
  }

  return lowestTTD;
}

void SyncRes::updateValidationState(vState& state, const vState stateUpdate)
{
  LOG(d_prefix<<"validation state was "<<std::string(vStates[state])<<", state update is "<<std::string(vStates[stateUpdate]));

  if (stateUpdate == TA) {
    state = Secure;
  }
  else if (stateUpdate == NTA) {
    state = Insecure;
  }
  else if (stateUpdate == Bogus) {
    state = Bogus;
  }
  else if (state == Indeterminate) {
    state = stateUpdate;
  }
  else if (stateUpdate == Insecure) {
    if (state != Bogus) {
      state = Insecure;
    }
  }
  LOG(", validation state is now "<<std::string(vStates[state])<<endl);
}

vState SyncRes::getTA(const DNSName& zone, dsmap_t& ds)
{
  auto luaLocal = g_luaconfs.getLocal();

  if (luaLocal->dsAnchors.empty()) {
    LOG(d_prefix<<": No trust anchors configured, everything is Insecure"<<endl);
    /* We have no TA, everything is insecure */
    return Insecure;
  }

  std::string reason;
  if (haveNegativeTrustAnchor(luaLocal->negAnchors, zone, reason)) {
    LOG(d_prefix<<": got NTA for '"<<zone<<"'"<<endl);
    return NTA;
  }

  if (getTrustAnchor(luaLocal->dsAnchors, zone, ds)) {
    LOG(d_prefix<<": got TA for '"<<zone<<"'"<<endl);
    return TA;
  }
  else {
    LOG(d_prefix<<": no TA found for '"<<zone<<"' among "<< luaLocal->dsAnchors.size()<<endl);
  }

  if (zone.isRoot()) {
    /* No TA for the root */
    return Insecure;
  }

  return Indeterminate;
}

static size_t countSupportedDS(const dsmap_t& dsmap)
{
  size_t count = 0;

  for (const auto& ds : dsmap) {
    if (isSupportedDS(ds)) {
      count++;
    }
  }

  return count;
}

vState SyncRes::getDSRecords(const DNSName& zone, dsmap_t& ds, bool taOnly, unsigned int depth, bool bogusOnNXD, bool* foundCut)
{
  vState result = getTA(zone, ds);

  if (result != Indeterminate || taOnly) {
    if (foundCut) {
      *foundCut = (result != Indeterminate);
    }

    if (result == TA) {
      if (countSupportedDS(ds) == 0) {
        ds.clear();
        result = Insecure;
      }
      else {
        result = Secure;
      }
    }
    else if (result == NTA) {
      result = Insecure;
    }

    return result;
  }

  bool oldSkipCNAME = d_skipCNAMECheck;
  d_skipCNAMECheck = true;

  std::set<GetBestNSAnswer> beenthere;
  std::vector<DNSRecord> dsrecords;

  vState state = Indeterminate;
  int rcode = doResolve(zone, QType(QType::DS), dsrecords, depth + 1, beenthere, state);
  d_skipCNAMECheck = oldSkipCNAME;

  if (rcode == RCode::NoError || (rcode == RCode::NXDomain && !bogusOnNXD)) {

    uint8_t bestDigestType = 0;

    if (state == Secure) {
      bool gotCNAME = false;
      for (const auto& record : dsrecords) {
        if (record.d_type == QType::DS) {
          const auto dscontent = getRR<DSRecordContent>(record);
          if (dscontent && isSupportedDS(*dscontent)) {
            // Make GOST a lower prio than SHA256
            if (dscontent->d_digesttype == DNSSECKeeper::GOST && bestDigestType == DNSSECKeeper::SHA256) {
              continue;
            }
            if (dscontent->d_digesttype > bestDigestType || (bestDigestType == DNSSECKeeper::GOST && dscontent->d_digesttype == DNSSECKeeper::SHA256)) {
              bestDigestType = dscontent->d_digesttype;
            }
            ds.insert(*dscontent);
          }
        }
        else if (record.d_type == QType::CNAME && record.d_name == zone) {
          gotCNAME = true;
        }
      }

      /* RFC 4509 section 3: "Validator implementations SHOULD ignore DS RRs containing SHA-1
       * digests if DS RRs with SHA-256 digests are present in the DS RRset."
       * As SHA348 is specified as well, the spirit of the this line is "use the best algorithm".
       */
      for (auto dsrec = ds.begin(); dsrec != ds.end(); ) {
        if (dsrec->d_digesttype != bestDigestType) {
          dsrec = ds.erase(dsrec);
        }
        else {
          ++dsrec;
        }
      }

      if (rcode == RCode::NoError && ds.empty()) {
        if (foundCut) {
          if (gotCNAME || denialProvesNoDelegation(zone, dsrecords)) {
            /* we are still inside the same Secure zone */

            *foundCut = false;
            return Secure;
          }

          *foundCut = true;
        }

        return Insecure;
      } else if (foundCut && rcode == RCode::NoError && !ds.empty()) {
        *foundCut = true;
      }
    }

    return state;
  }

  LOG(d_prefix<<": returning Bogus state from "<<__func__<<"("<<zone<<")"<<endl);
  return Bogus;
}

bool SyncRes::haveExactValidationStatus(const DNSName& domain)
{
  if (!shouldValidate()) {
    return false;
  }
  const auto& it = d_cutStates.find(domain);
  if (it != d_cutStates.cend()) {
    return true;
  }
  return false;
}

vState SyncRes::getValidationStatus(const DNSName& subdomain, bool allowIndeterminate)
{
  vState result = Indeterminate;

  if (!shouldValidate()) {
    return result;
  }
  DNSName name(subdomain);
  do {
    const auto& it = d_cutStates.find(name);
    if (it != d_cutStates.cend()) {
      if (allowIndeterminate || it->second != Indeterminate) {
        LOG(d_prefix<<": got status "<<vStates[it->second]<<" for name "<<subdomain<<" (from "<<name<<")"<<endl);
        return it->second;
      }
    }
  }
  while (name.chopOff());

  return result;
}

bool SyncRes::lookForCut(const DNSName& qname, unsigned int depth, const vState existingState, vState& newState)
{
  bool foundCut = false;
  dsmap_t ds;
  vState dsState = getDSRecords(qname, ds, newState == Bogus || existingState == Insecure || existingState == Bogus, depth, false, &foundCut);

  if (dsState != Indeterminate) {
    newState = dsState;
  }

  return foundCut;
}

void SyncRes::computeZoneCuts(const DNSName& begin, const DNSName& end, unsigned int depth)
{
  if(!begin.isPartOf(end)) {
    LOG(d_prefix<<" "<<begin.toLogString()<<" is not part of "<<end.toString()<<endl);
    throw PDNSException(begin.toLogString() + " is not part of " + end.toString());
  }

  if (d_cutStates.count(begin) != 0) {
    return;
  }

  dsmap_t ds;
  vState cutState = getDSRecords(end, ds, false, depth);
  LOG(d_prefix<<": setting cut state for "<<end<<" to "<<vStates[cutState]<<endl);
  d_cutStates[end] = cutState;

  if (!shouldValidate()) {
    return;
  }

  DNSName qname(end);
  std::vector<string> labelsToAdd = begin.makeRelative(end).getRawLabels();

  bool oldSkipCNAME = d_skipCNAMECheck;
  d_skipCNAMECheck = true;

  while(qname != begin) {
    if (labelsToAdd.empty())
      break;

    qname.prependRawLabel(labelsToAdd.back());
    labelsToAdd.pop_back();
    LOG(d_prefix<<": - Looking for a cut at "<<qname<<endl);

    const auto cutIt = d_cutStates.find(qname);
    if (cutIt != d_cutStates.cend()) {
      if (cutIt->second != Indeterminate) {
        LOG(d_prefix<<": - Cut already known at "<<qname<<endl);
        cutState = cutIt->second;
        continue;
      }
    }

    /* no need to look for NS and DS if we are already insecure or bogus,
       just look for (N)TA
    */
    if (cutState == Insecure || cutState == Bogus) {
      dsmap_t cutDS;
      vState newState = getDSRecords(qname, cutDS, true, depth);
      if (newState == Indeterminate) {
        continue;
      }

      LOG(d_prefix<<": New state for "<<qname<<" is "<<vStates[newState]<<endl);
      cutState = newState;

      d_cutStates[qname] = cutState;

      continue;
    }

    vState newState = Indeterminate;
    /* temporarily mark as Indeterminate, so that we won't enter an endless loop
       trying to determine that zone cut again. */
    d_cutStates[qname] = newState;
    bool foundCut = lookForCut(qname, depth + 1, cutState, newState);
    if (foundCut) {
      LOG(d_prefix<<": - Found cut at "<<qname<<endl);
      if (newState != Indeterminate) {
        cutState = newState;
      }
      LOG(d_prefix<<": New state for "<<qname<<" is "<<vStates[cutState]<<endl);
      d_cutStates[qname] = cutState;
    }
    else {
      /* remove the temporary cut */
      LOG(d_prefix<<qname<<": removing cut state for "<<qname<<endl);
      d_cutStates.erase(qname);
    }
  }

  d_skipCNAMECheck = oldSkipCNAME;

  LOG(d_prefix<<": list of cuts from "<<begin<<" to "<<end<<endl);
  for (const auto& cut : d_cutStates) {
    if (cut.first.isRoot() || (begin.isPartOf(cut.first) && cut.first.isPartOf(end))) {
      LOG(" - "<<cut.first<<": "<<vStates[cut.second]<<endl);
    }
  }
}

vState SyncRes::validateDNSKeys(const DNSName& zone, const std::vector<DNSRecord>& dnskeys, const std::vector<std::shared_ptr<RRSIGRecordContent> >& signatures, unsigned int depth)
{
  dsmap_t ds;
  if (!signatures.empty()) {
    DNSName signer = getSigner(signatures);

    if (!signer.empty() && zone.isPartOf(signer)) {
      vState state = getDSRecords(signer, ds, false, depth);

      if (state != Secure) {
        return state;
      }
    }
  }

  skeyset_t tentativeKeys;
  std::vector<shared_ptr<DNSRecordContent> > toSign;

  for (const auto& dnskey : dnskeys) {
    if (dnskey.d_type == QType::DNSKEY) {
      auto content = getRR<DNSKEYRecordContent>(dnskey);
      if (content) {
        tentativeKeys.insert(content);
        toSign.push_back(content);
      }
    }
  }

  LOG(d_prefix<<": trying to validate "<<std::to_string(tentativeKeys.size())<<" DNSKEYs with "<<std::to_string(ds.size())<<" DS"<<endl);
  skeyset_t validatedKeys;
  validateDNSKeysAgainstDS(d_now.tv_sec, zone, ds, tentativeKeys, toSign, signatures, validatedKeys);

  LOG(d_prefix<<": we now have "<<std::to_string(validatedKeys.size())<<" DNSKEYs"<<endl);

  /* if we found at least one valid RRSIG covering the set,
     all tentative keys are validated keys. Otherwise it means
     we haven't found at least one DNSKEY and a matching RRSIG
     covering this set, this looks Bogus. */
  if (validatedKeys.size() != tentativeKeys.size()) {
    LOG(d_prefix<<": returning Bogus state from "<<__func__<<"("<<zone<<")"<<endl);
    return Bogus;
  }

  return Secure;
}

vState SyncRes::getDNSKeys(const DNSName& signer, skeyset_t& keys, unsigned int depth)
{
  std::vector<DNSRecord> records;
  std::set<GetBestNSAnswer> beenthere;
  LOG(d_prefix<<"Retrieving DNSKeys for "<<signer<<endl);

  vState state = Indeterminate;
  /* following CNAME might lead to us to the wrong DNSKEY */
  bool oldSkipCNAME = d_skipCNAMECheck;
  d_skipCNAMECheck = true;
  int rcode = doResolve(signer, QType(QType::DNSKEY), records, depth + 1, beenthere, state);
  d_skipCNAMECheck = oldSkipCNAME;

  if (rcode == RCode::NoError) {
    if (state == Secure) {
      for (const auto& key : records) {
        if (key.d_type == QType::DNSKEY) {
          auto content = getRR<DNSKEYRecordContent>(key);
          if (content) {
            keys.insert(content);
          }
        }
      }
    }
    LOG(d_prefix<<"Retrieved "<<keys.size()<<" DNSKeys for "<<signer<<", state is "<<vStates[state]<<endl);
    return state;
  }

  LOG(d_prefix<<"Returning Bogus state from "<<__func__<<"("<<signer<<")"<<endl);
  return Bogus;
}

vState SyncRes::validateRecordsWithSigs(unsigned int depth, const DNSName& qname, const QType& qtype, const DNSName& name, const std::vector<DNSRecord>& records, const std::vector<std::shared_ptr<RRSIGRecordContent> >& signatures)
{
  skeyset_t keys;
  if (!signatures.empty()) {
    const DNSName signer = getSigner(signatures);
    if (!signer.empty() && name.isPartOf(signer)) {
      if ((qtype == QType::DNSKEY || qtype == QType::DS) && signer == qname) {
        /* we are already retrieving those keys, sorry */
        return Indeterminate;
      }
      vState state = getDNSKeys(signer, keys, depth);
      if (state != Secure) {
        return state;
      }
    }
  } else {
    LOG(d_prefix<<"Bogus!"<<endl);
    return Bogus;
  }

  std::vector<std::shared_ptr<DNSRecordContent> > recordcontents;
  for (const auto& record : records) {
    recordcontents.push_back(record.d_content);
  }

  LOG(d_prefix<<"Going to validate "<<recordcontents.size()<< " record contents with "<<signatures.size()<<" sigs and "<<keys.size()<<" keys for "<<name<<endl);
  if (validateWithKeySet(d_now.tv_sec, name, recordcontents, signatures, keys, false)) {
    LOG(d_prefix<<"Secure!"<<endl);
    return Secure;
  }

  LOG(d_prefix<<"Bogus!"<<endl);
  return Bogus;
}

RCode::rcodes_ SyncRes::updateCacheFromRecords(unsigned int depth, LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, bool wasForwarded, const boost::optional<Netmask> ednsmask, vState& state, bool& needWildcardProof, bool& gatherWildcardProof, unsigned int& wildcardLabelsCount, bool rdQuery)
{
  bool wasForwardRecurse = wasForwarded && rdQuery;
  tcache_t tcache;

  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  std::vector<std::shared_ptr<DNSRecord>> authorityRecs;
  const unsigned int labelCount = qname.countLabels();
  bool isCNAMEAnswer = false;
  for(const auto& rec : lwr.d_records) {
    if (rec.d_class != QClass::IN) {
      continue;
    }

    if(!isCNAMEAnswer && rec.d_place == DNSResourceRecord::ANSWER && rec.d_type == QType::CNAME && (!(qtype==QType(QType::CNAME))) && rec.d_name == qname) {
      isCNAMEAnswer = true;
    }

    /* if we have a positive answer synthetized from a wildcard,
       we need to store the corresponding NSEC/NSEC3 records proving
       that the exact name did not exist in the negative cache */
    if(gatherWildcardProof) {
      if (nsecTypes.count(rec.d_type)) {
        authorityRecs.push_back(std::make_shared<DNSRecord>(rec));
      }
      else if (rec.d_type == QType::RRSIG) {
        auto rrsig = getRR<RRSIGRecordContent>(rec);
        if (rrsig && nsecTypes.count(rrsig->d_type)) {
          authorityRecs.push_back(std::make_shared<DNSRecord>(rec));
        }
      }
    }
    if(rec.d_type == QType::RRSIG) {
      auto rrsig = getRR<RRSIGRecordContent>(rec);
      if (rrsig) {
        /* As illustrated in rfc4035's Appendix B.6, the RRSIG label
           count can be lower than the name's label count if it was
           synthetized from the wildcard. Note that the difference might
           be > 1. */
        if (rec.d_name == qname && isWildcardExpanded(labelCount, rrsig)) {
          gatherWildcardProof = true;
          if (!isWildcardExpandedOntoItself(rec.d_name, labelCount, rrsig)) {
            /* if we have a wildcard expanded onto itself, we don't need to prove
               that the exact name doesn't exist because it actually does.
               We still want to gather the corresponding NSEC/NSEC3 records
               to pass them to our client in case it wants to validate by itself.
            */
            LOG(prefix<<qname<<": RRSIG indicates the name was synthetized from a wildcard, we need a wildcard proof"<<endl);
            needWildcardProof = true;
          }
          else {
            LOG(prefix<<qname<<": RRSIG indicates the name was synthetized from a wildcard expanded onto itself, we need to gather wildcard proof"<<endl);
          }
          wildcardLabelsCount = rrsig->d_labels;
        }

        //	    cerr<<"Got an RRSIG for "<<DNSRecordContent::NumberToType(rrsig->d_type)<<" with name '"<<rec.d_name<<"'"<<endl;
        tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signatures.push_back(rrsig);
        tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signaturesTTL = std::min(tcache[{rec.d_name, rrsig->d_type, rec.d_place}].signaturesTTL, rec.d_ttl);
      }
    }
  }

  // reap all answers from this packet that are acceptable
  for(auto& rec : lwr.d_records) {
    if(rec.d_type == QType::OPT) {
      LOG(prefix<<qname<<": OPT answer '"<<rec.d_name<<"' from '"<<auth<<"' nameservers" <<endl);
      continue;
    }
    LOG(prefix<<qname<<": accept answer '"<<rec.d_name<<"|"<<DNSRecordContent::NumberToType(rec.d_type)<<"|"<<rec.d_content->getZoneRepresentation()<<"' from '"<<auth<<"' nameservers? ttl="<<rec.d_ttl<<", place="<<(int)rec.d_place<<" ");
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
      else if(lwr.d_aabit && lwr.d_rcode==RCode::NoError && rec.d_place==DNSResourceRecord::ANSWER && ((rec.d_type != QType::DNSKEY && rec.d_type != QType::DS) || rec.d_name != auth) && s_delegationOnly.count(auth)) {
        LOG("NO! Is from delegation-only zone"<<endl);
        s_nodelegated++;
        return RCode::NXDomain;
      }
      else {
        bool haveLogged = false;
        if (!t_sstorage.domainmap->empty()) {
          // Check if we are authoritative for a zone in this answer
          DNSName tmp_qname(rec.d_name);
          auto auth_domain_iter=getBestAuthZone(&tmp_qname);
          if(auth_domain_iter!=t_sstorage.domainmap->end() &&
             auth.countLabels() <= auth_domain_iter->first.countLabels()) {
            if (auth_domain_iter->first != auth) {
              LOG("NO! - we are authoritative for the zone "<<auth_domain_iter->first<<endl);
              continue;
            } else {
              LOG("YES! - This answer was ");
              if (!wasForwarded) {
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
        dr.d_ttl += d_now.tv_sec;
        dr.d_place=DNSResourceRecord::ANSWER;
        tcache[{rec.d_name,rec.d_type,rec.d_place}].records.push_back(dr);
      }
    }
    else
      LOG("NO!"<<endl);
  }

  // supplant
  for(tcache_t::iterator i = tcache.begin(); i != tcache.end(); ++i) {
    if((i->second.records.size() + i->second.signatures.size()) > 1) {  // need to group the ttl to be the minimum of the RRSET (RFC 2181, 5.2)
      uint32_t lowestTTD=computeLowestTTD(i->second.records, i->second.signatures, i->second.signaturesTTL);

      for(auto& record : i->second.records)
        record.d_ttl = lowestTTD; // boom
    }

//		cout<<"Have "<<i->second.records.size()<<" records and "<<i->second.signatures.size()<<" signatures for "<<i->first.name;
//		cout<<'|'<<DNSRecordContent::NumberToType(i->first.type)<<endl;
  }

  for(tcache_t::iterator i = tcache.begin(); i != tcache.end(); ++i) {

    if(i->second.records.empty()) // this happens when we did store signatures, but passed on the records themselves
      continue;

    /* Even if the AA bit is set, additional data cannot be considered
       as authoritative. This is especially important during validation
       because keeping records in the additional section is allowed even
       if the corresponding RRSIGs are not included, without setting the TC
       bit, as stated in rfc4035's section 3.1.1.  Including RRSIG RRs in a Response:
       "When placing a signed RRset in the Additional section, the name
       server MUST also place its RRSIG RRs in the Additional section.
       If space does not permit inclusion of both the RRset and its
       associated RRSIG RRs, the name server MAY retain the RRset while
       dropping the RRSIG RRs.  If this happens, the name server MUST NOT
       set the TC bit solely because these RRSIG RRs didn't fit."
    */
    bool isAA = lwr.d_aabit && i->first.place != DNSResourceRecord::ADDITIONAL;
    bool expectSignature = i->first.place == DNSResourceRecord::ANSWER || ((lwr.d_aabit || wasForwardRecurse) && i->first.place != DNSResourceRecord::ADDITIONAL);
    if (isCNAMEAnswer && (i->first.place != DNSResourceRecord::ANSWER || i->first.type != QType::CNAME || i->first.name != qname)) {
      /*
        rfc2181 states:
        Note that the answer section of an authoritative answer normally
        contains only authoritative data.  However when the name sought is an
        alias (see section 10.1.1) only the record describing that alias is
        necessarily authoritative.  Clients should assume that other records
        may have come from the server's cache.  Where authoritative answers
        are required, the client should query again, using the canonical name
        associated with the alias.
      */
      isAA = false;
      expectSignature = false;
    }

    vState recordState = getValidationStatus(i->first.name, false);
    LOG(d_prefix<<": got initial zone status "<<vStates[recordState]<<" for record "<<i->first.name<<endl);

    if (shouldValidate() && recordState == Secure) {
      vState initialState = recordState;

      if (expectSignature) {
        if (i->first.place != DNSResourceRecord::ADDITIONAL) {
          /* the additional entries can be insecure,
             like glue:
             "Glue address RRsets associated with delegations MUST NOT be signed"
          */
          if (i->first.type == QType::DNSKEY && i->first.place == DNSResourceRecord::ANSWER) {
            LOG(d_prefix<<"Validating DNSKEY for "<<i->first.name<<endl);
            recordState = validateDNSKeys(i->first.name, i->second.records, i->second.signatures, depth);
          }
          else {
            LOG(d_prefix<<"Validating non-additional record for "<<i->first.name<<endl);
            recordState = validateRecordsWithSigs(depth, qname, qtype, i->first.name, i->second.records, i->second.signatures);
            /* we might have missed a cut (zone cut within the same auth servers), causing the NS query for an Insecure zone to seem Bogus during zone cut determination */
            if (qtype == QType::NS && i->second.signatures.empty() && recordState == Bogus && haveExactValidationStatus(i->first.name) && getValidationStatus(i->first.name) == Indeterminate) {
              recordState = Indeterminate;
            }
          }
        }
      }
      else {
        recordState = Indeterminate;

        /* in a non authoritative answer, we only care about the DS record (or lack of)  */
        if ((i->first.type == QType::DS || i->first.type == QType::NSEC || i->first.type == QType::NSEC3) && i->first.place == DNSResourceRecord::AUTHORITY) {
          LOG(d_prefix<<"Validating DS record for "<<i->first.name<<endl);
          recordState = validateRecordsWithSigs(depth, qname, qtype, i->first.name, i->second.records, i->second.signatures);
        }
      }

      if (initialState == Secure && state != recordState && expectSignature) {
        updateValidationState(state, recordState);
      }
    }
    else {
      if (shouldValidate()) {
        LOG(d_prefix<<"Skipping validation because the current state is "<<vStates[recordState]<<endl);
      }
    }

    /* We don't need to store NSEC3 records in the positive cache because:
       - we don't allow direct NSEC3 queries
       - denial of existence proofs in wildcard expanded positive responses are stored in authorityRecs
       - denial of existence proofs for negative responses are stored in the negative cache
    */
    if (i->first.type != QType::NSEC3) {

      bool doCache = true;
      if (i->first.place == DNSResourceRecord::ANSWER && ednsmask) {
        // If ednsmask is relevant, we do not want to cache if the scope prefix length is large and TTL is small
        if (SyncRes::s_ecscachelimitttl > 0) {
          bool manyMaskBits = (ednsmask->isIpv4() && ednsmask->getBits() > SyncRes::s_ecsipv4cachelimit) ||
            (ednsmask->isIpv6() && ednsmask->getBits() > SyncRes::s_ecsipv6cachelimit);

          if (manyMaskBits) {
            uint32_t minttl = UINT32_MAX;
            for (const auto &it : i->second.records) {
              if (it.d_ttl < minttl)
                minttl = it.d_ttl;
            }
            bool ttlIsSmall = minttl < SyncRes::s_ecscachelimitttl + d_now.tv_sec;
            if (ttlIsSmall) {
              // Case: many bits and ttlIsSmall
              doCache = false;
            }
          }
        }
      }
      if (doCache) {
        t_RC->replace(d_now.tv_sec, i->first.name, QType(i->first.type), i->second.records, i->second.signatures, authorityRecs, i->first.type == QType::DS ? true : isAA, i->first.place == DNSResourceRecord::ANSWER ? ednsmask : boost::none, recordState);
      }
    }

    if(i->first.place == DNSResourceRecord::ANSWER && ednsmask)
      d_wasVariable=true;
  }

  return RCode::NoError;
}

void SyncRes::updateDenialValidationState(NegCache::NegCacheEntry& ne, vState& state, const dState denialState, const dState expectedState, bool allowOptOut)
{
  if (denialState == expectedState) {
    ne.d_validationState = Secure;
  }
  else {
    if (denialState == OPTOUT && allowOptOut) {
      LOG(d_prefix<<"OPT-out denial found for "<<ne.d_name<<endl);
      ne.d_validationState = Secure;
      return;
    }
    else if (denialState == INSECURE) {
      LOG(d_prefix<<"Insecure denial found for "<<ne.d_name<<", returning Insecure"<<endl);
      ne.d_validationState = Insecure;
    }
    else {
      LOG(d_prefix<<"Invalid denial found for "<<ne.d_name<<", returning Bogus, res="<<denialState<<", expectedState="<<expectedState<<endl);
      ne.d_validationState = Bogus;
    }
    updateValidationState(state, ne.d_validationState);
  }
}

dState SyncRes::getDenialValidationState(NegCache::NegCacheEntry& ne, const vState state, const dState expectedState, bool referralToUnsigned)
{
  cspmap_t csp = harvestCSPFromNE(ne);
  return getDenial(csp, ne.d_name, ne.d_qtype.getCode(), referralToUnsigned, expectedState == NXQTYPE);
}

bool SyncRes::processRecords(const std::string& prefix, const DNSName& qname, const QType& qtype, const DNSName& auth, LWResult& lwr, const bool sendRDQuery, vector<DNSRecord>& ret, set<DNSName>& nsset, DNSName& newtarget, DNSName& newauth, bool& realreferral, bool& negindic, vState& state, const bool needWildcardProof, const bool gatherWildcardProof, const unsigned int wildcardLabelsCount)
{
  bool done = false;

  for(auto& rec : lwr.d_records) {
    if (rec.d_type!=QType::OPT && rec.d_class!=QClass::IN)
      continue;

    if(rec.d_place==DNSResourceRecord::AUTHORITY && rec.d_type==QType::SOA &&
       lwr.d_rcode==RCode::NXDomain && qname.isPartOf(rec.d_name) && rec.d_name.isPartOf(auth)) {
      LOG(prefix<<qname<<": got negative caching indication for name '"<<qname<<"' (accept="<<rec.d_name.isPartOf(auth)<<"), newtarget='"<<newtarget<<"'"<<endl);

      rec.d_ttl = min(rec.d_ttl, s_maxnegttl);
      if(newtarget.empty()) // only add a SOA if we're not going anywhere after this
        ret.push_back(rec);

      NegCache::NegCacheEntry ne;

      uint32_t lowestTTL = rec.d_ttl;
      /* if we get an NXDomain answer with a CNAME, the name
         does exist but the target does not */
      ne.d_name = newtarget.empty() ? qname : newtarget;
      ne.d_qtype = QType(0); // this encodes 'whole record'
      ne.d_auth = rec.d_name;
      harvestNXRecords(lwr.d_records, ne, d_now.tv_sec, &lowestTTL);
      ne.d_ttd = d_now.tv_sec + lowestTTL;

      if (state == Secure) {
        dState denialState = getDenialValidationState(ne, state, NXDOMAIN, false);
        updateDenialValidationState(ne, state, denialState, NXDOMAIN, false);
      }
      else {
        ne.d_validationState = state;
      }

      /* if we get an NXDomain answer with a CNAME, let's not cache the
         target, even the server was authoritative for it,
         and do an additional query for the CNAME target.
         We have a regression test making sure we do exactly that.
      */
      if(!wasVariable() && newtarget.empty()) {
        t_sstorage.negcache.add(ne);
        if(s_rootNXTrust && ne.d_auth.isRoot() && auth.isRoot()) {
          ne.d_name = ne.d_name.getLastLabel();
          t_sstorage.negcache.add(ne);
        }
      }

      negindic=true;
    }
    else if(rec.d_place==DNSResourceRecord::ANSWER && rec.d_type==QType::CNAME && (!(qtype==QType(QType::CNAME))) && rec.d_name == qname) {
      ret.push_back(rec);
      if (auto content = getRR<CNAMERecordContent>(rec)) {
        newtarget=content->getTarget();
      }
    }
    /* if we have a positive answer synthetized from a wildcard, we need to
       return the corresponding NSEC/NSEC3 records from the AUTHORITY section
       proving that the exact name did not exist */
    else if(gatherWildcardProof && (rec.d_type==QType::RRSIG || rec.d_type==QType::NSEC || rec.d_type==QType::NSEC3) && rec.d_place==DNSResourceRecord::AUTHORITY) {
      ret.push_back(rec); // enjoy your DNSSEC
    }
    // for ANY answers we *must* have an authoritative answer, unless we are forwarding recursively
    else if(rec.d_place==DNSResourceRecord::ANSWER && rec.d_name == qname &&
            (
              rec.d_type==qtype.getCode() || ((lwr.d_aabit || sendRDQuery) && qtype == QType(QType::ANY))
              )
      )
    {
      LOG(prefix<<qname<<": answer is in: resolved to '"<< rec.d_content->getZoneRepresentation()<<"|"<<DNSRecordContent::NumberToType(rec.d_type)<<"'"<<endl);

      done=true;
      ret.push_back(rec);

      if (state == Secure && needWildcardProof) {
        /* We have a positive answer synthetized from a wildcard, we need to check that we have
           proof that the exact name doesn't exist so the wildcard can be used,
           as described in section 5.3.4 of RFC 4035 and 5.3 of FRC 7129.
        */
        NegCache::NegCacheEntry ne;

        uint32_t lowestTTL = rec.d_ttl;
        ne.d_name = qname;
        ne.d_qtype = QType(0); // this encodes 'whole record'
        harvestNXRecords(lwr.d_records, ne, d_now.tv_sec, &lowestTTL);

        cspmap_t csp = harvestCSPFromNE(ne);
        dState res = getDenial(csp, qname, ne.d_qtype.getCode(), false, false, false, wildcardLabelsCount);
        if (res != NXDOMAIN) {
          vState st = Bogus;
          if (res == INSECURE) {
            /* Some part could not be validated, for example a NSEC3 record with a too large number of iterations,
               this is not enough to warrant a Bogus, but go Insecure. */
            st = Insecure;
            LOG(d_prefix<<"Unable to validate denial in wildcard expanded positive response found for "<<qname<<", returning Insecure, res="<<res<<endl);
          }
          else {
            LOG(d_prefix<<"Invalid denial in wildcard expanded positive response found for "<<qname<<", returning Bogus, res="<<res<<endl);
          }

          updateValidationState(state, st);
          /* we already stored the record with a different validation status, let's fix it */
          t_RC->updateValidationStatus(d_now.tv_sec, qname, qtype, d_incomingECSFound ? d_incomingECSNetwork : d_requestor, lwr.d_aabit, st);
        }
      }
    }
    else if((rec.d_type==QType::RRSIG || rec.d_type==QType::NSEC || rec.d_type==QType::NSEC3) && rec.d_place==DNSResourceRecord::ANSWER) {
      if(rec.d_type != QType::RRSIG || rec.d_name == qname)
        ret.push_back(rec); // enjoy your DNSSEC
    }
    else if(rec.d_place==DNSResourceRecord::AUTHORITY && rec.d_type==QType::NS && qname.isPartOf(rec.d_name)) {
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
    else if(rec.d_place==DNSResourceRecord::AUTHORITY && rec.d_type==QType::DS && qname.isPartOf(rec.d_name)) {
      LOG(prefix<<qname<<": got DS record '"<<rec.d_name<<"' -> '"<<rec.d_content->getZoneRepresentation()<<"'"<<endl);
    }
    else if(realreferral && rec.d_place==DNSResourceRecord::AUTHORITY && (rec.d_type==QType::NSEC || rec.d_type==QType::NSEC3) && newauth.isPartOf(auth)) {
      /* we might have received a denial of the DS, let's check */
      if (state == Secure) {
        NegCache::NegCacheEntry ne;
        ne.d_auth = auth;
        ne.d_name = newauth;
        ne.d_qtype = QType::DS;
        rec.d_ttl = min(s_maxnegttl, rec.d_ttl);
        uint32_t lowestTTL = rec.d_ttl;
        harvestNXRecords(lwr.d_records, ne, d_now.tv_sec, &lowestTTL);

        dState denialState = getDenialValidationState(ne, state, NXQTYPE, true);

        if (denialState == NXQTYPE || denialState == OPTOUT || denialState == INSECURE) {
          ne.d_ttd = lowestTTL + d_now.tv_sec;
          ne.d_validationState = Secure;
          LOG(prefix<<qname<<": got negative indication of DS record for '"<<newauth<<"'"<<endl);

          if(!wasVariable()) {
            t_sstorage.negcache.add(ne);
          }

          if (qname == newauth && qtype == QType::DS) {
            /* we are actually done! */
            negindic=true;
            nsset.clear();
          }
        }
      }
    }
    else if(!done && rec.d_place==DNSResourceRecord::AUTHORITY && rec.d_type==QType::SOA &&
            lwr.d_rcode==RCode::NoError && qname.isPartOf(rec.d_name)) {
      LOG(prefix<<qname<<": got negative caching indication for '"<< qname<<"|"<<qtype.getName()<<"'"<<endl);

      if(!newtarget.empty()) {
        LOG(prefix<<qname<<": Hang on! Got a redirect to '"<<newtarget<<"' already"<<endl);
      }
      else {
        rec.d_ttl = min(s_maxnegttl, rec.d_ttl);
        ret.push_back(rec);

        NegCache::NegCacheEntry ne;
        ne.d_auth = rec.d_name;
        uint32_t lowestTTL = rec.d_ttl;
        ne.d_name = qname;
        ne.d_qtype = qtype;
        harvestNXRecords(lwr.d_records, ne, d_now.tv_sec, &lowestTTL);
        ne.d_ttd = d_now.tv_sec + lowestTTL;

        if (state == Secure) {
          dState denialState = getDenialValidationState(ne, state, NXQTYPE, false);
          updateDenialValidationState(ne, state, denialState, NXQTYPE, qtype == QType::DS);
        } else {
          ne.d_validationState = state;
        }

        if(!wasVariable()) {
          if(qtype.getCode()) {  // prevents us from blacking out a whole domain
            t_sstorage.negcache.add(ne);
          }
        }
        negindic=true;
      }
    }
  }

  return done;
}

bool SyncRes::doResolveAtThisIP(const std::string& prefix, const DNSName& qname, const QType& qtype, LWResult& lwr, boost::optional<Netmask>& ednsmask, const DNSName& auth, bool const sendRDQuery, const DNSName& nsName, const ComboAddress& remoteIP, bool doTCP, bool* truncated)
{
  bool chained = false;
  int resolveret = RCode::NoError;
  s_outqueries++;
  d_outqueries++;

  if(d_outqueries + d_throttledqueries > s_maxqperq) {
    throw ImmediateServFailException("more than "+std::to_string(s_maxqperq)+" (max-qperq) queries sent while resolving "+qname.toLogString());
  }

  if(s_maxtotusec && d_totUsec > s_maxtotusec) {
    throw ImmediateServFailException("Too much time waiting for "+qname.toLogString()+"|"+qtype.getName()+", timeouts: "+std::to_string(d_timeouts) +", throttles: "+std::to_string(d_throttledqueries) + ", queries: "+std::to_string(d_outqueries)+", "+std::to_string(d_totUsec/1000)+"msec");
  }

  if(doTCP) {
    LOG(prefix<<qname<<": using TCP with "<< remoteIP.toStringWithPort() <<endl);
    s_tcpoutqueries++;
    d_tcpoutqueries++;
  }

  if(d_pdl && d_pdl->preoutquery(remoteIP, d_requestor, qname, qtype, doTCP, lwr.d_records, resolveret)) {
    LOG(prefix<<qname<<": query handled by Lua"<<endl);
  }
  else {
    ednsmask=getEDNSSubnetMask(d_requestor, qname, remoteIP);
    if(ednsmask) {
      LOG(prefix<<qname<<": Adding EDNS Client Subnet Mask "<<ednsmask->toString()<<" to query"<<endl);
      s_ecsqueries++;
    }
    resolveret = asyncresolveWrapper(remoteIP, d_doDNSSEC, qname,  qtype.getCode(),
                                     doTCP, sendRDQuery, &d_now, ednsmask, &lwr, &chained);    // <- we go out on the wire!
    if(ednsmask) {
      s_ecsresponses++;
      LOG(prefix<<qname<<": Received EDNS Client Subnet Mask "<<ednsmask->toString()<<" on response"<<endl);
    }
  }

  /* preoutquery killed the query by setting dq.rcode to -3 */
  if(resolveret==-3) {
    throw ImmediateServFailException("Query killed by policy");
  }

  d_totUsec += lwr.d_usec;
  accountAuthLatency(lwr.d_usec, remoteIP.sin4.sin_family);

  if(resolveret != 1) {
    /* Error while resolving */
    if(resolveret == 0) {
      /* Time out */

      LOG(prefix<<qname<<": timeout resolving after "<<lwr.d_usec/1000.0<<"msec "<< (doTCP ? "over TCP" : "")<<endl);
      d_timeouts++;
      s_outgoingtimeouts++;

      if(remoteIP.sin4.sin_family == AF_INET)
        s_outgoing4timeouts++;
      else
        s_outgoing6timeouts++;
    }
    else if(resolveret == -2) {
      /* OS resource limit reached */
      LOG(prefix<<qname<<": hit a local resource limit resolving"<< (doTCP ? " over TCP" : "")<<", probable error: "<<stringerror()<<endl);
      g_stats.resourceLimits++;
    }
    else {
      /* -1 means server unreachable */
      s_unreachables++;
      d_unreachables++;
      LOG(prefix<<qname<<": error resolving from "<<remoteIP.toString()<< (doTCP ? " over TCP" : "") <<", possible error: "<<strerror(errno)<< endl);
    }

    if(resolveret != -2 && !chained) { // don't account for resource limits, they are our own fault
      t_sstorage.nsSpeeds[nsName].submit(remoteIP, 1000000, &d_now); // 1 sec

      // code below makes sure we don't filter COM or the root
      if (s_serverdownmaxfails > 0 && (auth != g_rootdnsname) && t_sstorage.fails.incr(remoteIP, d_now) >= s_serverdownmaxfails) {
        LOG(prefix<<qname<<": Max fails reached resolving on "<< remoteIP.toString() <<". Going full throttle for "<< s_serverdownthrottletime <<" seconds" <<endl);
        // mark server as down
        t_sstorage.throttle.throttle(d_now.tv_sec, boost::make_tuple(remoteIP, "", 0), s_serverdownthrottletime, 10000);
      }
      else if (resolveret == -1) {
        // unreachable, 1 minute or 100 queries
        t_sstorage.throttle.throttle(d_now.tv_sec, boost::make_tuple(remoteIP, qname, qtype.getCode()), 60, 100);
      }
      else {
        // timeout
        t_sstorage.throttle.throttle(d_now.tv_sec, boost::make_tuple(remoteIP, qname, qtype.getCode()), 10, 5);
      }
    }

    return false;
  }

  /* we got an answer */
  if(lwr.d_rcode==RCode::ServFail || lwr.d_rcode==RCode::Refused) {
    LOG(prefix<<qname<<": "<<nsName<<" ("<<remoteIP.toString()<<") returned a "<< (lwr.d_rcode==RCode::ServFail ? "ServFail" : "Refused") << ", trying sibling IP or NS"<<endl);
    if (!chained) {
      t_sstorage.throttle.throttle(d_now.tv_sec, boost::make_tuple(remoteIP, qname, qtype.getCode()), 60, 3);
    }
    return false;
  }

  /* this server sent a valid answer, mark it backup up if it was down */
  if(s_serverdownmaxfails > 0) {
    t_sstorage.fails.clear(remoteIP);
  }

  if(lwr.d_tcbit) {
    *truncated = true;

    if (doTCP) {
      LOG(prefix<<qname<<": truncated bit set, over TCP?"<<endl);
      /* let's treat that as a ServFail answer from this server */
      t_sstorage.throttle.throttle(d_now.tv_sec, boost::make_tuple(remoteIP, qname, qtype.getCode()), 60, 3);
      return false;
    }

    return true;
  }

  return true;
}

bool SyncRes::processAnswer(unsigned int depth, LWResult& lwr, const DNSName& qname, const QType& qtype, DNSName& auth, bool wasForwarded, const boost::optional<Netmask> ednsmask, bool sendRDQuery, NsSet &nameservers, std::vector<DNSRecord>& ret, const DNSFilterEngine& dfe, bool* gotNewServers, int* rcode, vState& state)
{
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  if(s_minimumTTL) {
    for(auto& rec : lwr.d_records) {
      rec.d_ttl = max(rec.d_ttl, s_minimumTTL);
    }
  }

  bool needWildcardProof = false;
  bool gatherWildcardProof = false;
  unsigned int wildcardLabelsCount;
  *rcode = updateCacheFromRecords(depth, lwr, qname, qtype, auth, wasForwarded, ednsmask, state, needWildcardProof, gatherWildcardProof, wildcardLabelsCount, sendRDQuery);
  if (*rcode != RCode::NoError) {
    return true;
  }

  LOG(prefix<<qname<<": determining status after receiving this packet"<<endl);

  set<DNSName> nsset;
  bool realreferral=false, negindic=false;
  DNSName newauth;
  DNSName newtarget;

  bool done = processRecords(prefix, qname, qtype, auth, lwr, sendRDQuery, ret, nsset, newtarget, newauth, realreferral, negindic, state, needWildcardProof, gatherWildcardProof, wildcardLabelsCount);

  if(done){
    LOG(prefix<<qname<<": status=got results, this level of recursion done"<<endl);
    LOG(prefix<<qname<<": validation status is "<<vStates[state]<<endl);
    *rcode = RCode::NoError;
    return true;
  }

  if(!newtarget.empty()) {
    if(newtarget == qname) {
      LOG(prefix<<qname<<": status=got a CNAME referral to self, returning SERVFAIL"<<endl);
      *rcode = RCode::ServFail;
      return true;
    }

    if(depth > 10) {
      LOG(prefix<<qname<<": status=got a CNAME referral, but recursing too deep, returning SERVFAIL"<<endl);
      *rcode = RCode::ServFail;
      return true;
    }

    if (qtype == QType::DS) {
      LOG(prefix<<qname<<": status=got a CNAME referral, but we are looking for a DS"<<endl);

      if(d_doDNSSEC)
        addNXNSECS(ret, lwr.d_records);

      *rcode = RCode::NoError;
      return true;
    }
    else {
      LOG(prefix<<qname<<": status=got a CNAME referral, starting over with "<<newtarget<<endl);

      set<GetBestNSAnswer> beenthere2;
      vState cnameState = Indeterminate;
      *rcode = doResolve(newtarget, qtype, ret, depth + 1, beenthere2, cnameState);
      LOG(prefix<<qname<<": updating validation state for response to "<<qname<<" from "<<vStates[state]<<" with the state from the CNAME quest: "<<vStates[cnameState]<<endl);
      updateValidationState(state, cnameState);
      return true;
    }
  }

  if(lwr.d_rcode == RCode::NXDomain) {
    LOG(prefix<<qname<<": status=NXDOMAIN, we are done "<<(negindic ? "(have negative SOA)" : "")<<endl);

    if(d_doDNSSEC)
      addNXNSECS(ret, lwr.d_records);

    *rcode = RCode::NXDomain;
    return true;
  }

  if(nsset.empty() && !lwr.d_rcode && (negindic || lwr.d_aabit || sendRDQuery)) {
    LOG(prefix<<qname<<": status=noerror, other types may exist, but we are done "<<(negindic ? "(have negative SOA) " : "")<<(lwr.d_aabit ? "(have aa bit) " : "")<<endl);

    if(state == Secure && lwr.d_aabit && !negindic) {
      updateValidationState(state, Bogus);
    }

    if(d_doDNSSEC)
      addNXNSECS(ret, lwr.d_records);

    *rcode = RCode::NoError;
    return true;
  }

  if(realreferral) {
    LOG(prefix<<qname<<": status=did not resolve, got "<<(unsigned int)nsset.size()<<" NS, ");

    nameservers.clear();
    for (auto const &nameserver : nsset) {
      if (d_wantsRPZ) {
        d_appliedPolicy = dfe.getProcessingPolicy(nameserver, d_discardedPolicies);
        if (d_appliedPolicy.d_kind != DNSFilterEngine::PolicyKind::NoAction) { // client query needs an RPZ response
          LOG("however "<<nameserver<<" was blocked by RPZ policy '"<<(d_appliedPolicy.d_name ? *d_appliedPolicy.d_name : "")<<"'"<<endl);
          *rcode = -2;
          return true;
        }
      }
      nameservers.insert({nameserver, {{}, false}});
    }
    LOG("looping to them"<<endl);
    *gotNewServers = true;
    auth=newauth;

    return false;
  }

  return false;
}

/** returns:
 *  -1 in case of no results
 *  -2 when a FilterEngine Policy was hit
 *  rcode otherwise
 */
int SyncRes::doResolveAt(NsSet &nameservers, DNSName auth, bool flawedNSSet, const DNSName &qname, const QType &qtype,
                         vector<DNSRecord>&ret,
                         unsigned int depth, set<GetBestNSAnswer>&beenthere, vState& state)
{
  auto luaconfsLocal = g_luaconfs.getLocal();
  string prefix;
  if(doLog()) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  LOG(prefix<<qname<<": Cache consultations done, have "<<(unsigned int)nameservers.size()<<" NS to contact");

  if (nameserversBlockedByRPZ(luaconfsLocal->dfe, nameservers)) {
    return -2;
  }

  LOG(endl);

  for(;;) { // we may get more specific nameservers
    vector<DNSName > rnameservers = shuffleInSpeedOrder(nameservers, doLog() ? (prefix+qname.toString()+": ") : string() );

    for(auto tns=rnameservers.cbegin();;++tns) {
      if(tns==rnameservers.cend()) {
        LOG(prefix<<qname<<": Failed to resolve via any of the "<<(unsigned int)rnameservers.size()<<" offered NS at level '"<<auth<<"'"<<endl);
        if(!auth.isRoot() && flawedNSSet) {
          LOG(prefix<<qname<<": Ageing nameservers for level '"<<auth<<"', next query might succeed"<<endl);

          if(t_RC->doAgeCache(d_now.tv_sec, auth, QType::NS, 10))
            g_stats.nsSetInvalidations++;
        }
        return -1;
      }

      bool cacheOnly = false;
      // this line needs to identify the 'self-resolving' behaviour
      if(qname == *tns && (qtype.getCode() == QType::A || qtype.getCode() == QType::AAAA)) {
        /* we might have a glue entry in cache so let's try this NS
           but only if we have enough in the cache to know how to reach it */
        LOG(prefix<<qname<<": Using NS to resolve itself, but only using what we have in cache ("<<(1+tns-rnameservers.cbegin())<<"/"<<rnameservers.size()<<")"<<endl);
        cacheOnly = true;
      }

      typedef vector<ComboAddress> remoteIPs_t;
      remoteIPs_t remoteIPs;
      remoteIPs_t::const_iterator remoteIP;
      bool pierceDontQuery=false;
      bool sendRDQuery=false;
      boost::optional<Netmask> ednsmask;
      LWResult lwr;
      const bool wasForwarded = tns->empty() && (!nameservers[*tns].first.empty());
      int rcode = RCode::NoError;
      bool gotNewServers = false;

      if(tns->empty() && !wasForwarded) {
        LOG(prefix<<qname<<": Domain is out-of-band"<<endl);
        /* setting state to indeterminate since validation is disabled for local auth zone,
           and Insecure would be misleading. */
        state = Indeterminate;
        d_wasOutOfBand = doOOBResolve(qname, qtype, lwr.d_records, depth, lwr.d_rcode);
        lwr.d_tcbit=false;
        lwr.d_aabit=true;

        /* we have received an answer, are we done ? */
        bool done = processAnswer(depth, lwr, qname, qtype, auth, false, ednsmask, sendRDQuery, nameservers, ret, luaconfsLocal->dfe, &gotNewServers, &rcode, state);
        if (done) {
          return rcode;
        }
        if (gotNewServers) {
          break;
        }
      }
      else {
        /* if tns is empty, retrieveAddressesForNS() knows we have hardcoded servers (i.e. "forwards") */
        remoteIPs = retrieveAddressesForNS(prefix, qname, tns, depth, beenthere, rnameservers, nameservers, sendRDQuery, pierceDontQuery, flawedNSSet, cacheOnly);

        if(remoteIPs.empty()) {
          LOG(prefix<<qname<<": Failed to get IP for NS "<<*tns<<", trying next if available"<<endl);
          flawedNSSet=true;
          continue;
        }
        else {
          bool hitPolicy{false};
          LOG(prefix<<qname<<": Resolved '"<<auth<<"' NS "<<*tns<<" to: ");
          for(remoteIP = remoteIPs.cbegin(); remoteIP != remoteIPs.cend(); ++remoteIP) {
            if(remoteIP != remoteIPs.cbegin()) {
              LOG(", ");
            }
            LOG(remoteIP->toString());
            if(nameserverIPBlockedByRPZ(luaconfsLocal->dfe, *remoteIP)) {
              hitPolicy = true;
            }
          }
          LOG(endl);
          if (hitPolicy) //implies d_wantsRPZ
            return -2;
        }

        for(remoteIP = remoteIPs.cbegin(); remoteIP != remoteIPs.cend(); ++remoteIP) {
          LOG(prefix<<qname<<": Trying IP "<< remoteIP->toStringWithPort() <<", asking '"<<qname<<"|"<<qtype.getName()<<"'"<<endl);

          if (throttledOrBlocked(prefix, *remoteIP, qname, qtype, pierceDontQuery)) {
            continue;
          }

          bool truncated = false;
          bool gotAnswer = doResolveAtThisIP(prefix, qname, qtype, lwr, ednsmask, auth, sendRDQuery,
                                             *tns, *remoteIP, false, &truncated);
          if (gotAnswer && truncated ) {
            /* retry, over TCP this time */
            gotAnswer = doResolveAtThisIP(prefix, qname, qtype, lwr, ednsmask, auth, sendRDQuery,
                                          *tns, *remoteIP, true, &truncated);
          }

          if (!gotAnswer) {
            continue;
          }

          LOG(prefix<<qname<<": Got "<<(unsigned int)lwr.d_records.size()<<" answers from "<<*tns<<" ("<< remoteIP->toString() <<"), rcode="<<lwr.d_rcode<<" ("<<RCode::to_s(lwr.d_rcode)<<"), aa="<<lwr.d_aabit<<", in "<<lwr.d_usec/1000<<"ms"<<endl);

          /*  // for you IPv6 fanatics :-)
              if(remoteIP->sin4.sin_family==AF_INET6)
              lwr.d_usec/=3;
          */
          //        cout<<"msec: "<<lwr.d_usec/1000.0<<", "<<g_avgLatency/1000.0<<'\n';

          t_sstorage.nsSpeeds[*tns].submit(*remoteIP, lwr.d_usec, &d_now);

          /* we have received an answer, are we done ? */
          bool done = processAnswer(depth, lwr, qname, qtype, auth, wasForwarded, ednsmask, sendRDQuery, nameservers, ret, luaconfsLocal->dfe, &gotNewServers, &rcode, state);
          if (done) {
            return rcode;
          }
          if (gotNewServers) {
            break;
          }
          /* was lame */
          t_sstorage.throttle.throttle(d_now.tv_sec, boost::make_tuple(*remoteIP, qname, qtype.getCode()), 60, 100);
        }

        if (gotNewServers) {
          break;
        }

        if(remoteIP == remoteIPs.cend())  // we tried all IP addresses, none worked
          continue;

      }
    }
  }
  return -1;
}

void SyncRes::setIncomingECS(boost::optional<const EDNSSubnetOpts&> incomingECS)
{
  d_incomingECS = incomingECS;
  if (incomingECS) {
    if (d_incomingECS->source.getBits() == 0) {
      /* RFC7871 says we MUST NOT send any ECS if the source scope is 0.
         But using an empty ECS in that case would mean inserting
         a non ECS-specific entry into the cache, preventing any further
         ECS-specific query to be sent.
         So instead we use the trick described in section 7.1.2:
         "The subsequent Recursive Resolver query to the Authoritative Nameserver
         will then either not include an ECS option or MAY optionally include
         its own address information, which is what the Authoritative
         Nameserver will almost certainly use to generate any Tailored
         Response in lieu of an option.  This allows the answer to be handled
         by the same caching mechanism as other queries, with an explicit
         indicator of the applicable scope.  Subsequent Stub Resolver queries
         for /0 can then be answered from this cached response.
      */
      d_incomingECS = s_ecsScopeZero;
      d_incomingECSNetwork = s_ecsScopeZero.source.getMaskedNetwork();
    }
    else {
      uint8_t bits = std::min(incomingECS->source.getBits(), (incomingECS->source.isIpv4() ? s_ecsipv4limit : s_ecsipv6limit));
      d_incomingECS->source = Netmask(incomingECS->source.getNetwork(), bits);
      d_incomingECSNetwork = d_incomingECS->source.getMaskedNetwork();
    }
  }
  else {
    d_incomingECSNetwork = ComboAddress();
  }
}

boost::optional<Netmask> SyncRes::getEDNSSubnetMask(const ComboAddress& local, const DNSName&dn, const ComboAddress& rem)
{
  boost::optional<Netmask> result;
  ComboAddress trunc;
  uint8_t bits;
  if(d_incomingECSFound) {
    trunc = d_incomingECSNetwork;
    bits = d_incomingECS->source.getBits();
  }
  else if(!local.isIPv4() || local.sin4.sin_addr.s_addr) { // detect unset 'requestor'
    trunc = local;
    bits = local.isIPv4() ? 32 : 128;
    bits = std::min(bits, (trunc.isIPv4() ? s_ecsipv4limit : s_ecsipv6limit));
  }
  else {
    /* nothing usable */
    return result;
  }

  if(s_ednsdomains.check(dn) || s_ednssubnets.match(rem)) {
    trunc.truncate(bits);
    return boost::optional<Netmask>(Netmask(trunc, bits));
  }

  return result;
}

void SyncRes::parseEDNSSubnetWhitelist(const std::string& wlist)
{
  vector<string> parts;
  stringtok(parts, wlist, ",; ");
  for(const auto& a : parts) {
    try {
      s_ednssubnets.addMask(Netmask(a));
    }
    catch(...) {
      s_ednsdomains.add(DNSName(a));
    }
  }
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

int SyncRes::getRootNS(struct timeval now, asyncresolve_t asyncCallback) {
  SyncRes sr(now);
  sr.setDoEDNS0(true);
  sr.setUpdatingRootNS();
  sr.setDoDNSSEC(g_dnssecmode != DNSSECMode::Off);
  sr.setDNSSECValidationRequested(g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate);
  sr.setAsyncCallback(asyncCallback);

  vector<DNSRecord> ret;
  int res=-1;
  try {
    res=sr.beginResolve(g_rootdnsname, QType(QType::NS), 1, ret);
    if (g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate) {
      auto state = sr.getValidationState();
      if (state == Bogus)
        throw PDNSException("Got Bogus validation result for .|NS");
    }
    return res;
  }
  catch(const PDNSException& e) {
    L<<Logger::Error<<"Failed to update . records, got an exception: "<<e.reason<<endl;
  }
  catch(const ImmediateServFailException& e) {
    L<<Logger::Error<<"Failed to update . records, got an exception: "<<e.reason<<endl;
  }
  catch(const std::exception& e) {
    L<<Logger::Error<<"Failed to update . records, got an exception: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Failed to update . records, got an exception"<<endl;
  }

  if(!res) {
    L<<Logger::Notice<<"Refreshed . records"<<endl;
  }
  else
    L<<Logger::Error<<"Failed to update . records, RCODE="<<res<<endl;

  return res;
}

