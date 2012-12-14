#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include <boost/format.hpp>
#include "config.h"
#ifndef RECURSOR
#include "statbag.hh"
StatBag S;
#endif

volatile bool g_ret; // make sure the optimizer does not get too smart
uint64_t g_totalRuns;

volatile bool g_stop;

void alarmHandler(int)
{
  g_stop=true;
}

template<typename C> void doRun(const C& cmd, int mseconds=100)
{
  struct itimerval it;
  it.it_value.tv_sec=mseconds/1000;
  it.it_value.tv_usec = 1000* (mseconds%1000);
  it.it_interval.tv_sec=0;
  it.it_interval.tv_usec=0;

  signal(SIGVTALRM, alarmHandler);
  setitimer(ITIMER_VIRTUAL, &it, 0);
  
  unsigned int runs=0;
  g_stop=false;
  DTime dt;
  dt.set();
  while(runs++, !g_stop) {
    cmd();
  }
  double delta=dt.udiff()/1000000.0;
  boost::format fmt("'%s' %.02f seconds: %.1f runs/s, %.02f usec/run");

  cerr<< (fmt % cmd.getName() % delta % (runs/delta) % (delta* 1000000.0/runs)) << endl;
  g_totalRuns += runs;
}

struct ARecordTest
{
  explicit ARecordTest(int records) : d_records(records) {}

  string getName() const
  {
    return (boost::format("%d a records") % d_records).str();
  }

  void operator()() const
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, "outpost.ds9a.nl", QType::A);
    for(int records = 0; records < d_records; records++) {
      pw.startRecord("outpost.ds9a.nl", QType::A);
      ARecordContent arc("1.2.3.4");
      arc.toPacket(pw);
    }
    pw.commit();
  }
  int d_records;
};


struct MakeStringFromCharStarTest
{
  MakeStringFromCharStarTest() : d_size(0){}
  string getName() const
  {
    return (boost::format("make a std::string")).str();
  }

  void operator()() const
  {
    string name("outpost.ds9a.nl");
    d_size += name.length();
    
  }
  mutable int d_size;
};


struct GetTimeTest
{
  string getName() const
  {
    return "gettimeofday-test";
  }

  void operator()() const
  {
    struct timeval tv;
    gettimeofday(&tv, 0);
  }
};

pthread_mutex_t s_testlock=PTHREAD_MUTEX_INITIALIZER;

struct GetLockUncontendedTest
{
  string getName() const
  {
    return "getlock-uncontended-test";
  }

  void operator()() const
  {
    pthread_mutex_lock(&s_testlock);
    pthread_mutex_unlock(&s_testlock);
  }
};


struct StaticMemberTest
{
  string getName() const
  {
    return "static-member-test";
  }

  void operator()() const
  {
    static string* s_ptr;
    if(!s_ptr)
      s_ptr = new string();
  }
};


struct MakeARecordTest
{
  string getName() const
  {
    return (boost::format("make a-record")).str();
  }

  void operator()() const
  {
      static string src("1.2.3.4");
      ARecordContent arc(src);
      //ARecordContent arc(0x01020304);

  }
};

struct MakeARecordTestMM
{
  string getName() const
  {
    return (boost::format("make a-record (mm)")).str();
  }

  void operator()() const
  {
      DNSRecordContent*drc = DNSRecordContent::mastermake(QType::A, 1, 
        						  "1.2.3.4");
      delete drc;
  }
};


struct A2RecordTest
{
  explicit A2RecordTest(int records) : d_records(records) {}

  string getName() const
  {
    return (boost::format("%d a records") % d_records).str();
  }

  void operator()() const
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, "outpost.ds9a.nl", QType::A);
    ARecordContent arc("1.2.3.4");
    string name("outpost.ds9a.nl");
    for(int records = 0; records < d_records; records++) {
      pw.startRecord(name, QType::A);

      arc.toPacket(pw);
    }
    pw.commit();
  }
  int d_records;
};


struct TXTRecordTest
{
  explicit TXTRecordTest(int records) : d_records(records) {}

  string getName() const
  {
    return (boost::format("%d TXT records") % d_records).str();
  }

  void operator()() const
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, "outpost.ds9a.nl", QType::TXT);
    for(int records = 0; records < d_records; records++) {
      pw.startRecord("outpost.ds9a.nl", QType::TXT);
      TXTRecordContent arc("\"een leuk verhaaltje in een TXT\"");
      arc.toPacket(pw);
    }
    pw.commit();
  }
  int d_records;
};


struct GenericRecordTest
{
  explicit GenericRecordTest(int records, uint16_t type, const std::string& content) 
    : d_records(records), d_type(type), d_content(content) {}

  string getName() const
  {
    return (boost::format("%d %s records") % d_records % 
            DNSRecordContent::NumberToType(d_type)).str();
  }

  void operator()() const
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, "outpost.ds9a.nl", d_type);
    for(int records = 0; records < d_records; records++) {
      pw.startRecord("outpost.ds9a.nl", d_type);
      DNSRecordContent*drc = DNSRecordContent::mastermake(d_type, 1, 
        						  d_content);
      drc->toPacket(pw);
      delete drc;
    }
    pw.commit();
  }
  int d_records;
  uint16_t d_type;
  string d_content;
};


struct AAAARecordTest
{
  explicit AAAARecordTest(int records) : d_records(records) {}

  string getName() const
  {
    return (boost::format("%d aaaa records (mm)") % d_records).str();
  }

  void operator()() const
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, "outpost.ds9a.nl", QType::AAAA);
    for(int records = 0; records < d_records; records++) {
      pw.startRecord("outpost.ds9a.nl", QType::AAAA);
      DNSRecordContent*drc = DNSRecordContent::mastermake(QType::AAAA, 1, "fe80::21d:92ff:fe6d:8441");
      drc->toPacket(pw);
      delete drc;
    }
    pw.commit();
  }
  int d_records;
};

struct SOARecordTest
{
  explicit SOARecordTest(int records) : d_records(records) {}

  string getName() const
  {
    return (boost::format("%d soa records (mm)") % d_records).str();
  }

  void operator()() const
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, "outpost.ds9a.nl", QType::SOA);

    for(int records = 0; records < d_records; records++) {
      pw.startRecord("outpost.ds9a.nl", QType::SOA);
      DNSRecordContent*drc = DNSRecordContent::mastermake(QType::SOA, 1, "a0.org.afilias-nst.info. noc.afilias-nst.info. 2008758137 1800 900 604800 86400");
      drc->toPacket(pw);
      delete drc;
    }
    pw.commit();
  }
  int d_records;
};

vector<uint8_t> makeEmptyQuery()
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, "outpost.ds9a.nl", QType::SOA);
  return  packet;
}


vector<uint8_t> makeRootReferral()
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, "outpost.ds9a.nl", QType::SOA);

  // nobody reads what we output, but it appears to be the magic that shuts some nameservers up
  static const char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
        	     "192.36.148.17","192.58.128.30", "193.0.14.129", "198.32.64.12", "202.12.27.33"};
  static char templ[40];
  strncpy(templ,"a.root-servers.net", sizeof(templ) - 1);
  
  
  for(char c='a';c<='m';++c) {
    *templ=c;
    pw.startRecord(".", QType::NS, 3600, 1, DNSPacketWriter::AUTHORITY);
    DNSRecordContent* drc = DNSRecordContent::mastermake(QType::NS, 1, templ);
    drc->toPacket(pw);
    delete drc;
  }

  for(char c='a';c<='m';++c) {
    *templ=c;
    pw.startRecord(".", QType::A, 3600, 1, DNSPacketWriter::ADDITIONAL);
    DNSRecordContent* drc = DNSRecordContent::mastermake(QType::A, 1, ips[c-'a']);
    drc->toPacket(pw);
    delete drc;
  }
  pw.commit();
  return  packet;

}

vector<uint8_t> makeTypicalReferral()
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, "outpost.ds9a.nl", QType::A);

  pw.startRecord("ds9a.nl", QType::NS, 3600, 1, DNSPacketWriter::AUTHORITY);
  DNSRecordContent* drc = DNSRecordContent::mastermake(QType::NS, 1, "ns1.ds9a.nl");
  drc->toPacket(pw);
  delete drc;

  pw.startRecord("ds9a.nl", QType::NS, 3600, 1, DNSPacketWriter::AUTHORITY);
  drc = DNSRecordContent::mastermake(QType::NS, 1, "ns2.ds9a.nl");
  drc->toPacket(pw);
  delete drc;


  pw.startRecord("ns1.ds9a.nl", QType::A, 3600, 1, DNSPacketWriter::ADDITIONAL);
  drc = DNSRecordContent::mastermake(QType::A, 1, "1.2.3.4");
  drc->toPacket(pw);
  delete drc;

  pw.startRecord("ns2.ds9a.nl", QType::A, 3600, 1, DNSPacketWriter::ADDITIONAL);
  drc = DNSRecordContent::mastermake(QType::A, 1, "4.3.2.1");
  drc->toPacket(pw);
  delete drc;

  pw.commit();
  return  packet;
}



struct RootRefTest
{
  string getName() const
  {
    return "write rootreferral";
  }

  void operator()() const
  {
    vector<uint8_t> packet=makeRootReferral();
  }

};

struct StackMallocTest
{
  string getName() const
  {
    return "stack allocation";
  }

  void operator()() const
  {
    char *buffer= new char[200000];
    delete buffer;
  }

};


struct EmptyQueryTest
{
  string getName() const
  {
    return "write empty query";
  }

  void operator()() const
  {
    vector<uint8_t> packet=makeEmptyQuery();
  }

};

struct TypicalRefTest
{
  string getName() const
  {
    return "write typical referral";
  }

  void operator()() const
  {
    vector<uint8_t> packet=makeTypicalReferral();
  }

};

struct TCacheComp
{
  bool operator()(const pair<string, QType>& a, const pair<string, QType>& b) const
  {
    int cmp=strcasecmp(a.first.c_str(), b.first.c_str());
    if(cmp < 0)
      return true;
    if(cmp > 0)
      return false;

    return a.second < b.second;
  }
};

struct NegCacheEntry
{
  string d_name;
  QType d_qtype;
  string d_qname;
  uint32_t d_ttd;
};

struct timeval d_now;

static bool magicAddrMatch(const QType& query, const QType& answer)
{
  if(query.getCode() != QType::ADDR)
    return false;
  return answer.getCode() == QType::A || answer.getCode() == QType::AAAA;
}


bool moreSpecificThan(const string& a, const string &b)
{
  static string dot(".");
  int counta=(a!=dot), countb=(b!=dot);
  
  for(string::size_type n=0;n<a.size();++n)
    if(a[n]=='.')
      counta++;
  for(string::size_type n=0;n<b.size();++n)
    if(b[n]=='.')
      countb++;
  return counta>countb;
}


struct ParsePacketTest
{
  explicit ParsePacketTest(const vector<uint8_t>& packet, const std::string& name) 
    : d_packet(packet), d_name(name)
  {}

  string getName() const
  {
    return "parse '"+d_name+"'";
  }

  void operator()() const
  {
    MOADNSParser mdp((const char*)&*d_packet.begin(), d_packet.size());
    typedef map<pair<string, QType>, set<DNSResourceRecord>, TCacheComp > tcache_t;
    tcache_t tcache;
    
    struct {
            vector<DNSResourceRecord> d_result;
            bool d_aabit;
            int d_rcode;
    } lwr;
    DNSResourceRecord rr;
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
      DNSResourceRecord rr;
      rr.qtype=i->first.d_type;
      rr.qname=i->first.d_label;
    
      rr.ttl=i->first.d_ttl;
      rr.content=i->first.d_content->getZoneRepresentation();  // this should be the serialised form
      rr.d_place=(DNSResourceRecord::Place) i->first.d_place;
      lwr.d_result.push_back(rr);
    }

    
    

      // reap all answers from this packet that are acceptable
      for(vector<DNSResourceRecord>::iterator i=lwr.d_result.begin();i != lwr.d_result.end();++i) {
        if(i->qtype.getCode() == QType::OPT) {
          // <<prefix<<qname<<": skipping OPT answer '"<<i->qname<<"' from '"<<auth<<"' nameservers" <<endl;
          continue;
        }
        // LOG<<prefix<<qname<<": accept answer '"<<i->qname<<"|"<<i->qtype.getName()<<"|"<<i->content<<"' from '"<<auth<<"' nameservers? ";
        if(i->qtype.getCode()==QType::ANY) {
          // LOG<<"NO! - we don't accept 'ANY' data"<<endl;
          continue;
        }
        string auth(".");
        if(dottedEndsOn(i->qname, auth)) {
          if(lwr.d_aabit && lwr.d_rcode==RCode::NoError && i->d_place==DNSResourceRecord::ANSWER && 0) {
            // LOG<<"NO! Is from delegation-only zone"<<endl;
            // s_nodelegated++;
            return; // RCode::NXDomain;
          }
          else {
            // LOG<<"YES!"<<endl;

          //  i->ttl=min(s_maxcachettl, i->ttl);
            
            DNSResourceRecord rr=*i;
            rr.d_place=DNSResourceRecord::ANSWER;

            // rr.ttl += d_now.tv_sec;

            if(rr.qtype.getCode() == QType::NS) // people fiddle with the case
              rr.content=toLower(rr.content); // this must stay! (the cache can't be case-insensitive on the RHS of records)
            tcache[make_pair(i->qname,i->qtype)].insert(rr);
          }
        }	  
        else
          ; // LOG<<"NO!"<<endl;
      }
    
      // supplant
      for(tcache_t::iterator i=tcache.begin();i!=tcache.end();++i) {
        if(i->second.size() > 1) {  // need to group the ttl to be the minimum of the RRSET (RFC 2181, 5.2)
          uint32_t lowestTTL=std::numeric_limits<uint32_t>::max();
          for(tcache_t::value_type::second_type::iterator j=i->second.begin(); j != i->second.end(); ++j)
            lowestTTL=min(lowestTTL, j->ttl);
          
          for(tcache_t::value_type::second_type::iterator j=i->second.begin(); j != i->second.end(); ++j)
            ((tcache_t::value_type::second_type::value_type*)&(*j))->ttl=lowestTTL;
        }

        // RC.replace(d_now.tv_sec, i->first.first, i->first.second, i->second, lwr.d_aabit);
      }
      set<string, CIStringCompare> nsset;  
      // LOG<<prefix<<qname<<": determining status after receiving this packet"<<endl;

      bool done=false, realreferral=false, negindic=false;
      string newauth, soaname, newtarget;
      string qname(".");
      vector<DNSResourceRecord> ret;
      QType qtype(QType::A);
      string auth(".");
 
      for(vector<DNSResourceRecord>::const_iterator i=lwr.d_result.begin();i!=lwr.d_result.end();++i) {
        if(i->d_place==DNSResourceRecord::AUTHORITY && dottedEndsOn(qname,i->qname) && i->qtype.getCode()==QType::SOA && 
           lwr.d_rcode==RCode::NXDomain) {
          // LOG<<prefix<<qname<<": got negative caching indication for RECORD '"<<qname+"'"<<endl;
          ret.push_back(*i);

          NegCacheEntry ne;

          ne.d_qname=i->qname;
          ne.d_ttd=d_now.tv_sec + min(i->ttl, 3600U); // controversial
          ne.d_name=qname;
          ne.d_qtype=QType(0); // this encodes 'whole record'
          
          {
            // Lock l(&s_negcachelock);
            // replacing_insert(s_negcache, ne);
          }
          negindic=true;
        }
        else if(i->d_place==DNSResourceRecord::ANSWER && pdns_iequals(i->qname, qname) && i->qtype.getCode()==QType::CNAME && (!(qtype==QType(QType::CNAME)))) {
          ret.push_back(*i);
          newtarget=i->content;
        }
        // for ANY answers we *must* have an authoritive answer
        else if(i->d_place==DNSResourceRecord::ANSWER && pdns_iequals(i->qname, qname) && 
        	(
        	 i->qtype==qtype || (lwr.d_aabit && (qtype==QType(QType::ANY) || magicAddrMatch(qtype, i->qtype) ) )
        	) 
               )   
          {
          
          // LOG<<prefix<<qname<<": answer is in: resolved to '"<< i->content<<"|"<<i->qtype.getName()<<"'"<<endl;

          done=true;
          ret.push_back(*i);
        }
        else if(i->d_place==DNSResourceRecord::AUTHORITY && dottedEndsOn(qname,i->qname) && i->qtype.getCode()==QType::NS) { 
          if(moreSpecificThan(i->qname,auth)) {
            newauth=i->qname;
            // LOG<<prefix<<qname<<": got NS record '"<<i->qname<<"' -> '"<<i->content<<"'"<<endl;
            realreferral=true;
          }
          else 
            ;// // LOG<<prefix<<qname<<": got upwards/level NS record '"<<i->qname<<"' -> '"<<i->content<<"', had '"<<auth<<"'"<<endl;
          nsset.insert(i->content);
        }
        else if(!done && i->d_place==DNSResourceRecord::AUTHORITY && dottedEndsOn(qname,i->qname) && i->qtype.getCode()==QType::SOA && 
           lwr.d_rcode==RCode::NoError) {
          // LOG<<prefix<<qname<<": got negative caching indication for '"<< (qname+"|"+i->qtype.getName()+"'") <<endl;
          ret.push_back(*i);
          
          NegCacheEntry ne;
          ne.d_qname=i->qname;
          ne.d_ttd=d_now.tv_sec + i->ttl;
          ne.d_name=qname;
          ne.d_qtype=qtype;
          if(qtype.getCode()) {  // prevents us from blacking out a whole domain
           // Lock l(&s_negcachelock);
            // replacing_insert(s_negcache, ne);
          }
          negindic=true;
        }
      }

  }
  const vector<uint8_t>& d_packet;
  std::string d_name;
};

struct ParsePacketBareTest
{
  explicit ParsePacketBareTest(const vector<uint8_t>& packet, const std::string& name) 
    : d_packet(packet), d_name(name)
  {}

  string getName() const
  {
    return "parse '"+d_name+"' bare";
  }

  void operator()() const
  {
    MOADNSParser mdp((const char*)&*d_packet.begin(), d_packet.size());
  }
  const vector<uint8_t>& d_packet;
  std::string d_name;
};


struct SimpleCompressTest
{
  explicit SimpleCompressTest(const std::string& name) 
    : d_name(name)
  {}

  string getName() const
  {
    return "compress '"+d_name+"'";
  }

  void operator()() const
  {
    simpleCompress(d_name);
  }
  std::string d_name;
};

struct VectorExpandTest
{
  string getName() const
  {
    return "vector expand";
  }

  void operator()() const
  {
    vector<uint8_t> d_record;
    d_record.resize(12);

    string out="\x03www\x04ds9a\x02nl";
    string::size_type len = d_record.size();
    d_record.resize(len + out.length());
    memcpy(&d_record[len], out.c_str(), out.length());
  }

};



struct IEqualsTest
{
  string getName() const
  {
    return "iequals test";
  }

  void operator()() const
  {
      static string a("www.ds9a.nl"), b("www.lwn.net");
      g_ret = boost::iequals(a, b);
  }

};

struct MyIEqualsTest
{
  string getName() const
  {
    return "pdns_iequals test";
  }

  void operator()() const
  {
      static string a("www.ds9a.nl"), b("www.lwn.net");
      g_ret = pdns_iequals(a, b);
  }

};


struct StrcasecmpTest
{
  string getName() const
  {
    return "strcasecmp test";
  }

  void operator()() const
  {
      static string a("www.ds9a.nl"), b("www.lwn.net");
      g_ret = strcasecmp(a.c_str(), b.c_str());
  }
};


struct NOPTest
{
  string getName() const
  {
    return "null test";
  }

  void operator()() const
  {
  }

};



int main(int argc, char** argv)
try
{
  reportAllTypes();
  doRun(NOPTest());

  doRun(IEqualsTest());
  doRun(MyIEqualsTest());
  doRun(StrcasecmpTest());

  doRun(StackMallocTest());

  vector<uint8_t> packet = makeRootReferral();
  doRun(ParsePacketBareTest(packet, "root-referral"));
  doRun(ParsePacketTest(packet, "root-referral"));

  doRun(RootRefTest());

  doRun(EmptyQueryTest());
  doRun(TypicalRefTest());


  packet = makeEmptyQuery();
  doRun(ParsePacketTest(packet, "empty-query"));

  packet = makeTypicalReferral();
  cerr<<"typical referral size: "<<packet.size()<<endl;
  doRun(ParsePacketBareTest(packet, "typical-referral"));

  doRun(ParsePacketTest(packet, "typical-referral"));

  doRun(SimpleCompressTest("www.france.ds9a.nl"));

  
  doRun(VectorExpandTest());

  doRun(GetTimeTest());
  
  doRun(GetLockUncontendedTest());
  doRun(StaticMemberTest());
  
  doRun(ARecordTest(1));
  doRun(ARecordTest(2));
  doRun(ARecordTest(4));
  doRun(ARecordTest(64));

  doRun(A2RecordTest(1));
  doRun(A2RecordTest(2));
  doRun(A2RecordTest(4));
  doRun(A2RecordTest(64));

  doRun(MakeStringFromCharStarTest());
  doRun(MakeARecordTest());
  doRun(MakeARecordTestMM());

  doRun(AAAARecordTest(1));
  doRun(AAAARecordTest(2));
  doRun(AAAARecordTest(4));
  doRun(AAAARecordTest(64));

  doRun(TXTRecordTest(1));
  doRun(TXTRecordTest(2));
  doRun(TXTRecordTest(4));
  doRun(TXTRecordTest(64));

  doRun(GenericRecordTest(1, QType::NS, "powerdnssec1.ds9a.nl"));
  doRun(GenericRecordTest(2, QType::NS, "powerdnssec1.ds9a.nl"));
  doRun(GenericRecordTest(4, QType::NS, "powerdnssec1.ds9a.nl"));
  doRun(GenericRecordTest(64, QType::NS, "powerdnssec1.ds9a.nl"));



  doRun(SOARecordTest(1));
  doRun(SOARecordTest(2));
  doRun(SOARecordTest(4));
  doRun(SOARecordTest(64));

  cerr<<"Total runs: " << g_totalRuns<<endl;

}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

