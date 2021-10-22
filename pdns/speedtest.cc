#include "config.h"
#include <boost/format.hpp>
#include <boost/container/string.hpp>
#include "credentials.hh"
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "iputils.hh"
#include <fstream>
#include "uuid-utils.hh"
#include "dnssecinfra.hh"
#include "lock.hh"
#include "dns_random.hh"
#include "arguments.hh"

#if defined(HAVE_LIBSODIUM)
#include <sodium.h>
#endif

#ifndef RECURSOR
#include "statbag.hh"
#include "base64.hh"
StatBag S;
#endif

volatile bool g_ret; // make sure the optimizer does not get too smart
uint64_t g_totalRuns;
volatile bool g_stop;

static void alarmHandler(int)
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

  signal(SIGPROF, alarmHandler);
  setitimer(ITIMER_PROF, &it, 0);

  unsigned int runs=0;
  g_stop=false;
  CPUTime dt;
  dt.start();
  while(runs++, !g_stop) {
    cmd();
  }
  double delta=dt.ndiff()/1000000000.0;
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
    DNSPacketWriter pw(packet, DNSName("outpost.ds9a.nl"), QType::A);
    for(int records = 0; records < d_records; records++) {
      pw.startRecord(DNSName("outpost.ds9a.nl"), QType::A);
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

struct GetLockUncontendedTest
{
  string getName() const
  {
    return "get-lock-uncontended-test";
  }

  void operator()() const
  {
    for (size_t idx = 0; idx < 1000; idx++) {
      d_testlock.lock();
      ++d_value;
      d_testlock.unlock();
    }
  }
private:
  mutable std::mutex d_testlock;
  mutable uint64_t d_value{0};
};

struct GetUniqueLockUncontendedTest
{
  string getName() const
  {
    return "get-unique-lock-uncontended-test";
  }

  void operator()() const
  {
    for (size_t idx = 0; idx < 1000; idx++) {
      std::unique_lock<decltype(d_testlock)> lock(d_testlock);
      ++d_value;
    }
  }
private:
  mutable std::mutex d_testlock;
  mutable uint64_t d_value{0};
};

struct GetLockGuardUncontendedTest
{
  string getName() const
  {
    return "get-lock-guard-uncontended-test";
  }

  void operator()() const
  {
    for (size_t idx = 0; idx < 1000; idx++) {
      std::lock_guard<decltype(d_testlock)> lock(d_testlock);
      ++d_value;
    }
  }
private:
  mutable std::mutex d_testlock;
  mutable uint64_t d_value{0};
};

struct GetLockGuardedUncontendedTest
{
  string getName() const
  {
    return "get-lock-guarded-uncontended-test";
  }

  void operator()() const
  {
    for (size_t idx = 0; idx < 1000; idx++) {
      ++*(d_value.lock());
    }
  }

private:
  mutable LockGuarded<uint64_t> d_value{0};
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

struct StringtokTest
{
  string getName() const
  {
    return "stringtok";
  }

  void operator()() const
  {
    string str("the quick brown fox jumped");
    vector<string> parts;
    stringtok(parts, str);
  }
};

struct VStringtokTest
{
  string getName() const
  {
    return "vstringtok";
  }

  void operator()() const
  {
    string str("the quick brown fox jumped");
    vector<pair<unsigned int, unsigned> > parts;
    vstringtok(parts, str);
  }
};

struct StringAppendTest
{
  string getName() const
  {
    return "stringappend";
  }

  void operator()() const
  {
    string str;
    static char i;
    for(int n=0; n < 1000; ++n)
      str.append(1, i);
    i++;
  }
};


struct BoostStringAppendTest
{
  string getName() const
  {
    return "booststringappend";
  }

  void operator()() const
  {
    boost::container::string str;
    static char i;
    for(int n=0; n < 1000; ++n)
      str.append(1, i);
    i++;
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

static vector<uint8_t> makeBigReferral()
{

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, DNSName("www.google.com"), QType::A);

  string gtld="x.gtld-servers.net";
  for(char c='a'; c<= 'm';++c) {
    pw.startRecord(DNSName("com"), QType::NS, 3600, 1, DNSResourceRecord::AUTHORITY);
    gtld[0]=c;
    auto drc = DNSRecordContent::mastermake(QType::NS, 1, gtld);
    drc->toPacket(pw);
  }

  for(char c='a'; c<= 'k';++c) {
    gtld[0]=c;
    pw.startRecord(DNSName(gtld), QType::A, 3600, 1, DNSResourceRecord::ADDITIONAL);
    auto drc = DNSRecordContent::mastermake(QType::A, 1, "1.2.3.4");
    drc->toPacket(pw);
  }


  pw.startRecord(DNSName("a.gtld-servers.net"), QType::AAAA, 3600, 1, DNSResourceRecord::ADDITIONAL);
  auto aaaarc = DNSRecordContent::mastermake(QType::AAAA, 1, "2001:503:a83e::2:30");
  aaaarc->toPacket(pw);

  pw.startRecord(DNSName("b.gtld-servers.net"), QType::AAAA, 3600, 1, DNSResourceRecord::ADDITIONAL);
  aaaarc = DNSRecordContent::mastermake(QType::AAAA, 1, "2001:503:231d::2:30");
  aaaarc->toPacket(pw);


  pw.commit();
  return  packet;
}

static vector<uint8_t> makeBigDNSPacketReferral()
{
  vector<DNSResourceRecord> records;
  DNSResourceRecord rr;
  rr.qtype = QType::NS;
  rr.ttl=3600;
  rr.qname=DNSName("com");

  string gtld="x.gtld-servers.net";
  for(char c='a'; c<= 'm';++c) {
    gtld[0]=c;
    rr.content = gtld;
    records.push_back(rr);
  }

  rr.qtype = QType::A;
  for(char c='a'; c<= 'k';++c) {
    gtld[0]=c;
    rr.qname=DNSName(gtld);
    rr.content="1.2.3.4";
    records.push_back(rr);
  }

  rr.qname=DNSName("a.gtld-servers.net");
  rr.qtype=QType::AAAA;
  rr.content="2001:503:a83e::2:30";
  records.push_back(rr);

  rr.qname=DNSName("b.gtld-servers.net");
  rr.qtype=QType::AAAA;
  rr.content="2001:503:231d::2:30";
  records.push_back(rr);


  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, DNSName("www.google.com"), QType::A);
  //  shuffle(records);
  for(const auto& rec : records) {
    pw.startRecord(rec.qname, rec.qtype.getCode(), rec.ttl, 1, DNSResourceRecord::ADDITIONAL);
    auto drc = DNSRecordContent::mastermake(rec.qtype.getCode(), 1, rec.content);
    drc->toPacket(pw);
  }

  pw.commit();
  return  packet;
}



struct MakeARecordTestMM
{
  string getName() const
  {
    return (boost::format("make a-record (mm)")).str();
  }

  void operator()() const
  {
      auto drc = DNSRecordContent::mastermake(QType::A, 1,
                                              "1.2.3.4");
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
    DNSPacketWriter pw(packet, DNSName("outpost.ds9a.nl"), QType::A);
    ARecordContent arc("1.2.3.4");
    DNSName name("outpost.ds9a.nl");
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
    DNSPacketWriter pw(packet, DNSName("outpost.ds9a.nl"), QType::TXT);
    for(int records = 0; records < d_records; records++) {
      pw.startRecord(DNSName("outpost.ds9a.nl"), QType::TXT);
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
    DNSPacketWriter pw(packet, DNSName("outpost.ds9a.nl"), d_type);
    for(int records = 0; records < d_records; records++) {
      pw.startRecord(DNSName("outpost.ds9a.nl"), d_type);
      auto drc = DNSRecordContent::mastermake(d_type, 1,
                                              d_content);
      drc->toPacket(pw);
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
    DNSPacketWriter pw(packet, DNSName("outpost.ds9a.nl"), QType::AAAA);
    for(int records = 0; records < d_records; records++) {
      pw.startRecord(DNSName("outpost.ds9a.nl"), QType::AAAA);
      auto drc = DNSRecordContent::mastermake(QType::AAAA, 1, "fe80::21d:92ff:fe6d:8441");
      drc->toPacket(pw);
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
    DNSPacketWriter pw(packet, DNSName("outpost.ds9a.nl"), QType::SOA);

    for(int records = 0; records < d_records; records++) {
      pw.startRecord(DNSName("outpost.ds9a.nl"), QType::SOA);
      auto drc = DNSRecordContent::mastermake(QType::SOA, 1, "a0.org.afilias-nst.info. noc.afilias-nst.info. 2008758137 1800 900 604800 86400");
      drc->toPacket(pw);
    }
    pw.commit();
  }
  int d_records;
};

static vector<uint8_t> makeEmptyQuery()
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, DNSName("outpost.ds9a.nl"), QType::SOA);
  return  packet;
}

static vector<uint8_t> makeTypicalReferral()
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, DNSName("outpost.ds9a.nl"), QType::A);

  pw.startRecord(DNSName("ds9a.nl"), QType::NS, 3600, 1, DNSResourceRecord::AUTHORITY);
  auto drc = DNSRecordContent::mastermake(QType::NS, 1, "ns1.ds9a.nl");
  drc->toPacket(pw);

  pw.startRecord(DNSName("ds9a.nl"), QType::NS, 3600, 1, DNSResourceRecord::AUTHORITY);
  drc = DNSRecordContent::mastermake(QType::NS, 1, "ns2.ds9a.nl");
  drc->toPacket(pw);


  pw.startRecord(DNSName("ns1.ds9a.nl"), QType::A, 3600, 1, DNSResourceRecord::ADDITIONAL);
  drc = DNSRecordContent::mastermake(QType::A, 1, "1.2.3.4");
  drc->toPacket(pw);

  pw.startRecord(DNSName("ns2.ds9a.nl"), QType::A, 3600, 1, DNSResourceRecord::ADDITIONAL);
  drc = DNSRecordContent::mastermake(QType::A, 1, "4.3.2.1");
  drc->toPacket(pw);

  pw.commit();
  return  packet;
}

struct StackMallocTest
{
  string getName() const
  {
    return "stack allocation";
  }

  void operator()() const
  {
    char *buffer= new char[200000];
    delete[] buffer;
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

struct BigRefTest
{
  string getName() const
  {
    return "write big referral";
  }

  void operator()() const
  {
    vector<uint8_t> packet=makeBigReferral();
  }

};

struct BigDNSPacketRefTest
{
  string getName() const
  {
    return "write big dnspacket referral";
  }

  void operator()() const
  {
    vector<uint8_t> packet=makeBigDNSPacketReferral();
  }

};


struct TCacheComp
{
  bool operator()(const pair<DNSName, QType>& a, const pair<DNSName, QType>& b) const
  {
    if(a.first < b.first)
      return true;
    if(b.first < a.first)
      return false;

    return a.second < b.second;
  }
};

struct NegCacheEntry
{
  DNSName d_name;
  QType d_qtype;
  DNSName d_qname;
  uint32_t d_ttd;
};

struct timeval d_now;



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
    MOADNSParser mdp(false, (const char*)&*d_packet.begin(), d_packet.size());
    typedef map<pair<DNSName, QType>, set<DNSResourceRecord>, TCacheComp > tcache_t;
    tcache_t tcache;

    struct {
            vector<DNSResourceRecord> d_result;
            bool d_aabit;
            int d_rcode;
    } lwr;
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
      DNSResourceRecord rr;
      rr.qtype=i->first.d_type;
      rr.qname=i->first.d_name;

      rr.ttl=i->first.d_ttl;
      rr.content=i->first.d_content->getZoneRepresentation();  // this should be the serialised form
      lwr.d_result.push_back(rr);
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
    MOADNSParser mdp(false, (const char*)&*d_packet.begin(), d_packet.size());
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

struct DNSNameParseTest
{
  string getName() const
  {
    return "DNSName parse";
  }

  void operator()() const
  {
    DNSName name("www.powerdns.com");
  }

};

struct DNSNameRootTest
{
  string getName() const
  {
    return "DNSName root";
  }

  void operator()() const
  {
    DNSName name(".");
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


struct Base64EncodeTest
{
  string getName() const
  {
    return "Bas64Encode test";
  }

  void operator()() const
  {
      static string a("dq4KydZjmcoQQ45VYBP2EDR8FqKaMul0eSHBt7Xx5F7A4HFtabXEzDLD01bnSiGK");
      Base64Encode(a);
  }
};


struct B64DecodeTest
{
  string getName() const
  {
    return "B64Decode test";
  }

  void operator()() const
  {
      static string a("ZHE0S3lkWmptY29RUTQ1VllCUDJFRFI4RnFLYU11bDBlU0hCdDdYeDVGN0E0SEZ0YWJYRXpETEQwMWJuU2lHSw=="), b;
      g_ret = B64Decode(a,b);
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

struct StatRingDNSNameQTypeToStringTest
{
  explicit StatRingDNSNameQTypeToStringTest(const DNSName &name, const QType type) : d_name(name), d_type(type) {}

  string getName() const { return "StatRing test with DNSName and QType to string"; }

  void operator()() const {
    S.ringAccount("testring", d_name.toLogString()+"/"+d_type.toString());
  };

  DNSName d_name;
  QType d_type;
};

struct StatRingDNSNameQTypeTest
{
  explicit StatRingDNSNameQTypeTest(const DNSName &name, const QType type) : d_name(name), d_type(type) {}

  string getName() const { return "StatRing test with DNSName and QType"; }

  void operator()() const {
    S.ringAccount("testringdnsname", d_name, d_type);
  };

  DNSName d_name;
  QType d_type;
};


struct NetmaskTreeTest
{
  string getName() const { return "NetmaskTreeTest"; }

  void operator()() const {
    Netmask nm("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/64");
    NetmaskTree<bool> tree;

    for (int i = 0; i < 100; i++)
      tree.insert_or_assign(nm, true);
  }
};

struct UUIDGenTest
{
  string getName() const { return "UUIDGenTest"; }

  void operator()() const {
    getUniqueID();
  }
};

struct NSEC3HashTest
{
  explicit NSEC3HashTest(int iterations, string salt) : d_iterations(iterations), d_salt(salt) {}

  string getName() const
  {
    return (boost::format("%d NSEC3 iterations, salt length %d") % d_iterations % d_salt.length()).str();
  }

  void operator()() const
  {
    hashQNameWithSalt(d_salt, d_iterations, d_name);
  }
  int d_iterations;
  string d_salt;
  DNSName d_name = DNSName("www.example.com");
};

struct SharedLockTest
{
  string getName() const { return "Shared lock"; }

  void operator()() const {
    for (size_t idx = 0; idx < 1000; idx++) {
      std::shared_lock<decltype(d_lock)> lock(d_lock);
      ++d_value;
    }
  }

private:
  mutable std::shared_mutex d_lock;
  mutable uint64_t d_value;
};

struct ReadWriteLockSharedTest
{
  explicit ReadWriteLockSharedTest(ReadWriteLock& lock): d_lock(lock)
  {
  }

  string getName() const { return "RW lock shared"; }

  void operator()() const {
    for (size_t idx = 0; idx < 1000; idx++) {
      ReadLock wl(d_lock);
    }
  }

private:
  ReadWriteLock& d_lock;
};

struct ReadWriteLockExclusiveTest
{
  explicit ReadWriteLockExclusiveTest(ReadWriteLock& lock): d_lock(lock)
  {
  }

  string getName() const { return "RW lock exclusive"; }

  void operator()() const {
    for (size_t idx = 0; idx < 1000; idx++) {
      WriteLock wl(d_lock);
    }
  }

private:
  ReadWriteLock& d_lock;
};

struct ReadWriteLockExclusiveTryTest
{
  explicit ReadWriteLockExclusiveTryTest(ReadWriteLock& lock, bool contended): d_lock(lock), d_contended(contended)
  {
  }

  string getName() const { return "RW lock try exclusive - " + std::string(d_contended ? "contended" : "non-contended"); }

  void operator()() const {
    for (size_t idx = 0; idx < 1000; idx++) {
      TryWriteLock wl(d_lock);
      if (!wl.gotIt() && !d_contended) {
        cerr<<"Error getting the lock"<<endl;
        _exit(0);
      }
      else if (wl.gotIt() && d_contended) {
        cerr<<"Got a contended lock"<<endl;
        _exit(0);
      }
    }
  }

private:
  ReadWriteLock& d_lock;
  bool d_contended;
};

struct ReadWriteLockSharedTryTest
{
  explicit ReadWriteLockSharedTryTest(ReadWriteLock& lock, bool contended): d_lock(lock), d_contended(contended)
  {
  }

  string getName() const { return "RW lock try shared - " + std::string(d_contended ? "contended" : "non-contended"); }

  void operator()() const {
    for (size_t idx = 0; idx < 1000; idx++) {
      TryReadLock wl(d_lock);
      if (!wl.gotIt() && !d_contended) {
        cerr<<"Error getting the lock"<<endl;
        _exit(0);
      }
      else if (wl.gotIt() && d_contended) {
        cerr<<"Got a contended lock"<<endl;
        _exit(0);
      }
    }
  }

private:
  ReadWriteLock& d_lock;
  bool d_contended;
};

struct CredentialsHashTest
{
  explicit CredentialsHashTest() {}

  string getName() const
  {
    return "Credentials hashing test";
  }

  void operator()() const
  {
    hashPassword(d_password);
  }

private:
  const std::string d_password{"test password"};
};

struct RndSpeedTest
{
  explicit RndSpeedTest(std::string which) : name(which){
    ::arg().set("entropy-source", "If set, read entropy from this file")="/dev/urandom";
    ::arg().set("rng", "") = which;
    dns_random_init("", true);
  }
  string getName() const
  {
    return "Random test " + name;
  }

  void operator()() const
  {
    dns_random_uint16();
  }

  const std::string name;
};

struct CredentialsVerifyTest
{
  explicit CredentialsVerifyTest() {
    d_hashed = hashPassword(d_password);
  }

  string getName() const
  {
    return "Credentials verification test";
  }

  void operator()() const
  {
    verifyPassword(d_hashed, d_password);
  }

private:
  std::string d_hashed;
  const std::string d_password{"test password"};
};

struct BurtleHashTest
{
  explicit BurtleHashTest(const string& str) : d_name(str) {}

  string getName() const
  {
    return "BurtleHash";
  }

  void operator()() const
  {
    burtle(reinterpret_cast<const unsigned char*>(d_name.data()), d_name.length(), 0);

  }

private:
  const string d_name;
};


#if defined(HAVE_LIBSODIUM)
struct SipHashTest
{
  explicit SipHashTest(const string& str) : d_name(str)
  {
    crypto_shorthash_keygen(d_key);
  }

  string getName() const
  {
    return "SipHash";
  }

  void operator()() const
  {
    unsigned char out[crypto_shorthash_BYTES];
    crypto_shorthash(out, reinterpret_cast<const unsigned char*>(d_name.data()), d_name.length(), d_key);
  }

private:
  const string d_name;
  unsigned char d_key[crypto_shorthash_KEYBYTES];
};
#endif

int main(int argc, char** argv)
try
{
  reportAllTypes();

  doRun(NOPTest());

  doRun(IEqualsTest());
  doRun(MyIEqualsTest());
  doRun(StrcasecmpTest());
  doRun(Base64EncodeTest());
  doRun(B64DecodeTest());

  doRun(StackMallocTest());

  doRun(EmptyQueryTest());
  doRun(TypicalRefTest());
  doRun(BigRefTest());
  doRun(BigDNSPacketRefTest());

  auto packet = makeEmptyQuery();
  doRun(ParsePacketTest(packet, "empty-query"));

  packet = makeTypicalReferral();
  cerr<<"typical referral size: "<<packet.size()<<endl;
  doRun(ParsePacketBareTest(packet, "typical-referral"));

  doRun(ParsePacketTest(packet, "typical-referral"));

  doRun(SimpleCompressTest("www.france.ds9a.nl"));


  doRun(VectorExpandTest());

  doRun(GetTimeTest());

  doRun(GetLockUncontendedTest());
  doRun(GetUniqueLockUncontendedTest());
  doRun(GetLockGuardUncontendedTest());
  doRun(GetLockGuardedUncontendedTest());
  doRun(SharedLockTest());

  {
    ReadWriteLock rwlock;
    doRun(ReadWriteLockSharedTest(rwlock));
    doRun(ReadWriteLockExclusiveTest(rwlock));
    doRun(ReadWriteLockExclusiveTryTest(rwlock, false));
    {
      ReadLock rl(rwlock);
      doRun(ReadWriteLockExclusiveTryTest(rwlock, true));
      doRun(ReadWriteLockSharedTryTest(rwlock, false));
    }
    {
      WriteLock wl(rwlock);
      doRun(ReadWriteLockSharedTryTest(rwlock, true));
    }
  }

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

  doRun(StringtokTest());
  doRun(VStringtokTest());
  doRun(StringAppendTest());
  doRun(BoostStringAppendTest());

  doRun(DNSNameParseTest());
  doRun(DNSNameRootTest());

  doRun(NetmaskTreeTest());

  doRun(UUIDGenTest());

#if defined(HAVE_GETRANDOM)
  doRun(RndSpeedTest("getrandom"));
#endif
#if defined(HAVE_ARC4RANDOM)
  doRun(RndSpeedTest("arc4random"));
#endif
#if defined(HAVE_RANDOMBYTES_STIR)
  doRun(RndSpeedTest("sodium"));
#endif
#if defined(HAVE_RAND_BYTES)
  doRun(RndSpeedTest("openssl"));
#endif
  doRun(RndSpeedTest("urandom"));

  doRun(NSEC3HashTest(1, "ABCD"));
  doRun(NSEC3HashTest(10, "ABCD"));
  doRun(NSEC3HashTest(50, "ABCD"));
  doRun(NSEC3HashTest(150, "ABCD"));
  doRun(NSEC3HashTest(500, "ABCD"));

  doRun(NSEC3HashTest(1, "ABCDABCDABCDABCDABCDABCDABCDABCD"));
  doRun(NSEC3HashTest(10, "ABCDABCDABCDABCDABCDABCDABCDABCD"));
  doRun(NSEC3HashTest(50, "ABCDABCDABCDABCDABCDABCDABCDABCD"));
  doRun(NSEC3HashTest(150, "ABCDABCDABCDABCDABCDABCDABCDABCD"));
  doRun(NSEC3HashTest(500, "ABCDABCDABCDABCDABCDABCDABCDABCD"));

#if defined(HAVE_LIBSODIUM) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  doRun(CredentialsHashTest());
  doRun(CredentialsVerifyTest());
#endif

#ifndef RECURSOR
  S.doRings();

  S.declareRing("testring", "Just some ring where we'll account things");
  doRun(StatRingDNSNameQTypeToStringTest(DNSName("example.com"), QType(1)));

  S.declareDNSNameQTypeRing("testringdnsname", "Just some ring where we'll account things");
  doRun(StatRingDNSNameQTypeTest(DNSName("example.com"), QType(1)));
#endif

  doRun(BurtleHashTest("a string of chars"));
#ifdef HAVE_LIBSODIUM
  doRun(SipHashTest("a string of chars"));
#endif

  cerr<<"Total runs: " << g_totalRuns<<endl;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

ArgvMap& arg()
{	
  static ArgvMap theArg;
  return theArg;
}
