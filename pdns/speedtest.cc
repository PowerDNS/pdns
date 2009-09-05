#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include <boost/format.hpp>
#ifndef RECURSOR
#include "statbag.hh"
StatBag S;
#endif

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
  static const char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
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
  signal(SIGVTALRM, alarmHandler);
  
  //  doRun(NOPTest());

  vector<uint8_t> packet = makeRootReferral();
  doRun(ParsePacketTest(packet, "root-referral"));

  doRun(RootRefTest());

  doRun(EmptyQueryTest());
  doRun(TypicalRefTest());


  packet = makeEmptyQuery();
  doRun(ParsePacketTest(packet, "empty-query"));

  packet = makeTypicalReferral();
  cerr<<"typical referral size: "<<packet.size()<<endl;
  doRun(ParsePacketTest(packet, "typical-referral"));


  doRun(SimpleCompressTest("www.france.ds9a.nl"));

  doRun(VectorExpandTest());

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

