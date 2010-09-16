#include <boost/accumulators/accumulators.hpp>
#include <boost/array.hpp>
#include <boost/accumulators/statistics.hpp>
#include <boost/accumulators/statistics/p_square_cumulative_distribution.hpp>
#include "inflighter.cc"
#include <deque>
#include "namespaces.hh"
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"

using namespace boost::accumulators;
using namespace boost;

StatBag S;

struct DNSResult
{
  vector<ComboAddress> ips;
  int rcode;
  bool seenauthsoa;
};

//  = 

struct SendReceive
{
  typedef int Identifier;
  typedef DNSResult Answer; // ip 
  int d_socket;
  deque<uint16_t> d_idqueue;
  
  
  typedef accumulator_set<
        double
      , stats<boost::accumulators::tag::extended_p_square,
	      boost::accumulators::tag::median(with_p_square_quantile),
              boost::accumulators::tag::mean(immediate)
	      >
    > acc_t;
  acc_t* d_acc;
  
  boost::array<double, 11> d_probs;
  
  SendReceive(const std::string& remoteAddr, uint16_t port)  
  {
    boost::array<double, 11> tmp ={{0.001,0.01, 0.025, 0.1, 0.25,0.5,0.75,0.9,0.975, 0.99,0.9999}};
    d_probs = tmp;
    d_acc = new acc_t(boost::accumulators::tag::extended_p_square::probabilities=d_probs);
    // 
    //d_acc = acc_t
    d_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int val=1;
    setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    
    ComboAddress remote(remoteAddr, port);
    connect(d_socket, (struct sockaddr*)&remote, remote.getSocklen());
    d_oks = d_errors = d_nodatas = d_nxdomains = d_unknowns = 0;
    d_receiveds = d_receiveerrors = d_senderrors = 0;
    for(unsigned int id =0 ; id < numeric_limits<uint16_t>::max(); ++id) 
      d_idqueue.push_back(id);
  }
  
  ~SendReceive()
  {
    close(d_socket);
  }
  
  Identifier send(string& domain)
  {
    //cerr<<"Sending query for '"<<domain<<"'"<<endl;
    
    // send it, copy code from 'sdig'
    vector<uint8_t> packet;
  
    DNSPacketWriter pw(packet, domain, QType::A);

    if(d_idqueue.empty()) {
      cerr<<"Exhausted ids!"<<endl;
      exit(1);
    }    
    pw.getHeader()->id = d_idqueue.front();
    d_idqueue.pop_front();
    pw.getHeader()->rd = 1;
    pw.getHeader()->qr = 0;
    
    if(::send(d_socket, &*packet.begin(), packet.size(), 0) < 0)
      d_senderrors++;
    
    return pw.getHeader()->id;
  }
  
  bool receive(Identifier& id, DNSResult& dr)
  {
    if(waitForData(d_socket, 0, 500000) > 0) {
      char buf[512];
          
      int len = recv(d_socket, buf, sizeof(buf), 0);
      if(len < 0) {
        d_receiveerrors++;
        return 0;
      }
      else {
        d_receiveds++;
      }
      // parse packet, set 'id', fill out 'ip' 
      
      MOADNSParser mdp(string(buf, len));
      cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
      cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
      cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;
      dr.rcode = mdp.d_header.rcode;
      for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
        if(i->first.d_place == 1 && i->first.d_type == QType::A)
          dr.ips.push_back(ComboAddress(i->first.d_content->getZoneRepresentation()));
        if(i->first.d_place == 2 && i->first.d_type == QType::SOA) {
          dr.seenauthsoa = 1;
        }
        cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
        cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
      }
      
      id = mdp.d_header.id;
      d_idqueue.push_back(id);
    
      return 1;
    }
    return 0;
  }
  
  void deliverTimeout(const Identifier& id)
  {
    d_idqueue.push_back(id);
  }
  
  void deliverAnswer(string& domain, const DNSResult& dr, unsigned int usec)
  {
    (*d_acc)(usec/1000.0);
//    if(usec > 1000000)
  //    cerr<<"Slow: "<<domain<<" ("<<usec/1000.0<<" msec)\n";
    cout<<domain<<": ("<<usec/1000.0<<"msec) rcode: "<<dr.rcode;
    BOOST_FOREACH(const ComboAddress& ca, dr.ips) {
      cout<<", "<<ca.toString();
    }
    cout<<endl;
    if(dr.rcode == RCode::NXDomain) {
      d_nxdomains++;
    }
    else if(dr.rcode) {
      d_errors++;
    }
    else if(dr.ips.empty() && dr.seenauthsoa) 
      d_nodatas++;
    else if(!dr.ips.empty())
      d_oks++;
    else {
      cout<<"UNKNOWN!! ^^"<<endl;
      d_unknowns++;
    }
  }
  unsigned int d_errors, d_nxdomains, d_nodatas, d_oks, d_unknowns;
  unsigned int d_receiveds, d_receiveerrors, d_senderrors;
  
  
};


int main(int argc, char** argv)
{
  if(argc != 3 && argc != 4) {
    cerr<<"Syntax: dnsbulktest ip-address port number [limit] < top-1m.csv"<<endl;
    exit(1);
  }
  SendReceive sr(argv[1], atoi(argv[2]));
  unsigned int limit = 0;
  if(argc==4)
    limit = atoi(argv[3]);
    
  reportAllTypes();
  vector<string> domains;
    
  Inflighter<vector<string>, SendReceive> inflighter(domains, sr);
  inflighter.d_maxInFlight = 100;
  inflighter.d_timeoutSeconds = 3;
  string line;
  
  pair<string, string> split;
  while(stringfgets(stdin, line)) {
    if(limit && domains.size() >= limit)
      break;
      
    trim_right(line);
    split=splitField(line,',');
    domains.push_back(split.second);
    domains.push_back("www."+split.second);
  }
  cerr<<"Read "<<domains.size()<<" domains!"<<endl;
  random_shuffle(domains.begin(), domains.end());

  boost::format datafmt("%s %|20t|%+15s  %|40t|%s %|60t|%+15s\n");

  for(;;) {
    try {
      inflighter.run();
      break;
    }
    catch(std::exception& e) {
      cerr<<"Caught exception: "<<e.what()<<endl;
    }
  }

  cerr<< datafmt % "Sending" % "" % "Receiving" % "";
  cerr<< datafmt % "  Queued " % domains.size() % "  Received" % sr.d_receiveds;
  cerr<< datafmt % "  Error -/-" % sr.d_senderrors %  "  Timeouts" % inflighter.getTimeouts();
  cerr<< datafmt % " " % "" %  "  Unexpected" % inflighter.getUnexpecteds();
  
  cerr<< datafmt % " Sent" % (domains.size() - sr.d_senderrors) %  " Total" % (sr.d_receiveds + inflighter.getTimeouts() + inflighter.getUnexpecteds());
  
  cerr<<endl;  
  cerr<< datafmt % "DNS Status" % ""       % "" % "";
  cerr<< datafmt % "  OK" % sr.d_oks       % "" % "";
  cerr<< datafmt % "  Error" % sr.d_errors       % "" % "";  
  cerr<< datafmt % "  No Data" % sr.d_nodatas       % "" % "";  
  cerr<< datafmt % "  NXDOMAIN" % sr.d_nxdomains      % "" % "";
  cerr<< datafmt % "  Unknowns" % sr.d_unknowns      % "" % "";  
  cerr<< datafmt % "Answers" % (sr.d_oks      +      sr.d_errors      +      sr.d_nodatas      + sr.d_nxdomains           +      sr.d_unknowns) % "" % "";
  cerr<< datafmt % "  Timeouts " % (inflighter.getTimeouts()) % "" % "";
  cerr<< datafmt % "Total " % (sr.d_oks      +      sr.d_errors      +      sr.d_nodatas      + sr.d_nxdomains           +      sr.d_unknowns + inflighter.getTimeouts()) % "" % "";
  
  cerr<<"\n";
  cerr<< "Mean response time: "<<mean(*sr.d_acc) << " msec"<<", median: "<<median(*sr.d_acc)<< " msec\n";
  typedef boost::iterator_range<std::vector<std::pair<double, double> >::iterator > histogram_type;
  
  boost::format statfmt("Time < %6.03f msec %|30t|%6.03f%% cumulative\n");
  
  for (unsigned int i = 0; i < sr.d_probs.size(); ++i) {
        cerr << statfmt % extended_p_square(*sr.d_acc)[i] % (100*sr.d_probs[i]);
    }



}


