#include "inflighter.cc"
#include "namespaces.hh"
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"

StatBag S;

struct DNSResult
{
  vector<ComboAddress> ips;
  int rcode;
};

struct SendReceive
{
  typedef int Identifier;
  typedef DNSResult Answer; // ip 
  int d_socket;
  uint16_t d_id;
  
  SendReceive()
  {
    d_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int val=1;
    setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    
    ComboAddress remote("127.0.0.1", 5300);
    connect(d_socket, (struct sockaddr*)&remote, remote.getSocklen());
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
    
    pw.getHeader()->id = d_id++;
    pw.getHeader()->rd = 1;
    pw.getHeader()->qr = 0;
    
    ::send(d_socket, &*packet.begin(), packet.size(), 0);
    
    return pw.getHeader()->id;
  }
  
  bool receive(Identifier& id, DNSResult& dr)
  {
    if(waitForData(d_socket, 0, 500000) > 0) {
      char buf[512];
    
      int len = recv(d_socket, buf, sizeof(buf), 0);
      if(len < 0)
        return 0;
      // parse packet, set 'id', fill out 'ip' 
      
      MOADNSParser mdp(string(buf, len));
      //cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
      //cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
      //cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;
      dr.rcode = mdp.d_header.rcode;
      for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
        if(i->first.d_place == 1 && i->first.d_type == QType::A)
          dr.ips.push_back(ComboAddress(i->first.d_content->getZoneRepresentation()));
        //cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
        //cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
      }
      id = mdp.d_header.id;
      return 1;
    }
    return 0;
  }
  
  void deliverAnswer(string& domain, const DNSResult& dr)
  {
    cerr<<domain<<": rcode: "<<dr.rcode;
    BOOST_FOREACH(const ComboAddress& ca, dr.ips) {
      cerr<<", "<<ca.toString();
    }
    cerr<<endl;
  }
};


int main()
{
  SendReceive sr;
  reportAllTypes();
  vector<string> domains;
    
  Inflighter<vector<string>, SendReceive> inflighter(domains, sr);
  inflighter.d_maxInFlight = 1000;
  string line;
  
  pair<string, string> split;
  while(stringfgets(stdin, line)) {
    trim_right(line);
    split=splitField(line,',');
    domains.push_back(split.second);
  }
  cerr<<"Read "<<domains.size()<<" domains!"<<endl;


  for(;;) {
    try {
      inflighter.run();
      break;
    }
    catch(exception& e) {
      cerr<<"Caught exception: "<<e.what()<<endl;
    }
  }
}


