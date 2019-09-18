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
#include "statbag.hh"
#include "zoneparser-tng.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"
#include <fstream>
#include <atomic>
#include <thread>
#include <unordered_set>
#include "inflighter.cc"
//#include "malloctrace.hh"
StatBag S;
bool g_quiet;
std::unique_ptr<ofstream> g_powerdns;
std::atomic<unsigned int> g_count;
std::atomic<bool> g_stop;


struct namecount {
  set<DNSName> names;
  unsigned int count;
  bool isPowerDNS{false};
};

struct DNSResult
{
  string content;
  int ttl{0};
  uint16_t qclass;
};

struct NSQuery
{
  ComboAddress a;
  set<DNSName> nsnames;
  DNSName qname;
  unsigned int count;
};

struct SendReceive
{
  typedef int Identifier;
  typedef DNSResult Answer; // ip 
  int d_socket;
  deque<uint16_t> d_idqueue;
    
  SendReceive(map<ComboAddress, namecount, ComboAddress::addressOnlyLessThan>& res) : d_res(res)
  {
    d_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int val=1;
    setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    
    for(unsigned int id =0 ; id < std::numeric_limits<uint16_t>::max(); ++id) 
      d_idqueue.push_back(id);
  }
  
  ~SendReceive()
  {
    close(d_socket);
  }
  
  Identifier send(NSQuery& domain)
  {
    //cerr<<"Sending query for '"<<domain<<"'"<<endl;
    
    // send it, copy code from 'sdig'
    vector<uint8_t> packet;
  
    DNSPacketWriter pw(packet, domain.qname, QType::TXT, 3);

    if(d_idqueue.empty()) {
      cerr<<"Exhausted ids!"<<endl;
      exit(1);
    }    
    pw.getHeader()->id = d_idqueue.front();
    d_idqueue.pop_front();
    pw.getHeader()->rd = 0;
    pw.getHeader()->qr = 0;
    
    if(::sendto(d_socket, &*packet.begin(), packet.size(), 0, (struct sockaddr*)&domain.a, domain.a.getSocklen()) < 0)
      d_senderrors++;
    
    return pw.getHeader()->id;
  }
  
  bool receive(Identifier& id, DNSResult& dr)
  {
    if(waitForData(d_socket, 0, 500000) > 0) {
      char buf[512];
      ComboAddress from;
      from.sin4.sin_family = AF_INET;
      socklen_t socklen=from.getSocklen();
      int len = recvfrom(d_socket, buf, sizeof(buf),0, (struct sockaddr*)&from, &socklen);
      if(len < 0) {
        d_receiveerrors++;
        return 0;
      }
      else {
        d_receiveds++;
      }
      // parse packet, set 'id', fill out 'ip' 
      
      MOADNSParser mdp(false, string(buf, len));
      if(!g_quiet) {
        cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
        cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
        cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;
      }
      id = mdp.d_header.id;
      d_idqueue.push_back(id);
      dr.qclass = mdp.d_qclass;
      dr.content.clear();
      dr.ttl=0;
      for(const auto& a : mdp.d_answers) {
        if(a.first.d_type == QType::TXT) {
          dr.content=a.first.d_content->getZoneRepresentation();
          dr.ttl=a.first.d_ttl;
        }
      }
      if(dr.content.empty()) 
        dr.content="RCode: "+RCode::to_s(mdp.d_header.rcode);
      return 1;
    }
    return 0;
  }
  
  void deliverTimeout(const Identifier& id)
  {
    if(!g_quiet) {
      cout<<"Timeout for id "<<id<<endl;
    }
    d_idqueue.push_back(id);
  }
  
  void deliverAnswer(NSQuery& domain, const DNSResult& dr, unsigned int usec)
  {
    cout<<domain.a.toString()<<"\t"<<domain.qname<<"\t";
    for(const auto& n : domain.nsnames)
      cout<<n<<",";
    cout<<"\t"<<domain.count<<"\t"<<dr.qclass<<'\t'<<dr.ttl<<": "<<dr.content<<endl;
    
    if(dr.qclass==1 || toLower(dr.content).find("powerdns") != string::npos || dr.ttl==5) {
      auto f = d_res.find(domain.a);
      if(!f->second.isPowerDNS) {
        (*g_powerdns)<<domain.a.toString()<<'\t'<<domain.count<<'\t';
        for(const auto& n : domain.nsnames)
          (*g_powerdns)<<n<<'\t';
        (*g_powerdns)<<"\n";
        f->second.isPowerDNS=true;
      }
      
    }

  }
  unsigned int d_errors, d_nxdomains, d_nodatas, d_oks, d_unknowns;
  unsigned int d_receiveds, d_receiveerrors, d_senderrors;
  map<ComboAddress, namecount, ComboAddress::addressOnlyLessThan>& d_res;
};


struct RESResult
{
  vector<ComboAddress> addrs;
  uint16_t rcode;
};

typedef DNSName RESQuery;

struct SendReceiveRes
{
  typedef int Identifier;
  typedef RESResult Answer; // ip 
  int d_socket;
  deque<uint16_t> d_idqueue;
  map<DNSName, vector<ComboAddress>>& d_out;
  SendReceiveRes(const ComboAddress& remote, map<DNSName,vector<ComboAddress>>& out) : d_out(out)
  {
    d_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int val=1;
    setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    connect(d_socket, (struct sockaddr*)&remote, remote.getSocklen());
    for(unsigned int id =0 ; id < std::numeric_limits<uint16_t>::max(); ++id) 
      d_idqueue.push_back(id);
  }
  
  ~SendReceiveRes()
  {
    close(d_socket);
  }
  
  Identifier send(RESQuery& domain)
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
    
    if(::send(d_socket, &*packet.begin(), packet.size(), 0) < 0) {
      cout<<"Error sending: "<<stringerror()<<endl;
      d_senderrors++;
    }
    
    return pw.getHeader()->id;
  }
  
  bool receive(Identifier& id, RESResult& dr)
  {
    if(waitForData(d_socket, 0, 500000) > 0) {
      char buf[512];
      ComboAddress from;
      from.sin4.sin_family = AF_INET;
      socklen_t socklen=from.getSocklen();
      int len = recvfrom(d_socket, buf, sizeof(buf),0, (struct sockaddr*)&from, &socklen);
      if(len < 0) {
        d_receiveerrors++;
        return 0;
      }
      else {
        d_receiveds++;
      }
      // parse packet, set 'id', fill out 'ip' 
      
      MOADNSParser mdp(false, string(buf, len));
      if(!g_quiet) {
        cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
        cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr<<", answers: "<<mdp.d_answers.size();
        cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;
      }
      id = mdp.d_header.id;
      d_idqueue.push_back(id);
      dr.rcode = mdp.d_header.rcode;
      dr.addrs.clear();
      for(const auto& a : mdp.d_answers) {
        if(a.first.d_name != mdp.d_qname) 
          continue;
        if(a.first.d_type == QType::A || a.first.d_type == QType::AAAA) {
          if(!g_quiet)
            cout<<a.first.d_content->getZoneRepresentation()<<endl;
          dr.addrs.push_back(getAddr(a.first));
        }
      }
      ++g_count;
      return 1;
    }
    return 0;
  }
  
  void deliverTimeout(const Identifier& id)
  {
    if(!g_quiet) {
      cout<<"Timeout for id "<<id<<endl;
    }
    ++g_count;
    d_idqueue.push_back(id);
  }
  
  void deliverAnswer(DNSName& domain, const RESResult& dr, unsigned int usec)
  {
    d_out[domain]=dr.addrs;
    cout<<domain<<"\t"<<dr.rcode<<'\t';
    for(const auto& a : dr.addrs)
      cout<<a.toString()<<'\t';
    cout<<'\n';
  }
  unsigned int d_errors, d_nxdomains, d_nodatas, d_oks, d_unknowns;
  unsigned int d_receiveds, d_receiveerrors, d_senderrors;
};


void printStats()
{
  while(!g_stop) {
    sleep(1);
    cerr<<"\r"<<g_count;
    cerr.flush();
  }
  cerr<<"\n";
}

int parseZone(const std::string& str, unsigned int limit)
{
  ZoneParserTNG zpt(str);
  DNSResourceRecord rr;

  std::thread stats(printStats);

  map<DNSName,unsigned int> nsnames;
  map<DNSName,set<ComboAddress,ComboAddress::addressOnlyLessThan> > addresses;

  
  while(zpt.get(rr)) {
    if(rr.qtype.getCode() == QType::NS)
      nsnames[DNSName(rr.content)]++;
    else if(rr.qtype.getCode() == QType::A || rr.qtype.getCode() == QType::AAAA) {
      DNSRecord dr(rr);
      addresses[rr.qname].insert(getAddr(dr, 53));
    }
    ++g_count;
    if(g_count == limit)
      break;
  }
  g_stop=true;
  stats.join();

  cout<<"Got "<<nsnames.size()<<" different nameserver names"<<endl;
  cout<<"Got at least one address for "<<addresses.size()<<" names"<<endl;

  ofstream ns(str+".nameservers");
  ofstream needres(str+".needres");
  for(const auto& a: nsnames) {
    ns<<a.first<<"\t"<<a.second<<"\t";
    if(auto hit=rplookup(addresses, a.first)) {
      for(const auto& b : *hit)
        ns<<b.toString()<<"\t";
    }
    else
      needres<<a.first<<"\n";
    ns<<"\n";
  }
  return 0;
}

int resolveNS(const std::string& fname)
{
  string line;
  ifstream needres(fname);
  if(!needres) 
    unixDie("Unable to open file "+fname);
  vector<DNSName> tores;
  while(getline(needres,line)) {
    tores.push_back(DNSName(line));
  }
  cerr<<"Going to resolve "<<tores.size()<<" names"<<endl;
  std::thread stats(printStats);
  map<DNSName, vector<ComboAddress>> output;
  SendReceiveRes sr(ComboAddress("192.168.1.2", 53), output);
  Inflighter<vector<DNSName>, SendReceiveRes> inflighter(tores, sr);
  inflighter.d_maxInFlight = 1000;
  inflighter.d_timeoutSeconds = 3;
  inflighter.d_burst = 100;
  for(;;) {
    try {
      inflighter.run();
      break;
    }
    catch(std::exception& e) {
      cerr<<"Caught exception: "<<e.what()<<endl;
    }
  }
  g_stop=true;
  stats.join();
  return EXIT_SUCCESS;
}

void readRESNames(const std::string& fname, map<DNSName, vector<ComboAddress>>& addrs)
{
  ifstream ifs(fname);
  if(!ifs)
    unixDie("Reading resolved names from "+fname+": "+stringerror());
  vector<string> parts;
  string line;
  addrs.clear();
  while(getline(ifs, line)) {
    parts.clear();
    stringtok(parts, line,"\t");
    for(unsigned int n=2; n < parts.size(); ++n)
      addrs[DNSName(parts[0])].push_back(ComboAddress(parts[n], 53));
  }
  //EARTH.DOMAINS.SHELTEK.CA.       0       67.15.253.219   67.15.47.188    67.15.253.252   67.15.253.251   67.15.47.189    67.15.253.220   
  cerr<<"Got "<<addrs.size()<<" resolved nameserver names from file"<<endl;

}

int main(int argc, char**argv)
try
{
  g_quiet=true;
  reportAllTypes();
  string mode=argv[1];
  if(mode == "parse-zone") {
    unsigned int limit = 0;
    if(argc > 3)
      limit = atoi(argv[3]);

    return parseZone(argv[2], limit);
  }
  else if(mode=="resolve-ns") {
    return resolveNS(string(argv[2])+".needres");
  }
  else if(mode=="scan-ns") {
    ifstream ns(string(argv[2])+".nameservers");
    g_powerdns = make_unique<ofstream>(string(argv[2])+".powerdns");
    string line;
    int count=0;
    vector<string> parts;

    struct NSCount
    {
      unsigned int count{0};
      vector<ComboAddress> addrs;
    };
    map<DNSName, NSCount> stats;
    NSCount nscount;
    // NS1.IHOST2000.COM.      9       162.251.82.122  162.251.82.123  162.251.82.250  162.251.82.251
    while(getline(ns, line)) {
      ++count;
      parts.clear();
      stringtok(parts, line,"\t");
      nscount.count=atoi(parts[1].c_str());
      nscount.addrs.clear();
      for(unsigned int n = 2; n < parts.size(); ++n)
        nscount.addrs.push_back(ComboAddress(parts[n], 53));
      stats.insert({DNSName(parts[0]), nscount});
    }
    cerr<<"Had "<<count<<" lines from summary"<<endl;

    map<DNSName, vector<ComboAddress>> lookedup;
    readRESNames(argv[2]+string(".resolved"), lookedup);
    
    map<ComboAddress, namecount, ComboAddress::addressOnlyLessThan> pure;
    
    unsigned int noaddrs=0;
    for(const auto& s : stats) {
      auto ptr = &s.second.addrs;
      if(ptr->empty()) {
        if(lookedup.count(s.first)) {
          ptr = &lookedup[s.first];
        }
        else {
          //cout<<"Have no address for "<<s.first.toString()<<endl;
          noaddrs++;
        }
      }
      
      for(const auto& a : *ptr) {
        pure[a].count += s.second.count;
        pure[a].names.insert(s.first);
      }
    }
    
    cerr<<"Have "<<pure.size()<<" IP addresses to query, "<<noaddrs<<" names w/o address"<<endl;
    SendReceive sr(pure);
    vector<NSQuery> domains;
    
    Inflighter<vector<NSQuery>, SendReceive> inflighter(domains, sr);
    inflighter.d_maxInFlight = 1000;
    inflighter.d_timeoutSeconds = 3;
    inflighter.d_burst = 100;

    for(const auto& p : pure) {
      NSQuery nsq;
      nsq.a=p.first;
      nsq.nsnames = p.second.names;
      nsq.count = p.second.count;

      nsq.qname=DNSName("version.bind");
      domains.push_back(nsq);
      nsq.qname=DNSName("id.server");
      domains.push_back(nsq);
      nsq.qname=DNSName("bind.version");
      domains.push_back(nsq);
    }

    sort(domains.begin(), domains.end(), [](const NSQuery& a, const NSQuery& b) { return b.count < a.count; });
    for(;;) {
      try {
        inflighter.run();
        break;
      }
      catch(std::exception& e) {
        cerr<<"Caught exception: "<<e.what()<<endl;
      }
    }
  }
  else if(mode=="score-ns") {
    std::unordered_set<DNSName> powerdns;
    ifstream ifs(string(argv[2])+".powerdns");
    string line;
    vector<string> parts;
    while(getline(ifs,line)) {
      // 64.96.240.53    1234     NS1.UNIREGISTRYMARKET.LINK.     NS1.INTERNETTRAFFIC.COM.        BUY.INTERNETTRAFFIC.COM.        NS3.SECUREDOFFERS.COM.  NS3.GI.NET.     NS3.IT.GI.NET.  NS3.EASILY.NET. 
      parts.clear();
      stringtok(parts, line);
      for(unsigned int n=2; n < parts.size(); ++n)
        powerdns.insert(DNSName(parts[n]));
    }
    cerr<<"Have "<<powerdns.size()<<" known NS names that are PowerDNS"<<endl;
    ZoneParserTNG zpt(argv[2]);
    DNSResourceRecord rr;
    
    set<DNSName> seen, pdnsdomains;
    int count=0;
    while(zpt.get(rr)) {
      if(!seen.count(rr.qname)) {
        seen.insert(rr.qname);
      } 
      if(rr.qtype.getCode() == QType::NS && powerdns.count(DNSName(rr.content)) && !pdnsdomains.count(DNSName(rr.qname))) {
        pdnsdomains.insert(DNSName(rr.qname));
      }
      if(!(count%100000)) {
        cerr<<"\rUnique domains: "<<seen.size()<<", PowerDNS domains: "<<pdnsdomains.size()<<" ("<<(pdnsdomains.size()*100.0/seen.size())<<"%)";
      }
      count++;
    }
    cerr<<"\n";
  }
  else {
    cerr<<"Unknown mode "<<argv[1]<<endl;
  }
  //  cout<<g_mtracer->topAllocatorsString(20)<<endl;
}
catch(PDNSException& pe) {
  cerr<<"Fatal error: "<<pe.reason<<endl;
}
