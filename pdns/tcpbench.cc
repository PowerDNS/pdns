#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include <boost/array.hpp>
StatBag S;

bool g_onlyTCP;
AtomicCounter g_networkErrors, g_otherErrors, g_OK, g_truncates;

// echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle 


void doQuery(const std::string& qname, uint16_t qtype, const ComboAddress& dest)
try
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qname, qtype);

  string reply;

  if(!g_onlyTCP) {
    Socket udpsock(InterNetwork, Datagram);
    
    udpsock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
    ComboAddress origin;
    udpsock.recvFrom(reply, origin);
    MOADNSParser mdp(reply);
    if(!mdp.d_header.tc)
      return;
    g_truncates++;
  }


  Socket sock(InterNetwork, Stream);
  int tmp=1;
  if(setsockopt(sock.getHandle(),SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) 
    throw runtime_error("Unable to set socket reuse: "+string(strerror(errno)));

  sock.connect(dest);
  uint16_t len;
  len = htons(packet.size());
  if(sock.write((char *) &len, 2) != 2)
    throw AhuException("tcp write failed");
  
  sock.writen(string((char*)&*packet.begin(), (char*)&*packet.end()));
  
  if(sock.read((char *) &len, 2) != 2)
    throw AhuException("tcp read failed");
  
  len=ntohs(len);
  char *creply = new char[len];
  int n=0;
  int numread;
  while(n<len) {
    numread=sock.read(creply+n, len-n);
    if(numread<0)
      throw AhuException("tcp read failed");
    n+=numread;
  }
  
  reply=string(creply, len);
  delete[] creply;
  
  MOADNSParser mdp(reply);
  //  cout<<"Had correct TCP/IP response, "<<mdp.d_answers.size()<<" answers, aabit="<<mdp.d_header.aa<<endl;
  g_OK++;
}
catch(NetworkError& ne)
{
  cerr<<"Network error: "<<ne.what()<<endl;
  g_networkErrors++;
}
catch(...)
{
  g_otherErrors++;
}
 

/* read queries from stdin, put in vector
   launch n worker threads, each picks a query using AtomicCounter
   If a worker reaches the end of its queue, it stops */

AtomicCounter g_pos;
struct Query
{
  Query(const std::string& qname_, uint16_t qtype_) : qname(qname_), qtype(qtype_) {}
  Query(){}
  std::string qname;
  uint16_t qtype;
};

vector<Query> g_queries;
ComboAddress g_dest;

void* worker(void*)
{
  Query q;
  for(;;) {
    unsigned int pos = g_pos++; 
    if(pos >= g_queries.size())
      break;
    q=g_queries[pos];
    doQuery(q.qname, q.qtype, g_dest);
  }
  return 0;
}


int main(int argc, char** argv)
try
{
  reportAllTypes();
  g_onlyTCP=false;

  uint16_t port=53;
  if(argc < 2) {
    cerr<<"Syntax: tcpbench remote [port] < queries"<<endl;
    cerr<<"Where queries is one query per line, format: qname qtype, just 1 space"<<endl;
    exit(EXIT_FAILURE);
  }
  if(argc > 2)
    port = atoi(argv[2]);

  g_dest = ComboAddress(argv[1], port);
  unsigned int numworkers=100;
  pthread_t workers[numworkers];

  FILE* fp=fdopen(0, "r");
  pair<string, string> q;
  string line;
  while(stringfgets(fp, line)) {
    trim_right(line);
    q=splitField(line, ' ');
    g_queries.push_back(Query(q.first, DNSRecordContent::TypeToNumber(q.second)));
  }
  fclose(fp);
    
  for(unsigned int n = 0; n < numworkers; ++n) {
    pthread_create(&workers[n], 0, worker, 0);
  }
  for(unsigned int n = 0; n < numworkers; ++n) {
    void* status;
    pthread_join(workers[n], &status);
  }
  cout<<"OK: "<<g_OK<<", network errors: "<<g_networkErrors<<", other errors: "<<g_otherErrors<<endl;
  cout<<"Truncateds: "<<g_truncates<<endl;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
