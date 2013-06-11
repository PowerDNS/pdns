#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include <boost/array.hpp>
StatBag S;

bool g_onlyTCP;

void doQuery(const std::string& qname, uint16_t qtype, const ComboAddress& dest)
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
  }


  Socket sock(InterNetwork, Stream);

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
    unsigned int pos = ++g_pos; 
    if(pos > g_queries.size())
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
  g_onlyTCP=true;
  g_dest = ComboAddress("127.0.0.1", 5300);
  unsigned int numworkers=100;
  pthread_t workers[numworkers];

  for(unsigned int n = 0; n < 1000000; ++n) {
    g_queries.push_back(Query("www.powerdns.com", QType::A));
  }

  for(unsigned int n = 0; n < numworkers; ++n) {
    pthread_create(&workers[n], 0, worker, 0);
  }
  for(unsigned int n = 0; n < numworkers; ++n) {
    void* status;
    pthread_join(workers[n], &status);
  }

}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
