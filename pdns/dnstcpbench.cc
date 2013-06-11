#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include <boost/array.hpp>
#include <boost/program_options.hpp>

StatBag S;
namespace po = boost::program_options;
po::variables_map g_vm;
bool g_verbose;
bool g_onlyTCP;
unsigned int g_timeoutMsec;
AtomicCounter g_networkErrors, g_otherErrors, g_OK, g_truncates, g_authAnswers, g_timeOuts;

// echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle 

void doQuery(const std::string& qname, uint16_t qtype, const ComboAddress& dest)
try
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qname, qtype);
  int res;
  string reply;

  if(!g_onlyTCP) {
    Socket udpsock(InterNetwork, Datagram);
    
    udpsock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
    ComboAddress origin;
    res = waitForData(udpsock.getHandle(), 0, 1000 * g_timeoutMsec);
    if(res < 0)
      throw NetworkError("Error waiting for response");
    if(!res) {
      g_timeOuts++;
      return;
    }

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
  uint16_t len = htons(packet.size());
  string tcppacket((char*)& len, 2);
  tcppacket.append((char*)&*packet.begin(), (char*)&*packet.end());

  sock.writen(tcppacket);

  res = waitForData(sock.getHandle(), 0, 1000 * g_timeoutMsec);
  if(res < 0)
    throw NetworkError("Error waiting for response");
  if(!res) {
    g_timeOuts++;
    return;
  }
  
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
  if(mdp.d_header.aa)
    g_authAnswers++;
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
  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("verbose,v", "be verbose")
    ("udp-first,u", "try UDP first")
    ("timeout-msec", po::value<int>()->default_value(10), "wait for this amount of milliseconds for an answer")
    ("workers", po::value<int>()->default_value(100), "number of parallel workers");

  hidden.add_options()
    ("remote-host", po::value<string>(), "remote-host")
    ("remote-port", po::value<int>()->default_value(53), "remote-port");
  alloptions.add(desc).add(hidden); 

  po::positional_options_description p;
  p.add("remote-host", 1);
  p.add("remote-port", 1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);
  
  if(g_vm.count("help")) {
    cout << desc<<endl;
    exit(EXIT_SUCCESS);
  }
  g_onlyTCP = !g_vm.count("udp-first");
  g_verbose = g_vm.count("verbose");
  g_timeoutMsec = g_vm["timeout-msec"].as<int>();

  reportAllTypes();

  if(g_vm["remote-host"].empty()) {
    cerr<<"Syntax: tcpbench remote [port] < queries"<<endl;
    cerr<<"Where queries is one query per line, format: qname qtype, just 1 space"<<endl;
    cerr<<desc<<endl;
    exit(EXIT_FAILURE);
  }

  g_dest = ComboAddress(g_vm["remote-host"].as<string>().c_str(), g_vm["remote-port"].as<int>());

  unsigned int numworkers=g_vm["workers"].as<int>();
  
  if(g_verbose) {
    cout<<"Sending queries to: "<<g_dest.toStringWithPort()<<endl;
    cout<<"Attempting UDP first: " << (g_onlyTCP ? "no" : "yes") <<endl;
    cout<<"Timeout: "<< g_timeoutMsec<<"msec"<<endl;
  }


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
  cout<<"Timeouts: "<<g_timeOuts<<endl;
  cout<<"Truncateds: "<<g_truncates<<", auth answers: "<<g_authAnswers<<endl;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
