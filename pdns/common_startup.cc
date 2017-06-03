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
#include "common_startup.hh"
#include "ws-auth.hh"
#include "secpoll-auth.hh"
#include <sys/time.h>
#include <sys/resource.h>
#include "dynhandler.hh"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

bool g_anyToTcp;
bool g_8bitDNS;
typedef Distributor<DNSPacket,DNSPacket,PacketHandler> DNSDistributor;

ArgvMap theArg;
StatBag S;  //!< Statistics are gathered across PDNS via the StatBag class S
AuthPacketCache PC; //!< This is the main PacketCache, shared across all threads
AuthQueryCache QC;
DNSProxy *DP;
DynListener *dl;
CommunicatorClass Communicator;
shared_ptr<UDPNameserver> N;
int avg_latency;
TCPNameserver *TN;
static vector<DNSDistributor*> g_distributors;
vector<std::shared_ptr<UDPNameserver> > g_udpReceivers;
AuthLua *LPE;

ArgvMap &arg()
{
  return theArg;
}

void declareArguments()
{
  ::arg().set("local-port","The port on which we listen")="53";
  ::arg().setSwitch("dnsupdate","Enable/Disable DNS update (RFC2136) support. Default is no.")="no";
  ::arg().setSwitch("write-pid","Write a PID file")="yes";
  ::arg().set("allow-dnsupdate-from","A global setting to allow DNS updates from these IP ranges.")="127.0.0.0/8,::1";
  ::arg().set("allow-unsigned-notify","Allow unsigned notifications for TSIG secured domains")="yes"; //FIXME: change to 'no' later
  ::arg().set("allow-unsigned-supermaster", "Allow supermasters to create zones without TSIG signed NOTIFY")="yes";
  ::arg().setSwitch("forward-dnsupdate","A global setting to allow DNS update packages that are for a Slave domain, to be forwarded to the master.")="yes";
  ::arg().setSwitch("log-dns-details","If PDNS should log DNS non-erroneous details")="no";
  ::arg().setSwitch("log-dns-queries","If PDNS should log all incoming DNS queries")="no";
  ::arg().set("local-address","Local IP addresses to which we bind")="0.0.0.0";
  ::arg().setSwitch("local-address-nonexist-fail","Fail to start if one or more of the local-address's do not exist on this server")="yes";
  ::arg().setSwitch("non-local-bind", "Enable binding to non-local addresses by using FREEBIND / BINDANY socket options")="no";
  ::arg().set("local-ipv6","Local IP address to which we bind")="::";
  ::arg().setSwitch("reuseport","Enable higher performance on compliant kernels by using SO_REUSEPORT allowing each receiver thread to open its own socket")="no";
  ::arg().setSwitch("local-ipv6-nonexist-fail","Fail to start if one or more of the local-ipv6 addresses do not exist on this server")="yes";
  ::arg().set("query-local-address","Source IP address for sending queries")="0.0.0.0";
  ::arg().set("query-local-address6","Source IPv6 address for sending queries")="::";
  ::arg().set("overload-queue-length","Maximum queuelength moving to packetcache only")="0";
  ::arg().set("max-queue-length","Maximum queuelength before considering situation lost")="5000";

  ::arg().set("retrieval-threads", "Number of AXFR-retrieval threads for slave operation")="2";
  ::arg().setSwitch("api", "Enable/disable the REST API (including HTTP listener)")="no";
  ::arg().set("api-key", "Static pre-shared authentication key for access to the REST API")="";
  ::arg().set("api-logfile", "Location of the server logfile (used by the REST API)")="/var/log/pdns.log";
  ::arg().setSwitch("api-readonly", "Disallow data modification through the REST API when set")="no";
  ::arg().setSwitch("dname-processing", "If we should support DNAME records")="no";

  ::arg().setCmd("help","Provide a helpful message");
  ::arg().setCmd("version","Output version and compilation date");
  ::arg().setCmd("config","Provide configuration file on standard output");
  ::arg().setCmd("list-modules","Lists all modules available");
  ::arg().setCmd("no-config","Don't parse configuration file");
  
  ::arg().set("version-string","PowerDNS version in packets - full, anonymous, powerdns or custom")="full"; 
  ::arg().set("control-console","Debugging switch - don't use")="no"; // but I know you will!
  ::arg().set("loglevel","Amount of logging. Higher is more. Do not set below 3")="4";
  ::arg().set("disable-syslog","Disable logging to syslog, useful when running inside a supervisor that logs stdout")="no";
  ::arg().set("default-soa-name","name to insert in the SOA record if none set in the backend")="a.misconfigured.powerdns.server";
  ::arg().set("default-soa-mail","mail address to insert in the SOA record if none set in the backend")="";
  ::arg().set("distributor-threads","Default number of Distributor (backend) threads to start")="3";
  ::arg().set("signing-threads","Default number of signer threads to start")="3";
  ::arg().set("receiver-threads","Default number of receiver threads to start")="1";
  ::arg().set("queue-limit","Maximum number of milliseconds to queue a query")="1500"; 
  ::arg().set("resolver","Use this resolver for ALIAS and the internal stub resolver")="no";
  ::arg().set("udp-truncation-threshold", "Maximum UDP response size before we truncate")="1680";
  ::arg().set("disable-tcp","Do not listen to TCP queries")="no";
  
  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";

  ::arg().set("load-modules","Load this module - supply absolute or relative path")="";
  ::arg().set("launch","Which backends to launch and order to query them in")="";
  ::arg().setSwitch("disable-axfr","Disable zonetransfers but do allow TCP queries")="no";
  ::arg().set("allow-axfr-ips","Allow zonetransfers only to these subnets")="127.0.0.0/8,::1";
  ::arg().set("only-notify", "Only send AXFR NOTIFY to these IP addresses or netmasks")="0.0.0.0/0,::/0";
  ::arg().set("also-notify", "When notifying a domain, also notify these nameservers")="";
  ::arg().set("allow-notify-from","Allow AXFR NOTIFY from these IP ranges. If empty, drop all incoming notifies.")="0.0.0.0/0,::/0";
  ::arg().set("slave-cycle-interval","Schedule slave freshness checks once every .. seconds")="60";

  ::arg().set("tcp-control-address","If set, PowerDNS can be controlled over TCP on this address")="";
  ::arg().set("tcp-control-port","If set, PowerDNS can be controlled over TCP on this address")="53000";
  ::arg().set("tcp-control-secret","If set, PowerDNS can be controlled over TCP after passing this secret")="";
  ::arg().set("tcp-control-range","If set, remote control of PowerDNS is possible over these networks only")="127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fe80::/10";
  
  ::arg().setSwitch("slave","Act as a slave")="no";
  ::arg().setSwitch("master","Act as a master")="no";
  ::arg().setSwitch("disable-axfr-rectify","Disable the rectify step during an outgoing AXFR. Only required for regression testing.")="no";
  ::arg().setSwitch("guardian","Run within a guardian process")="no";
  ::arg().setSwitch("prevent-self-notification","Don't send notifications to what we think is ourself")="yes";
  ::arg().setSwitch("any-to-tcp","Answer ANY queries with tc=1, shunting to TCP")="yes";
  ::arg().setSwitch("edns-subnet-processing","If we should act on EDNS Subnet options")="no";

  ::arg().setSwitch("webserver","Start a webserver for monitoring (api=yes also enables the HTTP listener)")="no";
  ::arg().setSwitch("webserver-print-arguments","If the webserver should print arguments")="no";
  ::arg().set("webserver-address","IP Address of webserver/API to listen on")="127.0.0.1";
  ::arg().set("webserver-port","Port of webserver/API to listen on")="8081";
  ::arg().set("webserver-password","Password required for accessing the webserver")="";
  ::arg().set("webserver-allow-from","Webserver/API access is only allowed from these subnets")="0.0.0.0/0,::/0";

  ::arg().setSwitch("out-of-zone-additional-processing","Do out of zone additional processing")="yes";
  ::arg().setSwitch("do-ipv6-additional-processing", "Do AAAA additional processing")="yes";
  ::arg().setSwitch("query-logging","Hint backends that queries should be logged")="no";

  ::arg().set("carbon-ourname", "If set, overrides our reported hostname for carbon stats")="";
  ::arg().set("carbon-server", "If set, send metrics in carbon (graphite) format to this server IP address")="";
  ::arg().set("carbon-interval", "Number of seconds between carbon (graphite) updates")="30";

  ::arg().set("cache-ttl","Seconds to store packets in the PacketCache")="20";
  ::arg().set("negquery-cache-ttl","Seconds to store negative query results in the QueryCache")="60";
  ::arg().set("query-cache-ttl","Seconds to store query results in the QueryCache")="20";
  ::arg().set("soa-minimum-ttl","Default SOA minimum ttl")="3600";
  ::arg().set("server-id", "Returned when queried for 'server.id' TXT or NSID, defaults to hostname - disabled or custom")="";
  ::arg().set("soa-refresh-default","Default SOA refresh")="10800";
  ::arg().set("soa-retry-default","Default SOA retry")="3600";
  ::arg().set("soa-expire-default","Default SOA expire")="604800";
  ::arg().set("default-soa-edit","Default SOA-EDIT value")="";
  ::arg().set("default-soa-edit-signed","Default SOA-EDIT value for signed zones")="";
  ::arg().set("dnssec-key-cache-ttl","Seconds to cache DNSSEC keys from the database")="30";
  ::arg().set("domain-metadata-cache-ttl","Seconds to cache domain metadata from the database")="60";

  ::arg().set("trusted-notification-proxy", "IP address of incoming notification proxy")="";
  ::arg().set("slave-renotify", "If we should send out notifications for slaved updates")="no";

  ::arg().set("default-ttl","Seconds a result is valid if not set otherwise")="3600";
  ::arg().set("max-tcp-connections","Maximum number of TCP connections")="20";
  ::arg().set("max-tcp-connections-per-client","Maximum number of simultaneous TCP connections per client")="0";
  ::arg().set("max-tcp-transactions-per-conn")="0";
  ::arg().set("max-tcp-connection-duration")="0";
  ::arg().set("tcp-idle-timeout")="5";

  ::arg().setSwitch("no-shuffle","Set this to prevent random shuffling of answers - for regression testing")="off";

  ::arg().set("setuid","If set, change user id to this uid for more security")="";
  ::arg().set("setgid","If set, change group id to this gid for more security")="";

  ::arg().set("max-cache-entries", "Maximum number of entries in the query cache")="1000000";
  ::arg().set("max-packet-cache-entries", "Maximum number of entries in the packet cache")="1000000";
  ::arg().set("max-signature-cache-entries", "Maximum number of signatures cache entries")="";
  ::arg().set("max-ent-entries", "Maximum number of empty non-terminals in a zone")="100000";
  ::arg().set("entropy-source", "If set, read entropy from this file")="/dev/urandom";

  ::arg().set("lua-prequery-script", "Lua script with prequery handler (DO NOT USE)")="";
  ::arg().set("lua-dnsupdate-policy-script", "Lua script with DNS update policy handler")="";
  ::arg().set("experimental-lua-policy-script", "Lua script for the policy engine")="";

  ::arg().setSwitch("traceback-handler","Enable the traceback handler (Linux only)")="yes";
  ::arg().setSwitch("direct-dnskey","Fetch DNSKEY RRs from backend during DNSKEY synthesis")="no";
  ::arg().set("default-ksk-algorithms","Default KSK algorithms")="ecdsa256";
  ::arg().set("default-ksk-size","Default KSK size (0 means default)")="0";
  ::arg().set("default-zsk-algorithms","Default ZSK algorithms")="";
  ::arg().set("default-zsk-size","Default ZSK size (0 means default)")="0";
  ::arg().set("max-nsec3-iterations","Limit the number of NSEC3 hash iterations")="500"; // RFC5155 10.3

  ::arg().set("include-dir","Include *.conf files from this directory");
  ::arg().set("security-poll-suffix","Domain name from which to query security update notifications")="secpoll.powerdns.com.";

  ::arg().setSwitch("expand-alias", "Expand ALIAS records")="no";
  ::arg().setSwitch("outgoing-axfr-expand-alias", "Expand ALIAS records during outgoing AXFR")="no";
  ::arg().setSwitch("8bit-dns", "Allow 8bit dns queries")="no";
  ::arg().setSwitch("axfr-lower-serial", "Also AXFR a zone from a master with a lower serial")="no";

  ::arg().set("lua-axfr-script", "Script to be used to edit incoming AXFRs")="";
  ::arg().set("xfr-max-received-mbytes", "Maximum number of megabytes received from an incoming XFR")="100";

  ::arg().set("tcp-fast-open", "Enable TCP Fast Open support on the listening sockets, using the supplied numerical value as the queue size")="0";
}

static time_t s_start=time(0);
static uint64_t uptimeOfProcess(const std::string& str)
{
  return time(0) - s_start;
}

static uint64_t getSysUserTimeMsec(const std::string& str)
{
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);

  if(str=="sys-msec") {
    return (ru.ru_stime.tv_sec*1000ULL + ru.ru_stime.tv_usec/1000);
  }
  else
    return (ru.ru_utime.tv_sec*1000ULL + ru.ru_utime.tv_usec/1000);

}

static uint64_t getQCount(const std::string& str)
try
{
  int totcount=0;
  for(DNSDistributor* d :  g_distributors) {
    if(!d)
      continue;
    totcount += d->getQueueSize();  // this does locking and other things, so don't get smart
  }
  return totcount;
}
catch(std::exception& e)
{
  L<<Logger::Error<<"Had error retrieving queue sizes: "<<e.what()<<endl;
  return 0;
}
catch(PDNSException& e)
{
  L<<Logger::Error<<"Had error retrieving queue sizes: "<<e.reason<<endl;
  return 0;
}

static uint64_t getLatency(const std::string& str) 
{
  return avg_latency;
}

void declareStats(void)
{
  S.declare("udp-queries","Number of UDP queries received");
  S.declare("udp-do-queries","Number of UDP queries received with DO bit");
  S.declare("udp-answers","Number of answers sent out over UDP");
  S.declare("udp-answers-bytes","Total size of answers sent out over UDP");
  S.declare("udp4-answers-bytes","Total size of answers sent out over UDPv4");
  S.declare("udp6-answers-bytes","Total size of answers sent out over UDPv6");

  S.declare("udp4-answers","Number of IPv4 answers sent out over UDP");
  S.declare("udp4-queries","Number of IPv4 UDP queries received");
  S.declare("udp6-answers","Number of IPv6 answers sent out over UDP");
  S.declare("udp6-queries","Number of IPv6 UDP queries received");
  S.declare("overload-drops","Queries dropped because backends overloaded");

  S.declare("rd-queries", "Number of recursion desired questions");
  S.declare("recursion-unanswered", "Number of packets unanswered by configured recursor");
  S.declare("recursing-answers","Number of recursive answers sent out");
  S.declare("recursing-questions","Number of questions sent to recursor");
  S.declare("corrupt-packets","Number of corrupt packets received");
  S.declare("signatures", "Number of DNSSEC signatures made");
  S.declare("tcp-queries","Number of TCP queries received");
  S.declare("tcp-answers","Number of answers sent out over TCP");
  S.declare("tcp-answers-bytes","Total size of answers sent out over TCP");
  S.declare("tcp4-answers-bytes","Total size of answers sent out over TCPv4");
  S.declare("tcp6-answers-bytes","Total size of answers sent out over TCPv6");

  S.declare("tcp4-queries","Number of IPv4 TCP queries received");
  S.declare("tcp4-answers","Number of IPv4 answers sent out over TCP");
  
  S.declare("tcp6-queries","Number of IPv6 TCP queries received");
  S.declare("tcp6-answers","Number of IPv6 answers sent out over TCP");
    

  S.declare("qsize-q","Number of questions waiting for database attention", getQCount);

  S.declare("dnsupdate-queries", "DNS update packets received.");
  S.declare("dnsupdate-answers", "DNS update packets successfully answered.");
  S.declare("dnsupdate-refused", "DNS update packets that are refused.");
  S.declare("dnsupdate-changes", "DNS update changes to records in total.");

  S.declare("incoming-notifications", "NOTIFY packets received.");

  S.declare("uptime", "Uptime of process in seconds", uptimeOfProcess);
  S.declare("real-memory-usage", "Actual unique use of memory in bytes (approx)", getRealMemoryUsage);
  S.declare("fd-usage", "Number of open filedescriptors", getOpenFileDescriptors);
#ifdef __linux__
  S.declare("udp-recvbuf-errors", "UDP 'recvbuf' errors", udpErrorStats);
  S.declare("udp-sndbuf-errors", "UDP 'sndbuf' errors", udpErrorStats);
  S.declare("udp-noport-errors", "UDP 'noport' errors", udpErrorStats);
  S.declare("udp-in-errors", "UDP 'in' errors", udpErrorStats);
#endif

  S.declare("sys-msec", "Number of msec spent in system time", getSysUserTimeMsec);
  S.declare("user-msec", "Number of msec spent in user time", getSysUserTimeMsec);
  S.declare("meta-cache-size", "Number of entries in the metadata cache", DNSSECKeeper::dbdnssecCacheSizes);
  S.declare("key-cache-size", "Number of entries in the key cache", DNSSECKeeper::dbdnssecCacheSizes);
  S.declare("signature-cache-size", "Number of entries in the signature cache", signatureCacheSize);

  S.declare("servfail-packets","Number of times a server-failed packet was sent out");
  S.declare("latency","Average number of microseconds needed to answer a question", getLatency);
  S.declare("timedout-packets","Number of packets which weren't answered within timeout set");
  S.declare("security-status", "Security status based on regular polling");
  S.declareRing("queries","UDP Queries Received");
  S.declareRing("nxdomain-queries","Queries for non-existent records within existent domains");
  S.declareRing("noerror-queries","Queries for existing records, but for type we don't have");
  S.declareRing("servfail-queries","Queries that could not be answered due to backend errors");
  S.declareRing("unauth-queries","Queries for domains that we are not authoritative for");
  S.declareRing("logmessages","Log Messages");
  S.declareComboRing("remotes","Remote server IP addresses");
  S.declareComboRing("remotes-unauth","Remote hosts querying domains for which we are not auth");
  S.declareComboRing("remotes-corrupt","Remote hosts sending corrupt packets");
}

int isGuarded(char **argv)
{
  char *p=strstr(argv[0],"-instance");

  return !!p;
}

void sendout(DNSPacket* a)
{
  if(!a)
    return;
  
  N->send(a);

  int diff=a->d_dt.udiff();
  avg_latency=(int)(0.999*avg_latency+0.001*diff);
  delete a;  
}

//! The qthread receives questions over the internet via the Nameserver class, and hands them to the Distributor for further processing
void *qthread(void *number)
try
{
  DNSPacket *P;
  DNSDistributor *distributor = DNSDistributor::Create(::arg().asNum("distributor-threads", 1)); // the big dispatcher!
  int num = (int)(unsigned long)number;
  g_distributors[num] = distributor;
  DNSPacket question(true);
  DNSPacket cached(false);

  AtomicCounter &numreceived=*S.getPointer("udp-queries");
  AtomicCounter &numreceiveddo=*S.getPointer("udp-do-queries");

  AtomicCounter &numreceived4=*S.getPointer("udp4-queries");

  AtomicCounter &numreceived6=*S.getPointer("udp6-queries");
  AtomicCounter &overloadDrops=*S.getPointer("overload-drops");

  int diff;
  bool logDNSQueries = ::arg().mustDo("log-dns-queries");
  shared_ptr<UDPNameserver> NS;

  // If we have SO_REUSEPORT then create a new port for all receiver threads
  // other than the first one.
  if( number != NULL && N->canReusePort() ) {
    NS = g_udpReceivers[num];
    if (NS == nullptr) {
      NS = N;
    }
  } else {
    NS = N;
  }

  for(;;) {
    if(!(P=NS->receive(&question))) { // receive a packet         inline
      continue;                    // packet was broken, try again
    }

    numreceived++;

    if(P->d_remote.getSocklen()==sizeof(sockaddr_in))
      numreceived4++;
    else
      numreceived6++;

    if(P->d_dnssecOk)
      numreceiveddo++;

     if(P->d.qr)
       continue;

    S.ringAccount("queries", P->qdomain.toLogString()+"/"+P->qtype.getName());
    S.ringAccount("remotes",P->d_remote);
    if(logDNSQueries) {
      string remote;
      if(P->hasEDNSSubnet()) 
        remote = P->getRemote().toString() + "<-" + P->getRealRemote().toString();
      else
        remote = P->getRemote().toString();
      L << Logger::Notice<<"Remote "<< remote <<" wants '" << P->qdomain<<"|"<<P->qtype.getName() << 
            "', do = " <<P->d_dnssecOk <<", bufsize = "<< P->getMaxReplyLen()<<": ";
    }

    if((P->d.opcode != Opcode::Notify && P->d.opcode != Opcode::Update) && P->couldBeCached()) {
      bool haveSomething=PC.get(P, &cached); // does the PacketCache recognize this question?
      if (haveSomething) {
        if(logDNSQueries)
          L<<"packetcache HIT"<<endl;
        cached.setRemote(&P->d_remote);  // inlined
        cached.setSocket(P->getSocket());                               // inlined
        cached.d_anyLocal = P->d_anyLocal;
        cached.setMaxReplyLen(P->getMaxReplyLen());
        cached.d.rd=P->d.rd; // copy in recursion desired bit
        cached.d.id=P->d.id;
        cached.commitD(); // commit d to the packet                        inlined

        int policyres = PolicyDecision::PASS;
        if(LPE)
        {
          // FIXME: cached does not have qdomainwild/qdomainzone because packetcache entries
          // go through tostring/noparse
          policyres = LPE->police(&question, &cached);
        }

        if (policyres == PolicyDecision::PASS) {
          NS->send(&cached);   // answer it then                              inlined
          diff=P->d_dt.udiff();
          avg_latency=(int)(0.999*avg_latency+0.001*diff); // 'EWMA'
        }
        // FIXME implement truncate

        continue;
      }
    }

    if(distributor->isOverloaded()) {
      if(logDNSQueries) 
        L<<"Dropped query, backends are overloaded"<<endl;
      overloadDrops++;
      continue;
    }
        
    if(logDNSQueries) 
      L<<"packetcache MISS"<<endl;

    try {
      distributor->question(P, &sendout); // otherwise, give to the distributor
    }
    catch(DistributorFatal& df) { // when this happens, we have leaked loads of memory. Bailing out time.
      _exit(1);
    }
  }
  return 0;
}
catch(PDNSException& pe)
{
  L<<Logger::Error<<"Fatal error in question thread: "<<pe.reason<<endl;
  _exit(1);
}

static void* dummyThread(void *)
{
  void* ignore=0;
  pthread_exit(ignore);
}

static void triggerLoadOfLibraries()
{
  pthread_t tid;
  pthread_create(&tid, 0, dummyThread, 0);
  void* res;
  pthread_join(tid, &res);
}

void mainthread()
{
   Utility::srandom(time(0) ^ getpid());

   int newgid=0;      
   if(!::arg()["setgid"].empty()) 
     newgid=Utility::makeGidNumeric(::arg()["setgid"]);      
   int newuid=0;      
   if(!::arg()["setuid"].empty())        
     newuid=Utility::makeUidNumeric(::arg()["setuid"]); 
   
   g_anyToTcp = ::arg().mustDo("any-to-tcp");
   g_8bitDNS = ::arg().mustDo("8bit-dns");

   DNSPacket::s_udpTruncationThreshold = std::max(512, ::arg().asNum("udp-truncation-threshold"));
   DNSPacket::s_doEDNSSubnetProcessing = ::arg().mustDo("edns-subnet-processing");

   PC.setTTL(::arg().asNum("cache-ttl"));
   PC.setMaxEntries(::arg().asNum("max-packet-cache-entries"));
   QC.setMaxEntries(::arg().asNum("max-cache-entries"));

   stubParseResolveConf();

   if(!::arg()["chroot"].empty()) {
#ifdef HAVE_SYSTEMD
     char *ns;
     ns = getenv("NOTIFY_SOCKET");
     if (ns != nullptr) {
       L<<Logger::Error<<"Unable to chroot when running from systemd. Please disable chroot= or set the 'Type' for this service to 'simple'"<<endl;
       exit(1);
     }
#endif
     triggerLoadOfLibraries();
     if(::arg().mustDo("master") || ::arg().mustDo("slave"))
        gethostbyname("a.root-servers.net"); // this forces all lookup libraries to be loaded
     Utility::dropGroupPrivs(newuid, newgid);
     if(chroot(::arg()["chroot"].c_str())<0 || chdir("/")<0) {
       L<<Logger::Error<<"Unable to chroot to '"+::arg()["chroot"]+"': "<<strerror(errno)<<", exiting"<<endl; 
       exit(1);
     }   
     else
       L<<Logger::Error<<"Chrooted to '"<<::arg()["chroot"]<<"'"<<endl;      
   } else {
     Utility::dropGroupPrivs(newuid, newgid);
   }

  AuthWebServer webserver;
  Utility::dropUserPrivs(newuid);

  // We need to start the Recursor Proxy before doing secpoll, see issue #2453
  if(::arg().mustDo("resolver")){
    DP=new DNSProxy(::arg()["resolver"]);
    DP->go();
  }

  try {
    doSecPoll(true);
  }
  catch(...) {}

  // NOW SAFE TO CREATE THREADS!
  dl->go();

  pthread_t qtid;

  if(::arg().mustDo("webserver") || ::arg().mustDo("api"))
    webserver.go();

  if(::arg().mustDo("slave") || ::arg().mustDo("master"))
    Communicator.go(); 

  if(!::arg()["experimental-lua-policy-script"].empty()){
    LPE=new AuthLua(::arg()["experimental-lua-policy-script"]);
    L<<Logger::Warning<<"Loaded Lua policy script "<<::arg()["experimental-lua-policy-script"]<<endl;
  }

  if(TN)
    TN->go(); // tcp nameserver launch

  //  fork(); (this worked :-))
  unsigned int max_rthreads= ::arg().asNum("receiver-threads", 1);
  g_distributors.resize(max_rthreads);
  for(unsigned int n=0; n < max_rthreads; ++n)
    pthread_create(&qtid,0,qthread, reinterpret_cast<void *>(n)); // receives packets

  pthread_create(&qtid,0,carbonDumpThread, 0); // runs even w/o carbon, might change @ runtime    

#ifdef HAVE_SYSTEMD
  /* If we are here, notify systemd that we are ay-ok! This might have some
   * timing issues with the backend-threads. e.g. if the initial MySQL connection
   * is slow and times out (leading to process termination through the backend)
   * We probably have told systemd already that we have started correctly.
   */
    sd_notify(0, "READY=1");
#endif

  for(;;) {
    sleep(1800);
    try {
      doSecPoll(false);
    }
    catch(...){}
  }
  
  L<<Logger::Error<<"Mainthread exiting - should never happen"<<endl;
}
