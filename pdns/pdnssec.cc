#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "statbag.hh"
#include "base32.hh"
#include <boost/foreach.hpp>
#include <boost/program_options.hpp>
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "arguments.hh"
#include "packetcache.hh"

StatBag S;
PacketCache PC;

using namespace boost;
namespace po = boost::program_options;
po::variables_map g_vm;

string s_programname="pdns_server";

ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
}


string humanTime(time_t t)
{
  char ret[256];
  struct tm tm;
  localtime_r(&t, &tm);
  strftime(ret, sizeof(ret)-1, "%c", &tm);   // %h:%M %Y-%m-%d
  return ret;
}

void loadMainConfig()
{
   static char pietje[128]="!@@SYSCONFDIR@@:";
  ::arg().set("config-dir","Location of configuration directory (pdns.conf)")=
    strcmp(pietje+1,"@@SYSCONFDIR@@:") ? pietje+strlen("@@SYSCONFDIR@@:")+1 : SYSCONFDIR;
  
  ::arg().set("launch","Which backends to launch");
  
  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  ::arg().setCmd("help","Provide a helpful message");
  //::arg().laxParse(argc,argv);

  if(::arg().mustDo("help")) {
    cerr<<"syntax:"<<endl<<endl;
    cerr<<::arg().helpstring(::arg()["help"])<<endl;
    exit(99);
  }

  if(::arg()["config-name"]!="") 
    s_programname+="-"+::arg()["config-name"];

  string configname=::arg()["config-dir"]+"/"+s_programname+".conf";
  cleanSlashes(configname);

  cerr<<"configname: '"<<configname<<"'\n";
  
  ::arg().laxFile(configname.c_str());


  BackendMakers().launch(::arg()["launch"]); // vrooooom!
  ::arg().laxFile(configname.c_str());    
  cerr<<::arg()["launch"]<<", '" << ::arg()["gmysql-dbname"] <<"'" <<endl;


  S.declare("qsize-q","Number of questions waiting for database attention");
    
  S.declare("deferred-cache-inserts","Amount of cache inserts that were deferred because of maintenance");
  S.declare("deferred-cache-lookup","Amount of cache lookups that were deferred because of maintenance");
          
  S.declare("query-cache-hit","Number of hits on the query cache");
  S.declare("query-cache-miss","Number of misses on the query cache");
  ::arg().set("max-cache-entries", "Maximum number of cache entries")="1000000";
  ::arg().set("recursor","If recursion is desired, IP address of a recursing nameserver")="no"; 
  ::arg().set("recursive-cache-ttl","Seconds to store packets in the PacketCache")="10";
  ::arg().set("cache-ttl","Seconds to store packets in the PacketCache")="20";              
  ::arg().set("negquery-cache-ttl","Seconds to store packets in the PacketCache")="60";
  ::arg().set("query-cache-ttl","Seconds to store packets in the PacketCache")="20";              
  ::arg().set("soa-refresh-default","Default SOA refresh")="10800";
  ::arg().set("soa-retry-default","Default SOA retry")="3600";
  ::arg().set("soa-expire-default","Default SOA expire")="604800";
    ::arg().setSwitch("query-logging","Hint backends that queries should be logged")="no";
  ::arg().set("soa-minimum-ttl","Default SOA mininum ttl")="3600";    
  UeberBackend::go();
}

void orderZone(const std::string& zone)
{
  loadMainConfig();
    
  UeberBackend* B = new UeberBackend("default");
  SOAData sd;
  
  if(!B->getSOA(zone, sd)) {
    cerr<<"No SOA!"<<endl;
    return;
  } 
  cerr<<"ID: "<<sd.domain_id<<endl;
  sd.db->list(zone, sd.domain_id);
  DNSResourceRecord rr;

  set<string> qnames;
  
  while(sd.db->get(rr)) {
  //  cerr<<rr.qname<<endl;
    qnames.insert(rr.qname);
  }
  
  string salt;
  char tmp[]={0xab, 0xcd};
  salt.assign(tmp, 2);
  BOOST_FOREACH(const string& qname, qnames)
  {
    string hashed=toBase32Hex(hashQNameWithSalt(100, salt, qname));
    cerr<<"'"<<qname<<"' -> '"<< hashed <<"'"<<endl;
	sd.db->updateDNSSECOrderAndAuthAbsolute(sd.domain_id, qname, hashed, true);
    // sd.db->updateDNSSECOrderAndAuth(sd.domain_id, zone, qname, true);
  }
  cerr<<"Done listing"<<endl;
}

int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("key-repository,k", po::value<string>()->default_value("./keys"), "Location of keys")
    ("verbose,v", po::value<bool>(), "be verbose")
    ("force", "force an action")
    ("commands", po::value<vector<string> >());

  po::positional_options_description p;
  p.add("commands", -1);
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), g_vm);
  po::notify(g_vm);

  vector<string> cmds;

  if(g_vm.count("commands")) 
    cmds = g_vm["commands"].as<vector<string> >();

  if(cmds.empty() || g_vm.count("help")) {
    cerr<<"Usage: \npdnssec [options] [show-zone] [sign-zone] [update-zone-keys]\n";
    cerr<<desc<<endl;
    return 0;
  }

  DNSSECKeeper dk(g_vm["key-repository"].as<string>());

  if(cmds[0] == "order-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    orderZone(cmds[1]);
  }
  else if(cmds[0] == "update-zone-keys") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }

    const string& zone=cmds[1];
    DNSSECPrivateKey dpk;
    
    if(!dk.haveKSKFor(zone, &dpk)) {
      cerr << "No KSK for zone '"<<zone<<"', can't update the ZSKs"<<endl;
      return 0;
    }
    DNSSECKeeper::zskset_t zskset=dk.getZSKsFor(zone);

    int inforce=0;
    time_t now = time(&now);
    
    
    if(!zskset.empty())  {
      cerr<<"There were ZSKs already for zone '"<<zone<<"': "<<endl;
      
      BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
        cerr<<"Tag = "<<value.first.getDNSKEY().getTag()<<"\tActive: "<<value.second.active<<", "<<humanTime(value.second.beginValidity)<<" - "<<humanTime(value.second.endValidity)<<endl;
        if(value.second.active) 
          inforce++;
        if(value.second.endValidity < now - 2*86400) { // 'expired more than two days ago'  
          cerr<<"\tThis key is no longer used and too old to keep around, deleting!\n";
          dk.deleteZSKFor(zone, value.second.fname);
        } else if(value.second.endValidity < now) { // 'expired more than two days ago'  
          cerr<<"\tThis key is no longer in active use, but needs to linger\n";
        }
      }
    }
      
    if(inforce >= 2) {
      cerr << "Two or more ZSKs were active already, not generating a third" << endl;
      return 0;
    }
    dk.addZSKFor(zone);
    dk.addZSKFor(zone, true); // 'next'

    zskset = dk.getZSKsFor(zone);
    if(zskset.empty()) {
      cerr<<"This should not happen, still no ZSK!"<<endl;
    }

    cerr<<"There are now "<<zskset.size()<<" ZSKs"<<endl;
    BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
      cerr<<"Tag = "<<value.first.getDNSKEY().getTag()<<"\tActive: "<<value.second.active<<endl;
    }

  }
  else if(cmds[0] == "show-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    DNSSECPrivateKey dpk;
    
    if(!dk.haveKSKFor(zone, &dpk)) {
      cerr << "No KSK for zone '"<<zone<<"'."<<endl;
    }
    else {
      cerr<<"KSK present:"<<endl;
      cerr<<"Tag = "<<dpk.getDNSKEY().getTag()<<endl;
      cerr<<"KSK DNSKEY = "<<zone<<" IN DNSKEY "<< dpk.getDNSKEY().getZoneRepresentation() << endl;
      cerr<<"DS = "<<zone<<" IN DS "<<makeDSFromDNSKey(zone, dpk.getDNSKEY()).getZoneRepresentation() << endl << endl;
    }
    
    
    DNSSECKeeper::zskset_t zskset=dk.getZSKsFor(zone);

    if(zskset.empty())  {
      cerr << "No ZSKs for zone '"<<zone<<"'."<<endl;
    }
    else {  
      cerr << "ZSKs for zone '"<<zone<<"':"<<endl;
      BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
        cerr<<"Tag = "<<value.first.getDNSKEY().getTag()<<"\tActive: "<<value.second.active<<", "<< humanTime(value.second.beginValidity)<<" - "<<humanTime(value.second.endValidity)<<endl;
      }
    }
  }
  else if(cmds[0] == "sign-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    DNSSECPrivateKey dpk;
    
    if(dk.haveKSKFor(zone, &dpk) && !g_vm.count("force")) {
      cerr << "There is a key already for zone '"<<zone<<"', use --force to overwrite"<<endl;
      return 0;
    }
      
    dk.addZone(zone);

    if(!dk.haveKSKFor(zone, &dpk)) {
      cerr << "This should not happen, still no key!" << endl;
    }
    cerr<<"Created KSK with tag "<<dpk.getDNSKEY().getTag()<<endl;
  
    DNSSECKeeper::zskset_t zskset=dk.getZSKsFor(zone);

    if(!zskset.empty() && !g_vm.count("force"))  {
      cerr<<"There were ZSKs already for zone '"<<zone<<"'"<<endl;
      return 0;
    }
      
    dk.addZSKFor(zone);
    dk.addZSKFor(zone, true); // 'next'

    zskset = dk.getZSKsFor(zone);
    if(zskset.empty()) {
      cerr<<"This should not happen, still no ZSK!"<<endl;
    }

    cerr<<"There are now "<<zskset.size()<<" ZSKs"<<endl;
    BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
      cerr<<"Tag = "<<value.first.getDNSKEY().getTag()<<"\tActive: "<<value.second.active<<endl;
    }
  }
  else {
    cerr<<"Unknown command '"<<cmds[0]<<"'\n";
    return 1;
  }
  return 0;
}
catch(AhuException& ae) {
  cerr<<"Error: "<<ae.reason<<endl;
}
