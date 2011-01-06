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

string s_programname="pdns";

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

void loadMainConfig(const std::string& configdir)
{
  ::arg().set("config-dir","Location of configuration directory (pdns.conf)")=configdir;
  
  ::arg().set("launch","Which backends to launch");
  ::arg().set("dnssec","if we should do dnssec")="true";
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
  ::arg().set("module-dir","Default directory for modules")=LIBDIR;
  BackendMakers().launch(::arg()["launch"]); // vrooooom!
  ::arg().laxFile(configname.c_str());    
  //cerr<<"Backend: "<<::arg()["launch"]<<", '" << ::arg()["gmysql-dbname"] <<"'" <<endl;

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

void rectifyZone(DNSSECKeeper& dk, const std::string& zone)
{
  UeberBackend* B = new UeberBackend("default");
  SOAData sd;
  
  if(!B->getSOA(zone, sd)) {
    cerr<<"No SOA known for '"<<zone<<"', is such a zone in the database?"<<endl;
    return;
  } 
  sd.db->list(zone, sd.domain_id);
  DNSResourceRecord rr;

  set<string> qnames, nsset;
  
  while(sd.db->get(rr)) {
    qnames.insert(rr.qname);
    if(rr.qtype.getCode() == QType::NS && !pdns_iequals(rr.qname, zone)) 
      nsset.insert(rr.qname);
  }

  NSEC3PARAMRecordContent ns3pr;
  bool narrow;
  dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
  string hashed;
  if(ns3pr.d_salt.empty()) 
    cerr<<"Adding NSEC ordering information"<<endl;
  else if(!narrow)
    cerr<<"Adding NSEC3 hashed ordering information for '"<<zone<<"'"<<endl;
  else 
    cerr<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields"<<endl;
  
  BOOST_FOREACH(const string& qname, qnames)
  {
    string shorter(qname);
    bool auth=true;
    do {
      if(nsset.count(shorter)) {  
        auth=false;
        break;
      }
    }while(chopOff(shorter));

    if(ns3pr.d_salt.empty()) // NSEC
      sd.db->updateDNSSECOrderAndAuth(sd.domain_id, zone, qname, auth);
    else {
      if(!narrow) {
        hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, qname)));
        cerr<<"'"<<qname<<"' -> '"<< hashed <<"'"<<endl;
      }
      sd.db->updateDNSSECOrderAndAuthAbsolute(sd.domain_id, qname, hashed, auth);
    }
  }
  cerr<<"Done listing"<<endl;
}

void checkZone(DNSSECKeeper& dk, const std::string& zone)
{
  reportAllTypes();  
  UeberBackend* B = new UeberBackend("default");
  SOAData sd;
  
  if(!B->getSOA(zone, sd)) {
    cerr<<"No SOA!"<<endl;
    return;
  } 
  cerr<<"ID: "<<sd.domain_id<<endl;
  sd.db->list(zone, sd.domain_id);
  DNSResourceRecord rr;
  uint64_t numrecords=0, numerrors=0;
  
  while(sd.db->get(rr)) {
    if(rr.qtype.getCode() == QType::MX) 
      rr.content = lexical_cast<string>(rr.priority)+" "+rr.content;
      
    try {
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content));
      string tmp=drc->serialize(rr.qname);
    }
    catch(std::exception& e) 
    {
      cerr<<"Following record had a problem: "<<rr.qname<<" IN " <<rr.qtype.getName()<< " " << rr.content<<endl;
      cerr<<"Error was: "<<e.what()<<endl;
      numerrors++;
    }
    numrecords++;
  }
  cerr<<"Checked "<<numrecords<<" records, "<<numerrors<<" errors"<<endl;
}


int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("verbose,v", po::value<bool>(), "be verbose")
    ("force", "force an action")
    ("config-dir", po::value<string>()->default_value(SYSCONFDIR), "location of pdns.conf")
    ("commands", po::value<vector<string> >());

  po::positional_options_description p;
  p.add("commands", -1);
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), g_vm);
  po::notify(g_vm);

  vector<string> cmds;

  if(g_vm.count("commands")) 
    cmds = g_vm["commands"].as<vector<string> >();

  if(cmds.empty() || g_vm.count("help")) {
    cerr<<"Usage: \npdnssec [options] [show-zone] [secure-zone] [rectify-zone] [add-zone-key] [deactivate-zone-key] [remove-zone-key] [activate-zone-key]\n";
    cerr<<"         [import-zone-key] [export-zone-key] [set-nsec3] [unset-nsec3] [export-zone-dnskey]\n\n";
    cerr<<"activate-zone-key ZONE KEY-ID   Activate the key with key id KEY-ID in ZONE\n";
    cerr<<"add-zone-key ZONE [zsk|ksk]     Add a ZSK or KSK to a zone (ZSK only now)\n";
    cerr<<"deactivate-zone-key             Dectivate the key with key id KEY-ID in ZONE\n";
    cerr<<"export-zone-dnskey ZONE KEY-ID  Export to stdout the public DNSKEY described\n";
    cerr<<"export-zone-key ZONE KEY-ID     Export to stdout the private key described\n";
    cerr<<"import-zone-key ZONE FILE       Import from a file a private KSK\n";            
    cerr<<"rectify-zone ZONE               Fix up DNSSEC fields (order, auth)\n";
    cerr<<"remove-zone-key ZONE KEY-ID     Remove key with KEY-ID from ZONE\n";
    cerr<<"secure-zone                     Add KSK and two ZSKs\n";
    cerr<<"set-nsec3 'params' [narrow]     Enable NSEC3 with PARAMs. Optionally narrow\n";
    cerr<<"show-zone ZONE                  Show DNSSEC (public) key details about a zone\n";
    cerr<<"unset-nsec3 ZONE                Switch back to NSEC\n\n";

    cerr<<"Options:"<<endl;
    cerr<<desc<<endl;
    return 0;
  }
  
  loadMainConfig(g_vm["config-dir"].as<string>());
  reportAllTypes();
  DNSSECKeeper dk;

  if(cmds[0] == "rectify-zone" || cmds[0] == "order-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    rectifyZone(dk, cmds[1]);
  }
  else if(cmds[0] == "check-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    checkZone(dk, cmds[1]);
  }

  else if(cmds[0] == "show-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    const string& zone=cmds[1];

    NSEC3PARAMRecordContent ns3pr;
    bool narrow;
    dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
    
    if(ns3pr.d_salt.empty()) 
      cerr<<"Zone has NSEC semantics"<<endl;
    else
      cerr<<"Zone has " << (narrow ? "NARROW " : "") <<"hashed NSEC3 semantics, configuration: "<<ns3pr.getZoneRepresentation()<<endl;
    
    DNSSECKeeper::keyset_t keyset=dk.getKeys(zone);

    if(keyset.empty())  {
      cerr << "No keys for zone '"<<zone<<"'."<<endl;
    }
    else {  
      cout << "keys: "<<endl;
      BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, keyset) {
        cout<<"ID = "<<value.second.id<<" ("<<(value.second.keyOrZone ? "KSK" : "ZSK")<<"), tag = "<<value.first.getDNSKEY().getTag();
        cout<<", algo = "<<(int)value.first.d_algorithm<<", bits = "<<value.first.d_key.getConstContext().len*8<<"\tActive: "<<value.second.active<< endl; // humanTime(value.second.beginValidity)<<" - "<<humanTime(value.second.endValidity)<<endl;
        if(value.second.keyOrZone) {
          cout<<"KSK DNSKEY = "<<zone<<" IN DNSKEY "<< value.first.getDNSKEY().getZoneRepresentation() << endl;
          cout<<"DS = "<<zone<<" IN DS "<<makeDSFromDNSKey(zone, value.first.getDNSKEY()).getZoneRepresentation() << endl << endl;
        }
      }
    }
  }
  else if(cmds[0] == "activate-zone-key") {
    const string& zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    dk.activateKey(zone, id);
  }
  else if(cmds[0] == "deactivate-zone-key") {
    const string& zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    dk.deactivateKey(zone, id);
  }
  else if(cmds[0] == "add-zone-key") {
    const string& zone=cmds[1];
    // need to get algorithm & ksk or zsk from commandline
    cerr<<"Adding a ZSK"<<endl;
    dk.addKey(zone, 0, 5, 0); 
  }
  else if(cmds[0] == "remove-zone-key") {
    const string& zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    dk.removeKey(zone, id);
  }
  
  else if(cmds[0] == "secure-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    DNSSECPrivateKey dpk;
    
    if(dk.haveActiveKSKFor(zone, &dpk) && !g_vm.count("force")) {
      cerr << "There is a key already for zone '"<<zone<<"', use --force to overwrite"<<endl;
      return 0;
    }
      
    dk.secureZone(zone, 5);

    if(!dk.haveActiveKSKFor(zone, &dpk)) {
      cerr << "This should not happen, still no key!" << endl;
      return 0;
    }
    cout<<"Created KSK with tag "<<dpk.getDNSKEY().getTag()<<endl;
  
    DNSSECKeeper::keyset_t zskset=dk.getKeys(zone, false);

    if(!zskset.empty() && !g_vm.count("force"))  {
      cerr<<"There were ZSKs already for zone '"<<zone<<"'"<<endl;
      return 0;
    }
      
    dk.addKey(zone, false, 5);
    dk.addKey(zone, false, 5, 0, false); // not active

    zskset = dk.getKeys(zone, false);
    if(zskset.empty()) {
      cerr<<"This should not happen, still no ZSK!"<<endl;
    }

    cout<<"There are now "<<zskset.size()<<" ZSKs"<<endl;
    BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, zskset) {
      cout<<"id = "<<value.second.id<<", tag = "<<value.first.getDNSKEY().getTag()<<", algo = "<<(int)value.first.d_algorithm<<
        ", bits = "<<value.first.d_key.getContext().len*8;
      cout<<"\tActive: "<<value.second.active<<endl;
    }
  }
  else if(cmds[0]=="set-nsec3") {
    string nsec3params =  cmds.size() > 2 ? cmds[2] : "1 0 1 ab";
    bool narrow = cmds.size() > 3 && cmds[3]=="narrow";
    NSEC3PARAMRecordContent ns3pr(nsec3params);
    dk.setNSEC3PARAM(cmds[1], ns3pr, narrow);
  }
  else if(cmds[0]=="unset-nsec3") {
    dk.unsetNSEC3PARAM(cmds[1]);
  }
  else if(cmds[0]=="export-zone-key") {
    string zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    DNSSECPrivateKey dpk=dk.getKeyById(zone, id);
    cout << dpk.d_key.convertToISC(dpk.d_algorithm) <<endl;
  }  
  else if(cmds[0]=="import-zone-key") {
    if(cmds.size()!=3) {
      cerr<<"Syntax: pdnssec import-zone-key zone-name filename"<<endl;
      exit(1);
    }
    string zone=cmds[1];
    string fname=cmds[2];
    DNSSECPrivateKey dpk;
    getRSAKeyFromISC(&dpk.d_key.getContext(), fname.c_str());
    dpk.d_algorithm = 5;
    dpk.d_flags = 257;
    dk.addKey(zone, true, dpk); // add a KSK
  }
  else if(cmds[0]=="export-zone-dnskey") {
    string zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    DNSSECPrivateKey dpk=dk.getKeyById(zone, id);
    cout << zone<<" IN DNSKEY "<<dpk.getDNSKEY().getZoneRepresentation() <<endl;
    if(dpk.d_flags == 257)
      cout << zone << " IN DS "<<makeDSFromDNSKey(zone, dpk.getDNSKEY()).getZoneRepresentation() << endl;
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
