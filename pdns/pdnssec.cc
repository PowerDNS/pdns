#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "statbag.hh"
#include "base32.hh"
#include "base64.hh"
#include <boost/foreach.hpp>
#include <boost/program_options.hpp>
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "arguments.hh"
#include "packetcache.hh"
#include "zoneparser-tng.hh"
#include "signingpipe.hh"
#include <boost/scoped_ptr.hpp>
#include "bindbackend2.hh"

StatBag S;
PacketCache PC;

using boost::scoped_ptr;
namespace po = boost::program_options;
po::variables_map g_vm;

string s_programname="pdns";

namespace {
  bool g_verbose; // doesn't yet do anything though
}

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
  ::arg().set("pipebackend-abi-version","Version of the pipe backend ABI")="1";
  ::arg().set("default-ttl","Seconds a result is valid if not set otherwise")="3600";
  ::arg().set("launch","Which backends to launch");
  ::arg().set("dnssec","if we should do dnssec")="true";
  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")=g_vm["config-name"].as<string>();
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
  ::arg().set("recursive-cache-ttl","Seconds to store packets for recursive queries in the PacketCache")="10";
  ::arg().set("cache-ttl","Seconds to store packets in the PacketCache")="20";              
  ::arg().set("negquery-cache-ttl","Seconds to store negative query results in the QueryCache")="60";
  ::arg().set("query-cache-ttl","Seconds to store query results in the QueryCache")="20";              
  ::arg().set("soa-refresh-default","Default SOA refresh")="10800";
  ::arg().set("soa-retry-default","Default SOA retry")="3600";
  ::arg().set("soa-expire-default","Default SOA expire")="604800";
  ::arg().setSwitch("query-logging","Hint backends that queries should be logged")="no";
  ::arg().set("soa-minimum-ttl","Default SOA minimum ttl")="3600";    
  
  UeberBackend::go();
}

// irritatingly enough, rectifyZone needs its own ueberbackend and can't therefore benefit from transactions outside its scope
// I think this has to do with interlocking transactions between B and DK, but unsure.
void rectifyZone(DNSSECKeeper& dk, const std::string& zone)
{
  scoped_ptr<UeberBackend> B(new UeberBackend("default"));
  bool doTransaction=true; // but see above
  SOAData sd;
  sd.db = (DNSBackend*)-1;
  
  if(!B->getSOA(zone, sd)) {
    cerr<<"No SOA known for '"<<zone<<"', is such a zone in the database?"<<endl;
    return;
  } 
  sd.db->list(zone, sd.domain_id);
  DNSResourceRecord rr;

  set<string> qnames, nsset, dsnames;
  
  while(sd.db->get(rr)) {
    qnames.insert(rr.qname);
    if(rr.qtype.getCode() == QType::NS && !pdns_iequals(rr.qname, zone)) 
      nsset.insert(rr.qname);
    if(rr.qtype.getCode() == QType::DS)
      dsnames.insert(rr.qname);
  }

  NSEC3PARAMRecordContent ns3pr;
  bool narrow;
  bool haveNSEC3=dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
  string hashed;
  if(!haveNSEC3) 
    cerr<<"Adding NSEC ordering information"<<endl;
  else if(!narrow)
    cerr<<"Adding NSEC3 hashed ordering information for '"<<zone<<"'"<<endl;
  else 
    cerr<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields"<<endl;
  
  if(doTransaction)
    sd.db->startTransaction("", -1);
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

    if(dsnames.count(qname))
      auth=true;

    if(haveNSEC3)
    {
      if(!narrow) {
        hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, qname)));
        if(g_verbose)
          cerr<<"'"<<qname<<"' -> '"<< hashed <<"'"<<endl;
      }
      sd.db->updateDNSSECOrderAndAuthAbsolute(sd.domain_id, qname, hashed, auth);
      if(!auth || dsnames.count(qname))
      {
        sd.db->nullifyDNSSECOrderNameAndAuth(sd.domain_id, qname, "NS");
        sd.db->nullifyDNSSECOrderNameAndAuth(sd.domain_id, qname, "A");
        sd.db->nullifyDNSSECOrderNameAndAuth(sd.domain_id, qname, "AAAA");
      }
    }
    else // NSEC
    {
      sd.db->updateDNSSECOrderAndAuth(sd.domain_id, zone, qname, auth);
      if(!auth || dsnames.count(qname))
      {
        sd.db->nullifyDNSSECOrderNameAndAuth(sd.domain_id, qname, "A");
        sd.db->nullifyDNSSECOrderNameAndAuth(sd.domain_id, qname, "AAAA");
      }
    }
  }
  if(doTransaction)
    sd.db->commitTransaction();
}

void rectifyAllZones(DNSSECKeeper &dk) 
{
  scoped_ptr<UeberBackend> B(new UeberBackend("default"));
  vector<DomainInfo> domainInfo;

  B->getAllDomains(&domainInfo);
  BOOST_FOREACH(DomainInfo di, domainInfo) {
    cerr<<"Rectifying "<<di.zone<<": ";
    rectifyZone(dk, di.zone);
  }
  cout<<"Rectified "<<domainInfo.size()<<" zones."<<endl;
}

int checkZone(DNSSECKeeper& dk, const std::string& zone)
{
  scoped_ptr<UeberBackend> B(new UeberBackend("default"));
  SOAData sd;
  sd.db=(DNSBackend*)-1;
  if(!B->getSOA(zone, sd)) {
    cout<<"No SOA for zone '"<<zone<<"'"<<endl;
    return -1;
  } 
  sd.db->list(zone, sd.domain_id);
  DNSResourceRecord rr;
  uint64_t numrecords=0, numerrors=0;
  
  while(sd.db->get(rr)) {
    if(rr.qtype.getCode() == QType::URL || rr.qtype.getCode() == QType::MBOXFW) {
      cout<<"The recordtype "<<rr.qtype.getName()<<" for record '"<<rr.qname<<"' is no longer supported."<<endl;
      numerrors++;
      continue;
    }
      
    if(rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV) 
      rr.content = lexical_cast<string>(rr.priority)+" "+rr.content;

    if(rr.qtype.getCode() == QType::TXT && !rr.content.empty() && rr.content[0]!='"')
      rr.content = "\""+rr.content+"\"";  
      
    if(rr.auth == 0 && rr.qtype.getCode()!=QType::NS && rr.qtype.getCode()!=QType::A && rr.qtype.getCode()!=QType::AAAA)
    {
      cout<<"Following record is auth=0, run pdnssec rectify-zone?: "<<rr.qname<<" IN " <<rr.qtype.getName()<< " " << rr.content<<endl;
      numerrors++;
    }
    try {
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content));
      string tmp=drc->serialize(rr.qname);
    }
    catch(std::exception& e) 
    {
      cout<<"Following record had a problem: "<<rr.qname<<" IN " <<rr.qtype.getName()<< " " << rr.content<<endl;
      cout<<"Error was: "<<e.what()<<endl;
      numerrors++;
    }
    numrecords++;
  }
  cout<<"Checked "<<numrecords<<" records of '"<<zone<<"', "<<numerrors<<" errors"<<endl;
  return numerrors;
}

int checkAllZones(DNSSECKeeper &dk) 
{
  scoped_ptr<UeberBackend> B(new UeberBackend("default"));
  vector<DomainInfo> domainInfo;

  B->getAllDomains(&domainInfo);
  int errors=0;
  BOOST_FOREACH(DomainInfo di, domainInfo) {
    if (checkZone(dk, di.zone) > 0) {
       errors++;
    }
  }
  cout<<"Checked "<<domainInfo.size()<<" zones, "<<errors<<" had errors."<<endl;
  return 0;
}

void testAlgorithm(int algo) 
{
  DNSCryptoKeyEngine::testOne(algo);
}

void testAlgorithms()
{
  DNSCryptoKeyEngine::testAll();
}

void testSpeed(DNSSECKeeper& dk, const string& zone, const string& remote, int cores)
{
  DNSResourceRecord rr;
  rr.qname="blah."+zone;
  rr.qtype=QType::A;
  rr.ttl=3600;
  rr.auth=1;
  rr.qclass = 1;
  rr.d_place=DNSResourceRecord::ANSWER;
  rr.priority=0;
  
  UeberBackend db("key-only");
  
  if ( ! db.backends.size() )
  {
    throw runtime_error("No backends available for DNSSEC key storage");
  }

  ChunkedSigningPipe csp(zone, 1, remote, cores);
  
  vector<DNSResourceRecord> signatures;
  uint32_t rnd;
  unsigned char* octets = (unsigned char*)&rnd;
  char tmp[25];
  DTime dt;
  dt.set();
  for(unsigned int n=0; n < 100000; ++n) {
    rnd = random();
    snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d", 
      octets[0], octets[1], octets[2], octets[3]);
    rr.content=tmp;
    
    snprintf(tmp, sizeof(tmp), "r-%u", rnd);
    rr.qname=string(tmp)+"."+zone;
    
    if(csp.submit(rr))
      while(signatures = csp.getChunk(), !signatures.empty())
        ;
  }
  cerr<<"Flushing the pipe, "<<csp.d_signed<<" signed, "<<csp.d_queued<<" queued, "<<csp.d_outstanding<<" outstanding"<< endl;
  cerr<<"Net speed: "<<csp.d_signed/ (dt.udiffNoReset()/1000000.0) << " sigs/s\n";
  while(signatures = csp.getChunk(true), !signatures.empty())
      ;
  cerr<<"Done, "<<csp.d_signed<<" signed, "<<csp.d_queued<<" queued, "<<csp.d_outstanding<<" outstanding"<< endl;
  cerr<<"Net speed: "<<csp.d_signed/ (dt.udiff()/1000000.0) << " sigs/s\n";
}

void verifyCrypto(const string& zone)
{
  ZoneParserTNG zpt(zone);
  DNSResourceRecord rr;
  DNSKEYRecordContent drc;
  RRSIGRecordContent rrc;
  DSRecordContent dsrc;
  vector<shared_ptr<DNSRecordContent> > toSign;
  unsigned int ttl;
  string qname, apex;
  dsrc.d_digesttype=0;
  while(zpt.get(rr)) {
    if(rr.qtype.getCode() == QType::DNSKEY) {
      cerr<<"got DNSKEY!"<<endl;
      apex=rr.qname;
      drc = *dynamic_cast<DNSKEYRecordContent*>(DNSRecordContent::mastermake(QType::DNSKEY, 1, rr.content));
    }
    else if(rr.qtype.getCode() == QType::RRSIG) {
      cerr<<"got RRSIG"<<endl;
      rrc = *dynamic_cast<RRSIGRecordContent*>(DNSRecordContent::mastermake(QType::RRSIG, 1, rr.content));
    }
    else if(rr.qtype.getCode() == QType::DS) {
      cerr<<"got DS"<<endl;
      dsrc = *dynamic_cast<DSRecordContent*>(DNSRecordContent::mastermake(QType::DS, 1, rr.content));
    }
    else {
      qname = rr.qname;
      ttl = rr.ttl;
      toSign.push_back(shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content)));
    }
  }
  
  string msg = getMessageForRRSET(qname, rrc, toSign);        
  cerr<<"Verify: "<<DNSCryptoKeyEngine::makeFromPublicKeyString(drc.d_algorithm, drc.d_key)->verify(msg, rrc.d_signature)<<endl;
  if(dsrc.d_digesttype) {
    cerr<<"Calculated DS: "<<apex<<" IN DS "<<makeDSFromDNSKey(apex, drc, dsrc.d_digesttype).getZoneRepresentation()<<endl;
    cerr<<"Original DS:   "<<apex<<" IN DS "<<dsrc.getZoneRepresentation()<<endl;
  }
#if 0
  DNSCryptoKeyEngine*key=DNSCryptoKeyEngine::makeFromISCString(drc, "Private-key-format: v1.2\n"
      "Algorithm: 12 (ECC-GOST)\n"
      "GostAsn1: MEUCAQAwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEEIgQg/9MiXtXKg9FDXDN/R9CmVhJDyuzRAIgh4tPwCu4NHIs=\n");
  string resign=key->sign(hash);
  cerr<<Base64Encode(resign)<<endl;
  cerr<<"Verify: "<<DNSCryptoKeyEngine::makeFromPublicKeyString(drc.d_algorithm, drc.d_key)->verify(hash, resign)<<endl;
#endif

}
void disableDNSSECOnZone(DNSSECKeeper& dk, const string& zone)
{
  if(!dk.isSecuredZone(zone)) {
    cerr<<"Zone is not secured\n";
    return;
  }
  DNSSECKeeper::keyset_t keyset=dk.getKeys(zone);

  if(keyset.empty())  {
    cerr << "No keys for zone '"<<zone<<"'."<<endl;
  }
  else {  
    BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, keyset) {
      dk.deactivateKey(zone, value.second.id);
      dk.removeKey(zone, value.second.id);
    }
  }
  dk.unsetNSEC3PARAM(zone);
  dk.unsetPresigned(zone);
}
void showZone(DNSSECKeeper& dk, const std::string& zone)
{
  if(!dk.isSecuredZone(zone)) {
    cerr<<"Zone is not secured\n";
    return;
  }
  NSEC3PARAMRecordContent ns3pr;
  bool narrow;
  bool haveNSEC3=dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
  
  if(!haveNSEC3) 
    cout<<"Zone has NSEC semantics"<<endl;
  else
    cout<<"Zone has " << (narrow ? "NARROW " : "") <<"hashed NSEC3 semantics, configuration: "<<ns3pr.getZoneRepresentation()<<endl;
  
  cout <<"Zone is " << (dk.isPresigned(zone) ? "" : "not ") << "presigned\n";
  
  DNSSECKeeper::keyset_t keyset=dk.getKeys(zone);

  if(keyset.empty())  {
    cerr << "No keys for zone '"<<zone<<"'."<<endl;
  }
  else {  
    cout << "keys: "<<endl;
    BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, keyset) {
      cout<<"ID = "<<value.second.id<<" ("<<(value.second.keyOrZone ? "KSK" : "ZSK")<<"), tag = "<<value.first.getDNSKEY().getTag();
      cout<<", algo = "<<(int)value.first.d_algorithm<<", bits = "<<value.first.getKey()->getBits()<<"\tActive: "<<value.second.active<< endl; 
      if(value.second.keyOrZone) {
        cout<<"KSK DNSKEY = "<<zone<<" IN DNSKEY "<< value.first.getDNSKEY().getZoneRepresentation() << endl;
        cout<<"DS = "<<zone<<" IN DS "<<makeDSFromDNSKey(zone, value.first.getDNSKEY(), 1).getZoneRepresentation() << endl;
        cout<<"DS = "<<zone<<" IN DS "<<makeDSFromDNSKey(zone, value.first.getDNSKEY(), 2).getZoneRepresentation() << endl;
        try {
          string output=makeDSFromDNSKey(zone, value.first.getDNSKEY(), 3).getZoneRepresentation();
          cout<<"DS = "<<zone<<" IN DS "<< output << endl;
        }
        catch(...)
        {
        }
        cout<<endl;  
      }
    }
  }
}

bool secureZone(DNSSECKeeper& dk, const std::string& zone)
{
  if(dk.isSecuredZone(zone)) {
    cerr << "Zone '"<<zone<<"' already secure, remove keys with pdnssec remove-zone-key if needed"<<endl;
    return false;
  }

  if(!dk.secureZone(zone, 8)) {
    cerr<<"No backend was able to secure '"<<zone<<"', most likely because no DNSSEC\n";
    cerr<<"capable backends are loaded, or because the backends have DNSSEC disabled.\n";
    cerr<<"For the Generic SQL backends, set the 'gsqlite3-dnssec', 'gmysql-dnssec' or\n";
    cerr<<"'gpgsql-dnssec' flag. Also make sure the schema has been updated for DNSSEC!\n";
    return false;
  }

  if(!dk.isSecuredZone(zone)) {
    cerr<<"Failed to secure zone. Is your backend dnssec enabled? (set \n";
    cerr<<"gsqlite3-dnssec, or gmysql-dnssec etc). Check this first.\n";
    cerr<<"If you run with the BIND backend, make sure you have configured\n";
    cerr<<"it to use DNSSEC with 'bind-dnssec-db' and 'pdnssec create-bind-db'!\n";
    return false;
  }

  DNSSECKeeper::keyset_t zskset=dk.getKeys(zone, false);

  if(!zskset.empty())  {
    cerr<<"There were ZSKs already for zone '"<<zone<<"', no need to add more"<<endl;
    return false;
  }
    
  dk.addKey(zone, false, 8);
  dk.addKey(zone, false, 8, 0, false); // not active
  // rectifyZone(dk, zone);
  // showZone(dk, zone);
  cout<<"Zone "<<zone<<" secured"<<endl;
  return true;
}

int main(int argc, char** argv)
try
{  
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("verbose,v", "be verbose")
    ("force", "force an action")
    ("config-name", po::value<string>()->default_value(""), "virtual configuration name")
    ("config-dir", po::value<string>()->default_value(SYSCONFDIR), "location of pdns.conf")
    ("commands", po::value<vector<string> >());

  po::positional_options_description p;
  p.add("commands", -1);
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), g_vm);
  po::notify(g_vm);

  vector<string> cmds;

  if(g_vm.count("commands")) 
    cmds = g_vm["commands"].as<vector<string> >();

  g_verbose = g_vm.count("verbose");

  if(cmds.empty() || g_vm.count("help")) {
    cerr<<"Usage: \npdnssec [options] <command> [params ..]\n\n";
    cerr<<"Commands:\n";
    cerr<<"activate-zone-key ZONE KEY-ID      Activate the key with key id KEY-ID in ZONE\n";
    cerr<<"add-zone-key ZONE zsk|ksk [bits]\n";
    cerr<<"             [rsasha1|rsasha256|rsasha512|gost|ecdsa256|ecdsa384]\n";
    cerr<<"                                   Add a ZSK or KSK to zone and specify algo&bits\n";
    cerr<<"check-zone ZONE                    Check a zone for correctness\n";
    cerr<<"check-all-zones                    Check all zones for correctness\n";
    cerr<<"create-bind-db FNAME               Create DNSSEC db for BIND backend (bind-dnssec-db)\n"; 
    cerr<<"deactivate-zone-key ZONE KEY-ID    Deactivate the key with key id KEY-ID in ZONE\n";
    cerr<<"disable-dnssec ZONE                Deactivate all keys and unset PRESIGNED in ZONE\n";
    cerr<<"export-zone-dnskey ZONE KEY-ID     Export to stdout the public DNSKEY described\n";
    cerr<<"export-zone-key ZONE KEY-ID        Export to stdout the private key described\n";
    cerr<<"hash-zone-record ZONE RNAME        Calculate the NSEC3 hash for RNAME in ZONE\n";
    cerr<<"import-zone-key ZONE FILE          Import from a file a private key, ZSK or KSK\n";            
    cerr<<"                [ksk|zsk]          Defaults to KSK\n";
    cerr<<"rectify-zone ZONE [ZONE ..]        Fix up DNSSEC fields (order, auth)\n";
    cerr<<"rectify-all-zones                  Rectify all zones.\n";
    cerr<<"remove-zone-key ZONE KEY-ID        Remove key with KEY-ID from ZONE\n";
    cerr<<"secure-zone ZONE [ZONE ..]         Add KSK and two ZSKs\n";
    cerr<<"set-nsec3 ZONE ['params' [narrow]] Enable NSEC3 with PARAMs. Optionally narrow\n";
    cerr<<"set-presigned ZONE                 Use presigned RRSIGs from storage\n";
    cerr<<"show-zone ZONE                     Show DNSSEC (public) key details about a zone\n";
    cerr<<"unset-nsec3 ZONE                   Switch back to NSEC\n";
    cerr<<"unset-presigned ZONE               No longer use presigned RRSIGs\n\n";
    cerr<<"Options:"<<endl;
    cerr<<desc<<endl;
    return 0;
  }
  
  if (cmds[0] == "test-algorithm") {
    testAlgorithm(lexical_cast<int>(cmds[1]));
    return 0; 
  }

  if(cmds[0] == "test-algorithms") {
    testAlgorithms();
    return 0;
  }

  loadMainConfig(g_vm["config-dir"].as<string>());
  reportAllTypes();
  
  
  if(cmds[0] == "create-bind-db") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec create-bind-db fname"<<endl;
      return 0;
    }
    try {
      Bind2Backend::createDNSSECDB(cmds[1]);
    }
    catch (AhuException& ae) {
      cerr<<"Error: "<<ae.reason<<endl;
      return 1;
    }
    return 0;
  }
  
  DNSSECKeeper dk;

  if(cmds[0] == "rectify-zone") {
    if(cmds.size() < 2) {
      cerr << "Syntax: pdnssec rectify-zone ZONE [ZONE..]"<<endl;
      return 0;
    }
    for(unsigned int n = 1; n < cmds.size(); ++n) 
      rectifyZone(dk, cmds[n]);
  }
  else if (cmds[0] == "rectify-all-zones") {
    rectifyAllZones(dk);
  }
  else if(cmds[0] == "check-zone") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec check-zone ZONE"<<endl;
      return 0;
    }
    exit(checkZone(dk, cmds[1]));
  }
  else if (cmds[0] == "check-all-zones") {
    exit(checkAllZones(dk));
  }
#if 0
  else if(cmds[0] == "signing-server" )
  {
    signingServer();
  }
  else if(cmds[0] == "signing-slave")
  {
    launchSigningService(0);
  }
#endif
  else if(cmds[0] == "test-speed") {
    if(cmds.size() < 2) {
      cerr << "Syntax: pdnssec test-speed numcores [signing-server]"<<endl;
      return 0;
    }
    testSpeed(dk, cmds[1],  (cmds.size() > 3) ? cmds[3] : "", atoi(cmds[2].c_str()));
  }
  else if(cmds[0] == "verify-crypto") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec verify-crypto FILE"<<endl;
      return 0;
    }
    verifyCrypto(cmds[1]);
  }

  else if(cmds[0] == "show-zone") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec show-zone ZONE"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    showZone(dk, zone);
  }
  else if(cmds[0] == "disable-dnssec") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec disable-dnssec ZONE"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    disableDNSSECOnZone(dk, zone);
  }
  else if(cmds[0] == "activate-zone-key") {
    if(cmds.size() != 3) {
      cerr << "Syntax: pdnssec activate-zone-key ZONE KEY-ID"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    if(!id)
    {
      cerr<<"Invalid KEY-ID"<<endl;
      return 1;
    }
    dk.activateKey(zone, id);
  }
  else if(cmds[0] == "deactivate-zone-key") {
    if(cmds.size() != 3) {
      cerr << "Syntax: pdnssec deactivate-zone-key ZONE KEY-ID"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    if(!id)
    {
      cerr<<"Invalid KEY-ID"<<endl;
      return 1;
    }
    dk.deactivateKey(zone, id);
  }
  else if(cmds[0] == "add-zone-key") {
    if(cmds.size() < 3 ) {
      cerr << "Syntax: pdnssec add-zone-key ZONE zsk|ksk [bits] [rsasha1|rsasha256|rsasha512|gost|ecdsa256|ecdsa384]"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    // need to get algorithm, bits & ksk or zsk from commandline
    bool keyOrZone=false;
    int bits=0;
    int algorithm=5;
    for(unsigned int n=2; n < cmds.size(); ++n) {
      if(pdns_iequals(cmds[n], "zsk"))
        keyOrZone = false;
      else if(pdns_iequals(cmds[n], "ksk"))
        keyOrZone = true;
      else if(pdns_iequals(cmds[n], "rsasha1"))
        algorithm=5;
      else if(pdns_iequals(cmds[n], "rsasha256"))
        algorithm=8;
      else if(pdns_iequals(cmds[n], "rsasha512"))
        algorithm=10;
      else if(pdns_iequals(cmds[n], "gost"))
        algorithm=12;
      else if(pdns_iequals(cmds[n], "ecdsa256"))
        algorithm=13;
      else if(pdns_iequals(cmds[n], "ecdsa384"))
        algorithm=14;
      else if(pdns_iequals(cmds[n], "ed25519"))
        algorithm=250;        
      else if(atoi(cmds[n].c_str()))
        bits = atoi(cmds[n].c_str());
      else { 
        cerr<<"Unknown algorithm, key flag or size '"<<cmds[n]<<"'"<<endl;
        return 0;
      }
    }
    cerr<<"Adding a " << (keyOrZone ? "KSK" : "ZSK")<<" with algorithm = "<<algorithm<<endl;
    if(bits)
      cerr<<"Requesting specific key size of "<<bits<<" bits"<<endl;
    dk.addKey(zone, keyOrZone, algorithm, bits, false); 
  }
  else if(cmds[0] == "remove-zone-key") {
    if(cmds.size() < 3) {
      cerr<<"Syntax: pdnssec remove-zone-key ZONE KEY-ID";
      return 0;
    }
    const string& zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    dk.removeKey(zone, id);
  }
  
  else if(cmds[0] == "secure-zone") {
    if(cmds.size() < 2) {
      cerr << "Syntax: pdnssec secure-zone ZONE"<<endl;
      return 0;
    }
    vector<string> mustRectify;
    dk.startTransaction();    
    unsigned int zoneErrors=0;
    for(unsigned int n = 1; n < cmds.size(); ++n) {
      const string& zone=cmds[n];
      if(secureZone(dk, zone)) {
        mustRectify.push_back(zone);
      } else {
        zoneErrors++;
      }
    }
    
    dk.commitTransaction();
    BOOST_FOREACH(string& zone, mustRectify)
      rectifyZone(dk, zone);

    if (zoneErrors) {
      return 1;
    }
    return 0;
  }
  else if(cmds[0]=="set-nsec3") {
    if(cmds.size() < 2) {
      cerr<<"Syntax: pdnssec set-nsec3 ZONE 'params' [narrow]"<<endl;
      return 0;
    }
    string nsec3params =  cmds.size() > 2 ? cmds[2] : "1 1 1 ab";
    bool narrow = cmds.size() > 3 && cmds[3]=="narrow";
    NSEC3PARAMRecordContent ns3pr(nsec3params);
    if(!ns3pr.d_flags) {
      cerr<<"PowerDNS only implements opt-out zones, please set the second parameter to '1' (example, '1 1 1 ab')"<<endl;
      return 0;
    }
    
    dk.setNSEC3PARAM(cmds[1], ns3pr, narrow);
  }
  else if(cmds[0]=="set-presigned") {
    if(cmds.size() < 2) {
      cerr<<"Syntax: pdnssec set-presigned ZONE"<<endl;
      return 0; 
    }
    dk.setPresigned(cmds[1]);
  }
  else if(cmds[0]=="unset-presigned") {
    if(cmds.size() < 2) {
      cerr<<"Syntax: pdnssec unset-presigned ZONE"<<endl;
      return 0;  
    }
    dk.unsetPresigned(cmds[1]);
  }
  else if(cmds[0]=="hash-zone-record") {
    if(cmds.size() < 3) {
      cerr<<"Syntax: pdnssec hash-zone-record ZONE RNAME"<<endl;
      return 0;
    }
    string& zone=cmds[1];
    string& record=cmds[2];
    NSEC3PARAMRecordContent ns3pr;
    bool narrow;
    if(!dk.getNSEC3PARAM(zone, &ns3pr, &narrow)) {
      cerr<<"The '"<<zone<<"' zone does not use NSEC3"<<endl;
      return 0;
    }
    if(narrow) {
      cerr<<"The '"<<zone<<"' zone uses narrow NSEC3, but calculating hash anyhow"<<endl;
    }
      
    cout<<toLower(toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, record)))<<endl;
  }
  else if(cmds[0]=="unset-nsec3") {
    if(cmds.size() < 2) {
      cerr<<"Syntax: pdnssec unset-nsec3 ZONE"<<endl;
      exit(1);
    }
    dk.unsetNSEC3PARAM(cmds[1]);
  }
  else if(cmds[0]=="export-zone-key") {
    if(cmds.size() < 3) {
      cerr<<"Syntax: pdnssec export-zone-key ZONE KEY-ID"<<endl;
      exit(1);
    }

    string zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    DNSSECPrivateKey dpk=dk.getKeyById(zone, id);
    cout << dpk.getKey()->convertToISC() <<endl;
  }  
  else if(cmds[0]=="import-zone-key-pem") {
    if(cmds.size() < 4) {
      cerr<<"Syntax: pdnssec import-zone-key ZONE FILE algorithm [zsk|ksk]"<<endl;
      exit(1);
    }
    string zone=cmds[1];
    string fname=cmds[2];
    string line;
    ifstream ifs(fname.c_str());
    string tmp, interim, raw;
    while(getline(ifs, line)) {
      if(line[0]=='-')
        continue;
      trim(line);
      interim += line;
    }
    B64Decode(interim, raw);
    DNSSECPrivateKey dpk;
    DNSKEYRecordContent drc;
    shared_ptr<DNSCryptoKeyEngine> key(DNSCryptoKeyEngine::makeFromPEMString(drc, raw));
    dpk.setKey(key);
    
    dpk.d_algorithm = atoi(cmds[3].c_str());
    
    if(dpk.d_algorithm == 7)
      dpk.d_algorithm = 5;
      
    cerr<<(int)dpk.d_algorithm<<endl;
    
    if(cmds.size() > 4) {
      if(pdns_iequals(cmds[4], "ZSK"))
        dpk.d_flags = 256;
      else if(pdns_iequals(cmds[4], "KSK"))
        dpk.d_flags = 257;
      else {
        cerr<<"Unknown key flag '"<<cmds[4]<<"'\n";
        exit(1);
      }
    }
    else
      dpk.d_flags = 257; // ksk
      
    dk.addKey(zone, dpk); 
    
  }
  else if(cmds[0]=="import-zone-key") {
    if(cmds.size() < 4) {
      cerr<<"Syntax: pdnssec import-zone-key ZONE FILE [zsk|ksk]"<<endl;
      exit(1);
    }
    string zone=cmds[1];
    string fname=cmds[2];
    DNSSECPrivateKey dpk;
    DNSKEYRecordContent drc;
    shared_ptr<DNSCryptoKeyEngine> key(DNSCryptoKeyEngine::makeFromISCFile(drc, fname.c_str()));
    dpk.setKey(key);
    dpk.d_algorithm = drc.d_algorithm;
    
    if(dpk.d_algorithm == 7)
      dpk.d_algorithm = 5;
      
    cerr<<(int)dpk.d_algorithm<<endl;
    
    if(cmds.size() > 3) {
      if(pdns_iequals(cmds[3], "ZSK"))
        dpk.d_flags = 256;
      else if(pdns_iequals(cmds[3], "KSK"))
        dpk.d_flags = 257;
      else {
        cerr<<"Unknown key flag '"<<cmds[3]<<"'\n";
        exit(1);
      }
    }
    else
      dpk.d_flags = 257; 
      
    dk.addKey(zone, dpk); 
  }
  else if(cmds[0]=="export-zone-dnskey") {
    if(cmds.size() < 3) {
      cerr<<"Syntax: pdnssec export-zone-dnskey ZONE KEY-ID"<<endl;
      exit(1);
    }

    string zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    DNSSECPrivateKey dpk=dk.getKeyById(zone, id);
    cout << zone<<" IN DNSKEY "<<dpk.getDNSKEY().getZoneRepresentation() <<endl;
    if(dpk.d_flags == 257) {
      cout << zone << " IN DS "<<makeDSFromDNSKey(zone, dpk.getDNSKEY(), 1).getZoneRepresentation() << endl;
      cout << zone << " IN DS "<<makeDSFromDNSKey(zone, dpk.getDNSKEY(), 2).getZoneRepresentation() << endl;
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
catch(std::exception& e) {
  cerr<<"Error: "<<e.what()<<endl;
}
