#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "iputils.hh"
#include "qtype.hh"
#include <boost/smart_ptr/make_shared_array.hpp>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <csignal>
#include <sys/wait.h>

#include "credentials.hh"
#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "statbag.hh"
#include "base32.hh"
#include "base64.hh"
#include "dns.hh"

#include <boost/program_options.hpp>
#include <boost/assign/std/vector.hpp>
#include <boost/assign/list_of.hpp>
#include "json11.hpp"
#include "tsigutils.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "arguments.hh"
#include "auth-packetcache.hh"
#include "auth-querycache.hh"
#include "auth-zonecache.hh"
#include "zoneparser-tng.hh"
#include "signingpipe.hh"
#include "dns_random.hh"
#include "ipcipher.hh"
#include "misc.hh"
#include "zonemd.hh"
#include <fstream>
#include <utility>
#include <cerrno>
#include <sys/stat.h>
#include <termios.h>            //termios, TCSANOW, ECHO, ICANON
#include "opensslsigners.hh"
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif
#ifdef HAVE_SQLITE3
#include "ssqlite3.hh"
#include "bind-dnssec.schema.sqlite3.sql.h"
#endif

StatBag S;
AuthPacketCache PC;
AuthQueryCache QC;
AuthZoneCache g_zoneCache;
uint16_t g_maxNSEC3Iterations{0};

namespace po = boost::program_options;
po::variables_map g_vm;

string g_programname="pdns";

namespace {
  bool g_force;
  bool g_quiet;
  bool g_verbose;
}

ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
}

static std::string comboAddressVecToString(const std::vector<ComboAddress>& vec) {
  vector<string> strs;
  strs.reserve(vec.size());
  for (const auto& ca : vec) {
    strs.push_back(ca.toStringWithPortExcept(53));
  }
  return boost::join(strs, ",");
}

static void loadMainConfig(const std::string& configdir)
{
  ::arg().set("config-dir","Location of configuration directory (pdns.conf)")=configdir;
  ::arg().set("default-ttl","Seconds a result is valid if not set otherwise")="3600";
  ::arg().set("launch","Which backends to launch");
  ::arg().set("dnssec","if we should do dnssec")="true";
  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")=g_vm["config-name"].as<string>();
  ::arg().setCmd("help","Provide a helpful message");
  ::arg().set("load-modules","Load this module - supply absolute or relative path")="";
  //::arg().laxParse(argc,argv);

  if(::arg().mustDo("help")) {
    cout<<"syntax:"<<endl<<endl;
    cout<<::arg().helpstring(::arg()["help"])<<endl;
    exit(0);
  }

  if(!::arg()["config-name"].empty())
    g_programname+="-"+::arg()["config-name"];

  string configname=::arg()["config-dir"]+"/"+g_programname+".conf";
  cleanSlashes(configname);

  ::arg().set("resolver","Use this resolver for ALIAS and the internal stub resolver")="no";
  ::arg().set("default-ksk-algorithm","Default KSK algorithm")="ecdsa256";
  ::arg().set("default-ksk-size","Default KSK size (0 means default)")="0";
  ::arg().set("default-zsk-algorithm","Default ZSK algorithm")="";
  ::arg().set("default-zsk-size","Default ZSK size (0 means default)")="0";
  ::arg().set("default-soa-edit","Default SOA-EDIT value")="";
  ::arg().set("default-soa-edit-signed","Default SOA-EDIT value for signed zones")="";
  ::arg().set("max-ent-entries", "Maximum number of empty non-terminals in a zone")="100000";
  ::arg().set("module-dir","Default directory for modules")=PKGLIBDIR;
  ::arg().set("entropy-source", "If set, read entropy from this file")="/dev/urandom";
  ::arg().setSwitch("query-logging","Hint backends that queries should be logged")="no";
  ::arg().set("loglevel","Amount of logging. Higher is more.")="3";
  ::arg().setSwitch("direct-dnskey","Fetch DNSKEY, CDS and CDNSKEY RRs from backend during DNSKEY or CDS/CDNSKEY synthesis")="no";
  ::arg().set("max-nsec3-iterations","Limit the number of NSEC3 hash iterations")="500"; // RFC5155 10.3
  ::arg().set("max-signature-cache-entries", "Maximum number of signatures cache entries")="";
  ::arg().set("rng", "Specify random number generator to use. Valid values are auto,sodium,openssl,getrandom,arc4random,urandom.")="auto";
  ::arg().set("max-generate-steps", "Maximum number of $GENERATE steps when loading a zone from a file")="0";
  ::arg().set("max-include-depth", "Maximum nested $INCLUDE depth when loading a zone from a file")="20";
  ::arg().setSwitch("upgrade-unknown-types","Transparently upgrade known TYPExxx records. Recommended to keep off, except for PowerDNS upgrades until data sources are cleaned up")="no";
  ::arg().setSwitch("views", "Enable views (variants) of zones, for backends which support them") = "no";
  ::arg().laxFile(configname);

  if(!::arg()["load-modules"].empty()) {
    vector<string> modules;

    stringtok(modules,::arg()["load-modules"], ", ");
    if (!UeberBackend::loadModules(modules, ::arg()["module-dir"])) {
      exit(1);
    }
  }

  g_log.toConsole(Logger::Error);   // so we print any errors
  BackendMakers().launch(::arg()["launch"]); // vrooooom!
  if(::arg().asNum("loglevel") >= 3) // so you can't kill our errors
    g_log.toConsole((Logger::Urgency)::arg().asNum("loglevel"));

  //cerr<<"Backend: "<<::arg()["launch"]<<", '" << ::arg()["gmysql-dbname"] <<"'" <<endl;

  S.declare("qsize-q","Number of questions waiting for database attention");

  ::arg().set("max-cache-entries", "Maximum number of cache entries")="1000000";
  ::arg().set("cache-ttl","Seconds to store packets in the PacketCache")="20";
  ::arg().set("negquery-cache-ttl","Seconds to store negative query results in the QueryCache")="60";
  ::arg().set("query-cache-ttl","Seconds to store query results in the QueryCache")="20";
  ::arg().set("default-soa-content","Default SOA content")="a.misconfigured.dns.server.invalid hostmaster.@ 0 10800 3600 604800 3600";
  ::arg().set("chroot","Switch to this chroot jail")="";
  ::arg().set("dnssec-key-cache-ttl","Seconds to cache DNSSEC keys from the database")="30";
  ::arg().set("domain-metadata-cache-ttl", "Seconds to cache zone metadata from the database") = "0";
  ::arg().set("zone-metadata-cache-ttl", "Seconds to cache zone metadata from the database") = "60";
  ::arg().set("consistent-backends", "Assume individual zones are not divided over backends. Send only ANY lookup operations to the backend to reduce the number of lookups") = "yes";


  // Keep this line below all ::arg().set() statements
  if (! ::arg().laxFile(configname)) {
    cerr<<"Warning: unable to read configuration file '"<<configname<<"': "<<stringerror()<<endl;
  }

#ifdef HAVE_LIBSODIUM
  if (sodium_init() == -1) {
    cerr<<"Unable to initialize sodium crypto library"<<endl;
    exit(99);
  }
#endif
  openssl_seed();

  if (!::arg()["chroot"].empty()) {
    if (chroot(::arg()["chroot"].c_str())<0 || chdir("/") < 0) {
      cerr<<"Unable to chroot to '"+::arg()["chroot"]+"': "<<strerror (errno)<<endl;
      exit(1);
    }
  }

  UeberBackend::go();
}

// This is a wrapper around UeberBackend, in order to be able to perform
// a file creation check at destructor time.
class UtilBackend : public UeberBackend
{
public:
  UtilBackend(const string& pname = "default"): UeberBackend(pname) {}
  UtilBackend(const UtilBackend &) = delete;
  UtilBackend(UtilBackend &&) = delete;
  UtilBackend& operator=(const UtilBackend&) = delete;
  UtilBackend& operator=(UtilBackend&&) = delete;
  ~UtilBackend();
};

UtilBackend::~UtilBackend()
{
  if (!g_quiet && hasCreatedLocalFiles()) {
    cout<<"WARNING: local files have been created as a result of this operation."<<endl
        <<"Be sure to check the files owner, group and permission to make sure that"<<endl
        <<"the authoritative server can correctly use them."<<endl;
  }
}

static int usage(const std::string_view synopsis)
{
  cerr << "Usage:" << endl;
  cerr << "pdnsutil " << synopsis << endl;
  return EXIT_FAILURE;
}

static bool rectifyZone(DNSSECKeeper& dsk, const ZoneName& zone, bool quiet = false, bool rectifyTransaction = true)
{
  string output;
  string error;
  bool ret = dsk.rectifyZone(zone, error, output, rectifyTransaction);
  if (!quiet || !ret) {
    // When quiet, only print output if there was an error
    if (!output.empty()) {
      cerr<<output<<endl;
    }
    if (!ret && !error.empty()) {
      cerr<<error<<endl;
    }
  }
  return ret;
}

static void dbBench(const std::string& fname)
{
  ::arg().set("query-cache-ttl")="0";
  ::arg().set("negquery-cache-ttl")="0";
  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  vector<string> domains;
  if(!fname.empty()) {
    ifstream ifs(fname.c_str());
    if(!ifs) {
      cerr << "Could not open '" << fname << "' for reading zone names to query" << endl;
    }
    string line;
    while(getline(ifs,line)) {
      boost::trim(line);
      domains.push_back(line);
    }
  }
  if(domains.empty())
    domains.emplace_back("powerdns.com");

  int n=0;
  DNSZoneRecord rr;
  DTime dt;
  dt.set();
  unsigned int hits=0, misses=0;
  for(; n < 10000; ++n) {
    DNSName domain(domains[dns_random(domains.size())]);
    // Safe to pass UnknownDomainID here
    B.lookup(QType(QType::NS), domain, UnknownDomainID);
    while(B.get(rr)) {
      hits++;
    }
    // Safe to pass UnknownDomainID here
    B.lookup(QType(QType::A), DNSName(std::to_string(dns_random_uint32()))+domain, UnknownDomainID);
    while(B.get(rr)) {
    }
    misses++;

  }
  cout<<0.001*dt.udiff()/n<<" millisecond/lookup"<<endl;
  cout<<"Retrieved "<<hits<<" records, did "<<misses<<" queries which should have no match"<<endl;
  cout<<"Packet cache reports: "<<S.read("query-cache-hit")<<" hits (should be 0) and "<<S.read("query-cache-miss") <<" misses"<<endl;
}

static bool rectifyAllZones(DNSSECKeeper &dk, bool quiet = false)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  vector<DomainInfo> domainInfo;
  bool result = true;

  B.getAllDomains(&domainInfo, false, false);
  for(const DomainInfo& di :  domainInfo) {
    if (!quiet) {
      cerr<<"Rectifying "<<di.zone<<": ";
    }
    if (!rectifyZone(dk, di.zone, quiet)) {
      result = false;
    }
  }
  if (!quiet) {
    cout<<"Rectified "<<domainInfo.size()<<" zones."<<endl;
  }
  return result;
}

static int checkZone(DNSSECKeeper &dk, UeberBackend &B, const ZoneName& zone, const vector<DNSResourceRecord>* suppliedrecords=nullptr) // NOLINT(readability-function-cognitive-complexity,readability-identifier-length)
{
  int numerrors=0;
  int numwarnings=0;

  DomainInfo di;
  try {
    if (!B.getDomainInfo(zone, di, false)) {
      cout << "[Error] Unable to get zone information for zone '" << zone << "'" << endl;
      return 1;
    }
  } catch(const PDNSException &e) {
    if (di.kind == DomainInfo::Secondary) {
      cout << "[Error] non-IP address for primaries: " << e.reason << endl;
      numerrors++;
    }
  }

  if (suppliedrecords == nullptr && (di.backend->getCapabilities() & DNSBackend::CAP_LIST) == 0) {
    cout << "Backend for zone '" << zone << "' does not support listing its contents." << endl;
    return 1;
  }

  SOAData sd;
  try {
    if (!B.getSOAUncached(zone, sd)) {
      cout << "[Error] No SOA record present, or active, in zone '" << zone << "'" << endl;
      numerrors++;
      cout << "Checked 0 records of '" << zone << "', " << numerrors << " errors, 0 warnings." << endl;
      return 1;
    }
  }
  catch (const PDNSException& e) {
    cout << "[Error] SOA lookup failed for zone '" << zone << "': " << e.reason << endl;
    numerrors++;
    if (sd.db == nullptr) {
      return 1;
    }
  }
  catch (const std::exception& e) {
    cout << "[Error] SOA lookup failed for zone '" << zone << "': " << e.what() << endl;
    numerrors++;
    if (sd.db == nullptr) {
      return 1;
    }
  }

  NSEC3PARAMRecordContent ns3pr;
  bool narrow = false;
  bool haveNSEC3 = dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
  bool isOptOut=(haveNSEC3 && ns3pr.d_flags != 0);

  bool isSecure=dk.isSecuredZone(zone);
  bool presigned=dk.isPresigned(zone);
  vector<string> checkKeyErrors;
  bool validKeys=dk.checkKeys(zone, checkKeyErrors);

  if (haveNSEC3) {
    auto wirelength = zone.operator const DNSName&().wirelength();
    if(isSecure && wirelength > 222) {
      numerrors++;
      cout<<"[Error] zone '" << zone << "' has NSEC3 semantics but is too long to have the hash prepended. Zone name is " << wirelength << " bytes long, whereas the maximum is 222 bytes." << endl;
    }

    vector<DNSBackend::KeyData> dbkeyset;
    B.getDomainKeys(zone, dbkeyset);

    for (DNSBackend::KeyData& kd : dbkeyset) {
      DNSKEYRecordContent dkrc;
      DNSCryptoKeyEngine::makeFromISCString(dkrc, kd.content);

      if(dkrc.d_algorithm == DNSSECKeeper::RSASHA1) {
        cout<<"[Error] zone '"<<zone<<"' has NSEC3 semantics, but the "<< (kd.active ? "" : "in" ) <<"active key with id "<<kd.id<<" has 'Algorithm: 5'. This should be corrected to 'Algorithm: 7' in the database (or NSEC3 should be disabled)."<<endl;
        numerrors++;
      }
    }
  }

  if (!validKeys) {
    numerrors++;
    cout<<"[Error] zone '" << zone << "' has at least one invalid DNS Private Key." << endl;
    for (const auto &msg : checkKeyErrors) {
      cout<<"\t"<<msg<<endl;
    }
  }

  // Check for delegation in parent zone
  ZoneName parent(zone);
  while(parent.chopOff()) {
    SOAData sd_p;
    if(B.getSOAUncached(parent, sd_p)) {
      bool ns=false;
      DNSZoneRecord zr;
      B.lookup(QType(QType::ANY), zone.operator const DNSName&(), sd_p.domain_id);
      while(B.get(zr))
        ns |= (zr.dr.d_type == QType::NS);
      if (!ns) {
        cout<<"[Error] No delegation for zone '"<<zone<<"' in parent '"<<parent<<"'"<<endl;
        numerrors++;
      }
      break;
    }
  }


  bool hasNsAtApex = false;
  set<DNSName> tlsas, cnames, noncnames, glue, checkglue, addresses, svcbAliases, httpsAliases, svcbRecords, httpsRecords, arecords, aaaarecords;
  vector<DNSResourceRecord> checkCNAME;
  set<pair<DNSName, QType> > checkOcclusion;
  set<string> recordcontents;
  map<string, unsigned int> ttl;
  // Record name, prio, target name, ipv4hint=auto, ipv6hint=auto
  set<std::tuple<DNSName, uint16_t, DNSName, bool, bool> > svcbTargets, httpsTargets;

  ostringstream content;
  pair<map<string, unsigned int>::iterator,bool> ret;

  vector<DNSResourceRecord> records;
  if(suppliedrecords == nullptr) {
    DNSResourceRecord drr;
    sd.db->list(zone, sd.domain_id, g_verbose);
    while(sd.db->get(drr)) {
      records.push_back(drr);
    }
  }
  else
    records=*suppliedrecords;

  for(auto &rr : records) { // we modify this
    if(rr.qtype.getCode() == QType::TLSA)
      tlsas.insert(rr.qname);
    if(rr.qtype.getCode() == QType::A || rr.qtype.getCode() == QType::AAAA) {
      addresses.insert(rr.qname);
    }
#ifdef HAVE_LUA_RECORDS
    if(rr.qtype.getCode() == QType::LUA) {
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(rr.qtype.getCode(), QClass::IN, rr.content));
      auto luarec = std::dynamic_pointer_cast<LUARecordContent>(drc);
      QType qtype = luarec->d_type;
      if(qtype == QType::A || qtype == QType::AAAA) {
        addresses.insert(rr.qname);
      }
    }
#endif
    if(rr.qtype.getCode() == QType::A) {
      arecords.insert(rr.qname);
    }
    if(rr.qtype.getCode() == QType::AAAA) {
      aaaarecords.insert(rr.qname);
    }
    if(rr.qtype.getCode() == QType::SOA) {
      vector<string>parts;
      stringtok(parts, rr.content);

      if(parts.size() < 7) {
        cout << "[Info] SOA autocomplete is deprecated, missing field(s) in SOA content: " << rr.qname << " IN " << rr.qtype.toString() << " '" << rr.content << "'" << endl;
      }

      if(parts.size() >= 2) {
        if(parts[1].find('@') != string::npos) {
          cout<<"[Warning] Found @-sign in SOA RNAME, should probably be a dot (.): "<<rr.qname<<" IN " <<rr.qtype.toString()<< " '" << rr.content<<"'"<<endl;
          numwarnings++;
        }
      }

      ostringstream o;
      o<<rr.content;
      for(auto pleft=parts.size(); pleft < 7; ++pleft) {
        o<<" 0";
      }
      rr.content=o.str();
    }

    if(rr.qtype.getCode() == QType::TXT && !rr.content.empty() && rr.content[0]!='"')
      rr.content = "\""+rr.content+"\"";

    try {
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(rr.qtype.getCode(), QClass::IN, rr.content));
      string tmp=drc->serialize(rr.qname);
      tmp = drc->getZoneRepresentation(true);
      if (rr.qtype.getCode() != QType::AAAA) {
        if (!pdns_iequals(tmp, rr.content)) {
          if(rr.qtype.getCode() == QType::SOA) {
            tmp = drc->getZoneRepresentation(false);
          }
          if(!pdns_iequals(tmp, rr.content)) {
            cout<<"[Warning] Parsed and original record content are not equal: "<<rr.qname<<" IN " <<rr.qtype.toString()<< " '" << rr.content<<"' (Content parsed as '"<<tmp<<"')"<<endl;
            numwarnings++;
          }
        }
      } else {
        struct in6_addr tmpbuf;
        if (inet_pton(AF_INET6, rr.content.c_str(), &tmpbuf) != 1) {
          cout<<"[Warning] Following record is not a valid IPv6 address: "<<rr.qname<<" IN " <<rr.qtype.toString()<< " '" << rr.content<<"'"<<endl;
          numwarnings++;
        }
      }
    }
    catch(std::exception& e)
    {
      cout<<"[Error] Following record had a problem: \""<<rr.qname<<" IN "<<rr.qtype.toString()<<" "<<rr.content<<"\""<<endl;
      cout<<"[Error] Error was: "<<e.what()<<endl;
      numerrors++;
      continue;
    }

    if(!rr.qname.isPartOf(zone)) {
      cout<<"[Error] Record '"<<rr.qname<<" IN "<<rr.qtype.toString()<<" "<<rr.content<<"' in zone '"<<zone<<"' is out-of-zone."<<endl;
      numerrors++;
      continue;
    }

    if (rr.qtype.getCode() == QType::SVCB || rr.qtype.getCode() == QType::HTTPS) {
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(rr.qtype.getCode(), QClass::IN, rr.content));
      // I, too, like to live dangerously
      auto svcbrc = std::dynamic_pointer_cast<SVCBBaseRecordContent>(drc);
      if (svcbrc->getPriority() == 0 && svcbrc->hasParams()) {
        cout<<"[Warning] Aliasform "<<rr.qtype.toString()<<" record "<<rr.qname<<" has service parameters."<<endl;
        numwarnings++;
      }

      if(svcbrc->getPriority() != 0) {
        // Service Form
        if (svcbrc->hasParam(SvcParam::no_default_alpn) && !svcbrc->hasParam(SvcParam::alpn)) {
          /* draft-ietf-dnsop-svcb-https-03 section 6.1
           *  When "no-default-alpn" is specified in an RR, "alpn" must
           *  also be specified in order for the RR to be "self-consistent
           *  (Section 2.4.3).
           */
          cout<<"[Warning] "<<rr.qname<<"|"<<rr.qtype.toString()<<" is not self-consistent: 'no-default-alpn' parameter without 'alpn' parameter"<<endl;
          numwarnings++;
        }
        if (svcbrc->hasParam(SvcParam::mandatory)) {
          auto keys = svcbrc->getParam(SvcParam::mandatory).getMandatory();
          for (auto const &k: keys) {
            if (!svcbrc->hasParam(k)) {
              cout<<"[Warning] "<<rr.qname<<"|"<<rr.qtype.toString()<<" is not self-consistent: 'mandatory' parameter lists '"+ SvcParam::keyToString(k) +"', but that parameter does not exist"<<endl;
              numwarnings++;
            }
          }
        }
      }

      switch (rr.qtype.getCode()) {
      case QType::SVCB:
        if (svcbrc->getPriority() == 0) {
          if (svcbAliases.find(rr.qname) != svcbAliases.end()) {
            cout << "[Warning] More than one Alias form SVCB record for " << rr.qname << " exists." << endl;
            numwarnings++;
          }
          svcbAliases.insert(rr.qname);
        }
        svcbTargets.emplace(rr.qname, svcbrc->getPriority(), svcbrc->getTarget(), svcbrc->autoHint(SvcParam::ipv4hint), svcbrc->autoHint(SvcParam::ipv6hint));
        svcbRecords.insert(rr.qname);
        break;
      case QType::HTTPS:
        if (svcbrc->getPriority() == 0) {
          if (httpsAliases.find(rr.qname) != httpsAliases.end()) {
            cout << "[Warning] More than one Alias form HTTPS record for " << rr.qname << " exists." << endl;
            numwarnings++;
          }
          httpsAliases.insert(rr.qname);
        }
        httpsTargets.emplace(rr.qname, svcbrc->getPriority(), svcbrc->getTarget(), svcbrc->autoHint(SvcParam::ipv4hint), svcbrc->autoHint(SvcParam::ipv6hint));
        httpsRecords.insert(rr.qname);
        break;
      }
    }

    content.str("");
    content<<rr.qname<<" "<<rr.qtype.toString()<<" "<<rr.content;
    string contentstr = content.str();
    if (rr.qtype.getCode() != QType::TXT) {
      contentstr=toLower(contentstr);
    }
    if (recordcontents.count(contentstr) != 0) {
      cout<<"[Error] Duplicate record found in rrset: '"<<rr.qname<<" IN "<<rr.qtype.toString()<<" "<<rr.content<<"'"<<endl;
      numerrors++;
      continue;
    }
    recordcontents.insert(std::move(contentstr));

    content.str("");
    content<<rr.qname<<" "<<rr.qtype.toString();
    if (rr.qtype.getCode() == QType::RRSIG) {
      RRSIGRecordContent rrc(rr.content);
      content<<" ("<<DNSRecordContent::NumberToType(rrc.d_type)<<")";
    }
    ret = ttl.insert(pair<string, unsigned int>(toLower(content.str()), rr.ttl));
    if (!ret.second && ret.first->second != rr.ttl) {
      cout<<"[Error] TTL mismatch in rrset: '"<<rr.qname<<" IN " <<rr.qtype.toString()<<" "<<rr.content<<"' ("<<ret.first->second<<" != "<<rr.ttl<<")"<<endl;
      numerrors++;
      continue;
    }

    if (isSecure && isOptOut && (rr.qname.countLabels() != 0 && rr.qname.getRawLabels()[0] == "*")) {
      cout<<"[Warning] wildcard record '"<<rr.qname<<" IN " <<rr.qtype.toString()<<" "<<rr.content<<"' is insecure"<<endl;
      cout<<"[Info] Wildcard records in opt-out zones are insecure. Disable the opt-out flag for this zone to avoid this warning. Command: pdnsutil set-nsec3 "<<zone<<endl;
      numwarnings++;
    }

    if(rr.qname==zone.operator const DNSName&()) {
      // apex checks
      if (rr.qtype.getCode() == QType::NS) {
        hasNsAtApex=true;
      } else if (rr.qtype.getCode() == QType::DS) {
        cout<<"[Warning] DS at apex in zone '"<<zone<<"', should not be here."<<endl;
        numwarnings++;
      }
    } else {
      // non-apex checks
      if (rr.qtype.getCode() == QType::SOA) {
        cout<<"[Error] SOA record not at apex '"<<rr.qname<<" IN "<<rr.qtype.toString()<<" "<<rr.content<<"' in zone '"<<zone<<"'"<<endl;
        numerrors++;
        continue;
      }
      if (rr.qtype.getCode() == QType::DNSKEY) {
        cout<<"[Warning] DNSKEY record not at apex '"<<rr.qname<<" IN "<<rr.qtype.toString()<<" "<<rr.content<<"' in zone '"<<zone<<"', should not be here."<<endl;
        numwarnings++;
      } else if (rr.qtype.getCode() == QType::NS) {
        if (DNSName(rr.content).isPartOf(rr.qname)) {
          checkglue.insert(DNSName(toLower(rr.content)));
        }
        checkOcclusion.insert({rr.qname, rr.qtype});
      } else if (rr.qtype.getCode() == QType::A || rr.qtype.getCode() == QType::AAAA) {
        glue.insert(rr.qname);
      }
    }

    // DNAMEs can occur both at the apex and below it
    if (rr.qtype == QType::DNAME) {
      checkOcclusion.insert({rr.qname, rr.qtype});
    }

    if((rr.qtype.getCode() == QType::A || rr.qtype.getCode() == QType::AAAA) && !rr.qname.isWildcard() && !rr.qname.isHostname())
      cout<<"[Info] "<<rr.qname.toString()<<" record for '"<<rr.qtype.toString()<<"' is not a valid hostname."<<endl;

    // Check if the DNSNames that should be hostnames, are hostnames
    try {
      checkHostnameCorrectness(rr);
    } catch (const std::exception& e) {
      cout << "[Warning] " << rr.qtype.toString() << " record in zone '" << zone << ": " << e.what() << endl;
      numwarnings++;
    }

    if (rr.qtype.getCode() == QType::CNAME) {
      if (cnames.count(rr.qname) == 0) {
        cnames.insert(rr.qname);
      }
      else {
        cout<<"[Error] Duplicate CNAME found at '"<<rr.qname<<"'"<<endl;
        numerrors++;
        continue;
      }
    } else {
      if (rr.qtype.getCode() == QType::RRSIG) {
        if(!presigned) {
          cout<<"[Error] RRSIG found at '"<<rr.qname<<"' in non-presigned zone. These do not belong in the database."<<endl;
          numerrors++;
          continue;
        }
      } else
        noncnames.insert(rr.qname);
    }

    if (rr.qtype == QType::MX || rr.qtype == QType::NS || rr.qtype == QType::SRV) {
      checkCNAME.push_back(rr);
    }

    if(rr.qtype.getCode() == QType::NSEC || rr.qtype.getCode() == QType::NSEC3)
    {
      cout<<"[Error] NSEC or NSEC3 found at '"<<rr.qname<<"'. These do not belong in the database."<<endl;
      numerrors++;
      continue;
    }

    if(!presigned && rr.qtype.getCode() == QType::DNSKEY)
    {
      if(::arg().mustDo("direct-dnskey"))
      {
        if(rr.ttl != sd.minimum)
        {
          cout<<"[Warning] DNSKEY TTL of "<<rr.ttl<<" at '"<<rr.qname<<"' differs from SOA minimum of "<<sd.minimum<<endl;
          numwarnings++;
        }
      }
      else
      {
        cout<<"[Warning] DNSKEY at '"<<rr.qname<<"' in non-presigned zone will mostly be ignored and can cause problems."<<endl;
        numwarnings++;
      }
    }
  }

  for(const auto &name: cnames) {
    if (noncnames.find(name) != noncnames.end()) {
      cout<<"[Error] CNAME "<<name<<" found, but other records with same label exist."<<endl;
      numerrors++;
    }
  }

  for(const auto &i: tlsas) {
    DNSName name = DNSName(i);
    name.trimToLabels(name.countLabels()-2);
    if (cnames.find(name) == cnames.end() && noncnames.find(name) == noncnames.end()) {
      // No specific record for the name in the TLSA record exists, this
      // is already worth emitting a warning. Let's see if a wildcard exist.
      cout<<"[Warning] ";
      DNSName wcname(name);
      wcname.chopOff();
      wcname.prependRawLabel("*");
      if (cnames.find(wcname) != cnames.end() || noncnames.find(wcname) != noncnames.end()) {
        cout<<"A wildcard record exist for '"<<wcname<<"' and a TLSA record for '"<<i<<"'.";
      } else {
        cout<<"No record for '"<<name<<"' exists, but a TLSA record for '"<<i<<"' does.";
      }
      numwarnings++;
      cout<<" A query for '"<<name<<"' will yield an empty response. This is most likely a mistake, please create records for '"<<name<<"'."<<endl;
    }
  }

  for (const auto& [name, prio, target, v4hintsAuto, v6hintsAuto] : svcbTargets) {
    if (name == target) {
      cout<<"[Error] SVCB record "<<name<<" has itself as target."<<endl;
      numerrors++;
    }

    if (prio == 0) {
      if (target.isPartOf(zone)) {
        if (svcbAliases.find(target) != svcbAliases.end()) {
          cout << "[Warning] SVCB record for " << name << " has an aliasform target (" << target << ") that is in aliasform itself." << endl;
          numwarnings++;
        }
        if (addresses.find(target) == addresses.end() && svcbRecords.find(target) == svcbRecords.end()) {
          cout<<"[Error] SVCB record "<<name<<" has a target "<<target<<" that has neither address nor SVCB records."<<endl;
          numerrors++;
        }
      }
    }

    const auto& trueTarget = target.isRoot() ? name : target;
    if (prio > 0) {
      if(v4hintsAuto && arecords.find(trueTarget) == arecords.end()) {
        cout << "[warning] SVCB record for "<< name << " has automatic IPv4 hints, but no A-record for the target at "<< trueTarget <<" exists."<<endl;
        numwarnings++;
      }
      if(v6hintsAuto && aaaarecords.find(trueTarget) == aaaarecords.end()) {
        cout << "[warning] SVCB record for "<< name << " has automatic IPv6 hints, but no AAAA-record for the target at "<< trueTarget <<" exists."<<endl;
        numwarnings++;
      }
    }
  }

  for (const auto& [name, prio, target, v4hintsAuto, v6hintsAuto] : httpsTargets) {
    if (name == target) {
      cout<<"[Error] HTTPS record "<<name<<" has itself as target."<<endl;
      numerrors++;
    }

    if (prio == 0) {
      if (target.isPartOf(zone)) {
        if (httpsAliases.find(target) != httpsAliases.end()) {
          cout << "[Warning] HTTPS record for " << name << " has an aliasform target (" << target << ") that is in aliasform itself." << endl;
          numwarnings++;
        }
        if (addresses.find(target) == addresses.end() && httpsRecords.find(target) == httpsRecords.end()) {
          cout<<"[Error] HTTPS record "<<name<<" has a target "<<target<<" that has neither address nor HTTPS records."<<endl;
          numerrors++;
        }
      }
    }

    const auto& trueTarget = target.isRoot() ? name : target;
    if (prio > 0) {
      if(v4hintsAuto && arecords.find(trueTarget) == arecords.end()) {
        cout << "[warning] HTTPS record for "<< name << " has automatic IPv4 hints, but no A-record for the target at "<< trueTarget <<" exists."<<endl;
        numwarnings++;
      }
      if(v6hintsAuto && aaaarecords.find(trueTarget) == aaaarecords.end()) {
        cout << "[warning] HTTPS record for "<< name << " has automatic IPv6 hints, but no AAAA-record for the target at "<< trueTarget <<" exists."<<endl;
        numwarnings++;
      }
    }
  }

  if(!hasNsAtApex) {
    cout<<"[Error] No NS record at zone apex in zone '"<<zone<<"'"<<endl;
    numerrors++;
  }

  for(const auto &qname : checkglue) {
    if (glue.count(qname) == 0) {
      cout<<"[Warning] Missing glue for '"<<qname<<"' in zone '"<<zone<<"'"<<endl;
      numwarnings++;
    }
  }

  for( const auto &qname : checkOcclusion ) {
    for( const auto &rr : records ) {
      // a name does not occlude itself in the following situations:
      // NS does not occlude DS+NS
      // a DNAME does not occlude itself
      if( qname.first == rr.qname && ((( rr.qtype == QType::NS || rr.qtype == QType::DS ) && qname.second == QType::NS ) || ( rr.qtype == QType::DNAME && qname.second == QType::DNAME ) ) ) {
        continue;
      }

      // for most types, X occludes X and (type-dependent) almost everything under X
      if( rr.qname.isPartOf( qname.first ) ) {

        // but a DNAME does not occlude anything at its name, only the things under it
        if( qname.second == QType::DNAME && rr.qname == qname.first ) {
          continue;
        }

        // the record under inspection is:
        // occluded by a DNAME, or
        // occluded by a delegation, and is not glue or ENTs leading towards that glue
        if( qname.second == QType::DNAME || ( rr.qtype != QType::ENT && rr.qtype.getCode() != QType::A && rr.qtype.getCode() != QType::AAAA ) ) {
          cout << "[Warning] '" << rr.qname << "|" << rr.qtype.toString() << "' in zone '" << zone << "' is occluded by a ";
          if( qname.second == QType::NS ) {
            cout << "delegation";
          } else {
            cout << "DNAME";
          }
          cout << " at '" << qname.first << "'" << endl;
          numwarnings++;
        }
      }
    }
  }

  for (auto const &rr : checkCNAME) {
    DNSName target;
    shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(rr.qtype.getCode(), QClass::IN, rr.content));
    switch (rr.qtype) {
      case QType::MX:
        target = std::dynamic_pointer_cast<MXRecordContent>(drc)->d_mxname;
        break;
      case QType::SRV:
        target = std::dynamic_pointer_cast<SRVRecordContent>(drc)->d_target;
        break;
      case QType::NS:
        target = std::dynamic_pointer_cast<NSRecordContent>(drc)->getNS();
        break;
      default:
        // programmer error, but let's not abort() :)
        break;
    }
    if (target.isPartOf(zone) && cnames.count(target) != 0) {
      cout<<"[Warning] '" << rr.qname << "|" << rr.qtype.toString() << " has a target (" << target << ") that is a CNAME." << endl;
      numwarnings++;
    }
  }

  bool ok, ds_ns, done;
  for( const auto &rr : records ) {
    ok = rr.auth;
    ds_ns = false;
    done = (suppliedrecords != nullptr || !sd.db->doesDNSSEC());
    for( const auto &qname : checkOcclusion ) {
      if( qname.second == QType::NS ) {
        if( qname.first == rr.qname ) {
          ds_ns = true;
        }
        if ( done ) {
          continue;
        }
        if(!rr.auth) {
          if( rr.qname.isPartOf( qname.first ) && ( qname.first != rr.qname || rr.qtype != QType::DS ) ) {
            ok = done = true;
          }
          if( rr.qtype == QType::ENT && qname.first.isPartOf( rr.qname ) ) {
            ok = done = true;
          }
        } else if( rr.qname.isPartOf( qname.first ) && ( ( qname.first != rr.qname || rr.qtype != QType::DS ) || rr.qtype == QType::NS ) ) {
          ok = false;
          done = true;
        }
      }
    }
    if( ! ds_ns && rr.qtype.getCode() == QType::DS && rr.qname != zone.operator const DNSName&() ) {
      cout << "[Warning] DS record without a delegation '" << rr.qname<<"'." << endl;
      numwarnings++;
    }
    if( ! ok && suppliedrecords == nullptr ) {
      cout << "[Error] Following record is auth=" << rr.auth << ", run pdnsutil rectify-zone?: " << rr.qname << " IN " << rr.qtype.toString() << " " << rr.content << endl;
      numerrors++;
    }
  }

  std::map<std::string, std::vector<std::string>> metadatas;
  if (B.getAllDomainMetadata(zone, metadatas)) {
    for (const auto& metaData : metadatas) {
      set<string> seen;
      set<string> messaged;

      for (const auto& value : metaData.second) {
        if (seen.count(value) == 0) {
          seen.insert(value);
        }
        else if (messaged.count(value) == 0) {
          cout << "[Error] Found duplicate metadata key value pair for zone " << zone << " with key '" << metaData.first << "' and value '" << value << "'" << endl;
          numerrors++;
          messaged.insert(value);
        }
      }
    }
  }

  cout<<"Checked "<<records.size()<<" records of '"<<zone<<"', "<<numerrors<<" errors, "<<numwarnings<<" warnings."<<endl;
  return numerrors;
}

static int checkAllZones(DNSSECKeeper &dk, bool exitOnError)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  vector<DomainInfo> domainInfo;
  multi_index_container<
    DomainInfo,
    indexed_by<
      ordered_non_unique< member<DomainInfo,ZoneName,&DomainInfo::zone>, CanonZoneNameCompare >,
      ordered_non_unique< member<DomainInfo,domainid_t,&DomainInfo::id> >
    >
  > seenInfos;
  auto& seenNames = seenInfos.get<0>();
  auto& seenIds = seenInfos.get<1>();

  B.getAllDomains(&domainInfo, true, true);
  int errors=0;
  for (auto& di : domainInfo) {
    if (checkZone(dk, B, di.zone) > 0) {
      errors++;
    }

    auto seenName = seenNames.find(di.zone);
    if (seenName != seenNames.end()) {
      cout<<"[Error] Another SOA for zone '"<<di.zone<<"' (serial "<<di.serial<<") has already been seen (serial "<<seenName->serial<<")."<<endl;
      errors++;
    }

    auto seenId = seenIds.find(di.id);
    if (seenId != seenIds.end()) {
      cout << "[Error] Zone ID " << di.id << " of '" << di.zone << "' in backend " << di.backend->getPrefix() << " has already been used by zone '" << seenId->zone << "' in backend " << seenId->backend->getPrefix() << "." << endl;
      errors++;
    }

    seenInfos.insert(std::move(di));

    if (errors != 0 && exitOnError) {
      return EXIT_FAILURE;
    }
  }
  cout<<"Checked "<<domainInfo.size()<<" zones, "<<errors<<" had errors."<<endl;
  if(errors == 0) {
    return EXIT_SUCCESS;
  }
  return EXIT_FAILURE;
}

static int increaseSerial(const ZoneName& zone, DNSSECKeeper &dsk)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  SOAData sd;
  if(!B.getSOAUncached(zone, sd)) {
    cerr<<"No SOA for zone '"<<zone<<"'"<<endl;
    return -1;
  }

  if (dsk.isPresigned(zone)) {
    cerr<<"Serial increase of presigned zone '"<<zone<<"' is not allowed."<<endl;
    return -1;
  }

  DomainInfo info;
  if (!B.getDomainInfo(zone, info, false)) {
    cout << "[Warning] Unable to get zone information for zone '" << zone << "'" << endl;
    if (!g_force) {
      throw PDNSException("Operation is not allowed unless --force");
    }
  }
  else {
    if (info.isSecondaryType() && !g_force) {
      throw PDNSException("Operation on a secondary zone is not allowed unless --force");
    }
  }

  string soaEditKind;
  dsk.getSoaEdit(zone, soaEditKind);

  DNSResourceRecord rr;
  makeIncreasedSOARecord(sd, "SOA-EDIT-INCREASE", soaEditKind, rr);

  sd.db->startTransaction(zone, UnknownDomainID);

  auto rrs = vector<DNSResourceRecord>{rr};
  if (!sd.db->replaceRRSet(sd.domain_id, zone.operator const DNSName&(), rr.qtype, rrs)) {
    cerr << "Backend did not replace SOA record. Backend might not support this operation." << endl;
    sd.db->abortTransaction();
    return -1;
  }

  if (sd.db->doesDNSSEC()) {
    NSEC3PARAMRecordContent ns3pr;
    bool narrow = false;
    bool haveNSEC3=dsk.getNSEC3PARAM(zone, &ns3pr, &narrow);

    DNSName ordername;
    if(haveNSEC3) {
      if(!narrow)
        ordername=DNSName(toBase32Hex(hashQNameWithSalt(ns3pr, zone.operator const DNSName&())));
    } else
      ordername=DNSName("");
    if(g_verbose)
      cerr<<"'"<<rr.qname<<"' -> '"<< ordername <<"'"<<endl;
    sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, rr.qname, ordername, true, QType::ANY, haveNSEC3 && !narrow);
  }

  sd.db->commitTransaction();

  cout<<"SOA serial for zone "<<zone<<" set to "<<sd.serial<<endl;
  return 0;
}

static int deleteZone(const ZoneName &zone) {
  UtilBackend B; //NOLINT(readability-identifier-length)
  DomainInfo di;
  if (! B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' not found!" << endl;
    return EXIT_FAILURE;
  }

  di.backend->startTransaction(zone, UnknownDomainID);
  try {
    if(di.backend->deleteDomain(zone)) {
      di.backend->commitTransaction();
      return EXIT_SUCCESS;
    }
  } catch (...) {
    try {
      di.backend->abortTransaction();
    } catch (...) {
      // Ignore this exception (which is likely "cannot rollback - no
      // transaction is active"), we have a more important one we want to
      // rethrow.
    }
    throw;
  }

  di.backend->abortTransaction();

  cerr << "Failed to delete zone '" << zone << "'" << endl;
  ;
  return EXIT_FAILURE;
}

static void listKey(DomainInfo const &di, DNSSECKeeper& dk, bool printHeader = true) {
  if (printHeader) {
    cout<<"Zone                          Type Act Pub Size    Algorithm       ID   Location    Keytag"<<endl;
    cout<<"------------------------------------------------------------------------------------------"<<endl;
  }
  unsigned int spacelen = 0;
  for (auto const &key : dk.getKeys(di.zone)) {
    cout<<di.zone;
    if (di.zone.toStringNoDot().length() > 29)
      cout<<endl<<string(30, ' ');
    else
      cout<<string(30 - di.zone.toStringNoDot().length(), ' ');

    cout<<DNSSECKeeper::keyTypeToString(key.second.keyType)<<"  ";

    if (key.second.active) {
      cout << "Act ";
    } else {
      cout << "    ";
    }

    if (key.second.published) {
      cout << "Pub ";
    } else {
      cout << "    ";
    }

    spacelen = (std::to_string(key.first.getKey()->getBits()).length() >= 8) ? 1 : 8 - std::to_string(key.first.getKey()->getBits()).length();
    if (key.first.getKey()->getBits() < 1) {
      cout<<"invalid "<<endl;
      continue;
    }
    cout<<key.first.getKey()->getBits()<<string(spacelen, ' ');

    string algname = DNSSECKeeper::algorithm2name(key.first.getAlgorithm());
    spacelen = (algname.length() >= 16) ? 1 : 16 - algname.length();
    cout<<algname<<string(spacelen, ' ');

    spacelen = (std::to_string(key.second.id).length() > 5) ? 1 : 5 - std::to_string(key.second.id).length();
    cout<<key.second.id<<string(spacelen, ' ');

#ifdef HAVE_P11KIT1
    auto stormap = key.first.getKey()->convertToISCVector();
    string engine;
    string slot;
    string label;
    for (auto const &elem : stormap) {
      //cout<<elem.first<<" "<<elem.second<<endl;
      if (elem.first == "Engine")
        engine = elem.second;
      if (elem.first == "Slot")
        slot = elem.second;
      if (elem.first == "Label")
        label = elem.second;
    }
    if (engine.empty() || slot.empty()){
      cout<<"cryptokeys  ";
    } else {
      spacelen = (engine.length()+slot.length()+label.length()+2 >= 12) ? 1 : 12 - engine.length()-slot.length()-label.length()-2;
      cout<<engine<<","<<slot<<","<<label<<string(spacelen, ' ');
    }
#else
    cout<<"cryptokeys  ";
#endif
    cout<<key.first.getDNSKEY().getTag()<<endl;
  }
}

static int listKeys(const string &zname, DNSSECKeeper& dk){
  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  if (!zname.empty()) {
    DomainInfo di;
    if(!B.getDomainInfo(ZoneName(zname), di)) {
      cerr << "Zone "<<zname<<" not found."<<endl;
      return EXIT_FAILURE;
    }
    listKey(di, dk);
  } else {
    vector<DomainInfo> domainInfo;
    B.getAllDomains(&domainInfo, false, g_verbose);
    bool printHeader = true;
    for (const auto& di : domainInfo) {
      listKey(di, dk, printHeader);
      printHeader = false;
    }
  }
  return EXIT_SUCCESS;
}

static int listZone(const ZoneName &zone) {
  UtilBackend B; //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (! B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' not found!" << endl;
    return EXIT_FAILURE;
  }
  if ((di.backend->getCapabilities() & DNSBackend::CAP_LIST) == 0) {
    cerr << "Backend for zone '" << zone << "' does not support listing its contents." << endl;
    return EXIT_FAILURE;
  }

  di.backend->list(zone, di.id);
  DNSResourceRecord rr;
  cout<<"$ORIGIN ."<<endl;
  std::ostream::sync_with_stdio(false);

  while(di.backend->get(rr)) {
    if(rr.qtype.getCode() != 0) {
      switch (rr.qtype.getCode()) {
      case QType::ALIAS:
      case QType::CNAME:
      case QType::MX:
      case QType::NS:
      case QType::SRV:
        if (!rr.content.empty() && rr.content[rr.content.size()-1] != '.') {
          rr.content.append(1, '.');
        }
        break;
      }

      cout<<rr.qname<<"\t"<<rr.ttl<<"\tIN\t"<<rr.qtype.toString()<<"\t"<<rr.content<<"\n";
    }
  }
  cout.flush();
  return EXIT_SUCCESS;
}

// lovingly copied from http://stackoverflow.com/questions/1798511/how-to-avoid-press-enter-with-any-getchar
static int read1char(){
    int c;
    static struct termios oldt, newt;

    /*tcgetattr gets the parameters of the current terminal
    STDIN_FILENO will tell tcgetattr that it should write the settings
    of stdin to oldt*/
    tcgetattr( STDIN_FILENO, &oldt);
    /*now the settings will be copied*/
    newt = oldt;

    /*ICANON normally takes care that one line at a time will be processed
    that means it will return if it sees a "\n" or an EOF or an EOL*/
    newt.c_lflag &= ~(ICANON);

    /*Those new settings will be set to STDIN
    TCSANOW tells tcsetattr to change attributes immediately. */
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    c=getchar();

    /*restore the old settings*/
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

    return c;
}

static int clearZone(const ZoneName &zone) {
  UtilBackend B; //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (! B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' not found!" << endl;
    return EXIT_FAILURE;
  }
  if(!di.backend->startTransaction(zone, di.id)) {
    cerr<<"Unable to start transaction for load of zone '"<<zone<<"'"<<endl;
    return EXIT_FAILURE;
  }
  di.backend->commitTransaction();
  return EXIT_SUCCESS;
}

class PDNSColors
{
public:
  PDNSColors(bool nocolors)
    : d_colors(!nocolors && isatty(STDOUT_FILENO) != 0 && getenv("NO_COLORS") == nullptr) // NOLINT(concurrency-mt-unsafe)
  {
  }
  [[nodiscard]] string red() const
  {
    return d_colors ? "\x1b[31m" : "";
  }
  [[nodiscard]] string green() const
  {
    return d_colors ? "\x1b[32m" : "";
  }
  [[nodiscard]] string bold() const
  {
    return d_colors ? "\x1b[1m" : "";
  }
  [[nodiscard]] string rst() const
  {
    return d_colors ? "\x1b[0m" : "";
  }
private:
  bool d_colors;
};

static bool spawnEditor(const std::string& editor, std::string_view tmpfile, int gotoline, int &result)
{
  sigset_t mask;
  sigset_t omask;

  // Ignore INT, QUIT and CHLD signals while the editor process runs
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);
  sigprocmask(SIG_BLOCK, &mask, &omask); // NOLINT(concurrency-mt-unsafe)

  switch (pid_t child = fork()) {
  case 0:
    {
      std::array<const char *, 4> args{};
      size_t pos{0};
      std::string gotolinestr;
      args.at(pos++) = editor.c_str();
      if (gotoline > 0) {
        // TODO: if editor is 'ed', skip this; if 'ex' or 'vi', use '-c number'
        gotolinestr = "+" + std::to_string(gotoline);
        args.at(pos++) = gotolinestr.c_str();
      }
      args.at(pos++) = tmpfile.data();
      args.at(pos++) = nullptr;
      if (::execvp(args.at(0), const_cast<char **>(args.data())) != 0) { // NOLINT(cppcoreguidelines-pro-type-const-cast)
        ::exit(errno); // NOLINT(concurrency-mt-unsafe)
      }
      // std::unreachable();
    }
    break;
  case -1:
    unixDie("Couldn't fork");
    break;
  default:
    {
      pid_t pid{-1};
      int status{0};
      do {
        pid = waitpid(child, &status, 0);
      } while (pid == -1 && errno == EINTR);
      sigprocmask(SIG_SETMASK, &omask, nullptr); // NOLINT(concurrency-mt-unsafe)
      if (pid == -1) {
        return false;
      }
      if (WIFEXITED(status)) {
        result = WEXITSTATUS(status);
        return true;
      }
      if (WIFSIGNALED(status)) {
        result = 128 + WTERMSIG(status);
        return true;
      }
    }
    break;
  }
  return false;
}

static int editZone(const ZoneName &zone, const PDNSColors& col) {
  UtilBackend B; //NOLINT(readability-identifier-length)
  DomainInfo di;
  DNSSECKeeper dk(&B);

  if (! B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' not found!" << endl;
    return EXIT_FAILURE;
  }
  if ((di.backend->getCapabilities() & DNSBackend::CAP_LIST) == 0) {
    cerr << "Backend for zone '" << zone << "' does not support listing its contents." << endl;
    return EXIT_FAILURE;
  }

  if (isatty(STDIN_FILENO) == 0) {
    cerr << "edit-zone requires a terminal" << endl;
    return EXIT_FAILURE;
  }

  if (di.isSecondaryType() && !g_force) {
    cout << "Zone '" << zone << "' is a secondary zone." << endl;
    while (true) {
      cout << "Edit the zone anyway? (N/y) " << std::flush;
      int resp = read1char();
      if (resp != '\n') {
        cout << endl;
      }
      if (resp == 'y' || resp == 'Y') {
        break;
      }
      if (resp == 'n' || resp == 'N' || resp == '\n') {
        return EXIT_FAILURE;
      }
    }
  }

  /* ensure that the temporary file will only
     be accessible by the current user, not even
     by other users in the same group, and certainly
     not by other users.
  */
  umask(S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
  vector<DNSRecord> pre, post;
  char tmpnam[]="/tmp/pdnsutil-XXXXXX";
  int tmpfd=mkstemp(tmpnam);
  if(tmpfd < 0)
    unixDie("Making temporary filename in "+string(tmpnam));
  struct deleteme {
    ~deleteme() { unlink(d_name.c_str()); }
    deleteme(string name) : d_name(std::move(name)) {}
    deleteme(const deleteme &) = delete;
    deleteme(deleteme &&) = delete;
    deleteme operator=(const deleteme &) = delete;
    deleteme operator=(deleteme &&) = delete;
    string d_name;
  } dm(tmpnam);

  vector<DNSResourceRecord> checkrr;
  int gotoline=0;
  string editor="editor";
  if(auto e=getenv("EDITOR")) // <3
    editor=e;
 editAgain:;
  di.backend->list(zone, di.id);
  pre.clear(); post.clear();
  {
    if(tmpfd < 0 && (tmpfd=open(tmpnam, O_CREAT | O_WRONLY | O_TRUNC, 0600)) < 0)
      unixDie("Error reopening temporary file "+string(tmpnam));
    string header("; Warning - every name in this file is ABSOLUTE!\n$ORIGIN .\n");
    if(write(tmpfd, header.c_str(), header.length()) < 0)
      unixDie("Writing zone to temporary file");
    DNSResourceRecord rr;
    while(di.backend->get(rr)) {
      if(rr.qtype.getCode() == 0) {
        continue;
      }
      DNSRecord dr(rr);
      pre.push_back(std::move(dr));
    }
    sort(pre.begin(), pre.end(), DNSRecord::prettyCompare);
    for(const auto& dr : pre) {
      ostringstream os;
      os<<dr.d_name<<"\t"<<dr.d_ttl<<"\tIN\t"<<DNSRecordContent::NumberToType(dr.d_type)<<"\t"<<dr.getContent()->getZoneRepresentation(true)<<endl;
      if(write(tmpfd, os.str().c_str(), os.str().length()) < 0)
        unixDie("Writing zone to temporary file");
    }
    close(tmpfd);
    tmpfd=-1;
  }
 editMore:;
  post.clear();
  int result{0};
  if (!spawnEditor(editor, tmpnam, gotoline, result)) { // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    unixDie("Editing file with: '"+editor+"', perhaps set EDITOR variable");
  }
  if (result != 0) {
    throw std::runtime_error("Editing file with: '" + editor + "' returned non-zero status " + std::to_string(result));
  }
  ZoneParserTNG zpt(static_cast<const char *>(tmpnam), g_rootzonename);
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
  zpt.setMaxIncludes(::arg().asNum("max-include-depth"));
  DNSResourceRecord zrr;
  map<pair<DNSName,uint16_t>, vector<DNSRecord> > grouped;
  try {
    while(zpt.get(zrr)) {
        DNSRecord dr(zrr);
        post.push_back(dr);
        grouped[{dr.d_name,dr.d_type}].push_back(dr);
    }
  }
  catch(std::exception& e) {
    cerr<<"Problem: "<<e.what()<<" "<<zpt.getLineOfFile()<<endl;
    auto fnum = zpt.getLineNumAndFile();
    gotoline = fnum.second;
    goto reAsk;
  }
  catch(PDNSException& e) {
    cerr<<"Problem: "<<e.reason<<" "<<zpt.getLineOfFile()<<endl;
    auto fnum = zpt.getLineNumAndFile();
    gotoline = fnum.second;
    goto reAsk;
  }

  sort(post.begin(), post.end(), DNSRecord::prettyCompare);
  checkrr.clear();

  for(const DNSRecord& rr : post) {
    DNSResourceRecord drr = DNSResourceRecord::fromWire(rr);
    drr.domain_id = di.id;
    checkrr.push_back(std::move(drr));
  }
  if(checkZone(dk, B, zone, &checkrr) != 0) {
  reAsk:;
    cerr << col.red() << col.bold() << "There was a problem with your zone" << col.rst() << "\nOptions are: (e)dit your changes, (r)etry with original zone, (a)pply change anyhow, (q)uit: " << std::flush;
    int c=read1char();
    cerr<<"\n";
    if(c=='e') {
      post.clear();
      goto editMore;
    } else if(c=='r') {
      post.clear();
      goto editAgain;
    } else if(c=='q') {
      return EXIT_FAILURE;
    } else if(c!='a') {
      goto reAsk;
    }
  }


  vector<DNSRecord> diff;

  map<pair<DNSName,uint16_t>, string> changed;
  set_difference(pre.cbegin(), pre.cend(), post.cbegin(), post.cend(), back_inserter(diff), DNSRecord::prettyCompare);
  for(const auto& d : diff) {
    ostringstream str;
    str << col.red() << "-" << d.d_name << " " << d.d_ttl << " IN " << DNSRecordContent::NumberToType(d.d_type) << " " <<d.getContent()->getZoneRepresentation(true) << col.rst() <<endl;
    changed[{d.d_name,d.d_type}] += str.str();

  }
  diff.clear();
  set_difference(post.cbegin(), post.cend(), pre.cbegin(), pre.cend(), back_inserter(diff), DNSRecord::prettyCompare);
  for(const auto& d : diff) {
    ostringstream str;

    str<<col.green() << "+" << d.d_name << " " << d.d_ttl << " IN " <<DNSRecordContent::NumberToType(d.d_type) << " " << d.getContent()->getZoneRepresentation(true) << col.rst() <<endl;
    changed[{d.d_name,d.d_type}]+=str.str();
  }
  cout<<"Detected the following changes:"<<endl;
  for(const auto& c : changed) {
    cout<<c.second;
  }
  if (!changed.empty()) {
    if (changed.find({zone.operator const DNSName&(), QType::SOA}) == changed.end()) {
     reAsk3:;
      cout<<endl<<"You have not updated the SOA record! Would you like to increase-serial?"<<endl;
      cout<<"(y)es - increase serial, (n)o - leave SOA record as is, (e)dit your changes, (q)uit: "<<std::flush;
      int c = read1char();
      switch(c) {
        case 'y':
          {
            DNSRecord oldSoaDR = grouped[{zone.operator const DNSName&(), QType::SOA}].at(0); // there should be only one SOA record, so we can use .at(0);
            ostringstream str;
            str<< col.red() << "-" << oldSoaDR.d_name << " " << oldSoaDR.d_ttl << " IN " << DNSRecordContent::NumberToType(oldSoaDR.d_type) << " " <<oldSoaDR.getContent()->getZoneRepresentation(true) << col.rst() <<endl;

            SOAData sd;
            B.getSOAUncached(zone, sd);
            // TODO: do we need to check for presigned? here or maybe even all the way before edit-zone starts?

            string soaEditKind;
            dk.getSoaEdit(zone, soaEditKind);

            DNSResourceRecord rr;
            makeIncreasedSOARecord(sd, "SOA-EDIT-INCREASE", soaEditKind, rr);
            DNSRecord dr(rr);
            str << col.green() << "+" << dr.d_name << " " << dr.d_ttl<< " IN " <<DNSRecordContent::NumberToType(dr.d_type) << " " <<dr.getContent()->getZoneRepresentation(true) << col.rst() <<endl;

            changed[{dr.d_name, dr.d_type}]+=str.str();
            grouped[{dr.d_name, dr.d_type}].at(0) = dr;
            cout<<endl<<"SOA serial for zone "<<zone<<" set to "<<sd.serial;
          }
          break;
        case 'q':
          return EXIT_FAILURE;
        case 'e':
          goto editMore;
        case 'n':
          goto reAsk2;
        default:
          goto reAsk3;
      }
    }
  }
  reAsk2:;
  if(changed.empty()) {
    cout<<endl<<"No changes to apply."<<endl;
    return(EXIT_SUCCESS);
  }
  cout<<endl<<"(a)pply these changes, (e)dit again, (r)etry with original zone, (q)uit: "<<std::flush;
  int c=read1char();
  post.clear();
  cerr<<'\n';
  if(c=='q')
    return(EXIT_SUCCESS);
  if(c=='e') {
    goto editMore;
  }
  else if(c=='r')
    goto editAgain;
  else if(changed.empty() || c!='a')
    goto reAsk2;

  di.backend->startTransaction(zone, UnknownDomainID);
  for(const auto& change : changed) {
    vector<DNSResourceRecord> vrr;
    for(const DNSRecord& rr : grouped[change.first]) {
      DNSResourceRecord crr = DNSResourceRecord::fromWire(rr);
      crr.domain_id = di.id;
      vrr.push_back(std::move(crr));
    }
    di.backend->replaceRRSet(di.id, change.first.first, QType(change.first.second), vrr);
  }
  rectifyZone(dk, zone, false, false);
  di.backend->commitTransaction();
  return EXIT_SUCCESS;
}

#ifdef HAVE_IPCIPHER
static int xcryptIP(const std::string& cmd, const std::string& ip, const std::string& rkey)
{

  ComboAddress ca(ip), ret;

  if(cmd=="ipencrypt")
    ret = encryptCA(ca, rkey);
  else
    ret = decryptCA(ca, rkey);

  cout<<ret.toString()<<endl;
  return EXIT_SUCCESS;
}
#endif /* HAVE_IPCIPHER */

static int zonemdVerifyFile(const ZoneName& zone, const string& fname) {
  ZoneParserTNG zpt(fname, zone, "", true);
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));

  bool validationDone, validationOK;

  try {
    auto zoneMD = pdns::ZoneMD(zone);
    zoneMD.readRecords(zpt);
    zoneMD.verify(validationDone, validationOK);
  }
  catch (const PDNSException& ex) {
    cerr << "zonemd-verify-file: " << ex.reason << endl;
    return EXIT_FAILURE;
  }
  catch (const std::exception& ex) {
    cerr << "zonemd-verify-file: " << ex.what() << endl;
    return EXIT_FAILURE;
  }

  if (validationDone) {
    if (validationOK) {
      cout << "zonemd-verify-file: Verification of ZONEMD record succeeded" << endl;
      return EXIT_SUCCESS;
    }
    cerr << "zonemd-verify-file: Verification of ZONEMD record(s) failed" << endl;
  }
  else {
    cerr << "zonemd-verify-file: No suitable ZONEMD record found to verify against" << endl;
  }
  return EXIT_FAILURE;
}

// Wrapper around UeberBackend::createDomain, which will also set up the
// default metadata, matching the behaviour of the REST API.
static bool createZoneWithDefaults(UtilBackend &backend, DomainInfo &info, const ZoneName& zone, DomainInfo::DomainKind kind, const vector<ComboAddress>& primaries)
{
  backend.createDomain(zone, kind, primaries, "");
  if (!backend.getDomainInfo(zone, info)) {
    cerr << "Zone '" << zone << "' was not created." << endl;
    return false;
  }
  info.backend->startTransaction(zone, static_cast<int>(info.id));
  info.backend->setDomainMetadataOne(zone, "SOA-EDIT-API", "DEFAULT");
  info.backend->commitTransaction();
  return true;
}

static int loadZone(const ZoneName& zone, const string& fname) {
  UtilBackend B; //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' exists already, replacing contents" << endl;
  }
  else {
    if ((B.getCapabilities() & DNSBackend::CAP_CREATE) == 0) {
      cerr << "None of the configured backends support zone creation." << endl;
      cerr << "Zone '" << zone << "' was not created." << endl;
      return EXIT_FAILURE;
    }
    if (zone.hasVariant() && (B.getCapabilities() & DNSBackend::CAP_VIEWS) == 0) {
      cerr << "None of the configured backends support views." << endl;
      cerr << "Zone '" << zone << "' was not created." << endl;
      return EXIT_FAILURE;
    }
    cerr<<"Creating '"<<zone<<"'"<<endl;
    if (!createZoneWithDefaults(B, di, zone, DomainInfo::Native, vector<ComboAddress>())) {
      return EXIT_FAILURE;
    }
  }
  DNSBackend* db = di.backend;
  ZoneParserTNG zpt(fname, zone);
  zpt.setDefaultTTL(::arg().asNum("default-ttl"));
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));

  DNSResourceRecord rr;
  if(!db->startTransaction(zone, di.id)) {
    cerr<<"Unable to start transaction for load of zone '"<<zone<<"'"<<endl;
    return EXIT_FAILURE;
  }
  rr.domain_id=di.id;
  bool haveSOA = false;
  while(zpt.get(rr)) {
    if(!rr.qname.isPartOf(zone)) {
      cerr<<"File contains record named '"<<rr.qname<<"' which is not part of zone '"<<zone<<"'"<<endl;
      return EXIT_FAILURE;
    }
    if (rr.qtype == QType::SOA) {
      if (haveSOA)
        continue;
      haveSOA = true;
    }
    try {
      DNSRecordContent::make(rr.qtype, QClass::IN, rr.content);
    }
    catch (const PDNSException &pe) {
      cerr<<"Bad record content in record for "<<rr.qname<<"|"<<rr.qtype.toString()<<": "<<pe.reason<<endl;
      return EXIT_FAILURE;
    }
    catch (const std::exception &e) {
      cerr<<"Bad record content in record for "<<rr.qname<<"|"<<rr.qtype.toString()<<": "<<e.what()<<endl;
      return EXIT_FAILURE;
    }
    db->feedRecord(rr, DNSName());
  }
  db->commitTransaction();
  return EXIT_SUCCESS;
}

static int createZone(const ZoneName &zone, const DNSName& nsname) {
  UtilBackend B; //NOLINT(readability-identifier-length)
  DomainInfo di;
  if (B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' exists already" << endl;
    return EXIT_FAILURE;
  }
  if ((B.getCapabilities() & DNSBackend::CAP_CREATE) == 0) {
    cerr << "None of the configured backends support zone creation." << endl;
    cerr << "Zone '" << zone << "' was not created." << endl;
    return EXIT_FAILURE;
  }
  if (zone.hasVariant() && (B.getCapabilities() & DNSBackend::CAP_VIEWS) == 0) {
    cerr << "None of the configured backends support views." << endl;
    cerr << "Zone '" << zone << "' was not created." << endl;
    return EXIT_FAILURE;
  }

  DNSResourceRecord rr;
  rr.qname = zone.operator const DNSName&();
  rr.auth = true;
  rr.ttl = ::arg().asNum("default-ttl");
  rr.qtype = "SOA";

  string soa = ::arg()["default-soa-content"];
  boost::replace_all(soa, "@", zone.operator const DNSName&().toStringNoDot());
  SOAData sd;
  try {
    fillSOAData(soa, sd);
  }
  catch(const std::exception& e) {
    cerr<<"Error while parsing default-soa-content ("<<soa<<"): "<<e.what()<<endl;
    cerr<<"Zone not created!"<<endl;
    return EXIT_FAILURE;
  }
  catch(const PDNSException& pe) {
    cerr<<"Error while parsing default-soa-content ("<<soa<<"): "<<pe.reason<<endl;
    cerr<<"Zone not created!"<<endl;
    return EXIT_FAILURE;
  }

  rr.content = makeSOAContent(sd)->getZoneRepresentation(true);

  cerr<<"Creating empty zone '"<<zone<<"'"<<endl;
  if (!createZoneWithDefaults(B, di, zone, DomainInfo::Native, vector<ComboAddress>())) {
    return EXIT_FAILURE;
  }

  rr.domain_id = di.id;
  di.backend->startTransaction(zone, di.id);
  di.backend->feedRecord(rr, DNSName());
  if(!nsname.empty()) {
    cout<<"Also adding one NS record"<<endl;
    rr.qtype=QType::NS;
    rr.content=nsname.toStringNoDot();
    di.backend->feedRecord(rr, DNSName());
  }

  di.backend->commitTransaction();

  // Zone is not secured yet, suggest applying default-soa-edit rule to the
  // serial number, if applicable.
  if (sd.serial == 0) {
    string edit_kind = ::arg()["default-soa-edit"];
    if (!edit_kind.empty() && !pdns_iequals(edit_kind, "NONE")) {
      cout << "Consider invoking 'pdnsutil increase-serial " << zone << "'" << endl;
    }
  }

  return EXIT_SUCCESS;
}

// add-record ZONE name type [ttl] "content" ["content"]
static int addOrReplaceRecord(bool isAdd, const vector<string>& cmds) {
  DNSResourceRecord rr;
  vector<DNSResourceRecord> newrrs;
  ZoneName zone(cmds.at(1));
  DNSName name;
  if (cmds.at(2) == "@")
    name=zone.operator const DNSName&();
  else
    name = DNSName(cmds.at(2)) + zone.operator const DNSName&();

  UtilBackend B; //NOLINT(readability-identifier-length)
  DomainInfo di;
  if(!B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' does not exist" << endl;
    return EXIT_FAILURE;
  }
  if (di.isSecondaryType() && !g_force) {
    throw PDNSException("Operation on a secondary zone is not allowed unless --force");
  }

  rr.qtype = DNSRecordContent::TypeToNumber(cmds.at(3));
  rr.ttl = ::arg().asNum("default-ttl");
  rr.auth = true;
  rr.domain_id = di.id;
  rr.qname = name;
  DNSResourceRecord oldrr;

  unsigned int contentStart = 4;
  if(cmds.size() > 5) {
    uint32_t ttl = atoi(cmds.at(4).c_str());
    if (std::to_string(ttl) == cmds.at(4)) {
      rr.ttl = ttl;
      contentStart++;
    }
  }

  di.backend->startTransaction(zone, UnknownDomainID);

  // Enforce that CNAME records can not be mixed with any other.
  // If we add a CNAME: there should be no existing records except for one
  // possible previous CNAME, which will get replaced.
  // If we add something else: there should be no existing CNAME record.
  bool reject{false};
  if (rr.qtype.getCode() == QType::CNAME) {
    di.backend->lookup(QType(QType::ANY), rr.qname, static_cast<int>(di.id));
    while (di.backend->get(oldrr)) {
      if (oldrr.qtype.getCode() == QType::CNAME) {
        if (not isAdd) {
          // Replacement operation: ok to replace CNAME with another
          continue;
        }
      }
      reject = true;
    }
    if (reject) {
      cerr<<"Attempting to add CNAME to "<<rr.qname<<" which already has existing records"<<endl;
      return EXIT_FAILURE;
    }
  }
  else {
    di.backend->lookup(QType(QType::CNAME), rr.qname, static_cast<int>(di.id));
    // TODO: It would be nice to have a way to complete a lookup and release its
    // resources without having to exhaust its results - here one successful
    // get() is all we need to decide to reject the operation. I'm looking at
    // you, lmdb backend.
    while (di.backend->get(oldrr)) {
      reject = true;
    }
    if (reject) {
      cerr<<"Attempting to add record to "<<rr.qname<<" which already has a CNAME record"<<endl;
      return EXIT_FAILURE;
    }
  }

  // Synthesize the new records.
  for(auto i = contentStart ; i < cmds.size() ; ++i) {
    rr.content = DNSRecordContent::make(rr.qtype.getCode(), QClass::IN, cmds.at(i))->getZoneRepresentation(true);

    bool skip{false};
    for (const auto &record: newrrs) {
      if (rr.content == record.content) {
        cout<<R"(Ignoring duplicate record content ")"<<rr.content<<R"(")"<<endl;
        skip = true;
        break;
      }
    }
    if (!skip) {
      newrrs.push_back(rr);
    }
  }

  if(isAdd) {
    // the 'add' case; preserve existing records, making sure to discard
    // would-be new records which contents are identical to the existing ones.
    vector<DNSResourceRecord> oldrrs;
    di.backend->lookup(rr.qtype, rr.qname, static_cast<int>(di.id));
    while (di.backend->get(oldrr)) {
      oldrrs.push_back(oldrr);
      for (auto iter = newrrs.begin(); iter != newrrs.end(); ++iter) {
        if (iter->content == oldrr.content) {
          newrrs.erase(iter);
          break;
        }
      }
    }
    oldrrs.insert(oldrrs.end(), newrrs.begin(), newrrs.end());
    newrrs = std::move(oldrrs);
  }
  else {
    cout<<"All existing records for "<<rr.qname<<" IN "<<rr.qtype.toString()<<" will be replaced"<<endl;
  }

  if(!di.backend->replaceRRSet(di.id, name, rr.qtype, newrrs)) {
    cerr<<"backend did not accept the new RRset, aborting"<<endl;
    return EXIT_FAILURE;
  }
  // need to be explicit to bypass the ueberbackend cache!
  di.backend->lookup(rr.qtype, name, di.id);
  cout<<"New rrset:"<<endl;
  while(di.backend->get(rr)) {
    cout<<rr.qname.toString()<<" "<<rr.ttl<<" IN "<<rr.qtype.toString()<<" "<<rr.content<<endl;
  }
  di.backend->commitTransaction();
  return EXIT_SUCCESS;
}

// addAutoPrimary add a new autoprimary
static int addAutoPrimary(const std::string& IP, const std::string& nameserver, const std::string& account)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  const AutoPrimary primary(IP, nameserver, account);
  if (B.autoPrimaryAdd(primary)) {
    return EXIT_SUCCESS;
  }
  cerr<<"could not find a backend with autosecondary support"<<endl;
  return EXIT_FAILURE;
}

static int removeAutoPrimary(const std::string &IP, const std::string &nameserver)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  const AutoPrimary primary(IP, nameserver, "");
  if ( B.autoPrimaryRemove(primary) ){
    return EXIT_SUCCESS;
  }
  cerr<<"could not find a backend with autosecondary support"<<endl;
  return EXIT_FAILURE;
}

static int listAutoPrimaries()
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  vector<AutoPrimary> primaries;
  if ( !B.autoPrimariesList(primaries) ){
    cerr<<"could not find a backend with autosecondary support"<<endl;
    return EXIT_FAILURE;
  }

  for(const auto& primary: primaries) {
    cout<<"IP="<<primary.ip<<", NS="<<primary.nameserver<<", account="<<primary.account<<endl;
  }

  return EXIT_SUCCESS;
}

// delete-rrset zone name type
static int deleteRRSet(const std::string& zone_, const std::string& name_, const std::string& type_)
{
  UtilBackend B; //NOLINT(readability-identifier-length)
  DomainInfo di;
  ZoneName zone(zone_);
  if(!B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' does not exist" << endl;
    return EXIT_FAILURE;
  }
  if (di.isSecondaryType() && !g_force) {
    throw PDNSException("Operation on a secondary zone is not allowed unless --force");
  }

  DNSName name;
  if(name_=="@")
    name=zone.operator const DNSName&();
  else
    name=DNSName(name_)+zone.operator const DNSName&();

  QType qt(QType::chartocode(type_.c_str()));
  di.backend->startTransaction(zone, UnknownDomainID);
  di.backend->replaceRRSet(di.id, name, qt, vector<DNSResourceRecord>());
  di.backend->commitTransaction();
  return EXIT_SUCCESS;
}

static int listAllZones(const std::string_view synopsis, const string &type="") {

  int kindFilter = -1;
  if (!type.empty()) {
    if (toUpper(type) == "PRIMARY" || toUpper(type) == "MASTER")
      kindFilter = 0;
    else if (toUpper(type) == "SECONDARY" || toUpper(type) == "SLAVE")
      kindFilter = 1;
    else if (toUpper(type) == "NATIVE")
      kindFilter = 2;
    else if (toUpper(type) == "PRODUCER")
      kindFilter = 3;
    else if (toUpper(type) == "CONSUMER")
      kindFilter = 4;
    else {
      return usage(synopsis);
    }
  }

  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  vector<DomainInfo> domains;
  B.getAllDomains(&domains, false, g_verbose);

  // Sort results, so that domains which have variants will appear
  // grouped in the output.
  std::sort(domains.begin(), domains.end());

  int count = 0;
  for (const auto& di: domains) {
    if (di.kind == kindFilter || kindFilter == -1) {
      cout<<di.zone<<endl;
      count++;
    }
  }

  if (g_verbose) {
    if (kindFilter != -1)
      cout<<type<<" zonecount: "<<count<<endl;
    else
      cout<<"All zonecount: "<<count<<endl;
  }

  return 0;
}

static int listMemberZones(const string& catalog)
{

  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  ZoneName catz(catalog);
  DomainInfo di;
  if (!B.getDomainInfo(catz, di)) {
    cerr << "Zone '" << catz << "' not found" << endl;
    return EXIT_FAILURE;
  }
  if (!di.isCatalogType()) {
    cerr << "Zone '" << catz << "' is not a catalog zone" << endl;
    return EXIT_FAILURE;
  }

  CatalogInfo::CatalogType type;
  if (di.kind == DomainInfo::Producer) {
    type = CatalogInfo::Producer;
  }
  else {
    type = CatalogInfo::Consumer;
  }

  vector<CatalogInfo> members;
  if (!di.backend->getCatalogMembers(catz, members, type)) {
    cerr << "Backend does not support catalog zones" << endl;
    return EXIT_FAILURE;
  }

  for (const auto& ci : members) {
    cout << ci.d_zone << endl;
  }

  if (g_verbose) {
    cout << "All zonecount: " << members.size() << endl;
  }

  return EXIT_SUCCESS;
}

static bool testAlgorithm(int algo)
{
  return DNSCryptoKeyEngine::testOne(algo);
}

static bool testAlgorithms()
{
  return DNSCryptoKeyEngine::testAll();
}

static void testSpeed(const ZoneName& zone, int cores)
{
  DNSResourceRecord rr;
  rr.qname=DNSName("blah")+zone.operator const DNSName&();
  rr.qtype=QType::A;
  rr.ttl=3600;
  rr.auth=true;
  rr.qclass = QClass::IN;

  UtilBackend db("key-only"); //NOLINT(readability-identifier-length)

  if ( db.backends.empty() )
  {
    throw runtime_error("No backends available for DNSSEC key storage");
  }

  ChunkedSigningPipe csp(zone, true, cores, 100);

  vector<DNSZoneRecord> signatures;
  uint32_t rnd;
  unsigned char* octets = (unsigned char*)&rnd;
  char tmp[25];
  DTime dt;
  dt.set();
  for(unsigned int n=0; n < 100000; ++n) {
    rnd = dns_random_uint32();
    snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d",
      octets[0], octets[1], octets[2], octets[3]);
    rr.content=tmp;

    snprintf(tmp, sizeof(tmp), "r-%u", rnd);
    rr.qname=DNSName(static_cast<const char *>(tmp))+zone.operator const DNSName&();
    DNSZoneRecord dzr;
    dzr.dr=DNSRecord(rr);
    if(csp.submit(dzr))
      while(signatures = csp.getChunk(), !signatures.empty())
        ;
  }
  cerr<<"Flushing the pipe, "<<csp.d_signed<<" signed, "<<csp.d_queued<<" queued, "<<csp.d_outstanding<<" outstanding"<< endl;
  cerr<<"Net speed: "<<csp.d_signed/ (dt.udiffNoReset()/1000000.0) << " sigs/s"<<endl;
  while(signatures = csp.getChunk(true), !signatures.empty())
      ;
  cerr<<"Done, "<<csp.d_signed<<" signed, "<<csp.d_queued<<" queued, "<<csp.d_outstanding<<" outstanding"<< endl;
  cerr<<"Net speed: "<<csp.d_signed/ (dt.udiff()/1000000.0) << " sigs/s"<<endl;
}

static void verifyCrypto(const string& zone)
{
  ZoneParserTNG zpt(zone);
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
  DNSResourceRecord rr;
  DNSKEYRecordContent drc;
  RRSIGRecordContent rrc;
  DSRecordContent dsrc;
  sortedRecords_t toSign;
  DNSName qname, apex;
  dsrc.d_digesttype=0;
  while(zpt.get(rr)) {
    if(rr.qtype.getCode() == QType::DNSKEY) {
      cerr<<"got DNSKEY!"<<endl;
      apex=rr.qname;
      drc = *std::dynamic_pointer_cast<DNSKEYRecordContent>(DNSRecordContent::make(QType::DNSKEY, QClass::IN, rr.content));
    }
    else if(rr.qtype.getCode() == QType::RRSIG) {
      cerr<<"got RRSIG"<<endl;
      rrc = *std::dynamic_pointer_cast<RRSIGRecordContent>(DNSRecordContent::make(QType::RRSIG, QClass::IN, rr.content));
    }
    else if(rr.qtype.getCode() == QType::DS) {
      cerr<<"got DS"<<endl;
      dsrc = *std::dynamic_pointer_cast<DSRecordContent>(DNSRecordContent::make(QType::DS, QClass::IN, rr.content));
    }
    else {
      qname = rr.qname;
      toSign.insert(DNSRecordContent::make(rr.qtype.getCode(), QClass::IN, rr.content));
    }
  }

  string msg = getMessageForRRSET(qname, rrc, toSign);
  cerr<<"Verify: "<<DNSCryptoKeyEngine::makeFromPublicKeyString(drc.d_algorithm, drc.d_key)->verify(msg, rrc.d_signature)<<endl;
  if(dsrc.d_digesttype != 0) {
    cerr<<"Calculated DS: "<<apex.toString()<<" IN DS "<<makeDSFromDNSKey(apex, drc, dsrc.d_digesttype).getZoneRepresentation()<<endl;
    cerr<<"Original DS:   "<<apex.toString()<<" IN DS "<<dsrc.getZoneRepresentation()<<endl;
  }
}

static bool disableDNSSECOnZone(DNSSECKeeper& dsk, const ZoneName& zone)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (!B.getDomainInfo(zone, di)){
    cerr << "No such zone in the database" << endl;
    return false;
  }

  string error, info;
  bool ret = dsk.unSecureZone(zone, error);
  if (!ret) {
    cerr << error << endl;
  }
  return ret;
}

static int setZoneOptionsJson(const ZoneName& zone, const string& options)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (!B.getDomainInfo(zone, di)) {
    cerr << "No such zone " << zone << " in the database" << endl;
    return EXIT_FAILURE;
  }
  if (!di.backend->setOptions(zone, options)) {
    cerr << "Could not find backend willing to accept new zone configuration" << endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static int setZoneOption(const ZoneName& zone, const string& type, const string& option, const set<string>& values)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di;
  CatalogInfo ci;

  if (!B.getDomainInfo(zone, di)) {
    cerr << "No such zone " << zone << " in the database" << endl;
    return EXIT_FAILURE;
  }

  CatalogInfo::CatalogType ctype;
  if (type == "producer") {
    ctype = CatalogInfo::CatalogType::Producer;
  }
  else {
    ctype = CatalogInfo::CatalogType::Consumer;
  }

  ci.fromJson(di.options, ctype);

  if (option == "coo") {
    ci.d_coo = (!values.empty() ? DNSName(*values.begin()) : DNSName());
  }
  else if (option == "unique") {
    ci.d_unique = (!values.empty() ? DNSName(*values.begin()) : DNSName());
  }
  else if (option == "group") {
    ci.d_group = values;
  }

  if (!di.backend->setOptions(zone, ci.toJson())) {
    cerr << "Could not find backend willing to accept new zone configuration" << endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

static int setZoneCatalog(const ZoneName& zone, const ZoneName& catalog)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (!B.getDomainInfo(zone, di)) {
    cerr << "No such zone " << zone << " in the database" << endl;
    return EXIT_FAILURE;
  }
  if (!di.backend->setCatalog(zone, catalog)) {
    cerr << "Could not find backend willing to accept new zone configuration" << endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static int setZoneAccount(const ZoneName& zone, const string &account)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (!B.getDomainInfo(zone, di)){
    cerr << "No such zone "<<zone<<" in the database" << endl;
    return EXIT_FAILURE;
  }
  if(!di.backend->setAccount(zone, account)) {
    cerr<<"Could not find backend willing to accept new zone configuration"<<endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static int setZoneKind(const ZoneName& zone, const DomainInfo::DomainKind kind)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (!B.getDomainInfo(zone, di)){
    cerr << "No such zone "<<zone<<" in the database" << endl;
    return EXIT_FAILURE;
  }
  if(!di.backend->setKind(zone, kind)) {
    cerr<<"Could not find backend willing to accept new zone configuration"<<endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static bool showZone(DNSSECKeeper& dnsseckeeper, const ZoneName& zone, bool exportDS = false) // NOLINT(readability-function-cognitive-complexity)
{
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (!B.getDomainInfo(zone, di)){
    cerr << "No such zone in the database" << endl;
    return false;
  }

  if (!di.account.empty()) {
      cout<<"This zone is owned by "<<di.account<<endl;
  }
  if (!exportDS) {
    cout << "This is a " << DomainInfo::getKindString(di.kind) << " zone";
    if (g_verbose) {
      cout << " (" << di.id << ")";
    }
    cout << endl;
    auto variant = di.zone.getVariant();
    if (!variant.empty()) {
      cout<<"Variant: " << variant << endl;
    }
    if (di.isPrimaryType()) {
      cout<<"Last SOA serial number we notified: "<<di.notified_serial<<" ";
      SOAData sd;
      if(B.getSOAUncached(zone, sd)) {
        if(sd.serial == di.notified_serial)
          cout<< "== ";
        else
          cout << "!= ";
        cout<<sd.serial<<" (serial in the database)"<<endl;
      }
    }
    else if (di.isSecondaryType()) {
      cout << "Primar" << addS(di.primaries, "y", "ies") << ": ";
      for (const auto& m : di.primaries)
        cout<<m.toStringWithPort()<<" ";
      cout<<endl;
      struct tm tm;
      localtime_r(&di.last_check, &tm);
      char buf[80];
      if(di.last_check != 0) {
        strftime(buf, sizeof(buf)-1, "%a %F %H:%M:%S", &tm);
      }
      else {
        strncpy(buf, "Never", sizeof(buf)-1);
      }
      buf[sizeof(buf)-1] = '\0';
      cout << "Last time we got update from primary: " << buf << endl;
      SOAData sd;
      if(B.getSOAUncached(zone, sd)) {
        cout<<"SOA serial in database: "<<sd.serial<<endl;
        cout<<"Refresh interval: "<<sd.refresh<<" seconds"<<endl;
      }
      else
        cout<<"No SOA serial found in database"<<endl;
    }
  }

  if(!dnsseckeeper.isSecuredZone(zone)) {
    auto &outstream = (exportDS ? cerr : cout);
    outstream << "Zone is not actively secured" << endl;
    if (exportDS) {
      // it does not make sense to proceed here, and it might be useful
      // for scripts to know that something is odd here
      return false;
    }
  }

  NSEC3PARAMRecordContent ns3pr;
  bool narrow = false;
  bool haveNSEC3=dnsseckeeper.getNSEC3PARAM(zone, &ns3pr, &narrow);

  DNSSECKeeper::keyset_t keyset=dnsseckeeper.getKeys(zone);

  if (!exportDS) {
    std::vector<std::string> meta;

    if (B.getDomainMetadata(zone, "TSIG-ALLOW-AXFR", meta) && !meta.empty()) {
      cout << "Zone has following allowed TSIG key(s): " << boost::join(meta, ",") << endl;
    }

    meta.clear();
    if (B.getDomainMetadata(zone, "AXFR-MASTER-TSIG", meta) && !meta.empty()) {
      cout << "Zone uses following TSIG key(s): " << boost::join(meta, ",") << endl;
    }

    std::map<std::string, std::vector<std::string> > metamap;
    if(B.getAllDomainMetadata(zone, metamap)) {
      cout<<"Metadata items: ";
      if(metamap.empty())
        cout<<"None";
      cout<<endl;

      for(const auto& m : metamap) {
        for(const auto& i : m.second)
          cout << '\t' << m.first<<'\t' << i <<endl;
      }
    }

  }

  if (dnsseckeeper.isPresigned(zone)) {
    if (!exportDS) {
      cout <<"Zone is presigned"<<endl;
    }

    // get us some keys
    vector<DNSKEYRecordContent> keys;
    DNSZoneRecord zr;

    di.backend->lookup(QType(QType::DNSKEY), zone.operator const DNSName&(), di.id );
    while(di.backend->get(zr)) {
      keys.push_back(*getRR<DNSKEYRecordContent>(zr.dr));
    }

    if(keys.empty()) {
      cerr << "No keys for zone '"<<zone<<"'."<<endl;
      return true;
    }

    if (!exportDS) {
      if(!haveNSEC3)
        cout<<"Zone has NSEC semantics"<<endl;
      else
        cout<<"Zone has " << (narrow ? "NARROW " : "") <<"hashed NSEC3 semantics, configuration: "<<ns3pr.getZoneRepresentation()<<endl;
      cout << "keys: "<<endl;
    }

    sort(keys.begin(),keys.end());
    reverse(keys.begin(),keys.end());
    for(const auto& key : keys) {
      string algname = DNSSECKeeper::algorithm2name(key.d_algorithm);

      int bits = -1;
      try {
        auto engine = DNSCryptoKeyEngine::makeFromPublicKeyString(key.d_algorithm, key.d_key); // throws on unknown algo or bad key
        bits=engine->getBits();
      }
      catch (const std::exception& e) {
        cerr<<"Could not process key to extract metadata: "<<e.what()<<endl;
      }
      if (!exportDS) {
        cout << (key.d_flags == 257 ? "KSK" : "ZSK") << ", tag = " << key.getTag() << ", algo = "<<(int)key.d_algorithm << ", bits = " << bits << endl;
        cout << "DNSKEY = " <<zone.operator const DNSName&().toString()<<" IN DNSKEY "<< key.getZoneRepresentation() << "; ( " + algname + " ) " <<endl;
      }

      const std::string prefix(exportDS ? "" : "DS = ");
      if (g_verbose) {
        cout<<prefix<<zone.operator const DNSName&().toString()<<" IN DS "<<makeDSFromDNSKey(zone.operator const DNSName&(), key, DNSSECKeeper::DIGEST_SHA1).getZoneRepresentation() << " ; ( SHA1 digest )" << endl;
      }
      cout<<prefix<<zone.operator const DNSName&().toString()<<" IN DS "<<makeDSFromDNSKey(zone.operator const DNSName&(), key, DNSSECKeeper::DIGEST_SHA256).getZoneRepresentation() << " ; ( SHA256 digest )" << endl;
      if (g_verbose) {
        try {
          string output=makeDSFromDNSKey(zone.operator const DNSName&(), key, DNSSECKeeper::DIGEST_GOST).getZoneRepresentation();
          cout<<prefix<<zone.operator const DNSName&().toString()<<" IN DS "<<output<< " ; ( GOST R 34.11-94 digest )" << endl;
        }
        catch(...)
        {}
      }
      try {
        string output=makeDSFromDNSKey(zone.operator const DNSName&(), key, DNSSECKeeper::DIGEST_SHA384).getZoneRepresentation();
        cout<<prefix<<zone.operator const DNSName&().toString()<<" IN DS "<<output<< " ; ( SHA-384 digest )" << endl;
      }
      catch(...)
      {}
    }
  }
  else if(keyset.empty())  {
    cerr << "No keys for zone '"<<zone<<"'."<<endl;
  }
  else {
    if (!exportDS) {
      if(!haveNSEC3)
        cout<<"Zone has NSEC semantics"<<endl;
      else
        cout<<"Zone has " << (narrow ? "NARROW " : "") <<"hashed NSEC3 semantics, configuration: "<<ns3pr.getZoneRepresentation()<<endl;
      cout << "keys: "<<endl;
    }

    for(const DNSSECKeeper::keyset_t::value_type& value :  keyset) {
      string algname = DNSSECKeeper::algorithm2name(value.first.getAlgorithm());
      if (!exportDS) {
        cout<<"ID = "<<value.second.id<<" ("<<DNSSECKeeper::keyTypeToString(value.second.keyType)<<")";
      }
      if (value.first.getKey()->getBits() < 1) {
        cout<<" <key missing or defunct, perhaps you should run pdnsutil hsm create-key>" <<endl;
        continue;
      }
      if (!exportDS) {
        cout<<", flags = "<<std::to_string(value.first.getFlags());
        cout<<", tag = "<<value.first.getDNSKEY().getTag();
        cout<<", algo = "<<(int)value.first.getAlgorithm()<<", bits = "<<value.first.getKey()->getBits()<<"\t"<<((int)value.second.active == 1 ? "  A" : "Ina")<<"ctive\t"<<(value.second.published ? " Published" : " Unpublished")<<"  ( " + algname + " ) "<<endl;
      }

      if (!exportDS) {
        if (value.second.keyType == DNSSECKeeper::KSK || value.second.keyType == DNSSECKeeper::CSK || ::arg().mustDo("direct-dnskey")) {
          cout<<DNSSECKeeper::keyTypeToString(value.second.keyType)<<" DNSKEY = "<<zone.operator const DNSName&().toString()<<" IN DNSKEY "<< value.first.getDNSKEY().getZoneRepresentation() << " ; ( "  + algname + " )" << endl;
        }
      }
      if (value.second.keyType == DNSSECKeeper::KSK || value.second.keyType == DNSSECKeeper::CSK) {
        const auto &key = value.first.getDNSKEY();
        const std::string prefix(exportDS ? "" : "DS = ");
        if (g_verbose) {
          cout<<prefix<<zone.operator const DNSName&().toString()<<" IN DS "<<makeDSFromDNSKey(zone.operator const DNSName&(), key, DNSSECKeeper::DIGEST_SHA1).getZoneRepresentation() << " ; ( SHA1 digest )" << endl;
        }
        cout<<prefix<<zone.operator const DNSName&().toString()<<" IN DS "<<makeDSFromDNSKey(zone.operator const DNSName&(), key, DNSSECKeeper::DIGEST_SHA256).getZoneRepresentation() << " ; ( SHA256 digest )" << endl;
        if (g_verbose) {
          try {
            string output=makeDSFromDNSKey(zone.operator const DNSName&(), key, DNSSECKeeper::DIGEST_GOST).getZoneRepresentation();
            cout<<prefix<<zone.operator const DNSName&().toString()<<" IN DS "<<output<< " ; ( GOST R 34.11-94 digest )" << endl;
          }
          catch(...)
          {}
        }
        try {
          string output=makeDSFromDNSKey(zone.operator const DNSName&(), key, DNSSECKeeper::DIGEST_SHA384).getZoneRepresentation();
          cout<<prefix<<zone.operator const DNSName&().toString()<<" IN DS "<<output<< " ; ( SHA-384 digest )" << endl;
        }
        catch(...)
        {}
      }
    }
  }
  if (!di.options.empty()) {
    cout << "Options:" << endl;
    cout << di.options << endl;
  }
  if (!di.catalog.empty()) {
    cout << "Catalog: " << endl;
    cout << di.catalog << endl;
  }
  return true;
}

static bool secureZone(DNSSECKeeper& dsk, const ZoneName& zone)
{
  // temp var for addKey
  int64_t id{-1};

  // parse attribute
  string k_algo = ::arg()["default-ksk-algorithm"];
  int k_size = ::arg().asNum("default-ksk-size");
  string z_algo = ::arg()["default-zsk-algorithm"];
  int z_size = ::arg().asNum("default-zsk-size");

  if (k_size < 0) {
     throw runtime_error("KSK key size must be equal to or greater than 0");
  }

  if (k_algo.empty() && z_algo.empty()) {
     throw runtime_error("Zero algorithms given for KSK+ZSK in total");
  }

  if (z_size < 0) {
     throw runtime_error("ZSK key size must be equal to or greater than 0");
  }

  if(dsk.isSecuredZone(zone)) {
    cerr << "Zone '"<<zone<<"' already secure, remove keys with pdnsutil remove-zone-key if needed"<<endl;
    return false;
  }

  DomainInfo di;
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  // di.backend and B are mostly identical
  if(!B.getDomainInfo(zone, di, false) || di.backend == nullptr) {
    cerr<<"Can't find a zone called '"<<zone<<"'"<<endl;
    return false;
  }

  if (di.kind == DomainInfo::Secondary) {
    cerr << "Warning! This is a secondary zone! If this was a mistake, please run" << endl;
    cerr<<"pdnsutil disable-dnssec "<<zone<<" right now!"<<endl;
  }

  if (!k_algo.empty()) { // Add a KSK
    if (k_size)
      cout << "Securing zone with key size " << k_size << endl;
    else
      cout << "Securing zone with default key size" << endl;

    cout << "Adding " << (z_algo.empty() ? "CSK (257)" : "KSK") << " with algorithm " << k_algo << endl;

    int k_real_algo = DNSSECKeeper::shorthand2algorithm(k_algo);

    if (!dsk.addKey(zone, true, k_real_algo, id, k_size, true, true)) {
      cerr<<"No backend was able to secure '"<<zone<<"', most likely because no DNSSEC"<<endl;
      cerr<<"capable backends are loaded, or because the backends have DNSSEC disabled."<<endl;
      cerr<<"For the Generic SQL backends, set the 'gsqlite3-dnssec', 'gmysql-dnssec' or"<<endl;
      cerr<<"'gpgsql-dnssec' flag. Also make sure the schema has been updated for DNSSEC!"<<endl;
      return false;
    }
  }

  if (!z_algo.empty()) {
    cout << "Adding " << (k_algo.empty() ? "CSK (256)" : "ZSK") << " with algorithm " << z_algo << endl;

    int z_real_algo = DNSSECKeeper::shorthand2algorithm(z_algo);

    if (!dsk.addKey(zone, false, z_real_algo, id, z_size, true, true)) {
      cerr<<"No backend was able to secure '"<<zone<<"', most likely because no DNSSEC"<<endl;
      cerr<<"capable backends are loaded, or because the backends have DNSSEC disabled."<<endl;
      cerr<<"For the Generic SQL backends, set the 'gsqlite3-dnssec', 'gmysql-dnssec' or"<<endl;
      cerr<<"'gpgsql-dnssec' flag. Also make sure the schema has been updated for DNSSEC!"<<endl;
      return false;
    }
  }

  if(!dsk.isSecuredZone(zone)) {
    cerr<<"Failed to secure zone. Is your backend dnssec enabled? (set "<<endl;
    cerr<<"gsqlite3-dnssec, or gmysql-dnssec etc). Check this first."<<endl;
    cerr<<"If you run with the BIND backend, make sure you have configured"<<endl;
    cerr<<"it to use DNSSEC with 'bind-dnssec-db=/path/fname' and"<<endl;
    cerr<<"'pdnsutil create-bind-db /path/fname'!"<<endl;
    return false;
  }

  // rectifyZone(dsk, zone);
  // showZone(dsk, zone);
  cout<<"Zone "<<zone<<" secured"<<endl;
  return true;
}

static int testSchema(DNSSECKeeper& dsk, const ZoneName& zone)
{
  cout<<"Note: test-schema will try to create the zone, but it will not remove it."<<endl;
  cout<<"Please clean up after this."<<endl;
  cout<<endl;
  cout<<"If this test reports an error and aborts, please check your database schema."<<endl;
  cout<<"Constructing UeberBackend"<<endl;
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  cout<<"Picking first backend - if this is not what you want, edit launch line!"<<endl;
  DNSBackend *db = B.backends[0].get();
  cout << "Creating secondary zone " << zone << endl;
  db->createSecondaryDomain("127.0.0.1", zone, "", "_testschema");
  cout << "Secondary zone created" << endl;

  DomainInfo di;
  // di.backend and B are mostly identical
  if(!B.getDomainInfo(zone, di) || di.backend == nullptr) {
    cout << "Can't find zone we just created, aborting" << endl;
    return EXIT_FAILURE;
  }
  db=di.backend;
  DNSResourceRecord rr, rrget;
  cout<<"Starting transaction to feed records"<<endl;
  db->startTransaction(zone, di.id);

  rr.qtype=QType::SOA;
  rr.qname=zone.operator const DNSName&();
  rr.ttl=86400;
  rr.domain_id=di.id;
  rr.auth=true;
  rr.content="ns1.example.com. ahu.example.com. 2012081039 7200 3600 1209600 3600";
  cout<<"Feeding SOA"<<endl;
  db->feedRecord(rr, DNSName());
  rr.qtype=QType::TXT;
  // 300 As
  rr.content="\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"";
  cout<<"Feeding overlong TXT"<<endl;
  db->feedRecord(rr, DNSName());
  cout<<"Committing"<<endl;
  db->commitTransaction();
  cout<<"Querying TXT"<<endl;
  db->lookup(QType(QType::TXT), zone.operator const DNSName&(), di.id);
  if(db->get(rrget))
  {
    DNSResourceRecord rrthrowaway;
    if(db->get(rrthrowaway)) // should not touch rr but don't assume anything
    {
      cout<<"Expected one record, got multiple, aborting"<<endl;
      return EXIT_FAILURE;
    }
    auto size=rrget.content.size();
    if(size != 302)
    {
      cout<<"Expected 302 bytes, got "<<size<<", aborting"<<endl;
      return EXIT_FAILURE;
    }
  }
  cout<<"[+] content field is over 255 bytes"<<endl;

  cout<<"Dropping all records, inserting SOA+2xA"<<endl;
  db->startTransaction(zone, di.id);

  rr.qtype=QType::SOA;
  rr.qname=zone.operator const DNSName&();
  rr.ttl=86400;
  rr.domain_id=di.id;
  rr.auth=true;
  rr.content="ns1.example.com. ahu.example.com. 2012081039 7200 3600 1209600 3600";
  cout<<"Feeding SOA"<<endl;
  db->feedRecord(rr, DNSName());

  rr.qtype=QType::A;
  rr.qname=DNSName("_underscore")+zone.operator const DNSName&();
  rr.content="127.0.0.1";
  db->feedRecord(rr, DNSName());

  rr.qname=DNSName("bla")+zone.operator const DNSName&();
  cout<<"Committing"<<endl;
  db->commitTransaction();

  cout<<"Securing zone"<<endl;
  secureZone(dsk, zone);
  cout<<"Rectifying zone"<<endl;
  rectifyZone(dsk, zone);
  cout<<"Checking underscore ordering"<<endl;
  DNSName before, after;
  db->getBeforeAndAfterNames(di.id, zone, DNSName("z")+zone.operator const DNSName&(), before, after);
  cout<<"got '"<<before.toString()<<"' < 'z."<<zone.operator const DNSName&().toString()<<"' < '"<<after.toString()<<"'"<<endl;
  if(before != DNSName("_underscore")+zone.operator const DNSName&())
  {
    cout<<"before is wrong, got '"<<before.toString()<<"', expected '_underscore."<<zone.operator const DNSName&().toString()<<"', aborting"<<endl;
    return EXIT_FAILURE;
  }
  if(after != zone.operator const DNSName&())
  {
    cout<<"after is wrong, got '"<<after.toString()<<"', expected '"<<zone.operator const DNSName&().toString()<<"', aborting"<<endl;
    return EXIT_FAILURE;
  }
  cout<<"[+] ordername sorting is correct for names starting with _"<<endl;
  cout<<"Setting low notified serial"<<endl;
  db->setNotified(di.id, 500);
  db->getDomainInfo(zone, di);
  if(di.notified_serial != 500) {
    cout<<"[-] Set serial 500, got back "<<di.notified_serial<<", aborting"<<endl;
    return EXIT_FAILURE;
  }
  cout<<"Setting serial that needs 32 bits"<<endl;
  try {
    db->setNotified(di.id, 2147484148);
  } catch(const PDNSException &pe) {
    cout<<"While setting serial, got error: "<<pe.reason<<endl;
    cout<<"aborting"<<endl;
    return EXIT_FAILURE;
  }
  db->getDomainInfo(zone, di);
  if(di.notified_serial != 2147484148) {
    cout<<"[-] Set serial 2147484148, got back "<<di.notified_serial<<", aborting"<<endl;
    return EXIT_FAILURE;
  }
  cout<<"[+] Big serials work correctly"<<endl;
  cout<<endl;
  cout << "End of tests, please remove " << zone << " from zones+records" << endl;

  return EXIT_SUCCESS;
}

static int addOrSetMeta(const ZoneName& zone, const string& kind, const vector<string>& values, bool clobber) {
  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di;

  if (!B.getDomainInfo(zone, di)) {
    cerr << "Invalid zone '" << zone << "'" << endl;
    return 1;
  }

  vector<string> all_metadata;

  if (!clobber) {
    B.getDomainMetadata(zone, kind, all_metadata);
  }

  all_metadata.insert(all_metadata.end(), values.begin(), values.end());

  if (!B.setDomainMetadata(zone, kind, all_metadata)) {
    cerr << "Unable to set meta for '" << zone << "'" << endl;
    return 1;
  }

  cout << "Set '" << zone << "' meta " << kind << " = " << boost::join(all_metadata, ", ") << endl;
  return 0;
}

// Command handlers

static int lmdbGetBackendVersion([[maybe_unused]] vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
  cout << "6" << endl; // FIXME this should reuse the constant from lmdbbackend but that is currently a #define in a .cc
  return 0;
}

static int testAlgorithm(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  if (testAlgorithm(pdns::checked_stoi<int>(cmds.at(1)))) {
    return 0;
  }
  return 1;
}

static int ipEncrypt(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3 || (cmds.size() == 4 && cmds.at(3) != "key")) {
    return usage(synopsis);
  }
#ifdef HAVE_IPCIPHER
  string key;
  if(cmds.size()==4) {
    if (B64Decode(cmds.at(2), key) < 0) {
      cerr << "Could not parse '" << cmds.at(3) << "' as base64" << endl;
      return 0;
    }
  }
  else {
    key = makeIPCipherKey(cmds.at(2));
  }
  return xcryptIP(cmds.at(0), cmds.at(1), key);
#else
  cerr<<cmds.at(0)<<" requires ipcipher support which is not available"<<endl;
  return 0;
#endif /* HAVE_IPCIPHER */
}

static int testAlgorithms([[maybe_unused]] vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
  if (testAlgorithms()) {
    return 0;
  }
  return 1;
}

static int listAlgorithms(vector<string>& cmds, const std::string_view synopsis)
{
  if ((cmds.size() == 2 && cmds.at(1) != "with-backend") || cmds.size() > 2) {
    return usage(synopsis);
  }

  cout<<"DNSKEY algorithms supported by this installation of PowerDNS:"<<endl;

  auto algosWithBackend = DNSCryptoKeyEngine::listAllAlgosWithBackend();
  for (const auto& algoWithBackend : algosWithBackend){
    string algoName = DNSSECKeeper::algorithm2name(algoWithBackend.first);
    cout<<std::to_string(algoWithBackend.first)<<" - "<<algoName;
    if (cmds.size() == 2 && cmds.at(1) == "with-backend") {
      cout<<" using "<<algoWithBackend.second;
    }
    cout<<endl;
  }
  return 0;
}


// these need reportAllTypes
static int createBindDb([[maybe_unused]] vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
#ifdef HAVE_SQLITE3
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  try {
    SSQLite3 db(cmds.at(1), "", true); // create=ok //NOLINT(readability-identifier-length)
    vector<string> statements;
    stringtok(statements, static_cast<char *>(sqlCreate), ";");
    for(const string& statement :  statements) {
      db.execute(statement);
    }
  }
  catch(SSqlException& se) {
    throw PDNSException("Error creating database in BIND backend: "+se.txtReason());
  }
  return 0;
#else
  cerr<<"create-bind-db requires building PowerDNS with SQLite3"<<endl;
  return 1;
#endif
}

static int rawLuaFromContent(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }

  // DNSResourceRecord rr;
  // rr.qtype = DNSRecordContent::TypeToNumber(cmds.at(1));
  // rr.content = cmds.at(2);
  auto drc = DNSRecordContent::make(DNSRecordContent::TypeToNumber(cmds.at(1)), QClass::IN, cmds.at(2));
  cout<<makeLuaString(drc->serialize(DNSName(), true))<<endl;

  return 0;
}

static int hashPassword(vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
  uint64_t workFactor = CredentialsHolder::s_defaultWorkFactor;
  if (cmds.size() > 1) {
    try {
      pdns::checked_stoi_into(workFactor, cmds.at(1));
    }
    catch (const std::exception& e) {
      cerr<<"Unable to parse the supplied work factor: "<<e.what()<<endl;
      return 1;
    }
  }

  auto password = CredentialsHolder::readFromTerminal();

  try {
    cout<<hashPassword(password.getString(), workFactor, CredentialsHolder::s_defaultParallelFactor, CredentialsHolder::s_defaultBlockSize)<<endl;
    return EXIT_SUCCESS;
  }
  catch (const std::exception& e) {
    cerr<<"Error while hashing the supplied password: "<<e.what()<<endl;
    return 1;
  }
}

static int zonemdVerifyFile(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }
  if(cmds[1]==".") {
    cmds[1].clear();
  }

  return zonemdVerifyFile(ZoneName(cmds[1]), cmds[2]);
}


// these need DNSSECKeeper
static int testSchema(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  return testSchema(dk, ZoneName(cmds.at(1)));
}

static int rectifyZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  int exitCode = 0;
  for(unsigned int n = 1; n < cmds.size(); ++n) { // NOLINT(readability-identifier-length)
    if (!rectifyZone(dk, ZoneName(cmds.at(n)))) {
      exitCode = 1;
    }
  }
  return exitCode;
}

static int rectifyAllZones(vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
  bool quiet = (cmds.size() >= 2 && cmds.at(1) == "quiet");
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!rectifyAllZones(dk, quiet || g_quiet)) {
    return 1;
  }
  return 0;
}

static int checkZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  return checkZone(dk, B, ZoneName(cmds.at(1)));
}

static int benchDb(vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
  dbBench(cmds.size() > 1 ? cmds.at(1) : "");
  return 0;
}

static int checkAllZones(vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
  bool exitOnError = ((cmds.size() >= 2 ? cmds.at(1) : "") == "exit-on-error");
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  return checkAllZones(dk, exitOnError);
}

static int listAllZones(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() > 2) {
    return usage(synopsis);
  }
  if (cmds.size() == 2) {
    return listAllZones(synopsis, cmds.at(1));
  }
  return listAllZones(synopsis);
}

static int listMemberZones(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() != 2) {
    return usage(synopsis);
  }
  return listMemberZones(cmds.at(1));
}

static int testSpeed(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }
  testSpeed(ZoneName(cmds.at(1)), pdns::checked_stoi<int>(cmds.at(2)));
  return 0;
}

static int verifyCrypto(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  verifyCrypto(cmds.at(1));
  return 0;
}

static int showZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!showZone(dk, ZoneName(cmds.at(1)))) {
    return 1;
  }
  return 0;
}

static int exportZoneDS(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!showZone(dk, ZoneName(cmds.at(1)), true)) {
    return 1;
  }
  return 0;
}

static int disableDNSSEC(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));
  if(!disableDNSSECOnZone(dk, zone)) {
    cerr << "Cannot disable DNSSEC on " << zone << endl;
    return 1;
  }
  return 0;
}

static int activateZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 3) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  // NOLINTNEXTLINE(readability-identifier-length)
  unsigned int id = atoi(cmds.at(2).c_str()); // if you make this pdns::checked_stoi, the error gets worse
  if(id == 0)
  {
    cerr << "Invalid KEY-ID '" << cmds.at(2) << "'" << endl;
    return 1;
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  try {
    dk.getKeyById(zone, id);
  } catch (std::exception& e) {
    cerr<<e.what()<<endl;
    return 1;
  }
  if (!dk.activateKey(zone, id)) {
    cerr<<"Activation of key failed"<<endl;
    return 1;
  }
  return 0;
}

static int deactivateZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 3) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  auto id = pdns::checked_stoi<unsigned int>(cmds.at(2)); // NOLINT(readability-identifier-length)
  if(id == 0)
  {
    cerr<<"Invalid KEY-ID"<<endl;
    return 1;
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  try {
    dk.getKeyById(zone, id);
  } catch (std::exception& e) {
    cerr<<e.what()<<endl;
    return 1;
  }
  if (!dk.deactivateKey(zone, id)) {
    cerr<<"Deactivation of key failed"<<endl;
    return 1;
  }
  return 0;
}

static int publishZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 3) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  // NOLINTNEXTLINE(readability-identifier-length)
  unsigned int id = atoi(cmds.at(2).c_str()); // if you make this pdns::checked_stoi, the error gets worse
  if(id == 0)
  {
    cerr << "Invalid KEY-ID '" << cmds.at(2) << "'" << endl;
    return 1;
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  try {
    dk.getKeyById(zone, id);
  } catch (std::exception& e) {
    cerr<<e.what()<<endl;
    return 1;
  }
  if (!dk.publishKey(zone, id)) {
    cerr<<"Publishing of key failed"<<endl;
    return 1;
  }
  return 0;
}

static int unpublishZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 3) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  // NOLINTNEXTLINE(readability-identifier-length)
  unsigned int id = atoi(cmds.at(2).c_str()); // if you make this pdns::checked_stoi, the error gets worse
  if(id == 0)
  {
    cerr << "Invalid KEY-ID '" << cmds.at(2) << "'" << endl;
    return 1;
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  try {
    dk.getKeyById(zone, id);
  } catch (std::exception& e) {
    cerr<<e.what()<<endl;
    return 1;
  }
  if (!dk.unpublishKey(zone, id)) {
    cerr<<"Unpublishing of key failed"<<endl;
    return 1;
  }
  return 0;
}

static int checkZoneKey(DNSSECKeeper &dsk, ZoneName &zone, int64_t keyId)
{
  if (keyId == -1) {
    cerr<<std::to_string(keyId)<<": Key was added, but backend does not support returning of key id"<<endl;
    return 0;
  }
  if (keyId < -1) {
    cerr<<std::to_string(keyId)<<": Key was added, but there was a failure while returning the key id"<<endl;
    return 1;
  }
  try {
    dsk.getKeyById(zone, keyId);
    cout<<std::to_string(keyId)<<endl;
  } catch (std::exception& exc) {
    cerr<<std::to_string(keyId)<<": Key was added, but there was a failure while reading it back: " <<exc.what()<<endl;
    return 1;
  }
  return 0;
}

static int addZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3 ) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));

  UtilBackend B("default"); //NOLINT(readability-identifier-length)
  DomainInfo di; //NOLINT(readability-identifier-length)

  if (!B.getDomainInfo(zone, di)){
    cerr << "No such zone in the database" << endl;
    return 0;
  }

  // Try to get algorithm, bits & ksk or zsk from commandline
  bool keyOrZone=true; // default to KSK
  int tmp_algo=0;
  int bits=0;
  int algorithm=-1;
  bool active=false;
  bool published=true;
  for(unsigned int n=2; n < cmds.size(); ++n) { //NOLINT(readability-identifier-length)
    if (pdns_iequals(cmds.at(n), "zsk")) {
      keyOrZone = false;
    }
    else if (pdns_iequals(cmds.at(n), "ksk")) {
      keyOrZone = true;
    }
    else if ((tmp_algo = DNSSECKeeper::shorthand2algorithm(cmds.at(n))) > 0) {
      algorithm = tmp_algo;
    }
    else if (pdns_iequals(cmds.at(n), "active")) {
      active=true;
    }
    else if (pdns_iequals(cmds.at(n), "inactive") || pdns_iequals(cmds.at(n), "passive")) { // 'passive' eventually needs to be removed
      active=false;
    }
    else if (pdns_iequals(cmds.at(n), "published")) {
      published = true;
    }
    else if (pdns_iequals(cmds.at(n), "unpublished")) {
      published = false;
    }
    else if (pdns::checked_stoi<int>(cmds.at(n)) != 0) {
      pdns::checked_stoi_into(bits, cmds.at(n));
    }
    else {
      cerr << "Unknown algorithm, key flag or size '" << cmds.at(n) << "'" << endl;
      return EXIT_FAILURE;
    }
  }
  // Use configuration defaults for missing values
  if (bits == 0) {
    if (keyOrZone) {
      bits = ::arg().asNum("default-ksk-size");
      if (bits < 0) {
         throw runtime_error("Default KSK key size must be equal to or greater than 0");
      }
    }
    else {
      bits = ::arg().asNum("default-zsk-size");
      if (bits < 0) {
         throw runtime_error("Default ZSK key size must be equal to or greater than 0");
      }
    }
  }
  if (algorithm == -1) {
    algorithm=DNSSECKeeper::ECDSA256; // default if no override in conf
    if (keyOrZone) {
      string k_algo = ::arg()["default-ksk-algorithm"];
      if (!k_algo.empty()) {
        if ((tmp_algo = DNSSECKeeper::shorthand2algorithm(k_algo)) > 0) {
          algorithm = tmp_algo;
        }
        else {
          cout<<"[Warning] Default KSK algorithm is invalid, using ECDSA256"<<endl;
        }
      }
    }
    else {
      string z_algo = ::arg()["default-zsk-algorithm"];
      if (!z_algo.empty()) {
        if ((tmp_algo = DNSSECKeeper::shorthand2algorithm(z_algo)) > 0) {
          algorithm = tmp_algo;
        }
        else {
          cout<<"[Warning] Default ZSK algorithm is invalid, using ECDSA256"<<endl;
        }
      }
    }
  }
  int64_t id{-1}; //NOLINT(readability-identifier-length)
  if (!dk.addKey(zone, keyOrZone, algorithm, id, bits, active, published)) {
    cerr<<"Adding key failed, perhaps DNSSEC not enabled in configuration?"<<endl;
    return 1;
  }
  cerr<<"Added a " << (keyOrZone ? "KSK" : "ZSK")<<" with algorithm = "<<algorithm<<", active="<<active<<endl;
  if (bits != 0) {
    cerr<<"Requested specific key size of "<<bits<<" bits"<<endl;
  }
  return checkZoneKey(dk, zone, id);
}

static int removeZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));
  auto id = pdns::checked_stoi<unsigned int>(cmds.at(2)); // NOLINT(readability-identifier-length)
  if (!dk.removeKey(zone, id)) {
     cerr<<"Cannot remove key " << id << " from " << zone <<endl;
    return 1;
  }
  return 0;
}

static int deleteZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  return deleteZone(ZoneName(cmds.at(1)));
}

static int createZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2 && cmds.size()!=3 ) {
    return usage(synopsis);
  }
  return createZone(ZoneName(cmds.at(1)), cmds.size() > 2 ? DNSName(cmds.at(2)) : DNSName());
}

static int createSecondaryZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3 ) {
    return usage(synopsis);
  }
  UtilBackend B; // NOLINT(readability-identifier-length)
  DomainInfo di; // NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));
  if (B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' exists already" << endl;
    return EXIT_FAILURE;
  }
  if ((B.getCapabilities() & DNSBackend::CAP_CREATE) == 0) {
    cerr << "None of the configured backends support zone creation." << endl;
    cerr << "Zone '" << zone << "' was not created." << endl;
    return EXIT_FAILURE;
  }
  if (zone.hasVariant() && (B.getCapabilities() & DNSBackend::CAP_VIEWS) == 0) {
    cerr << "None of the configured backends support views." << endl;
    cerr << "Zone '" << zone << "' was not created." << endl;
    return EXIT_FAILURE;
  }
  vector<ComboAddress> primaries;
  for (unsigned i=2; i < cmds.size(); i++) {
    primaries.emplace_back(cmds.at(i), 53);
  }
  cerr << "Creating secondary zone '" << zone << "', with primaries '" << comboAddressVecToString(primaries) << "'" << endl;
  if (!createZoneWithDefaults(B, di, zone, DomainInfo::Secondary, primaries)) {
    cerr << "Zone '" << zone << "' was not created!" << endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static int changeSecondaryZonePrimary(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3 ) {
    return usage(synopsis);
  }
  UtilBackend B; // NOLINT(readability-identifier-length)
  DomainInfo di; // NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));
  if (!B.getDomainInfo(zone, di)) {
    cerr << "Zone '" << zone << "' doesn't exist" << endl;
    return EXIT_FAILURE;
  }
  vector<ComboAddress> primaries;
  for (unsigned i=2; i < cmds.size(); i++) {
    primaries.emplace_back(cmds.at(i), 53);
  }
  cerr << "Updating secondary zone '" << zone << "', primaries to '" << comboAddressVecToString(primaries) << "'" << endl;
  try {
    di.backend->setPrimaries(zone, primaries);
    return EXIT_SUCCESS;
  }
  catch (PDNSException& e) {
    cerr << "Setting primary for zone '" << zone << "' failed: " << e.reason << endl;
    return EXIT_FAILURE;
  }
}

static int addRecord(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 5) {
    return usage(synopsis);
  }
  return addOrReplaceRecord(true, cmds);
}

static int addAutoprimary(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }
  return addAutoPrimary(cmds.at(1), cmds.at(2), cmds.size() > 3 ? cmds.at(3) : "");
}

static int removeAutoprimary(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }
  return removeAutoPrimary(cmds.at(1), cmds.at(2));
}

static int listAutoprimaries([[maybe_unused]] vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
  return listAutoPrimaries();
}

static int replaceRRSet(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 5) {
    return usage(synopsis);
  }
  return addOrReplaceRecord(false , cmds);
}

static int deleteRRSet(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 4) {
    return usage(synopsis);
  }
  return deleteRRSet(cmds.at(1), cmds.at(2), cmds.at(3));
}

static int listZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  if (cmds.at(1) == ".") {
    cmds.at(1).clear();
  }

  return listZone(ZoneName(cmds.at(1)));
}

static int editZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  if (cmds.at(1) == ".") {
    cmds.at(1).clear();
  }

  PDNSColors col(g_vm.count("no-colors") != 0);
  return editZone(ZoneName(cmds.at(1)), col);
}

static int clearZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 2) {
    return usage(synopsis);
  }
  if (cmds.at(1) == ".") {
    cmds.at(1).clear();
  }

  return clearZone(ZoneName(cmds.at(1)));
}

static int listKeys(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() > 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  string zname;
  if (cmds.size() == 2) {
    zname = cmds.at(1);
  }
  return listKeys(zname, dk);
}

static int loadZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }
  if (cmds.at(1) == ".") {
    cmds.at(1).clear();
  }

  for(size_t n=1; n + 2 <= cmds.size(); n+=2) { // NOLINT(readability-identifier-length)
    int ret = loadZone(ZoneName(cmds.at(n)), cmds.at(n + 1));
    if (ret != 0) {
      return ret;
    }
  }
  return 0;
}

static int secureZone(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  vector<ZoneName> mustRectify;
  unsigned int zoneErrors=0;
  for(unsigned int n = 1; n < cmds.size(); ++n) { // NOLINT(readability-identifier-length)
    ZoneName zone(cmds.at(n));
    dk.startTransaction(zone);
    if(secureZone(dk, zone)) {
      mustRectify.push_back(std::move(zone));
    } else {
      zoneErrors++;
    }
    dk.commitTransaction();
  }

  for(const auto& zone : mustRectify) {
    rectifyZone(dk, zone);
  }

  if (zoneErrors != 0) {
    return 1;
  }
  return 0;
}

static int secureAllZones(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() >= 2 && !pdns_iequals(cmds.at(1), "increase-serial")) {
    return usage(synopsis);
  }

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  UtilBackend B("default"); // NOLINT(readability-identifier-length)

  vector<DomainInfo> domainInfo;
  B.getAllDomains(&domainInfo, false, false);

  unsigned int zonesSecured=0;
  unsigned int zoneErrors=0;
  for(const DomainInfo& di :  domainInfo) { // NOLINT(readability-identifier-length)
    if(!dk.isSecuredZone(di.zone)) {
      cout<<"Securing "<<di.zone<<": ";
      if (secureZone(dk, di.zone)) {
        zonesSecured++;
        if (cmds.size() == 2) {
          if (increaseSerial(di.zone, dk) == 0) {
            continue;
          }
        } else {
          continue;
        }
      }
      zoneErrors++;
    }
  }

  cout<<"Secured: "<<zonesSecured<<" zones. Errors: "<<zoneErrors<<endl;

  if (zoneErrors != 0) {
    return 1;
  }
  return 0;
}

static int setKind(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 3) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  auto kind = DomainInfo::stringToKind(cmds.at(2));
  return setZoneKind(zone, kind);
}

static int setOptionsJson(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() != 3) {
    return usage(synopsis);
  }

  // Verify json
  if (!cmds.at(2).empty()) {
    std::string err;
    json11::Json doc = json11::Json::parse(cmds.at(2), err);
    if (doc.is_null()) {
      cerr << "Parsing of JSON document failed:" << err << endl;
      return EXIT_FAILURE;
    }
  }

  ZoneName zone(cmds.at(1));

  return setZoneOptionsJson(zone, cmds.at(2));
}

static int setOption(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 5 || (cmds.size() > 5 && (cmds.at(3) != "group"))) {
    return usage(synopsis);
  }
  if ((cmds.at(2) != "producer" && cmds.at(2) != "consumer") || (cmds.at(3) != "coo" && cmds.at(3) != "unique" && cmds.at(3) != "group")) {
    return usage(synopsis);
  }

  ZoneName zone(cmds.at(1));
  set<string> values;
  for (unsigned int n = 4; n < cmds.size(); ++n) { // NOLINT(readability-identifier-length)
    if (!cmds.at(n).empty()) {
      values.insert(cmds.at(n));
    }
  }

  return setZoneOption(zone, cmds.at(2), cmds.at(3), values);
}

static int setCatalog(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 2) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  ZoneName catalog; // Create an empty ZoneName()
  if (cmds.size() > 2 && !cmds.at(2).empty()) {
    catalog = ZoneName(cmds.at(2));
  }
  return setZoneCatalog(zone, catalog);
}

static int setAccount(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() != 3) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  return setZoneAccount(zone, cmds.at(2));
}

static int setNsec3(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }
  string nsec3params = cmds.size() > 2 ? cmds.at(2) : "1 0 0 -";
  bool narrow = cmds.size() > 3 && cmds.at(3) == "narrow";
  NSEC3PARAMRecordContent ns3pr(nsec3params);

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));
  if (auto wirelength = zone.operator const DNSName&().wirelength(); wirelength > 222) {
    cerr<<"Cannot enable NSEC3 for " << zone << " as it is too long (" << wirelength << " bytes, maximum is 222 bytes)"<<endl;
    return 1;
  }
  if(ns3pr.d_algorithm != 1) {
    cerr<<"NSEC3PARAM algorithm set to '"<<std::to_string(ns3pr.d_algorithm)<<"', but '1' is the only valid value"<<endl;
    return EXIT_FAILURE;
  }
  if (! dk.setNSEC3PARAM(zone, ns3pr, narrow)) {
    cerr<<"Cannot set NSEC3 param for " << zone << endl;
    return 1;
  }

  if (ns3pr.d_flags == 0) {
    cerr<<"NSEC3 set, ";
  }
  else {
    cerr<<"NSEC3 (opt-out) set, ";
  }

  if(dk.isSecuredZone(zone)) {
    cerr<<"Done, please rectify your zone if your backend needs it (or reload it if you are using the bindbackend)"<<endl;
  }
  else {
    cerr<<"Done, please secure and rectify your zone (or reload it if you are using the bindbackend)"<<endl;
  }

  return 0;
}

static int setPresigned(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!dk.setPresigned(ZoneName(cmds.at(1)))) {
    cerr << "Could not set presigned for " << cmds.at(1) << " (is DNSSEC enabled in your backend?)" << endl;
    return 1;
  }
  return 0;
}

static int setPublishCDNSKey(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 2 || (cmds.size() == 3 && cmds.at(2) != "delete")) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!dk.setPublishCDNSKEY(ZoneName(cmds.at(1)), (cmds.size() == 3 && cmds.at(2) == "delete"))) {
    cerr << "Could not set publishing for CDNSKEY records for " << cmds.at(1) << endl;
    return 1;
  }
  return 0;
}

static int setPublishCDs(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }

  // If DIGESTALGOS is unset
  if(cmds.size() == 2) {
    cmds.emplace_back("2");
  }

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!dk.setPublishCDS(ZoneName(cmds.at(1)), cmds.at(2))) {
    cerr << "Could not set publishing for CDS records for " << cmds.at(1) << endl;
    return 1;
  }
  return 0;
}

static int unsetPresigned(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!dk.unsetPresigned(ZoneName(cmds.at(1)))) {
    cerr << "Could not unset presigned on for " << cmds.at(1) << endl;
    return 1;
  }
  return 0;
}

static int unsetPublishCDNSKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!dk.unsetPublishCDNSKEY(ZoneName(cmds.at(1)))) {
    cerr << "Could not unset publishing for CDNSKEY records for " << cmds.at(1) << endl;
    return 1;
  }
  return 0;
}

static int unsetPublishCDs(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!dk.unsetPublishCDS(ZoneName(cmds.at(1)))) {
    cerr << "Could not unset publishing for CDS records for " << cmds.at(1) << endl;
    return 1;
  }
  return 0;
}

static int hashZoneRecord(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));
  DNSName record(cmds.at(2));
  NSEC3PARAMRecordContent ns3pr;
  bool narrow = false;
  if(!dk.getNSEC3PARAM(zone, &ns3pr, &narrow)) {
    cerr<<"The '"<<zone<<"' zone does not use NSEC3"<<endl;
    return 0;
  }
  if(narrow) {
    cerr<<"The '"<<zone<<"' zone uses narrow NSEC3, but calculating hash anyhow"<<endl;
  }

  cout<<toBase32Hex(hashQNameWithSalt(ns3pr, record))<<endl;
  return 0;
}

static int unsetNSec3(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!dk.unsetNSEC3PARAM(ZoneName(cmds.at(1)))) {
    cerr << "Cannot unset NSEC3 param for " << cmds.at(1) << endl;
    return 1;
  }
  cerr<<"Done, please rectify your zone if your backend needs it (or reload it if you are using the bindbackend)"<<endl;

  return 0;
}

static int exportZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  string zone = cmds.at(1);
  auto id = pdns::checked_stoi<unsigned int>(cmds.at(2)); // NOLINT(readability-identifier-length)
  DNSSECPrivateKey dpk = dk.getKeyById(ZoneName(zone), id);
  cout << dpk.getKey()->convertToISC() << endl;
  return 0;
}

static int exportZoneKeyPEM(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  string zone = cmds.at(1);
  auto id = pdns::checked_stoi<unsigned int>(cmds.at(2)); // NOLINT(readability-identifier-length)
  DNSSECPrivateKey dpk = dk.getKeyById(ZoneName(zone), id);
  dpk.getKey()->convertToPEMFile(*stdout);
  return 0;
}

static int increaseSerial(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  return increaseSerial(ZoneName(cmds.at(1)), dk);
}

static int importZoneKeyPEM(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 4) {
    return usage(synopsis);
  }

  ZoneName zone(cmds.at(1));
  const string filename = cmds.at(2);
  const auto algorithm = pdns::checked_stoi<unsigned int>(cmds.at(3));

  errno = 0;
  pdns::UniqueFilePtr filePtr{std::fopen(filename.c_str(), "r")};
  if (filePtr == nullptr) {
    auto errMsg = pdns::getMessageFromErrno(errno);
    throw runtime_error("Failed to open PEM file `" + filename + "`: " + errMsg);
  }

  DNSKEYRecordContent drc;
  shared_ptr<DNSCryptoKeyEngine> key{DNSCryptoKeyEngine::makeFromPEMFile(drc, algorithm, *filePtr, filename)};
  if (!key) {
    cerr << "Could not convert key from PEM to internal format" << endl;
    return 1;
  }

  DNSSECPrivateKey dpk;

  uint8_t algo = 0;
  pdns::checked_stoi_into(algo, cmds.at(3));
  if (algo == DNSSECKeeper::RSASHA1NSEC3SHA1) {
    algo = DNSSECKeeper::RSASHA1;
  }

  cerr << std::to_string(algo) << endl;

  uint16_t flags = 0;
  if (cmds.size() > 4) {
    if (pdns_iequals(cmds.at(4), "ZSK")) {
      flags = 256;
    }
    else if (pdns_iequals(cmds.at(4), "KSK")) {
      flags = 257;
    }
    else {
      cerr << "Unknown key flag '" << cmds.at(4) << "'" << endl;
      return 1;
    }
  }
  else {
    flags = 257; // ksk
  }
  dpk.setKey(key, flags, algo);

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  int64_t id{-1}; // NOLINT(readability-identifier-length)
  if (!dk.addKey(zone, dpk, id)) {
    cerr << "Adding key failed, perhaps DNSSEC not enabled in configuration?" << endl;
    return 1;
  }
  return checkZoneKey(dk, zone, id);
}

static int importZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  string fname = cmds.at(2);
  DNSKEYRecordContent drc;
  shared_ptr<DNSCryptoKeyEngine> key(DNSCryptoKeyEngine::makeFromISCFile(drc, fname.c_str()));

  uint16_t flags = 257;
  bool active=true;
  bool published=true;

  for(unsigned int n = 3; n < cmds.size(); ++n) { // NOLINT(readability-identifier-length)
    if (pdns_iequals(cmds.at(n), "ZSK")) {
      flags = 256;
    }
    else if (pdns_iequals(cmds.at(n), "KSK")) {
      flags = 257;
    }
    else if (pdns_iequals(cmds.at(n), "active")) {
      active = true;
    }
    else if (pdns_iequals(cmds.at(n), "passive") || pdns_iequals(cmds.at(n), "inactive")) { // passive eventually needs to be removed
      active = false;
    }
    else if (pdns_iequals(cmds.at(n), "published")) {
      published = true;
    }
    else if (pdns_iequals(cmds.at(n), "unpublished")) {
      published = false;
    }
    else {
      cerr << "Unknown key flag '" << cmds.at(n) << "'" << endl;
      return 1;
    }
  }

  DNSSECPrivateKey dpk;
  uint8_t algo = key->getAlgorithm();
  if (algo == DNSSECKeeper::RSASHA1NSEC3SHA1) {
    algo = DNSSECKeeper::RSASHA1;
  }
  dpk.setKey(key, flags, algo);

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  int64_t id{-1}; // NOLINT(readability-identifier-length)
  if (!dk.addKey(zone, dpk, id, active, published)) {
    cerr<<"Adding key failed, perhaps DNSSEC not enabled in configuration?"<<endl;
    return 1;
  }
  return checkZoneKey(dk, zone, id);
}

static int exportZoneDNSKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 3) {
    return usage(synopsis);
  }

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));
  auto id = pdns::checked_stoi<unsigned int>(cmds.at(2)); // NOLINT(readability-identifier-length)
  DNSSECPrivateKey dpk=dk.getKeyById(zone, id);
  cout << zone<<" IN DNSKEY "<<dpk.getDNSKEY().getZoneRepresentation() <<endl;
  return 0;
}

static int generateZoneKey(vector<string>& cmds, const std::string_view synopsis)
{
  if(cmds.size() < 2 ) {
    return usage(synopsis);
  }
  // need to get algorithm, bits & ksk or zsk from commandline
  bool keyOrZone=false;
  int tmp_algo=0;
  int bits=0;
  int algorithm=DNSSECKeeper::ECDSA256;
  for(unsigned int n=1; n < cmds.size(); ++n) { // NOLINT(readability-identifier-length)
    if (pdns_iequals(cmds.at(n), "zsk")) {
      keyOrZone = false;
    }
    else if (pdns_iequals(cmds.at(n), "ksk")) {
      keyOrZone = true;
    }
    else if ((tmp_algo = DNSSECKeeper::shorthand2algorithm(cmds.at(n))) > 0) {
      algorithm = tmp_algo;
    }
    else if (pdns::checked_stoi<int>(cmds.at(n)) != 0) {
      pdns::checked_stoi_into(bits, cmds.at(n));
    }
    else {
      cerr << "Unknown algorithm, key flag or size '" << cmds.at(n) << "'" << endl;
      return 0;
    }
  }
  cerr<<"Generating a " << (keyOrZone ? "KSK" : "ZSK")<<" with algorithm = "<<algorithm<<endl;
  if(bits != 0) {
    cerr<<"Requesting specific key size of "<<bits<<" bits"<<endl;
  }

  shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(algorithm));
  if(bits == 0) {
    if(algorithm <= 10) {
      bits = keyOrZone ? 2048 : 1024;
    }
    else {
      if(algorithm == DNSSECKeeper::ECCGOST || algorithm == DNSSECKeeper::ECDSA256 || algorithm == DNSSECKeeper::ED25519) {
        bits = 256;
      }
      else if(algorithm == DNSSECKeeper::ECDSA384) {
        bits = 384;
      }
      else if(algorithm == DNSSECKeeper::ED448) {
        bits = 456;
      }
      else {
        throw runtime_error("Can not guess key size for algorithm "+std::to_string(algorithm));
      }
    }
  }
  dpk->create(bits);
  DNSSECPrivateKey dspk;
  dspk.setKey(dpk, keyOrZone ? 257 : 256, algorithm);

  // print key to stdout
  cout << "Flags: " << dspk.getFlags() << endl <<
           dspk.getKey()->convertToISC() << endl;
  return 0;
}

static int generateTSIGKey(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }
  DNSName name(cmds.at(1));
  DNSName algo(cmds.at(2));
  string key;
  try {
    key = makeTSIGKey(algo);
  } catch(const PDNSException& e) {
    cerr << "Could not create new TSIG key " << name << " " << algo << ": "<< e.reason << endl;
    return 1;
  }

  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  if (B.setTSIGKey(name, DNSName(algo), key)) { // you are feeling bored, put up DNSName(algo) up earlier
    cout << "Create new TSIG key " << name << " " << algo << " " << key << endl;
  } else {
    cerr << "Failure storing new TSIG key " << name << " " << algo << " " << key << endl;
    return 1;
  }
  return 0;
}

static int importTSIGKey(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 4) {
    return usage(synopsis);
  }
  DNSName name(cmds.at(1));
  string algo = cmds.at(2);
  string key = cmds.at(3);

  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  if (B.setTSIGKey(name, DNSName(algo), key)) {
    cout << "Imported TSIG key " << name << " " << algo << endl;
  }
  else {
    cerr << "Failure importing TSIG key " << name << " " << algo << endl;
    return 1;
  }
  return 0;
}

static int deleteTSIGKey(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 2) {
    return usage(synopsis);
  }
  DNSName name(cmds.at(1));

  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  if (B.deleteTSIGKey(name)) {
    cout << "Deleted TSIG key " << name << endl;
  }
  else {
    cerr << "Failure deleting TSIG key " << name << endl;
    return 1;
  }
  return 0;
}

static int listTSIGKeys([[maybe_unused]] vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
  std::vector<struct TSIGKey> keys;
  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  if (B.getTSIGKeys(keys)) {
    for (const TSIGKey& key : keys) {
      cout << key.name.toString() << " " << key.algorithm.toString() << " " << key.key << endl;
    }
  }
  return 0;
}

static int activateTSIGKey(vector<string>& cmds, const std::string_view synopsis)
{
  string metaKey;
  if (cmds.size() < 4) {
    return usage(synopsis);
  }
  ZoneName zname(cmds.at(1));
  string name = cmds.at(2);
  if (cmds.at(3) == "primary" || cmds.at(3) == "producer") {
    metaKey = "TSIG-ALLOW-AXFR";
  }
  else if (cmds.at(3) == "secondary" || cmds.at(3) == "consumer") {
    metaKey = "AXFR-MASTER-TSIG";
  }
  else {
    return usage(synopsis);
  }
  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  DomainInfo di; // NOLINT(readability-identifier-length)
  if (!B.getDomainInfo(zname, di)) {
    cerr << "Zone '" << zname << "' does not exist" << endl;
    return 1;
  }
  std::vector<std::string> meta;
  if (!B.getDomainMetadata(zname, metaKey, meta)) {
    cerr << "Failure enabling TSIG key " << name << " for " << zname << endl;
    return 1;
  }
  bool found = false;
  for (const std::string& tmpname : meta) {
    if (tmpname == name) {
      found = true;
      break;
    }
  }
  if (!found) {
    meta.push_back(name);
  }
  if (B.setDomainMetadata(zname, metaKey, meta)) {
    cout << "Enabled TSIG key " << name << " for " << zname << endl;
  }
  else {
    cerr << "Failure enabling TSIG key " << name << " for " << zname << endl;
    return 1;
  }
  return 0;
}

static int deactivateTSIGKey(vector<string>& cmds, const std::string_view synopsis)
{
  string metaKey;
  if (cmds.size() < 4) {
    return usage(synopsis);
  }
  ZoneName zname(cmds.at(1));
  string name = cmds.at(2);
  if (cmds.at(3) == "primary" || cmds.at(3) == "producer") {
    metaKey = "TSIG-ALLOW-AXFR";
  }
  else if (cmds.at(3) == "secondary" || cmds.at(3) == "consumer") {
    metaKey = "AXFR-MASTER-TSIG";
  }
  else {
    return usage(synopsis);
  }

  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  DomainInfo di; // NOLINT(readability-identifier-length)
  if (!B.getDomainInfo(zname, di)) {
    cerr << "Zone '" << zname << "' does not exist" << endl;
    return 1;
  }
  std::vector<std::string> meta;
  if (!B.getDomainMetadata(zname, metaKey, meta)) {
    cerr << "Failure disabling TSIG key " << name << " for " << zname << endl;
    return 1;
  }
  auto iter = meta.begin();
  for (; iter != meta.end(); ++iter) {
    if (*iter == name) {
      break;
    }
  }
  if (iter != meta.end()) {
    meta.erase(iter);
  }
  if (B.setDomainMetadata(zname, metaKey, meta)) {
    cout << "Disabled TSIG key " << name << " for " << zname << endl;
  }
  else {
    cerr << "Failure disabling TSIG key " << name << " for " << zname << endl;
    return 1;
  }
  return 0;
}

static int getMeta(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 2) {
    return usage(synopsis);
  }
  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(1));
  vector<string> keys;

  DomainInfo di; // NOLINT(readability-identifier-length)
  if (!B.getDomainInfo(zone, di)) {
     cerr << "Invalid zone '" << zone << "'" << endl;
     return 1;
  }

  if (cmds.size() > 2) {
    keys.assign(cmds.begin() + 2, cmds.end());
    std::cout << "Metadata for '" << zone << "'" << endl;
    for(const auto& kind :  keys) {
      vector<string> meta;
      meta.clear();
      if (B.getDomainMetadata(zone, kind, meta)) {
        cout << kind << " = " << boost::join(meta, ", ") << endl;
      }
    }
  } else {
    std::map<std::string, std::vector<std::string> > meta;
    std::cout << "Metadata for '" << zone << "'" << endl;
    B.getAllDomainMetadata(zone, meta);
    for(const auto& each_meta: meta) {
      cout << each_meta.first << " = " << boost::join(each_meta.second, ", ") << endl;
    }
  }
  return 0;
}

static int setMeta(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }
  ZoneName zone(cmds.at(1));
  string kind = cmds.at(2);
  const static std::array<string, 7> multiMetaWhitelist = {"ALLOW-AXFR-FROM", "ALLOW-DNSUPDATE-FROM",
    "ALSO-NOTIFY", "TSIG-ALLOW-AXFR", "TSIG-ALLOW-DNSUPDATE", "GSS-ALLOW-AXFR-PRINCIPAL",
    "PUBLISH-CDS"};
  bool clobber = true;
  if (cmds.at(0) == "add-meta") {
    clobber = false;
    if (find(multiMetaWhitelist.begin(), multiMetaWhitelist.end(), kind) == multiMetaWhitelist.end() && kind.find("X-") != 0) {
      cerr<<"Refusing to add metadata to single-value metadata "<<kind<<endl;
      return 1;
    }
  }
  vector<string> meta(cmds.begin() + 3, cmds.end());
  return addOrSetMeta(zone, kind, meta, clobber);
}

#ifdef HAVE_P11KIT1 // {

static int HSMAssign(vector<string>& cmds, const std::string_view synopsis)
{
  DNSCryptoKeyEngine::storvector_t storvect;
  DomainInfo di; // NOLINT(readability-identifier-length)
  std::vector<DNSBackend::KeyData> keys;

  if (cmds.size() < 9) {
    return usage(synopsis);
  }

  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(2));

  // verify zone
  if (!B.getDomainInfo(zone, di)) {
    cerr << "Unable to assign module to unknown zone '" << zone << "'" << std::endl;
    return 1;
  }

  int algorithm = DNSSECKeeper::shorthand2algorithm(cmds.at(3));
  if (algorithm<0) {
    cerr << "Unable to use unknown algorithm '" << cmds.at(3) << "'" << std::endl;
    return 1;
  }

  bool keyOrZone = cmds.at(4) == "ksk";
  string module = cmds.at(5);
  string slot = cmds.at(6);
  string pin = cmds.at(7);
  string label = cmds.at(8);
  string pub_label;
  if (cmds.size() > 9) {
    pub_label = cmds.at(9);
  }
  else {
     pub_label = label;
  }

  std::ostringstream iscString;
  iscString << "Private-key-format: v1.2" << std::endl <<
    "Algorithm: " << algorithm << std::endl <<
    "Engine: " << module << std::endl <<
    "Slot: " << slot << std::endl <<
    "PIN: " << pin << std::endl <<
    "Label: " << label << std::endl <<
    "PubLabel: " << pub_label << std::endl;

  DNSKEYRecordContent drc;

  shared_ptr<DNSCryptoKeyEngine> dke(DNSCryptoKeyEngine::makeFromISCString(drc, iscString.str()));
  if(!dke->checkKey()) {
    cerr << "Invalid DNS Private Key in engine " << module << " slot " << slot << std::endl;
    return 1;
  }
  DNSSECPrivateKey dpk;
  dpk.setKey(dke, keyOrZone ? 257 : 256);

  // make sure this key isn't being reused.
  B.getDomainKeys(zone, keys);

  int64_t id{-1}; // NOLINT(readability-identifier-length)
  for(DNSBackend::KeyData& kd : keys) { // NOLINT(readability-identifier-length)
    if (kd.content == iscString.str()) {
      // it's this one, I guess...
      id = kd.id;
      break;
    }
  }

  if (id > -1) {
    cerr << "You have already assigned this key with ID=" << id << std::endl;
    return 1;
  }

  DNSSECKeeper dk; //NOLINT(readability-identifier-length)
  if (!dk.addKey(zone, dpk, id)) {
    cerr << "Unable to assign module slot to zone" << std::endl;
    return 1;
  }

  cerr << "Module " << module << " slot " << slot << " assigned to " << zone << " with key id " << id << endl;

  return 0;
}

static int HSMCreateKey(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 4) {
    return usage(synopsis);
  }
  UtilBackend B("default"); // NOLINT(readability-identifier-length)
  DomainInfo di; // NOLINT(readability-identifier-length)
  ZoneName zone(cmds.at(2));
  unsigned int id{0}; // NOLINT(readability-identifier-length)
  int bits = 2048;
  // verify zone
  if (!B.getDomainInfo(zone, di)) {
    cerr << "Unable to create key for unknown zone '" << zone << "'" << std::endl;
    return 1;
  }

  pdns::checked_stoi_into(id, cmds.at(3));
  std::vector<DNSBackend::KeyData> keys;
  if (!B.getDomainKeys(zone, keys)) {
    cerr << "No keys found for zone " << zone << std::endl;
    return 1;
  }

  std::unique_ptr<DNSCryptoKeyEngine> dke = nullptr;
  // lookup correct key
  for(DNSBackend::KeyData &kd : keys) { // NOLINT(readability-identifier-length)
    if (kd.id == id) {
      // found our key.
      DNSKEYRecordContent dkrc;
      dke = DNSCryptoKeyEngine::makeFromISCString(dkrc, kd.content);
    }
  }

  if (!dke) {
    cerr << "Could not find key with ID " << id << endl;
    return 1;
  }
  if (cmds.size() > 4) {
    pdns::checked_stoi_into(bits, cmds.at(4));
  }
  if (bits < 1) {
    cerr << "Invalid bit size " << bits << "given, must be positive integer";
    return 1;
  }
  try {
    dke->create(bits);
  } catch (PDNSException& e) {
     cerr << e.reason << endl;
     return 1;
  }

  cerr << "Key of size " << dke->getBits() << " created" << std::endl;
  return 0;
}

struct HSMcommandDispatcher {
  int (*handler)(std::vector<std::string>&, const std::string_view);
  const std::string_view synopsis; // one-line command synopsis
  const std::string_view help; // short description, may span multiple lines,
                               // every line starts with a tab for indent
};

// We use std::map instead of std::unordered_map here in order to be able
// to display a sorted list of commands (the main command set does not
// need this because the help display groups them in a temporary map).
// clang-format off
static const std::map<std::string, HSMcommandDispatcher> HSMcommands{
  {"assign", {HSMAssign,
    "hsm assign ZONE ALGORITHM {ksk|zsk} MODULE SLOT PIN LABEL [PUBLABEL]",
    "\tAssign a Hardware Signing Module to a ZONE"}},
  {"create-key", {HSMCreateKey,
    "hsm create-key ZONE KEY_ID [BITS]",
    "\tcreate a key using Hardware Signing Module for ZONE (use assign first);\n"
    "\tBITS defaults to 2048"}}
};
// clang-format on

#endif // }

static int HSM([[maybe_unused]] vector<string>& cmds, [[maybe_unused]] const std::string_view synopsis)
{
#ifdef HAVE_P11KIT1
  if (cmds.size() < 2 || cmds.at(1) == "help") {
    for (const auto& iter : HSMcommands) {
      cout << iter.second.synopsis << endl;
      cout << iter.second.help << endl;
    }
    return 0;
  }

  const auto iter = HSMcommands.find(cmds.at(1));
  if (iter != HSMcommands.end()) {
    const auto dispatcher = iter->second;
    return dispatcher.handler(cmds, dispatcher.synopsis);
  }

  cerr<<"Unknown hsm sub-command '"<<cmds.at(1)<<"'"<<endl;
  return 1;
#else
  cerr<<"PKCS#11 support not enabled"<<endl;
  return 1;
#endif
}

static int B2BMigrate(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }

  if (cmds.at(1) == cmds.at(2)) {
    cerr << "Error: b2b-migrate OLD NEW: OLD cannot be the same as NEW" << endl;
    return 1;
  }

  unique_ptr<DNSBackend> src{nullptr};
  unique_ptr<DNSBackend> tgt{nullptr};

  for (auto& backend : BackendMakers().all()) {
    if (backend->getPrefix() == cmds.at(1)) {
       src = std::move(backend);
    }
    else if (backend->getPrefix() == cmds.at(2)) {
       tgt = std::move(backend);
    }
  }

  if (src == nullptr) {
    cerr << "Unknown source backend '" << cmds.at(1) << "'" << endl;
    return 1;
  }
  if (tgt == nullptr) {
    cerr << "Unknown target backend '" << cmds.at(2) << "'" << endl;
    return 1;
  }

  if ((src->getCapabilities() & DNSBackend::CAP_LIST) == 0) {
    cerr << "Source backend does not support listing zone contents." << endl;
    return 1;
  }
  if ((tgt->getCapabilities() & DNSBackend::CAP_CREATE) == 0) {
    cerr << "Target backend does not support zone creation." << endl;
    return 1;
  }

  cout<<"Moving zone(s) from "<<src->getPrefix()<<" to "<<tgt->getPrefix()<<endl;

  vector<DomainInfo> domains;

  tgt->getAllDomains(&domains, false, true);
  if (!domains.empty()) {
    throw PDNSException("Target backend has zone(s), please clean it first");
  }

  src->getAllDomains(&domains, false, true);
  // iterate zones
  for(const DomainInfo& di: domains) { // NOLINT(readability-identifier-length)
    size_t nr{0}; // NOLINT(readability-identifier-length)
    size_t nc{0}; // NOLINT(readability-identifier-length)
    size_t nm{0}; // NOLINT(readability-identifier-length)
    size_t nk{0}; // NOLINT(readability-identifier-length)
    DomainInfo di_new;
    DNSResourceRecord rr; // NOLINT(readability-identifier-length)
    cout<<"Processing '"<<di.zone<<"'"<<endl;
    // create zone
    if (di.zone.hasVariant() && (tgt->getCapabilities() & DNSBackend::CAP_VIEWS) == 0) {
      cerr << "Target backend does not support views." << endl;
      throw PDNSException("Failed to create zone");
    }
    if (!tgt->createDomain(di.zone, di.kind, di.primaries, di.account)) {
      throw PDNSException("Failed to create zone");
    }
    if (!tgt->getDomainInfo(di.zone, di_new)) {
      throw PDNSException("Failed to create zone");
    }
    // move records
    if (!src->list(di.zone, di.id, true)) {
      throw PDNSException("Failed to list records");
    }
    nr=0;

    tgt->startTransaction(di.zone, di_new.id);

    while(src->get(rr)) {
      rr.domain_id = di_new.id;
      if (!tgt->feedRecord(rr, DNSName())) {
        throw PDNSException("Failed to feed record");
      }
      nr++;
    }

    // move comments
    nc=0;
    if (src->listComments(di.id)) {
      if ((tgt->getCapabilities() & DNSBackend::CAP_COMMENTS) == 0) {
        throw PDNSException("Target backend does not support comments - remove them first");
      }
      Comment c; // NOLINT(readability-identifier-length)
      while(src->getComment(c)) {
        c.domain_id = di_new.id;
        if (!tgt->feedComment(c)) {
          throw PDNSException("Failed to feed zone comments");
        }
        nc++;
      }
    }
    // move metadata
    nm=0;
    std::map<std::string, std::vector<std::string> > meta;
    if (src->getAllDomainMetadata(di.zone, meta)) {
      for (const auto& i : meta) { // NOLINT(readability-identifier-length)
        if (!tgt->setDomainMetadata(di.zone, i.first, i.second)) {
          throw PDNSException("Failed to feed zone metadata");
        }
        nm++;
      }
    }
    // move keys
    nk=0;
    // temp var for KeyID
    int64_t keyID{-1};
    std::vector<DNSBackend::KeyData> keys;
    if (src->getDomainKeys(di.zone, keys)) {
      for(const DNSBackend::KeyData& k: keys) { // NOLINT(readability-identifier-length)
        tgt->addDomainKey(di.zone, k, keyID);
        nk++;
      }
    }
    tgt->commitTransaction();
    cout<<"Moved "<<nr<<" record(s), "<<nc<<" comment(s), "<<nm<<" metadata(s) and "<<nk<<" cryptokey(s)"<<endl;
  }

  int ntk=0;
  // move tsig keys
  std::vector<struct TSIGKey> tkeys;
  if (src->getTSIGKeys(tkeys)) {
    for(auto& tk: tkeys) { // NOLINT(readability-identifier-length)
      if (!tgt->setTSIGKey(tk.name, tk.algorithm, tk.key)) {
        throw PDNSException("Failed to feed TSIG key");
      }
      ntk++;
    }
  }
  cout<<"Moved "<<ntk<<" TSIG key(s)"<<endl;

  cout<<"Remember to drop the old backend and run rectify-all-zones"<<endl;

  return 0;
}

static int backendCmd(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }

  std::unique_ptr<DNSBackend> matchingBackend{nullptr};

  for (auto& backend : BackendMakers().all()) {
    if (backend->getPrefix() == cmds.at(1)) {
      matchingBackend = std::move(backend);
    }
  }

  if (matchingBackend == nullptr) {
    cerr << "Unknown backend '" << cmds.at(1) << "'" << endl;
    return 1;
  }

  if ((matchingBackend->getCapabilities() & DNSBackend::CAP_DIRECT) == 0) {
    cerr << "Backend '" << cmds.at(1) << "' does not support direct commands" << endl;
    return 1;
  }

  for (auto i = next(begin(cmds), 2); i != end(cmds); ++i) {
    cerr << "== " << *i << endl;
    cout << matchingBackend->directBackendCmd(*i);
  }

  return 0;
}

static int backendLookup(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }

  std::unique_ptr<DNSBackend> matchingBackend{nullptr};

  for (auto& backend : BackendMakers().all()) {
    if (backend->getPrefix() == cmds.at(1)) {
      matchingBackend = std::move(backend);
    }
  }

  if (matchingBackend == nullptr) {
    cerr << "Unknown backend '" << cmds.at(1) << "'" << endl;
    return 1;
  }

  QType type = QType::ANY;
  if (cmds.size() > 3) {
    type = DNSRecordContent::TypeToNumber(cmds.at(3));
  }

  ZoneName name{cmds.at(2)};
  domainid_t domain_id{UnknownDomainID};

  if (name.hasVariant()) {
    ZoneName zone(name);
    do {
      SOAData soa;
      if (matchingBackend->getSOA(zone, UnknownDomainID, soa)) {
        domain_id = soa.domain_id;
        break;
      }
    } while (zone.chopOff());
    if (domain_id == UnknownDomainID) {
      cerr << "Backend found no matching zone" << endl;
      return 1;
    }
  }

  DNSPacket queryPacket(true);
  Netmask clientNetmask;
  if (cmds.size() > 4) {
    clientNetmask = cmds.at(4);
    queryPacket.setRealRemote(clientNetmask);
  }

  matchingBackend->lookup(type, name.operator const DNSName&(), domain_id, &queryPacket);

  bool found = false;
  DNSZoneRecord resultZoneRecord;
  while (matchingBackend->get(resultZoneRecord)) {
    cout << resultZoneRecord.dr.d_name.toString() << "\t" << std::to_string(resultZoneRecord.dr.d_ttl) << "\t" << QClass(resultZoneRecord.dr.d_class).toString() << "\t" << DNSRecordContent::NumberToType(resultZoneRecord.dr.d_type, resultZoneRecord.dr.d_class) << "\t" << resultZoneRecord.dr.getContent()->getZoneRepresentation();
    if (resultZoneRecord.scopeMask > 0) {
      clientNetmask.setBits(resultZoneRecord.scopeMask);
      cout << "\t" << "; " << clientNetmask.toString();
    }
    cout << endl;
    found = true;
  }
  if (!found) {
    cerr << "Backend found 0 zone record results";
    if (type != QType::ANY) {
      cerr << "- maybe retry with type ANY?";
    }
    cerr << endl;
    return 1;
  }

  return 0;
}

static int listView(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() != 2) {
    return usage(synopsis);
  }

  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  vector<ZoneName> ret;
  B.viewListZones(cmds.at(1), ret);

  for (const auto& zone : ret) {
    cout << zone << endl;
  }
  return 0;
}

static int listViews(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() != 1) {
    return usage(synopsis);
  }

  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  vector<string> ret;
  B.viewList(ret);

  for (const auto& view : ret) {
    cout << view << endl;
  }
  return 0;
}

static int viewAddZone(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }

  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  string view{cmds.at(1)};
  ZoneName zone{cmds.at(2)};
  if (!B.viewAddZone(view, zone)) {
    cerr<<"Operation failed."<<endl;
    return 1;
  }
  if (!g_quiet) {
    DomainInfo info;
    if (!B.getDomainInfo(zone, info)) {
      cout << "Zone '" << zone << "' does not exist yet."<< endl;
      cout << "Consider creating it with 'pdnsutil create-zone " << zone << "'" << endl;
    }
  }
  return 0;
}

static int viewDelZone(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 3) {
    return usage(synopsis);
  }

  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  string view{cmds.at(1)};
  ZoneName zone{cmds.at(2)};
  if (!B.viewDelZone(view, zone)) {
    cerr<<"Operation failed."<<endl;
    return 1;
 }
  return 0;
}

static int listNetwork(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.empty()) {
    return usage(synopsis);
  }

  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  vector<pair<Netmask, string> > ret;

  B.networkList(ret);

  for (auto &[net, view] : ret) {
    cout<<net.toString()<<"\t"<<view<<endl; // FIXME: this prints "invalid" when there is no match
  }
  return 0;
}

static int setNetwork(vector<string>& cmds, const std::string_view synopsis)
{
  if (cmds.size() < 2) {
    return usage(synopsis);
  }

  UtilBackend B("default"); //NOLINT(readability-identifier-length)

  Netmask net{cmds.at(1)};
  string view{};
  if (cmds.size() > 2) {
    view = cmds.at(2);
  }
  if (!B.networkSet(net, view)) {
    cerr<<"Operation failed."<<endl;
    return 1;
 }
  return 0;
}

enum commandGroup {
  GROUP_AUTOPRIMARY,
  GROUP_CATALOG,
  GROUP_META,
  GROUP_ZONE,
  GROUP_RRSET,
  GROUP_DNSSEC,
  GROUP_CDNSKEY,
  GROUP_NSEC3,
  GROUP_TSIGKEY,
  GROUP_ZONEKEY,
  GROUP_VIEWS,
  GROUP_OTHER,
  GROUP_LAST,
  GROUP_FIRST = GROUP_AUTOPRIMARY,
};

static const std::array<std::string_view, GROUP_LAST> groupNames{
  "Autoprimary",
  "Catalog",
  "Metadata",
  "Zone",
  "RRSet",
  "DNSSEC",
  "CDS/CDNSKEY",
  "NSEC3",
  "TSIG key",
  "Zone key",
  "Views",
  "Other"
};

struct commandDispatcher {
  bool requiresInitialization; // need to invoke reportAllTypes() before handler
  int (*handler)(std::vector<std::string>&, const std::string_view);
  commandGroup group;
  const std::string_view synopsis; // one-line command synopsis
  const std::string_view help; // short description, may span multiple lines,
                               // every line starts with a tab for indent
};

// clang-format off
static const std::unordered_map<std::string, commandDispatcher> commands{
  {"activate-tsig-key", {true, activateTSIGKey, GROUP_TSIGKEY,
   "activate-tsig-key ZONE NAME {primary|secondary|producer|consumer}",
   "\tEnable TSIG authenticated AXFR using the key NAME for ZONE"}},
  {"activate-zone-key", {true, activateZoneKey, GROUP_ZONEKEY,
   "activate-zone-key ZONE KEY_ID",
   "\tActivate the key with key id KEY_ID in ZONE"}},
  {"add-autoprimary", {true, addAutoprimary, GROUP_AUTOPRIMARY,
   "add-autoprimary IP NAMESERVER [ACCOUNT]",
   "\tAdd a new autoprimary "}},
  {"add-meta", {true, setMeta, GROUP_META,
   "add-meta ZONE KIND VALUE [VALUE...]",
   "\tAdd zone metadata, this adds to the existing KIND"}},
  {"add-record", {true, addRecord, GROUP_ZONE,
   R"(add-record ZONE NAME TYPE [TTL] "CONTENT" ["CONTENT"...])",
   "\tAdd one or more records to ZONE"}},
  {"add-zone-key", {true, addZoneKey, GROUP_ZONEKEY,
   "add-zone-key ZONE [zsk|ksk] [BITS] [active|inactive] [published|unpublished]\n"
   "    [rsasha1|rsasha1-nsec3-sha1|rsasha256|rsasha512|ecdsa256|ecdsa384"
#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO_ED25519)
        "|ed25519"
#endif
#if defined(HAVE_LIBCRYPTO_ED448)
        "|ed448"
#endif
        "]",
   "\tAdd a ZSK or KSK to zone with specific algorithm and size in bits.\n"
   "\tIf zsk or ksk is omitted, defaults to zsk"}},
  {"b2b-migrate", {true, B2BMigrate, GROUP_OTHER,
   "b2b-migrate OLD NEW",
   "\tMove all data from one backend to another"}},
  {"backend-cmd", {true, backendCmd, GROUP_OTHER,
   "backend-cmd BACKEND CMD [CMD...]",
   "\tPerform one or more backend commands"}},
  {"backend-lookup", {true, backendLookup, GROUP_OTHER,
   "backend-lookup BACKEND NAME [[TYPE] CLIENT_IP_SUBNET]",
   "\tPerform a backend lookup of NAME, TYPE (defaulting to ANY) and\n"
   "\tCLIENT_IP_SUBNET"}},
  {"bench-db", {true, benchDb, GROUP_OTHER,
   "bench-db [FILENAME]",
   "\tBenchmark database backend with queries, one zone per line"}},
  {"change-secondary-zone-primary", {true, changeSecondaryZonePrimary, GROUP_ZONE,
   "change-secondary-zone-primary ZONE PRIMARY_IP [PRIMARY_IP...]",
   "\tChange secondary zone ZONE primary IP address(es) to PRIMARY_IP"}},
  {"check-all-zones", {true, checkAllZones, GROUP_ZONE,
   "check-all-zones [exit-on-error]",
   "\tCheck all zones for correctness. Use exit-on-error to exit immediately\n"
   "\tupon finding the first error in any zone"}},
  {"check-zone", {true, checkZone, GROUP_ZONE,
   "check-zone ZONE",
   "\tCheck a zone for correctness"}},
  {"clear-zone", {true, clearZone, GROUP_ZONE,
   "clear-zone ZONE",
   "\tClear all records of a zone, but keep everything else"}},
  {"create-bind-db", {true, createBindDb, GROUP_DNSSEC,
   "create-bind-db FILENAME",
   "\tCreate DNSSEC db for BIND backend (bind-dnssec-db)"}},
  {"create-secondary-zone", {true, createSecondaryZone, GROUP_ZONE,
   "create-secondary-zone ZONE PRIMARY_IP [PRIMARY_IP...]",
   "\tCreate secondary zone ZONE with primary IP address(es) PRIMARY_IP"}},
  {"create-zone", {true, createZone, GROUP_ZONE,
   "create-zone ZONE [NSNAME]",
   "\tCreate empty zone ZONE"}},
  {"deactivate-tsig-key", {true, deactivateTSIGKey, GROUP_TSIGKEY,
   "deactivate-tsig-key ZONE NAME {primary|secondary|producer|consumer}",
   "\tDisable TSIG authenticated AXFR using the key NAME for ZONE"}},
  {"deactivate-zone-key", {true, deactivateZoneKey, GROUP_ZONEKEY,
   "deactivate-zone-key ZONE KEY_ID",
   "\tDeactivate the key with key id KEY_ID in ZONE"}},
  {"delete-rrset", {true, deleteRRSet, GROUP_RRSET,
   "delete-rrset ZONE NAME TYPE",
   "\tDelete named RRSET from ZONE"}},
  {"delete-tsig-key", {true, deleteTSIGKey, GROUP_TSIGKEY,
   "delete-tsig-key NAME",
   "\tDelete TSIG key (warning: will not unmap key!)"}},
  {"delete-zone", {true, deleteZone, GROUP_ZONE,
   "delete-zone ZONE",
   "\tDelete zone ZONE"}},
  {"disable-dnssec", {true, disableDNSSEC, GROUP_DNSSEC,
   "disable-dnssec ZONE",
   "\tDeactivate all keys and unset PRESIGNED in ZONE"}},
  {"edit-zone", {true, editZone, GROUP_ZONE,
   "edit-zone ZONE",
   "\tEdit zone contents using $EDITOR"}},
  {"export-zone-dnskey", {true, exportZoneDNSKey, GROUP_CDNSKEY,
   "export-zone-dnskey ZONE KEY_ID",
   "\tExport the public DNSKEY with the given ID to stdout"}},
  {"export-zone-ds", {true, exportZoneDS, GROUP_CDNSKEY,
   "export-zone-ds ZONE",
   "\tExport all KSK DS records for ZONE to stdout"}},
  {"export-zone-key", {true, exportZoneKey, GROUP_ZONEKEY,
   "export-zone-key ZONE KEY_ID",
   "\tExport the private key with the given ID to stdout"}},
  {"export-zone-key-pem", {true, exportZoneKeyPEM, GROUP_ZONEKEY,
   "export-zone-key-pem ZONE KEY_ID",
   "\tExport the private key with the given ID to stdout in PEM format"}},
  {"generate-tsig-key", {true, generateTSIGKey, GROUP_TSIGKEY,
   "generate-tsig-key NAME ALGORITHM",
   "\tGenerate new TSIG key.\n"
   "\tALGORITHM is one of hmac-{md5,sha1,sha224,sha256,sha384,sha512}"}},
  {"generate-zone-key", {true, generateZoneKey, GROUP_ZONEKEY,
   "generate-zone-key {zsk|ksk} [ALGORITHM] [BITS]",
   "\tGenerate a ZSK or KSK to stdout with specified ALGORITHM and BITS"}},
  {"get-meta", {true, getMeta, GROUP_META,
   "get-meta ZONE [KIND...]",
   "\tGet zone metadata. If no KIND is given, lists all known"}},
  {"hash-password", {true, hashPassword, GROUP_OTHER,
   "hash-password [WORK FACTOR]",
   "\tAsk for a plaintext password or API key and output a salted and hashed\n"
   "\tversion"}},
  {"hash-zone-record", {true, hashZoneRecord, GROUP_NSEC3,
   "hash-zone-record ZONE RNAME",
   "\tCalculate the NSEC3 hash for RNAME in ZONE"}},
  {"hsm", {true, HSM, GROUP_OTHER,
#ifdef HAVE_P11KIT1
   "hsm SUB_COMMAND [ARGUMENTS...]",
   "\tHardware Signing Module-related commands.\n"
   "\tUse \"hsm help\" to get more information"
#else
   "", "" // not functional so hide it
#endif
   }},
  {"import-tsig-key", {true, importTSIGKey, GROUP_TSIGKEY,
   "import-tsig-key NAME ALGORITHM KEY",
   "\tImport TSIG key"}},
  {"import-zone-key", {true, importZoneKey, GROUP_ZONEKEY,
   "import-zone-key ZONE FILE [active|inactive] [ksk|zsk] [published|unpublished]",
   "\tImport from a file a private key, ZSK or KSK; defaults to KSK, active\n"
   "\tand published"}},
  {"import-zone-key-pem", {true, importZoneKeyPEM, GROUP_ZONEKEY,
   "import-zone-key-pem ZONE FILE ALGORITHM [ksk|zsk]}",
   "\tImport a private key from a PEM file"}},
  {"increase-serial", {true, increaseSerial, GROUP_ZONE,
   "increase-serial ZONE",
   "\tIncreases the SOA-serial by 1. Uses SOA-EDIT"}},
  {"ipdecrypt", {false, ipEncrypt, GROUP_OTHER,
   "ipdecrypt IP_ADDRESS PASSPHRASE_OR_KEY [key]",
   "\tDecrypt IP address using passphrase or base64 key"}},
  {"ipencrypt", {false, ipEncrypt, GROUP_OTHER,
   "ipencrypt IP_ADDRESS PASSPHRASE_OR_KEY [key]",
   "\tEncrypt IP address using passphrase or base64 key"}},
  {"list-algorithms", {false, listAlgorithms, GROUP_DNSSEC,
   "list-algorithms [with-backend]",
   "\tList all DNSSEC algorithms supported, optionally also listing the\n"
   "\tcryptographic library used"}},
  {"list-all-zones", {true, listAllZones, GROUP_ZONE,
   "list-all-zones [primary|secondary|native|producer|consumer]",
   "\tList all active zone names.\n"
   "\tUse --verbose (-v) to include disabled or empty zones"}},
  {"list-autoprimaries", {true, listAutoprimaries, GROUP_AUTOPRIMARY,
   "list-autoprimaries",
   "\tList all autoprimaries"}},
  {"list-keys", {true, listKeys, GROUP_DNSSEC,
   "list-keys [ZONE]",
   "\tList DNSSEC keys for ZONE.\n"
   "\tWhen ZONE is unset, display keys for all active zones"}},
  {"list-member-zones", {true, listMemberZones, GROUP_ZONE,
   "list-member-zones CATALOG",
   "\tList all members of catalog zone CATALOG"}},
  {"list-networks", {true, listNetwork, GROUP_VIEWS,
   "list-networks",
   "\tList all defined networks with their chosen views"}},
  {"list-tsig-keys", {true, listTSIGKeys, GROUP_TSIGKEY,
   "list-tsig-keys",
   "\tList all TSIG keys"}},
  {"list-view", {true, listView, GROUP_VIEWS,
   "list-view VIEW",
   "\tList all zones within VIEW"}},
  {"list-views", {true, listViews, GROUP_VIEWS,
   "list-views",
   "\tList all view names"}},
  {"list-zone", {true, listZone, GROUP_ZONE,
   "list-zone ZONE",
   "\tList zone contents"}},
  {"lmdb-get-backend-version", {false, lmdbGetBackendVersion, GROUP_OTHER,
   "lmdb-get-backend-version",
   "\tGet schema version supported by backend"}},
  {"load-zone", {true, loadZone, GROUP_ZONE,
   "load-zone ZONE FILENAME [ZONE FILENAME]...",
   "\tLoad ZONE from FILENAME, possibly creating zone or atomically replacing\n"
   "\tcontents; --verbose or -v will also include the keys for disabled or\n"
   "\tempty zones"}},
  {"publish-zone-key", {true, publishZoneKey, GROUP_ZONEKEY,
   "publish-zone-key ZONE KEY_ID",
   "\tPublish the zone key with key id KEY_ID in ZONE"}},
  {"raw-lua-from-content", {true, rawLuaFromContent, GROUP_OTHER,
   "raw-lua-from-content TYPE CONTENT",
   "\tDisplay record contents in a form suitable for dnsdist's\n"
   "\t`SpoofRawAction`"}},
  {"rectify-all-zones", {true, rectifyAllZones, GROUP_DNSSEC,
   "rectify-all-zones [quiet]",
   "\tRectify all zones. Optionally quiet output with errors only"}},
  {"rectify-zone", {true, rectifyZone, GROUP_DNSSEC,
   "rectify-zone ZONE [ZONE...]",
   "\tFix up DNSSEC fields (order, auth)"}},
  {"remove-autoprimary", {true, removeAutoprimary, GROUP_AUTOPRIMARY,
   "remove-autoprimary IP NAMESERVER",
   "\tRemove an autoprimary"}},
  {"remove-zone-key", {true, removeZoneKey, GROUP_ZONEKEY,
   "remove-zone-key ZONE KEY_ID",
   "\tRemove key with KEY_ID from ZONE"}},
  {"replace-rrset", {true, replaceRRSet, GROUP_RRSET,
   R"(replace-rrset ZONE NAME TYPE [TTL] "CONTENT" ["CONTENT"...])",
   "\tReplace named RRSET from ZONE"}},
  {"secure-all-zones", {true, secureAllZones, GROUP_DNSSEC,
   "secure-all-zones [increase-serial]",
   "\tSecure all zones without keys"}},
  {"secure-zone", {true, secureZone, GROUP_DNSSEC,
   "secure-zone ZONE [ZONE...]",
   "\tAdd DNSSEC to zone ZONE"}},
  {"set-account", {true, setAccount, GROUP_ZONE,
   "set-account ZONE ACCOUNT",
   "\tChange the account (owner) of ZONE to ACCOUNT"}},
  {"set-catalog", {true, setCatalog, GROUP_CATALOG,
   "set-catalog ZONE [CATALOG]",
   "\tChange the catalog of ZONE to CATALOG, or removes ZONE from its current\n"
   "\tcatalog if no catalog provided"}},
  {"set-kind", {true, setKind, GROUP_ZONE,
   "set-kind ZONE KIND",
   "\tChange the kind of ZONE to KIND (primary, secondary, native, producer,\n"
   "\tor consumer)"}},
  {"set-meta", {true, setMeta, GROUP_META,
   "set-meta ZONE KIND [VALUE...]",
   "\tSet zone metadata, replacing all existing records of KIND, optionally\n"
   "\tproviding a value. An omitted value clears the metadata"}},
  {"set-network", {true, setNetwork, GROUP_VIEWS,
   "set-network NET [VIEW]",
   "\tSet the view for a network, or delete if no view argument."}},
  {"set-nsec3", {true, setNsec3, GROUP_NSEC3,
   "set-nsec3 ZONE ['PARAMS' [narrow]]",
   "\tEnable NSEC3 with PARAMS (default: '1 0 0 -'). Optionally narrow"}},
  {"set-option", {true, setOption, GROUP_ZONE,
   "set-option ZONE [producer|consumer] [coo|unique|group] VALUE [VALUE...]",
   "\tSet or remove an option for ZONE. Providing an empty value removes the\n"
   "\toption"}},
  {"set-options-json", {true, setOptionsJson, GROUP_ZONE,
   "set-options-json ZONE JSONFILE",
   "\tChange the options of ZONE to JSONFILE"}},
  {"set-presigned", {true, setPresigned, GROUP_DNSSEC,
   "set-presigned ZONE",
   "\tUse presigned RRSIGs from storage"}},
  {"set-publish-cdnskey", {true, setPublishCDNSKey, GROUP_CDNSKEY,
   "set-publish-cdnskey ZONE [delete]",
   "\tEnable sending CDNSKEY responses for ZONE. Add 'delete' to publish\n"
   "\ta CDNSKEY with a DNSSEC delete algorithm"}},
  {"set-publish-cds", {true, setPublishCDs, GROUP_CDNSKEY,
   "set-publish-cds ZONE [DIGESTALGOS]",
   "\tEnable sending CDS responses for ZONE, using DIGESTALGOS as signature\n"
   "\talgorithms; DIGESTALGOS should be a comma-separated list of numbers,\n"
   "\t(default: '2')"}},
  {"show-zone", {true, showZone, GROUP_DNSSEC,
   "show-zone ZONE",
   "\tShow DNSSEC (public) key details about a zone"}},
  {"test-algorithm", {false, testAlgorithm, GROUP_OTHER,
   "test-algorithm ALGONUM",
   ""}}, // TODO: short help line
  {"test-algorithms", {false, testAlgorithms, GROUP_OTHER,
   "", ""}}, // TODO: synopsis and short help line
  {"test-schema", {true, testSchema, GROUP_OTHER,
   "test-schema ZONE",
   "\tTest DB schema - will create ZONE"}},
  {"test-speed", {true, testSpeed, GROUP_OTHER,
   "test-speed ZONE NUM_CORES", ""}}, // TODO: short help line
  {"unpublish-zone-key", {true, unpublishZoneKey, GROUP_ZONEKEY,
   "unpublish-zone-key ZONE KEY_ID",
   "\tUnpublish the zone key with key id KEY_ID in ZONE"}},
  {"unset-nsec3", {true, unsetNSec3, GROUP_NSEC3,
   "unset-nsec3 ZONE",
   "\tSwitch ZONE back to NSEC"}},
  {"unset-presigned", {true, unsetPresigned, GROUP_DNSSEC,
   "unset-presigned ZONE",
   "\tStop using presigned RRSIGs on ZONE"}},
  {"unset-publish-cdnskey", {true, unsetPublishCDNSKey, GROUP_CDNSKEY,
   "unset-publish-cdnskey ZONE",
   "\tDisable sending CDNSKEY responses for ZONE"}},
  {"unset-publish-cds", {true, unsetPublishCDs, GROUP_CDNSKEY,
   "unset-publish-cds ZONE",
   "\tDisable sending CDS responses for ZONE"}},
  {"verify-crypto", {true, verifyCrypto, GROUP_OTHER,
   "verify-crypto FILENAME", ""}}, // TODO: short help line
  {"view-add-zone", {true, viewAddZone, GROUP_VIEWS,
   "view-add-zone VIEW ZONE..VARIANT",
   "\tAdd a zone variant to a view"}},
  {"view-del-zone", {true, viewDelZone, GROUP_VIEWS,
   "view-del-zone VIEW ZONE..VARIANT",
   "\tRemove a zone variant from a view"}},
  {"zonemd-verify-file", {true, zonemdVerifyFile, GROUP_ZONE,
   "zonemd-verify-file ZONE FILENAME",
   "\tValidate ZONEMD for ZONE"}}
};
// clang-format on

static const std::unordered_map<std::string, std::string> aliases{
  {"test-zone", "check-zone"},
  {"test-all-zones", "check-all-zones"}
};

int main(int argc, char** argv)
try
{
  po::options_description desc("Common options");
  desc.add_options()
    ("help,h", "produce help message")
    ("version", "show version")
    ("verbose,v", "be verbose")
    ("force,f", "force an action")
    ("quiet,q", "be quiet")
    ("config-name", po::value<string>()->default_value(""), "virtual configuration name")
    ("config-dir", po::value<string>()->default_value(SYSCONFDIR), "location of pdns.conf")
    ("no-colors", "do not use colors in output")
    ("commands", po::value<vector<string> >());

  po::positional_options_description p; // NOLINT(readability-identifier-length)
  p.add("commands", -1);
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), g_vm);
  po::notify(g_vm);

  vector<string> cmds;

  if(g_vm.count("commands") != 0) {
    cmds = g_vm["commands"].as<vector<string> >();
  }

  g_force = g_vm.count("force") != 0;
  g_quiet = g_vm.count("quiet") != 0;
  g_verbose = g_vm.count("verbose") != 0;

  if (g_vm.count("version") != 0) {
    cout<<"pdnsutil "<<VERSION<<endl;
    return 0;
  }

  if (cmds.empty() || g_vm.count("help") != 0 || cmds.at(0) == "help") {
    cout << "Usage:\npdnsutil [options] <command> [params...]\n"
         << endl;

    for (unsigned int group = GROUP_FIRST; group < GROUP_LAST; ++group) {
      cout << groupNames.at(group) << " commands:" << endl << endl;
      std::map<std::string, commandDispatcher> groupCommands;
      for (const auto& iter : commands) {
        if (iter.second.group == group) {
          groupCommands.insert(iter);
        }
      }
      for (const auto& iter : groupCommands) {
        auto synopsis = iter.second.synopsis;
        auto help = iter.second.help;
        if (synopsis.empty() || help.empty()) { // Don't mention "HSM" command if support not compiled in
          continue;
        }
        cout << synopsis << endl;
        cout << help << endl;
      }
      cout << endl;
    }

    cout << desc << endl;

    return 0;
  }

  loadMainConfig(g_vm["config-dir"].as<string>());

  const std::string writtencommand = cmds.at(0);
  const commandDispatcher* dispatcher{nullptr};
  bool exchanged{false};
  while (true) {
    // Search for an exact command name.
    if (const auto iter = commands.find(cmds.at(0)); iter != commands.end()) {
      dispatcher = &iter->second;
      break;
    }
    // Search for an alias
    if (const auto alias = aliases.find(cmds.at(0)); alias != aliases.end()) {
      if (const auto iter = commands.find(alias->second); iter != commands.end()) {
        dispatcher = &iter->second;
        break;
      }
    }
    std::string cmd = cmds.at(0);
    auto dash = cmd.find('-');
    // If the command name contains no dash, coalesce with the next argument
    // and try again.
    if (dash == std::string::npos && cmds.size() > 1) {
      cmd.append(1, '-');
      cmd += cmds.at(1);
      cmds.erase(cmds.begin());
      cmds.at(0) = std::move(cmd);
      continue;
    }
    // If the command name contains exactly one dash, exchange both sides
    // and try again, but only once.
    if (exchanged) {
      break;
    }
    if (dash != std::string::npos && cmd.find('-', dash + 1) == std::string::npos) {
      std::string left = cmd.substr(0, dash);
      std::string right = cmd.substr(dash + 1);
      right.append(1, '-');
      right += left;
      cmds.at(0) = std::move(right);
      exchanged = true;
      continue;
    }
    break;
  }
  if (dispatcher != nullptr) {
    if (dispatcher->requiresInitialization) {
      reportAllTypes();
    }
    return dispatcher->handler(cmds, dispatcher->synopsis);
  }

  cerr << "Unknown command '" << writtencommand << "'" << endl;
  return 1;
}
catch (PDNSException& ae) {
  cerr << "Error: " << ae.reason << endl;
  return 1;
}
catch (std::exception& e) {
  cerr << "Error: " << e.what() << endl;
  return 1;
}
catch (...) {
  cerr << "Caught an unknown exception" << endl;
  return 1;
}
