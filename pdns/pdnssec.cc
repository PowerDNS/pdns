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
#include "dns_random.hh"

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

static void algorithm2name(uint8_t algo, string &name) {
        switch(algo) {
        case 0:
           name = "Reserved"; return;
        case 1:
           name = "RSAMD5"; return;
        case 2:
           name = "DH"; return;
        case 3:
           name = "DSA"; return;
        case 4:
           name = "ECC"; return;
        case 5:
           name = "RSASHA1"; return;
        case 6:
           name = "DSA-NSEC3-SHA1"; return;
        case 7:
           name = "RSASHA1-NSEC3-SHA1"; return;
        case 8:
           name = "RSASHA256"; return;
        case 9:
           name = "Reserved"; return;
        case 10:
           name = "RSASHA512"; return;
        case 11:
           name = "Reserved"; return;
        case 12:
           name = "ECC-GOST"; return;
        case 13:
           name = "ECDSAP256SHA256"; return;
        case 14:
           name = "ECDSAP384SHA384"; return;
        case 252:
           name = "INDIRECT"; return;
        case 253:
           name = "PRIVATEDNS"; return;
        case 254:
           name = "PRIVATEOID"; return;
        default:
           name = "Unallocated/Reserved"; return;
	}
};

static int shorthand2algorithm(const string &algorithm)
{
  if (!algorithm.compare("rsamd5")) return 1;
  if (!algorithm.compare("dh")) return 2;
  if (!algorithm.compare("dsa")) return 3;
  if (!algorithm.compare("ecc")) return 4;
  if (!algorithm.compare("rsasha1")) return 5;
  if (!algorithm.compare("rsasha256")) return 8;
  if (!algorithm.compare("rsasha512")) return 10;
  if (!algorithm.compare("gost")) return 12;
  if (!algorithm.compare("ecdsa256")) return 13;
  if (!algorithm.compare("ecdsa384")) return 14;
  if (!algorithm.compare("ed25519")) return 250;
  return -1;
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

  ::arg().set("default-ksk-algorithms","Default KSK algorithms")="rsasha256";
  ::arg().set("default-ksk-size","Default KSK size (0 means default)")="0";
  ::arg().set("default-zsk-algorithms","Default ZSK algorithms")="rsasha256";
  ::arg().set("default-zsk-size","Default KSK size (0 means default)")="0";
  ::arg().set("max-ent-entries", "Maximum number of empty non-terminals in a zone")="100000";
  ::arg().set("module-dir","Default directory for modules")=LIBDIR;
  ::arg().set("entropy-source", "If set, read entropy from this file")="/dev/urandom";

  ::arg().setSwitch("experimental-direct-dnskey","EXPERIMENTAL: fetch DNSKEY RRs from backend during DNSKEY synthesis")="no";
  ::arg().laxFile(configname.c_str());

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
  ::arg().set("default-soa-name","name to insert in the SOA record if none set in the backend")="a.misconfigured.powerdns.server";
  ::arg().set("default-soa-mail","mail address to insert in the SOA record if none set in the backend")="";
  ::arg().set("soa-refresh-default","Default SOA refresh")="10800";
  ::arg().set("soa-retry-default","Default SOA retry")="3600";
  ::arg().set("soa-expire-default","Default SOA expire")="604800";
  ::arg().setSwitch("query-logging","Hint backends that queries should be logged")="no";
  ::arg().set("soa-minimum-ttl","Default SOA minimum ttl")="3600";    

  UeberBackend::go();
}

// irritatingly enough, rectifyZone needs its own ueberbackend and can't therefore benefit from transactions outside its scope
// I think this has to do with interlocking transactions between B and DK, but unsure.
bool rectifyZone(DNSSECKeeper& dk, const std::string& zone)
{
  if(dk.isPresigned(zone)){
    cerr<<"Rectify presigned zone '"<<zone<<"' is not allowed/necessary."<<endl;
    return false;
  }

  UeberBackend B("default");
  bool doTransaction=true; // but see above
  SOAData sd;
  sd.db = (DNSBackend*)-1;
  
  if(!B.getSOA(zone, sd)) {
    cerr<<"No SOA known for '"<<zone<<"', is such a zone in the database?"<<endl;
    return false;
  } 
  sd.db->list(zone, sd.domain_id);

  DNSResourceRecord rr;
  set<string> qnames, nsset, dsnames, nonterm, insnonterm, delnonterm;
  bool doent=true;
  
  while(sd.db->get(rr)) {
    if (rr.qtype.getCode())
    {
      qnames.insert(rr.qname);
      if(rr.qtype.getCode() == QType::NS && !pdns_iequals(rr.qname, zone)) 
        nsset.insert(rr.qname);
      if(rr.qtype.getCode() == QType::DS)
        dsnames.insert(rr.qname);
    }
    else
      if(doent)
        delnonterm.insert(rr.qname);
  }

  NSEC3PARAMRecordContent ns3pr;
  bool narrow;
  bool haveNSEC3=dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
  if(sd.db->doesDNSSEC())
  {
    if(!haveNSEC3) 
      cerr<<"Adding NSEC ordering information "<<endl;
    else if(!narrow)
      cerr<<"Adding NSEC3 hashed ordering information for '"<<zone<<"'"<<endl;
    else 
      cerr<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields"<<endl;
  }
  else
    cerr<<"Non DNSSEC zone, only adding empty non-terminals"<<endl;
  
  if(doTransaction)
    sd.db->startTransaction("", -1);
    
  bool realrr=true;
  string hashed;

  uint32_t maxent = ::arg().asNum("max-ent-entries");

  dononterm:;
  BOOST_FOREACH(const string& qname, qnames)
  {
    bool auth=true;
    string shorter(qname);

    if(realrr) {
      do {
        if(nsset.count(shorter)) {
          auth=false;
          break;
        }
      } while(chopOff(shorter));
    }

    if(haveNSEC3)
    {
      if(!narrow) {
        hashed=toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, qname));
        if(g_verbose)
          cerr<<"'"<<qname<<"' -> '"<< hashed <<"'"<<endl;
        sd.db->updateDNSSECOrderAndAuthAbsolute(sd.domain_id, qname, hashed, auth);
      }
      else
        sd.db->nullifyDNSSECOrderNameAndUpdateAuth(sd.domain_id, qname, auth);
    }
    else // NSEC
    {
      sd.db->updateDNSSECOrderAndAuth(sd.domain_id, zone, qname, auth);
      if (!realrr)
        sd.db->nullifyDNSSECOrderNameAndUpdateAuth(sd.domain_id, qname, auth);
    }

    if(realrr)
    {
      if (dsnames.count(qname))
        sd.db->setDNSSECAuthOnDsRecord(sd.domain_id, qname);
      if (!auth || nsset.count(qname)) {
        if(haveNSEC3 && ns3pr.d_flags)
          sd.db->nullifyDNSSECOrderNameAndAuth(sd.domain_id, qname, "NS");
        sd.db->nullifyDNSSECOrderNameAndAuth(sd.domain_id, qname, "A");
        sd.db->nullifyDNSSECOrderNameAndAuth(sd.domain_id, qname, "AAAA");
      }

      if(auth && doent)
      {
        shorter=qname;
        while(!pdns_iequals(shorter, zone) && chopOff(shorter))
        {
          if(!qnames.count(shorter) && !nonterm.count(shorter))
          {
            if(!(maxent))
            {
              cerr<<"Zone '"<<zone<<"' has too many empty non terminals."<<endl;
              insnonterm.clear();
              delnonterm.clear();
              doent=false;
              break;
            }
            nonterm.insert(shorter);
            if (!delnonterm.count(shorter))
              insnonterm.insert(shorter);
            else
              delnonterm.erase(shorter);
            --maxent;
          }
        }
      }
    }
  }

  if(realrr)
  {
    //cerr<<"Total: "<<nonterm.size()<<" Insert: "<<insnonterm.size()<<" Delete: "<<delnonterm.size()<<endl;
    if(!insnonterm.empty() || !delnonterm.empty() || !doent)
    {
      sd.db->updateEmptyNonTerminals(sd.domain_id, zone, insnonterm, delnonterm, !doent);
    }
    if(doent)
    {
      realrr=false;
      qnames=nonterm;
      goto dononterm;
    }
  }

  if(doTransaction)
    sd.db->commitTransaction();

  return true;
}

void rectifyAllZones(DNSSECKeeper &dk) 
{
  UeberBackend B("default");
  vector<DomainInfo> domainInfo;

  B.getAllDomains(&domainInfo);
  BOOST_FOREACH(DomainInfo di, domainInfo) {
    cerr<<"Rectifying "<<di.zone<<": ";
    rectifyZone(dk, di.zone);
  }
  cout<<"Rectified "<<domainInfo.size()<<" zones."<<endl;
}

int checkZone(DNSSECKeeper &dk, UeberBackend &B, const std::string& zone)
{
  SOAData sd;
  sd.db=(DNSBackend*)-1;
  if(!B.getSOA(zone, sd)) {
    cout<<"No SOA for zone '"<<zone<<"'"<<endl;
    return -1;
  }
  bool presigned=dk.isPresigned(zone);
  sd.db->list(zone, sd.domain_id);
  DNSResourceRecord rr;
  uint64_t numrecords=0, numerrors=0, numwarnings=0;

  bool hasNsAtApex = false;
  set<string> records, cnames, noncnames;
  map<string, unsigned int> ttl;

  ostringstream content;
  pair<map<string, unsigned int>::iterator,bool> ret;

  while(sd.db->get(rr)) {
    if(!rr.qtype.getCode())
      continue;

    numrecords++;

    if(rr.qtype.getCode() == QType::SOA) {
      vector<string>parts;
      stringtok(parts, rr.content);

      ostringstream o;
      o<<rr.content;
      for(int pleft=parts.size(); pleft < 7; ++pleft) {
        o<<" 0";
      }
      rr.content=o.str();
    }

    if(rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV)
      rr.content = lexical_cast<string>(rr.priority)+" "+rr.content;

    if(rr.qtype.getCode() == QType::TXT && !rr.content.empty() && rr.content[0]!='"')
      rr.content = "\""+rr.content+"\"";

    try {
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content));
      string tmp=drc->serialize(rr.qname);
      tmp = drc->getZoneRepresentation();
      if (rr.qtype.getCode() != QType::AAAA) {
        if (!pdns_iequals(tmp, rr.content)) {
          cout<<"[Warning] Parsed and original record content are not equal: "<<rr.qname<<" IN " <<rr.qtype.getName()<< " '" << rr.content<<"' (Content parsed as '"<<tmp<<"')"<<endl;
          rr.content=tmp;
          numwarnings++;
        }
      } else {
        struct addrinfo hint, *res;
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = AF_INET6;
        hint.ai_flags = AI_NUMERICHOST;
        if(getaddrinfo(rr.content.c_str(), 0, &hint, &res)) {
          cout<<"[Warning] Folowing record is not a vallid IPv6 address: "<<rr.qname<<" IN " <<rr.qtype.getName()<< " '" << rr.content<<"'"<<endl;
          numwarnings++;
        } else
          freeaddrinfo(res);
        rr.content=tmp;
      }
    }
    catch(std::exception& e)
    {
      cout<<"[Error] Following record had a problem: "<<rr.qname<<" IN " <<rr.qtype.getName()<< " " << rr.content<<endl;
      cout<<"[Error] Error was: "<<e.what()<<endl;
      numerrors++;
      continue;
    }

    if(!endsOn(rr.qname, zone)) {
      cout<<"[Warning] Record '"<<rr.qname<<" IN "<<rr.qtype.getName()<<" "<<rr.content<<"' in zone '"<<zone<<"' is out-of-zone."<<endl;
      numwarnings++;
      continue;
    }

    content.str("");
    content<<rr.qname<<" "<<rr.qtype.getName()<<" "<<rr.content;
    if (records.count(toLower(content.str()))) {
      cout<<"[Error] Duplicate record found in rrset: '"<<rr.qname<<" IN "<<rr.qtype.getName()<<" "<<rr.content<<"'"<<endl;
      numerrors++;
      continue;
    } else
      records.insert(toLower(content.str()));

    content.str("");
    content<<rr.qname<<" "<<rr.qtype.getName();
    ret = ttl.insert(pair<string, unsigned int>(toLower(content.str()), rr.ttl));
    if (ret.second == false && ret.first->second != rr.ttl) {
      cout<<"[Error] TTL mismatch in rrset: '"<<rr.qname<<" IN " <<rr.qtype.getName()<<" "<<rr.content<<"' ("<<ret.first->second<<" != "<<rr.ttl<<")"<<endl;
      numerrors++;
      continue;
    }

    if(pdns_iequals(rr.qname, zone)) {
      if (rr.qtype.getCode() == QType::NS) {
        hasNsAtApex=true;
      } else if (rr.qtype.getCode() == QType::DS) {
        cout<<"[Warning] DS at apex in zone '"<<zone<<"', should no be here."<<endl;
        numwarnings++;
      }
    } else {
      if (rr.qtype.getCode() == QType::SOA) {
        cout<<"[Error] SOA record not at apex '"<<rr.qname<<" IN "<<rr.qtype.getName()<<" "<<rr.content<<"' in zone '"<<zone<<"'"<<endl;
        numerrors++;
        continue;
      } else if (rr.qtype.getCode() == QType::DNSKEY) {
        cout<<"[Warning] DNSKEY record not at apex '"<<rr.qname<<" IN "<<rr.qtype.getName()<<" "<<rr.content<<"' in zone '"<<zone<<"', should not be here."<<endl;
        numwarnings++;
      }
    }

    if (rr.qtype.getCode() == QType::CNAME) {
      if (!cnames.count(toLower(rr.qname)))
        cnames.insert(toLower(rr.qname));
      else {
        cout<<"[Error] Duplicate CNAME found at '"<<rr.qname<<"'"<<endl;
        numerrors++;
        continue;
      }
    } else {
      if (rr.qtype.getCode() == QType::RRSIG) {
        if(presigned) {
          cout<<"[Error] RRSIG found at '"<<rr.qname<<"' in non-presigned zone. These do not belong in the database."<<endl;
          numerrors++;
          continue;
        }
      } else
        noncnames.insert(toLower(rr.qname));
    }

    if(rr.qtype.getCode() == QType::NSEC || rr.qtype.getCode() == QType::NSEC3)
    {
      cout<<"[Error] NSEC or NSEC3 found at '"<<rr.qname<<"'. These do not belong in the database."<<endl;
      numerrors++;
      continue;
    }

    if(rr.qtype.getCode() == QType::DNSKEY)
    {
      if(presigned)
      {
        if(::arg().mustDo("experimental-direct-dnskey"))
        {
          if(rr.ttl != sd.default_ttl)
          {
            cout<<"[Warning] DNSKEY TTL of "<<rr.ttl<<" at '"<<rr.qname<<"' differs from SOA minimum of "<<sd.default_ttl<<endl;
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

    if(rr.qtype.getCode() == QType::URL || rr.qtype.getCode() == QType::MBOXFW) {
      cout<<"[Error] The recordtype "<<rr.qtype.getName()<<" for record '"<<rr.qname<<"' is no longer supported."<<endl;
      numerrors++;
      continue;
    }

    if (rr.qname[rr.qname.size()-1] == '.') {
      cout<<"[Error] Record '"<<rr.qname<<"' has a trailing dot. PowerDNS will ignore this record!"<<endl;
      numerrors++;
    }

    if ( (rr.qtype.getCode() == QType::NS || rr.qtype.getCode() == QType::SRV || rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::CNAME) &&
         rr.content[rr.content.size()-1] == '.') {
      cout<<"[Warning] The record "<<rr.qname<<" with type "<<rr.qtype.getName()<<" has a trailing dot in the content ("<<rr.content<<"). Your backend might not work well with this."<<endl;
      numwarnings++;
    }

    if(rr.auth == 0 && rr.qtype.getCode()!=QType::NS && rr.qtype.getCode()!=QType::A && rr.qtype.getCode()!=QType::AAAA)
    {
      cout<<"[Error] Following record is auth=0, run pdnssec rectify-zone?: "<<rr.qname<<" IN " <<rr.qtype.getName()<< " " << rr.content<<endl;
      numerrors++;
    }
  }

  for(set<string>::const_iterator i = cnames.begin(); i != cnames.end(); i++) {
    if (noncnames.find(*i) != noncnames.end()) {
      cout<<"[Error] CNAME "<<*i<<" found, but other records with same label exist."<<endl;
      numerrors++;
    }
  }

  if(!hasNsAtApex) {
    cout<<"[Error] No NS record at zone apex in zone '"<<zone<<"'"<<endl;
    numerrors++;
  }

  cout<<"Checked "<<numrecords<<" records of '"<<zone<<"', "<<numerrors<<" errors, "<<numwarnings<<" warnings."<<endl;
  return numerrors;
}

int checkAllZones(DNSSECKeeper &dk) 
{
  UeberBackend B("default");
  vector<DomainInfo> domainInfo;

  B.getAllDomains(&domainInfo);
  int errors=0;
  BOOST_FOREACH(DomainInfo di, domainInfo) {
    if (checkZone(dk, B, di.zone) > 0) 
       errors++;
  }
  cout<<"Checked "<<domainInfo.size()<<" zones, "<<errors<<" had errors."<<endl;
  return 0;
}

int increaseSerial(const string& zone, DNSSECKeeper &dk)
{
  UeberBackend B("default");
  SOAData sd;
  sd.db=(DNSBackend*)-1;
  if(!B.getSOA(zone, sd)) {
    cout<<"No SOA for zone '"<<zone<<"'"<<endl;
    return -1;
  }
  
  string soaEditKind;
  dk.getFromMeta(zone, "SOA-EDIT", soaEditKind);

  sd.db->lookup(QType(QType::SOA), zone);
  vector<DNSResourceRecord> rrs;
  DNSResourceRecord rr;
  while (sd.db->get(rr)) {
    if (rr.qtype.getCode() == QType::SOA)
      rrs.push_back(rr);
  } 

  if (rrs.size() > 1) {
    cerr<<rrs.size()<<" SOA records found for "<<zone<<"!"<<endl;
    return -1;
  }
  if (rrs.size() < 1) {
     cerr<<zone<<" not found!"<<endl;
  }
  
  if (soaEditKind.empty()) {
    sd.serial++;
  }
  else if(pdns_iequals(soaEditKind,"INCREMENT-WEEKS")) {
    sd.serial++;
  }
  else if(pdns_iequals(soaEditKind,"INCEPTION-INCREMENT")) {
    uint32_t today_serial = localtime_format_YYYYMMDDSS(time(NULL), 1);

    if (sd.serial < today_serial) {
      sd.serial = today_serial;
    }
    else {
      sd.serial++;
    }
  }
  else {
    sd.serial = calculateEditSOA(sd, soaEditKind) + 1;
  }
  rrs[0].content = serializeSOAData(sd);

  if (! sd.db->replaceRRSet(sd.domain_id, zone, rr.qtype, rrs)) {
   cerr<<"Backend did not replace SOA record. Backend might not support this operation."<<endl;
   return -1;
  }
  cout<<"SOA serial for zone "<<zone<<" set to "<<sd.serial<<endl;
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
bool disableDNSSECOnZone(DNSSECKeeper& dk, const string& zone)
{
  UeberBackend B("default");
  DomainInfo di;

  if (!B.getDomainInfo(zone, di)){
    cerr << "No such zone in the database" << endl;
    return false;
  }

  if(!dk.isSecuredZone(zone)) {
    cerr<<"Zone is not secured\n";
    return false;
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
  return true;
}
bool showZone(DNSSECKeeper& dk, const std::string& zone)
{
  UeberBackend B("default");
  DomainInfo di;
  std::vector<std::string> meta;

  if (!B.getDomainInfo(zone, di)){
    cerr << "No such zone in the database" << endl;
    return false;
  }

  if(!dk.isSecuredZone(zone)) {
    cerr<<"Zone is not actively secured\n";
  }
  NSEC3PARAMRecordContent ns3pr;
  bool narrow;
  bool haveNSEC3=dk.getNSEC3PARAM(zone, &ns3pr, &narrow);
  
  DNSSECKeeper::keyset_t keyset=dk.getKeys(zone);
  if (B.getDomainMetadata(zone, "TSIG-ALLOW-AXFR", meta) && meta.size() > 0) {
     cerr << "Zone has following allowed TSIG key(s): " << boost::join(meta, ",") << endl;
  }

  meta.clear();
  if (B.getDomainMetadata(zone, "AXFR-MASTER-TSIG", meta) && meta.size() > 0) {
     cerr << "Zone uses following TSIG key(s): " << boost::join(meta, ",") << endl;
  }
  
  cout <<"Zone is " << (dk.isPresigned(zone) ? "" : "not ") << "presigned\n";

  if(keyset.empty())  {
    cerr << "No keys for zone '"<<zone<<"'."<<endl;
  }
  else {  
    if(!haveNSEC3) 
      cout<<"Zone has NSEC semantics"<<endl;
    else
      cout<<"Zone has " << (narrow ? "NARROW " : "") <<"hashed NSEC3 semantics, configuration: "<<ns3pr.getZoneRepresentation()<<endl;
  
    cout << "keys: "<<endl;
    BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, keyset) {
      string algname;
      algorithm2name(value.first.d_algorithm, algname);
      cout<<"ID = "<<value.second.id<<" ("<<(value.second.keyOrZone ? "KSK" : "ZSK")<<"), tag = "<<value.first.getDNSKEY().getTag();
      cout<<", algo = "<<(int)value.first.d_algorithm<<", bits = "<<value.first.getKey()->getBits()<<"\tActive: "<<value.second.active<< " ( " + algname + " ) "<<endl;
      if(value.second.keyOrZone || ::arg().mustDo("experimental-direct-dnskey"))
        cout<<(value.second.keyOrZone ? "KSK" : "ZSK")<<" DNSKEY = "<<zone<<" IN DNSKEY "<< value.first.getDNSKEY().getZoneRepresentation() << " ; ( "  + algname + " )" << endl;
      if(value.second.keyOrZone) {
        cout<<"DS = "<<zone<<" IN DS "<<makeDSFromDNSKey(zone, value.first.getDNSKEY(), 1).getZoneRepresentation() << " ; ( SHA1 digest )" << endl;
        cout<<"DS = "<<zone<<" IN DS "<<makeDSFromDNSKey(zone, value.first.getDNSKEY(), 2).getZoneRepresentation() << " ; ( SHA256 digest )" << endl;
        try {
          string output=makeDSFromDNSKey(zone, value.first.getDNSKEY(), 3).getZoneRepresentation();
          cout<<"DS = "<<zone<<" IN DS "<< output << " ; ( GOST R 34.11-94 digest )" << endl;
        }
        catch(...)
        {
        }
        try {
          string output=makeDSFromDNSKey(zone, value.first.getDNSKEY(), 4).getZoneRepresentation();
          cout<<"DS = "<<zone<<" IN DS "<< output << " ; ( SHA-384 digest )" << endl;
        }
        catch(...)
        {
        }
        cout<<endl;  
      }
    }
  }
  return true;
}

bool secureZone(DNSSECKeeper& dk, const std::string& zone)
{
  // parse attribute
  vector<string> k_algos;
  vector<string> z_algos;
  int k_size;
  int z_size; 

  stringtok(k_algos, ::arg()["default-ksk-algorithms"], " ,");
  k_size = ::arg().asNum("default-ksk-size");
  stringtok(z_algos, ::arg()["default-zsk-algorithms"], " ,");
  z_size = ::arg().asNum("default-zsk-size");

  if (k_size < 0) {
     throw runtime_error("KSK key size must be equal to or greater than 0");
  }

  if (k_algos.size() < 1) {
     throw runtime_error("No algorithm(s) given for KSK");
  }

  if (z_size < 0) {
     throw runtime_error("ZSK key size must be equal to or greater than 0");
  }

  if (z_algos.size() < 1) {
     throw runtime_error("No algorithm(s) given for ZSK");
  }

  if(dk.isSecuredZone(zone)) {
    cerr << "Zone '"<<zone<<"' already secure, remove keys with pdnssec remove-zone-key if needed"<<endl;
    return false;
  }

  DomainInfo di;
  UeberBackend B("default");
  if(!B.getDomainInfo(zone, di) || !di.backend) { // di.backend and B are mostly identical
    cout<<"Can't find a zone called '"<<zone<<"'"<<endl;
    return false;
  }

  if(di.kind == DomainInfo::Slave)
  {
    cout<<"Warning! This is a slave domain! If this was a mistake, please run"<<endl;
    cout<<"pdnssec disable-dnssec "<<zone<<" right now!"<<endl;
  }

  if (k_size)
    cout << "Securing zone with " << k_algos[0] << " algorithm with key size " << k_size << endl;
  else
    cout << "Securing zone with " << k_algos[0] << " algorithm with default key size" << endl;

  // run secure-zone with first default algorith, then add keys
  if(!dk.secureZone(zone, shorthand2algorithm(k_algos[0]), k_size)) {
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
    cerr<<"it to use DNSSEC with 'bind-dnssec-db=/path/fname' and\n";
    cerr<<"'pdnssec create-bind-db /path/fname'!\n";
    return false;
  }

  DNSSECKeeper::keyset_t zskset=dk.getKeys(zone, false);

  if(!zskset.empty())  {
    cerr<<"There were ZSKs already for zone '"<<zone<<"', no need to add more"<<endl;
    return false;
  }
  
  for(vector<string>::iterator i = k_algos.begin()+1; i != k_algos.end(); i++)
    dk.addKey(zone, true, shorthand2algorithm(*i), k_size, true); // obvious errors will have been caught above

  BOOST_FOREACH(string z_algo, z_algos)
  {
    int algo = shorthand2algorithm(z_algo);
    dk.addKey(zone, false, algo, z_size);
  }

  // rectifyZone(dk, zone);
  // showZone(dk, zone);
  cout<<"Zone "<<zone<<" secured"<<endl;
  return true;
}

void testSchema(DNSSECKeeper& dk, const std::string& zone)
{
  cout<<"Note: test-schema will try to create the zone, but it will not remove it."<<endl;
  cout<<"Please clean up after this."<<endl;
  cout<<endl;
  cout<<"Constructing UeberBackend"<<endl;
  UeberBackend B("default");
  cout<<"Picking first backend - if this is not what you want, edit launch line!"<<endl;
  DNSBackend *db = B.backends[0];
  cout<<"Creating slave domain "<<zone<<endl;
  db->createSlaveDomain("127.0.0.1", zone, "_testschema");
  cout<<"Slave domain created"<<endl;

  DomainInfo di;
  if(!B.getDomainInfo(zone, di) || !di.backend) { // di.backend and B are mostly identical
    cout<<"Can't find domain we just created, aborting"<<endl;
    return;
  }
  db=di.backend;
  DNSResourceRecord rr, rrget;
  cout<<"Starting transaction to feed records"<<endl;
  db->startTransaction(zone, di.id);

  rr.qtype=QType::SOA;
  rr.qname=zone;
  rr.ttl=86400;
  rr.domain_id=di.id;
  rr.auth=1;
  rr.content="ns1.example.com. ahu.example.com. 2012081039 7200 3600 1209600 3600";
  cout<<"Feeding SOA"<<endl;
  db->feedRecord(rr);
  rr.qtype=QType::TXT;
  // 300 As
  rr.content="\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"";
  cout<<"Feeding overlong TXT"<<endl;
  db->feedRecord(rr);
  cout<<"Committing"<<endl;
  db->commitTransaction();
  cout<<"Querying TXT"<<endl;
  db->lookup(QType(QType::TXT), zone, NULL, di.id);
  if(db->get(rrget))
  {
    DNSResourceRecord rrthrowaway;
    if(db->get(rrthrowaway)) // should not touch rr but don't assume anything
    {
      cout<<"Expected one record, got multiple, aborting"<<endl;
      return;
    }
    int size=rrget.content.size();
    if(size != 302)
    {
      cout<<"Expected 302 bytes, got "<<size<<", aborting"<<endl;
      return;
    }
  }
  cout<<"[+] content field is over 255 bytes"<<endl;

  cout<<"Dropping all records, inserting SOA+2xA"<<endl;
  db->startTransaction(zone, di.id);

  rr.qtype=QType::SOA;
  rr.qname=zone;
  rr.ttl=86400;
  rr.domain_id=di.id;
  rr.auth=1;
  rr.content="ns1.example.com. ahu.example.com. 2012081039 7200 3600 1209600 3600";
  cout<<"Feeding SOA"<<endl;
  db->feedRecord(rr);

  rr.qtype=QType::A;
  rr.qname="_underscore."+zone;
  rr.content="127.0.0.1";
  db->feedRecord(rr);

  rr.qname="bla."+zone;
  cout<<"Committing"<<endl;
  db->commitTransaction();

  cout<<"Securing zone"<<endl;
  secureZone(dk, zone);
  cout<<"Rectifying zone"<<endl;
  rectifyZone(dk, zone);
  cout<<"Checking underscore ordering"<<endl;
  string before, after;
  db->getBeforeAndAfterNames(di.id, zone, "z."+zone, before, after);
  cout<<"got '"<<before<<"' < 'z."<<zone<<"' < '"<<after<<"'"<<endl;
  if(before != "_underscore."+zone)
  {
    cout<<"before is wrong, got '"<<before<<"', expected '_underscore."<<zone<<"', aborting"<<endl;
    return;
  }
  if(after != zone)
  {
    cout<<"after is wrong, got '"<<after<<"', expected '"<<zone<<"', aborting"<<endl;
    return;
  }
  cout<<"[+] ordername sorting is correct for names starting with _"<<endl;
  cout<<endl;
  cout<<"End of tests, please remove "<<zone<<" from domains+records"<<endl;
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
    cerr<<"add-zone-key ZONE zsk|ksk [bits] [active|passive]\n";
    cerr<<"             [rsasha1|rsasha256|rsasha512|gost|ecdsa256|ecdsa384]\n";
    cerr<<"                                   Add a ZSK or KSK to zone and specify algo&bits\n";
    cerr<<"check-zone ZONE                    Check a zone for correctness\n";
    cerr<<"check-all-zones                    Check all zones for correctness\n";
    cerr<<"create-bind-db FNAME               Create DNSSEC db for BIND backend (bind-dnssec-db)\n"; 
    cerr<<"deactivate-zone-key ZONE KEY-ID    Deactivate the key with key id KEY-ID in ZONE\n";
    cerr<<"disable-dnssec ZONE                Deactivate all keys and unset PRESIGNED in ZONE\n";
    cerr<<"export-zone-dnskey ZONE KEY-ID     Export to stdout the public DNSKEY described\n";
    cerr<<"export-zone-key ZONE KEY-ID        Export to stdout the private key described\n";
    cerr<<"generate-zone-key zsk|ksk [algorithm] [bits]\n";
    cerr<<"                                   Generate a ZSK or KSK to stdout with specified algo&bits\n";
    cerr<<"hash-zone-record ZONE RNAME        Calculate the NSEC3 hash for RNAME in ZONE\n";
    cerr<<"increase-serial ZONE               Increases the SOA-serial by 1. Uses SOA-EDIT\n";
    cerr<<"import-zone-key ZONE FILE          Import from a file a private key, ZSK or KSK\n";            
    cerr<<"       [active|passive][ksk|zsk]   Defaults to KSK and active\n";
    cerr<<"rectify-zone ZONE [ZONE ..]        Fix up DNSSEC fields (order, auth)\n";
    cerr<<"rectify-all-zones                  Rectify all zones.\n";
    cerr<<"remove-zone-key ZONE KEY-ID        Remove key with KEY-ID from ZONE\n";
    cerr<<"secure-zone ZONE [ZONE ..]         Add KSK and two ZSKs\n";
    cerr<<"set-nsec3 ZONE ['params' [narrow]] Enable NSEC3 with PARAMs. Optionally narrow\n";
    cerr<<"set-presigned ZONE                 Use presigned RRSIGs from storage\n";
    cerr<<"show-zone ZONE                     Show DNSSEC (public) key details about a zone\n";
    cerr<<"unset-nsec3 ZONE                   Switch back to NSEC\n";
    cerr<<"unset-presigned ZONE               No longer use presigned RRSIGs\n";
    cerr<<"test-schema ZONE                   Test DB schema - will create ZONE\n";
    cerr<<"import-tsig-key NAME ALGORITHM KEY Import TSIG key\n";
    cerr<<"create-tsig-key NAME ALGORITHM     Generate new TSIG key\n";
    cerr<<"list-tsig-keys                     List all TSIG keys\n";
    cerr<<"delete-tsig-key NAME               Delete TSIG key (warning! will not unmap key!)\n";
    cerr<<"enable-tsig-key ZONE NAME [master|slave]\n";
    cerr<<"                                   Enable TSIG key for a zone\n";
    cerr<<"disable-tsig-key ZONE NAME [master|slave]\n";
    cerr<<"                                   Disable TSIG key for a zone\n";
    cerr<<desc<<endl;
    return 0;
  }
  
  if (cmds[0] == "test-algorithm") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec test-algorithm algonum"<<endl;
      return 0;
    }
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
    catch (PDNSException& ae) {
      cerr<<"Error: "<<ae.reason<<endl;
      return 1;
    }
    return 0;
  }
  
  DNSSECKeeper dk;

  if (cmds[0] == "test-schema") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec test-schema ZONE"<<endl;
      return 0;
    }
    testSchema(dk, cmds[1]);
    return 0;
  }
  if(cmds[0] == "rectify-zone") {
    if(cmds.size() < 2) {
      cerr << "Syntax: pdnssec rectify-zone ZONE [ZONE..]"<<endl;
      return 0;
    }
    unsigned int exitCode = 0;
    for(unsigned int n = 1; n < cmds.size(); ++n) 
      if (!rectifyZone(dk, cmds[n])) exitCode = 1;
    return exitCode;
  }
  else if (cmds[0] == "rectify-all-zones") {
    rectifyAllZones(dk);
  }
  else if(cmds[0] == "check-zone") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec check-zone ZONE"<<endl;
      return 0;
    }
    UeberBackend B("default");
    exit(checkZone(dk, B, cmds[1]));
  }
  else if (cmds[0] == "check-all-zones") {
    exit(checkAllZones(dk));
  }
  else if (cmds[0] == "test-zone") {
    cerr << "Did you mean check-zone?"<<endl;
    return 0;
  }
  else if (cmds[0] == "test-all-zones") {
    cerr << "Did you mean check-all-zones?"<<endl;
    return 0;
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
    if (!showZone(dk, zone)) return 1;
  }
  else if(cmds[0] == "disable-dnssec") {
    if(cmds.size() != 2) {
      cerr << "Syntax: pdnssec disable-dnssec ZONE"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    if(!disableDNSSECOnZone(dk, zone)) {
      cerr << "Cannot disable DNSSEC on " << zone << endl;
      return 1;
    }
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
    if (!dk.activateKey(zone, id)) {
      cerr<<"Activation of key failed"<<endl;
      return 1;
    }
    return 0;
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
    if (!dk.deactivateKey(zone, id)) {
      cerr<<"Deactivation of key failed"<<endl;
      return 1;
    }
    return 0;
  }
  else if(cmds[0] == "add-zone-key") {
    if(cmds.size() < 3 ) {
      cerr << "Syntax: pdnssec add-zone-key ZONE zsk|ksk [bits] [rsasha1|rsasha256|rsasha512|gost|ecdsa256|ecdsa384]"<<endl;
      return 0;
    }
    const string& zone=cmds[1];

    UeberBackend B("default");
    DomainInfo di;

    if (!B.getDomainInfo(zone, di)){
      cerr << "No such zone in the database" << endl;
      return 0;
    }

    // need to get algorithm, bits & ksk or zsk from commandline
    bool keyOrZone=false;
    int tmp_algo=0;
    int bits=0;
    int algorithm=8;
    bool active=false;
    for(unsigned int n=2; n < cmds.size(); ++n) {
      if(pdns_iequals(cmds[n], "zsk"))
        keyOrZone = false;
      else if(pdns_iequals(cmds[n], "ksk"))
        keyOrZone = true;
      else if((tmp_algo = shorthand2algorithm(cmds[n]))>0) {
        algorithm = tmp_algo;
      } else if(pdns_iequals(cmds[n], "active")) {
        active=true;
      } else if(pdns_iequals(cmds[n], "inactive") || pdns_iequals(cmds[n], "passive")) {
        active=false;
      } else if(atoi(cmds[n].c_str())) {
        bits = atoi(cmds[n].c_str());
      } else { 
        cerr<<"Unknown algorithm, key flag or size '"<<cmds[n]<<"'"<<endl;
        exit(EXIT_FAILURE);;
      }
    }
    if(!dk.addKey(zone, keyOrZone, algorithm, bits, active)) {
      cerr<<"Adding key failed, perhaps DNSSEC not enabled in configuration?"<<endl;
      exit(1);
    }
    else {
      cerr<<"Added a " << (keyOrZone ? "KSK" : "ZSK")<<" with algorithm = "<<algorithm<<", active="<<active<<endl;
      if(bits)
	cerr<<"Requested specific key size of "<<bits<<" bits"<<endl;
    }
  }
  else if(cmds[0] == "remove-zone-key") {
    if(cmds.size() < 3) {
      cerr<<"Syntax: pdnssec remove-zone-key ZONE KEY-ID"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    if (!dk.removeKey(zone, id)) {
       cerr<<"Cannot remove key " << id << " from " << zone <<endl;
      return 1;
    }
    return 0;
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
    string nsec3params =  cmds.size() > 2 ? cmds[2] : "1 0 1 ab";
    bool narrow = cmds.size() > 3 && cmds[3]=="narrow";
    NSEC3PARAMRecordContent ns3pr(nsec3params);
    
    string zone=cmds[1];
    if(!dk.isSecuredZone(zone)) {
      cerr<<"Zone '"<<zone<<"' is not secured, can't set NSEC3 parameters"<<endl;
      exit(EXIT_FAILURE);
    }
    dk.setNSEC3PARAM(zone, ns3pr, narrow);
    
    if (!ns3pr.d_flags)
      cerr<<"NSEC3 set, please rectify-zone if your backend needs it"<<endl;
    else
      cerr<<"NSEC3 (opt-out) set, please rectify-zone if your backend needs it"<<endl;
  }
  else if(cmds[0]=="set-presigned") {
    if(cmds.size() < 2) {
      cerr<<"Syntax: pdnssec set-presigned ZONE"<<endl;
      return 0; 
    }
    if (! dk.setPresigned(cmds[1])) {
      cerr << "Could not set presigned on for " << cmds[1] << endl;
      return 1;
    }
    return 0;
  }
  else if(cmds[0]=="unset-presigned") {
    if(cmds.size() < 2) {
      cerr<<"Syntax: pdnssec unset-presigned ZONE"<<endl;
      return 0;  
    }
    if (! dk.unsetPresigned(cmds[1])) {
      cerr << "Could not unset presigned on for " << cmds[1] << endl;
      return 1;
    }
    return 0;
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
      
    cout<<toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, record))<<endl;
  }
  else if(cmds[0]=="unset-nsec3") {
    if(cmds.size() < 2) {
      cerr<<"Syntax: pdnssec unset-nsec3 ZONE"<<endl;
      return 0;
    }
    if ( ! dk.unsetNSEC3PARAM(cmds[1])) {
      cerr<<"Cannot unset NSEC3 param for " << cmds[1] << endl;
      return 1;
    }
    return 0;
  }
  else if(cmds[0]=="export-zone-key") {
    if(cmds.size() < 3) {
      cerr<<"Syntax: pdnssec export-zone-key ZONE KEY-ID"<<endl;
      return 0;
    }

    string zone=cmds[1];
    unsigned int id=atoi(cmds[2].c_str());
    DNSSECPrivateKey dpk=dk.getKeyById(zone, id);
    cout << dpk.getKey()->convertToISC() <<endl;
  }  
  else if(cmds[0]=="increase-serial") {
    if (cmds.size() < 2) {
      cerr<<"Syntax: pdnssec increase-serial ZONE"<<endl;
      return 0;
    }
    return increaseSerial(cmds[1], dk);
  }
  else if(cmds[0]=="import-zone-key-pem") {
    if(cmds.size() < 4) {
      cerr<<"Syntax: pdnssec import-zone-key-pem ZONE FILE algorithm [ksk|zsk]"<<endl;
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
      
    if(!dk.addKey(zone, dpk)) {
      cerr<<"Adding key failed, perhaps DNSSEC not enabled in configuration?"<<endl;
      exit(1);
    }
    
  }
  else if(cmds[0]=="import-zone-key") {
    if(cmds.size() < 3) {
      cerr<<"Syntax: pdnssec import-zone-key ZONE FILE [ksk|zsk] [active|passive]"<<endl;
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
    
    dpk.d_flags = 257; 
    bool active=true;

    for(unsigned int n = 3; n < cmds.size(); ++n) {
      if(pdns_iequals(cmds[n], "ZSK"))
	dpk.d_flags = 256;
      else if(pdns_iequals(cmds[n], "KSK"))
	dpk.d_flags = 257;
      else if(pdns_iequals(cmds[n], "active"))
	active = 1;
      else if(pdns_iequals(cmds[n], "passive") || pdns_iequals(cmds[n], "inactive"))
	active = 0;
      else { 
	cerr<<"Unknown key flag '"<<cmds[n]<<"'\n";
	exit(1);
      }	  
    }
    if(!dk.addKey(zone, dpk, active)) {
      cerr<<"Adding key failed, perhaps DNSSEC not enabled in configuration?"<<endl;
      exit(1);
    }
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
  else if(cmds[0] == "generate-zone-key") {
    if(cmds.size() < 2 ) {
      cerr << "Syntax: pdnssec generate-zone-key zsk|ksk [rsasha1|rsasha256|rsasha512|gost|ecdsa256|ecdsa384] [bits]"<<endl;
      return 0;
    }
    // need to get algorithm, bits & ksk or zsk from commandline
    bool keyOrZone=false;
    int tmp_algo=0;
    int bits=0;
    int algorithm=8;
    for(unsigned int n=1; n < cmds.size(); ++n) {
      if(pdns_iequals(cmds[n], "zsk"))
        keyOrZone = false;
      else if(pdns_iequals(cmds[n], "ksk"))
        keyOrZone = true;
      else if((tmp_algo = shorthand2algorithm(cmds[n]))>0) {
        algorithm = tmp_algo;
      } else if(atoi(cmds[n].c_str()))
        bits = atoi(cmds[n].c_str());
      else {
        cerr<<"Unknown algorithm, key flag or size '"<<cmds[n]<<"'"<<endl;
        return 0;
      }
    }
    cerr<<"Generating a " << (keyOrZone ? "KSK" : "ZSK")<<" with algorithm = "<<algorithm<<endl;
    if(bits)
      cerr<<"Requesting specific key size of "<<bits<<" bits"<<endl;

    DNSSECPrivateKey dspk; 
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(algorithm)); // defaults to RSA for now, could be smart w/algorithm! XXX FIXME 
    if(!bits) {
      if(algorithm <= 10)
        bits = keyOrZone ? 2048 : 1024;
      else {
        if(algorithm == 12 || algorithm == 13 || algorithm == 250) // ECDSA, GOST, ED25519
          bits = 256;
        else if(algorithm == 14)
          bits = 384;
        else {
          throw runtime_error("Can't guess key size for algoritm "+lexical_cast<string>(algorithm));
        }
      }
    }
    dpk->create(bits); 
    dspk.setKey(dpk); 
    dspk.d_algorithm = algorithm; 
    dspk.d_flags = keyOrZone ? 257 : 256; 

    // print key to stdout 
    cout << "Flags: " << dspk.d_flags << endl << 
             dspk.getKey()->convertToISC() << endl; 
  } else if (cmds[0]=="create-tsig-key") {
     if (cmds.size() < 3) {
        cerr << "Syntax: " << cmds[0] << " name (hmac-md5|hmac-sha1|hmac-sha224|hmac-sha256|hmac-sha384|hmac-sha512)" << endl;
        return 0;
     }
     string name = cmds[1];
     string algo = cmds[2];
     string key;
     char tmpkey[64];

     size_t klen = 0;
     if (algo == "hmac-md5") {
       klen = 32;
     } else if (algo == "hmac-sha1") {
       klen = 32;
     } else if (algo == "hmac-sha224") {
       klen = 32;
     } else if (algo == "hmac-sha256") {
       klen = 64;
     } else if (algo == "hmac-sha384") {
       klen = 64;
     } else if (algo == "hmac-sha512") {
       klen = 64;
     } else {
       cerr << "Cannot generate key for " << algo << endl;
       return 1;
     }

     cerr << "Generating new key with " << klen << " bytes (this can take a while)" << endl;
     seedRandom(::arg()["entropy-source"]);
     for(size_t i = 0; i < klen; i+=4) {
        *(unsigned int*)(tmpkey+i) = dns_random(0xffffffff);
     }
     key = Base64Encode(std::string(tmpkey, klen));

     UeberBackend B("default");
     if (B.setTSIGKey(name, algo, key)) {
       cout << "Create new TSIG key " << name << " " << algo << " " << key << endl;
     } else {
       cout << "Failure storing new TSIG key " << name << " " << algo << " " << key << endl;
       return 1;
     }
     return 0;
  } else if (cmds[0]=="import-tsig-key") {
     if (cmds.size() < 4) {
        cerr << "Syntax: " << cmds[0] << " name algorithm key" << endl;
        return 0;
     }
     string name = cmds[1];
     string algo = cmds[2];
     string key = cmds[3];

     UeberBackend B("default");
     if (B.setTSIGKey(name, algo, key)) {
       cout << "Imported TSIG key " << name << " " << algo << endl;
     } else {
       cout << "Failure importing TSIG key " << name << " " << algo << endl;
       return 1;
     }
     return 0;
  } else if (cmds[0]=="delete-tsig-key") {
     if (cmds.size() < 2) {
        cerr << "Syntax: " << cmds[0] << " name" << endl;
        return 0;
     }
     string name = cmds[1];
     string algo = cmds[2];

     UeberBackend B("default");
     if (B.deleteTSIGKey(name)) {
       cout << "Deleted TSIG key " << name << endl;
     } else {
       cout << "Failure deleting TSIG key " << name << endl;
       return 1;
     }
     return 0;
  } else if (cmds[0]=="list-tsig-keys") {
     std::vector<struct TSIGKey> keys;
     UeberBackend B("default");
     if (B.getTSIGKeys(keys)) {
        BOOST_FOREACH(const struct TSIGKey &key, keys) {
           cout << key.name << " " << key.algorithm << " " << key.key << endl;
        }
     }
     return 0;
  } else if (cmds[0]=="enable-tsig-key") {
     string metaKey;
     if (cmds.size() < 4) {
        cerr << "Syntax: " << cmds[0] << " zone name [master|slave]" << endl;
        return 0;
     }
     string zname = cmds[1];
     string name = cmds[2];
     if (cmds[3] == "master")
        metaKey = "TSIG-ALLOW-AXFR";
     else if (cmds[3] == "slave")
        metaKey = "AXFR-MASTER-TSIG";
     else {
        cerr << "Invalid parameter '" << cmds[3] << "', expected master or slave" << endl;
        return 1;
     }
     UeberBackend B("default");
     std::vector<std::string> meta; 
     if (!B.getDomainMetadata(zname, metaKey, meta)) {
       cout << "Failure enabling TSIG key " << name << " for " << zname << endl;
       return 1;
     }
     bool found = false;
     BOOST_FOREACH(std::string tmpname, meta) {
          if (tmpname == name) { found = true; break; }
     }
     if (!found) meta.push_back(name);
     if (B.setDomainMetadata(zname, metaKey, meta)) {
       cout << "Enabled TSIG key " << name << " for " << zname << endl;
     } else {
       cout << "Failure enabling TSIG key " << name << " for " << zname << endl;
       return 1;
     }
     return 0;
  } else if (cmds[0]=="disable-tsig-key") {
     string metaKey;
     if (cmds.size() < 4) {
        cerr << "Syntax: " << cmds[0] << " zone name [master|slave]" << endl;
        return 0;
     }
     string zname = cmds[1];
     string name = cmds[2];
     if (cmds[3] == "master")
        metaKey = "TSIG-ALLOW-AXFR";
     else if (cmds[3] == "slave")
        metaKey = "AXFR-MASTER-TSIG";
     else {
        cerr << "Invalid parameter '" << cmds[3] << "', expected master or slave" << endl;
        return 1;
     }

     UeberBackend B("default");
     std::vector<std::string> meta;
     if (!B.getDomainMetadata(zname, metaKey, meta)) {
       cout << "Failure disabling TSIG key " << name << " for " << zname << endl;
       return 1;
     }
     std::vector<std::string>::iterator iter = meta.begin();
     for(;iter != meta.end(); iter++) if (*iter == name) break;
     if (iter != meta.end()) meta.erase(iter);
     if (B.setDomainMetadata(zname, metaKey, meta)) {
       cout << "Disabled TSIG key " << name << " for " << zname << endl;
     } else {
       cout << "Failure disabling TSIG key " << name << " for " << zname << endl;
       return 1;
     }
     return 0;
  }
  else {
    cerr<<"Unknown command '"<<cmds[0] << endl;
    return 1;
  }
  return 0;
}
catch(PDNSException& ae) {
  cerr<<"Error: "<<ae.reason<<endl;
}
catch(std::exception& e) {
  cerr<<"Error: "<<e.what()<<endl;
}

