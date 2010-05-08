#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "iputils.hh"
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include <polarssl/rsa.h>
#include <polarssl/base64.h>
#include <polarssl/sha1.h>
#include <polarssl/sha2.h>
#include "dnssecinfra.hh" 
#include "dnsseckeeper.hh"

using namespace boost;
using namespace std;

DNSKEYRecordContent getRSAKeyFromISC(rsa_context* rsa, const char* fname)
{
  char line[1024];

  string sline;
  string key,value;
  map<string, mpi*> places;

  FILE *fp=fopen(fname, "r");
  if(!fp)
    unixDie("opening file '"+string(fname)+"'");

  rsa_init(rsa, RSA_PKCS_V15, 0, NULL, NULL );

  places["Modulus"]=&rsa->N;
  places["PublicExponent"]=&rsa->E;
  places["PrivateExponent"]=&rsa->D;
  places["Prime1"]=&rsa->P;
  places["Prime2"]=&rsa->Q;
  places["Exponent1"]=&rsa->DP;
  places["Exponent2"]=&rsa->DQ;
  places["Coefficient"]=&rsa->QP;

  unsigned char decoded[1024];
  DNSKEYRecordContent drc;
  string modulus, exponent;
  while(fgets(line, sizeof(line),fp)) {
    sline.assign(line);
    tie(key,value)=splitField(line, ':');
    trim(value);

    if(places.count(key)) {
      if(places[key]) {

	int len=sizeof(decoded);
	if(base64_decode(decoded, &len, (unsigned char*)value.c_str(), value.length()) < 0) {
	  cerr<<"Error base64 decoding '"<<value<<"'\n";
	  exit(1);
	}
	//	B64Decode(value, decoded);
	//	cerr<<key<<" decoded.length(): "<<8*len<<endl;
	mpi_read_binary(places[key], decoded, len);
	if(key=="Modulus")
	  modulus.assign((const char*)decoded,len);
	if(key=="PublicExponent")
	  exponent.assign((const char*)decoded,len);
      }
    }
    else {
      if(key != "Private-key-format" && key != "Algorithm") 
	cerr<<"Unknown field '"<<key<<"'\n";
    }
  }
  rsa->len = ( mpi_msb( &rsa->N ) + 7 ) >> 3; // no clue what this does

  if(exponent.length() < 255) 
    drc.d_key.assign(1, (char) (unsigned int) exponent.length());
  else {
    drc.d_key.assign(1, 0);
    uint16_t len=htons(exponent.length());
    drc.d_key.append((char*)&len, 2);
  }
  drc.d_key.append(exponent);
  drc.d_key.append(modulus);
  drc.d_protocol=3;
  drc.d_algorithm = 5;
  fclose(fp);
  return drc;
}


void makeRSAPublicKeyFromDNS(rsa_context* rc, const DNSKEYRecordContent& dkrc)
{
  rsa_init(rc, RSA_PKCS_V15, 0, NULL, NULL );

  mpi_read_binary(&rc->E, (unsigned char*)dkrc.getExponent().c_str(), dkrc.getExponent().length());    // exponent
  mpi_read_binary(&rc->N, (unsigned char*)dkrc.getModulus().c_str(), dkrc.getModulus().length());    // modulus
  rc->len = ( mpi_msb( &rc->N ) + 7 ) >> 3; // no clue what this does
}

bool sharedDNSSECCompare(const shared_ptr<DNSRecordContent>& a, const shared_ptr<DNSRecordContent>& b)
{
  return a->serialize("", true) < b->serialize("", true);
}

string getSHA1HashForRRSET(const std::string& qname, const RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& signRecords) 
{
  sort(signRecords.begin(), signRecords.end(), sharedDNSSECCompare);

  string toHash;
  toHash.append(const_cast<RRSIGRecordContent&>(rrc).serialize("", true));
  toHash.resize(toHash.size() - rrc.d_signature.length()); // chop off the end;
  //  cerr<<"toHash start size: "<<toHash.size()<<", signature length: "<<rrc.d_signature.length()<<endl;


  BOOST_FOREACH(shared_ptr<DNSRecordContent>& add, signRecords) {
    //  cerr<<"\t IN "<<rrc.d_originalttl<<"\t"<<add->getZoneRepresentation()<<"\n";
    toHash.append(toLower(simpleCompress(qname, "")));
    uint16_t tmp=htons(rrc.d_type);
    toHash.append((char*)&tmp, 2);
    tmp=htons(1); // class
    toHash.append((char*)&tmp, 2);
    uint32_t ttl=htonl(rrc.d_originalttl);
    toHash.append((char*)&ttl, 4);
    string rdata=add->serialize("", true);  // case issues hiding here..
    tmp=htons(rdata.length());
    toHash.append((char*)&tmp, 2);
    toHash.append(rdata);
  }
  //  cerr<<"toHash: "<<makeHexDump(toHash)<<endl;
  unsigned char hash[20];
  sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
  return string((char*)hash, 20);
}

DSRecordContent makeDSFromDNSKey(const std::string& qname, const DNSKEYRecordContent& drc, int digest)
{
  string toHash;
  toHash.assign(toLower(simpleCompress(qname)));
  toHash.append(const_cast<DNSKEYRecordContent&>(drc).serialize("", true));

  unsigned char hash[32];
  if(digest==1)
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
  else
    sha2((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);

  DSRecordContent dsrc;
  dsrc.d_algorithm=5;
  dsrc.d_digesttype=digest;
  dsrc.d_tag=const_cast<DNSKEYRecordContent&>(drc).getTag();
  dsrc.d_digest.assign((const char*)hash, digest == 1 ? 20 : 32);
  return dsrc;
}

DNSKEYRecordContent makeDNSKEYFromRSAKey(rsa_context* rc)
{
  DNSKEYRecordContent drc;
  char tmp[256];

  //  cerr<<"in makeDNSKEY rsa_check_pubkey: "<<rsa_check_pubkey(rc)<<", bits="<<mpi_size(&rc->N)*8<<endl;

  mpi_write_binary(&rc->E, (unsigned char*)tmp, mpi_size(&rc->E) );
  string exponent((char*)tmp, mpi_size(&rc->E));

  mpi_write_binary(&rc->N, (unsigned char*)tmp, mpi_size(&rc->N) );
  string modulus((char*)tmp, mpi_size(&rc->N));

  if(exponent.length() < 255) 
    drc.d_key.assign(1, (char) (unsigned int) exponent.length());
  else {
    drc.d_key.assign(1, 0);
    uint16_t len=htons(exponent.length());
    drc.d_key.append((char*)&len, 2);
  }
  drc.d_key.append(exponent);
  drc.d_key.append(modulus);

  drc.d_protocol=3;
  drc.d_algorithm = 5;

  drc.d_flags=256 + (modulus.length()>128);  // oops, I just made this up..

  return drc;
}

bool getSignerFor(const std::string& keyRepositoryDir, const std::string& qname, std::string &signer)
{
  DNSSECKeeper dk(keyRepositoryDir); 

  signer=qname;
  do {
    if(dk.haveKSKFor(signer)) 
      return true;
  } while(chopOff(signer));
  return false;
}

int countLabels(const std::string& signQName)
{
  int count =1;
  for(string::const_iterator pos = signQName.begin(); pos != signQName.end() ; ++pos) 
    if(*pos == '.' && pos+1 != signQName.end()) 
      count++;

  if(starts_with(signQName, "*."))
    count--;
  return count;
}

DNSKEYRecordContent getDNSKEYFor(const std::string& keyRepositoryDir, const std::string& qname, bool withKSK, RSAContext* rc)
{
  DNSSECKeeper dk(keyRepositoryDir);
  cerr<<"Asked for a DNSKEY for '"<<qname<<"', withKSK="<<withKSK<<"\n";
  DNSSECPrivateKey dpk;

  if(!withKSK) {
    DNSSECKeeper::zskset_t zskset=dk.getZSKsFor(qname);
    BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
      if(value.second.active) {
        cerr<<"Found a ZSK for '"<<qname<<"', key tag = "<<value.first.getDNSKEY().getTag()<<endl;
        *rc=value.first.d_key;
        return value.first.getDNSKEY();
      }
      else 
        cerr<<"Found an expired ZSK for '"<<qname<<"', key tag = "<<value.first.getDNSKEY().getTag()<<endl;
    }
    cerr<<"withKSK was not true, but found nothing!"<<endl;
    exit(1);
  }
  else if(dk.haveKSKFor(qname, &dpk)) {
    cerr<<"Found something"<<endl;
    *rc=dpk.d_key;
    return dpk.getDNSKEY();
  } else {
      cerr<<"DID NOT FIND A ZSK!"<<endl;
      exit(1);
  }
}


map<pair<string, uint16_t>, RRSIGRecordContent> g_rrsigs;

void fillOutRRSIG(const std::string& keyrepodir, const std::string& signQName, RRSIGRecordContent& rrc, const std::string& hash, vector<shared_ptr<DNSRecordContent> >& toSign, bool withKSK) 
{
  RSAContext rc;

  DNSKEYRecordContent drc =getDNSKEYFor(keyrepodir, rrc.d_signer, withKSK, &rc);
  rrc.d_tag = drc.getTag();
  
  if(g_rrsigs.count(make_pair(hash, rrc.d_tag))) {
    cerr<<"RRSIG cache hit !"<<endl;
    rrc = g_rrsigs[make_pair(hash, rrc.d_tag)];
    return;
  }
    
  string realhash=getSHA1HashForRRSET(signQName, rrc, toSign);

  unsigned char signature[mpi_size(&rc.getContext().N)];

  int ret=rsa_pkcs1_sign(&rc.getContext(), RSA_PRIVATE, SIG_RSA_SHA1, 20, (unsigned char*) realhash.c_str(), signature);
  
  if(ret!=0) {
    cerr<<"signing returned: "<<ret<<endl;
    exit(1);
  }
  
  rrc.d_signature.assign((char*)signature, sizeof(signature));
  
  g_rrsigs[make_pair(hash, rrc.d_tag)] = rrc;

}

uint32_t getCurrentInception()
{
  uint32_t now = time(0);
  now -= (now % (7*86400));
  return now;
}


int getRRSIGForRRSET(const std::string& keyrepodir, const std::string signQName, uint16_t signQType, uint32_t signTTL, 
		     vector<shared_ptr<DNSRecordContent> >& toSign, RRSIGRecordContent& rrc, bool ksk)
{
  if(toSign.empty())
    return -1;

  rrc.d_type=signQType;
  rrc.d_algorithm=5;      // rsasha1
  rrc.d_labels=countLabels(signQName); 
  rrc.d_originalttl=signTTL; 
  rrc.d_siginception=getCurrentInception();;
  rrc.d_sigexpire = rrc.d_siginception + 14*86400;

  rrc.d_tag=0;
  if(!getSignerFor(keyrepodir, signQName, rrc.d_signer)) {
    cerr<<"No signer known for '"<<signQName<<"'\n";
    return -1;
  }
    
  string hash= getSHA1HashForRRSET(signQName,  rrc, toSign);
  fillOutRRSIG(keyrepodir, signQName, rrc, hash, toSign, ksk);
  return 0;
}

void addSignature(const std::string& keyrepodir, const std::string signQName, const std::string& wildcardname, uint16_t signQType, uint32_t signTTL, DNSPacketWriter::Place signPlace, vector<shared_ptr<DNSRecordContent> >& toSign, DNSPacketWriter& pw)
{
  cerr<<"Asked to sign '"<<signQName<<"'|"<<DNSRecordContent::NumberToType(signQType)<<", "<<toSign.size()<<" records\n";

  RRSIGRecordContent rrc;
  if(toSign.empty())
    return;

  for(int ksk = 0; ksk < 2; ++ksk) {
    if(getRRSIGForRRSET(keyrepodir, wildcardname.empty() ? signQName : wildcardname, signQType, signTTL, toSign, rrc, ksk) < 0) {
      cerr<<"Error signing a record!"<<endl;
      return;
    }
    
    pw.startRecord(signQName, QType::RRSIG, 3600, 1, 
		   signQType==QType::DNSKEY ? DNSPacketWriter:: ANSWER : signPlace); 
    rrc.toPacket(pw);
    
    pw.commit();
    if(signQType != QType::DNSKEY)
      break;
  }

  toSign.clear();
}


std::string hashQNameWithSalt(unsigned int times, const std::string& salt, const std::string& qname)
{
  string toHash;
  toHash.assign(simpleCompress(toLower(qname)));
  toHash.append(salt);

  cerr<<makeHexDump(toHash)<<endl;
  unsigned char hash[20];
  for(;;) {
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
    if(!times--) 
      break;
    toHash.assign((char*)hash, 20);
    toHash.append(salt);
  }
  return string((char*)hash, 20);
}
