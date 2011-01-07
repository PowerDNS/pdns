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
#include <polarssl/havege.h>
#include <polarssl/base64.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>

using namespace boost;
using namespace std;
using namespace boost::assign;

void RSAContext::create(unsigned int bits)
{
  havege_state hs;
  havege_init( &hs );
  
  rsa_init(&d_context, RSA_PKCS_V15, 0, havege_rand, &hs ); // FIXME this leaks memory
  int ret=rsa_gen_key(&d_context, bits, 65537);
  if(ret < 0) 
    throw runtime_error("Key generation failed");
}

std::string RSAContext::convertToISC(unsigned int algorithm) const
{
  string ret;
  typedef vector<pair<string, const mpi*> > outputs_t;
  outputs_t outputs;
  push_back(outputs)("Modulus", &d_context.N)("PublicExponent",&d_context.E)
    ("PrivateExponent",&d_context.D)
    ("Prime1",&d_context.P)
    ("Prime2",&d_context.Q)
    ("Exponent1",&d_context.DP)
    ("Exponent2",&d_context.DQ)
    ("Coefficient",&d_context.QP);

  ret = "Private-key-format: v1.2\nAlgorithm: "+lexical_cast<string>(algorithm);
  switch(algorithm) {
    case 5:
    case 7 :
      ret+= " (RSASHA1)";
      break;
    case 8:
      ret += " (RSASHA256)";
      break;
  }
  ret += "\n";

  BOOST_FOREACH(outputs_t::value_type value, outputs) {
    ret += value.first;
    ret += ": ";
    unsigned char tmp[mpi_size(value.second)];
    mpi_write_binary(value.second, tmp, sizeof(tmp));
    unsigned char base64tmp[sizeof(tmp)*2];
    int dlen=sizeof(base64tmp);
    base64_encode(base64tmp, &dlen, tmp, sizeof(tmp));
    ret.append((const char*)base64tmp, dlen);
    ret.append(1, '\n');
  }
  return ret;
}


DNSKEYRecordContent getRSAKeyFromISC(rsa_context* rsa, const char* fname)
{
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
  while(stringfgets(fp, sline)) {
    tie(key,value)=splitField(sline, ':');
    trim(value);
    trim(key);
    if(key.empty())
      continue;
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
      if(key=="Algorithm") {
        drc.d_algorithm = atoi(value.c_str());
      }
      else if(key != "Private-key-format")
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
  fclose(fp);
  return drc;
}

DNSKEYRecordContent getRSAKeyFromISCString(rsa_context* rsa, const std::string& content)
{
  string sline;
  string key,value;
  map<string, mpi*> places;

  
  rsa_init(rsa, RSA_PKCS_V15, 0, NULL, NULL );

  places["Modulus"]=&rsa->N;
  places["PublicExponent"]=&rsa->E;
  places["PrivateExponent"]=&rsa->D;
  places["Prime1"]=&rsa->P;
  places["Prime2"]=&rsa->Q;
  places["Exponent1"]=&rsa->DP;
  places["Exponent2"]=&rsa->DQ;
  places["Coefficient"]=&rsa->QP;

  DNSKEYRecordContent drc;
  string modulus, exponent;
  istringstream str(content);
  unsigned char decoded[1024];
  while(getline(str, sline)) {
    tie(key,value)=splitField(sline, ':');
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
      if(key == "Algorithm") 
        drc.d_algorithm = atoi(value.c_str());
      else if(key != "Private-key-format")
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
  return a->serialize("", true, true) < b->serialize("", true, true);
}

string getSHA1HashForRRSET(const std::string& qname, const RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& signRecords) 
{
  sort(signRecords.begin(), signRecords.end(), sharedDNSSECCompare);

  string toHash;
  toHash.append(const_cast<RRSIGRecordContent&>(rrc).serialize("", true, true));
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
    string rdata=add->serialize("", true, true); 
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
  toHash.append(const_cast<DNSKEYRecordContent&>(drc).serialize("", true, true));

  unsigned char hash[32];
  if(digest==1)
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
  else
    sha2((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);

  DSRecordContent dsrc;
  dsrc.d_algorithm= drc.d_algorithm;
  dsrc.d_digesttype=digest;
  dsrc.d_tag=const_cast<DNSKEYRecordContent&>(drc).getTag();
  dsrc.d_digest.assign((const char*)hash, digest == 1 ? 20 : 32);
  return dsrc;
}

DNSKEYRecordContent makeDNSKEYFromRSAKey(const rsa_context* rc, uint8_t algorithm, uint16_t flags)
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
  drc.d_algorithm = algorithm;

  drc.d_flags=flags;

  return drc;
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



uint32_t getCurrentInception()
{
  uint32_t now = time(0);
  now -= (now % (7*86400));
  return now;
}



std::string hashQNameWithSalt(unsigned int times, const std::string& salt, const std::string& qname)
{
  string toHash;
  toHash.assign(simpleCompress(toLower(qname)));
  toHash.append(salt);

//  cerr<<makeHexDump(toHash)<<endl;
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
DNSKEYRecordContent DNSSECPrivateKey::getDNSKEY() const
{
  return makeDNSKEYFromRSAKey(&d_key.getConstContext(), d_algorithm, d_flags);
}
