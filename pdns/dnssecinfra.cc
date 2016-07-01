#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#ifndef RECURSOR
#include "statbag.hh"
#endif
#include "iputils.hh"

#include <boost/algorithm/string.hpp>
#include "dnssecinfra.hh" 
#include "dnsseckeeper.hh"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>
#include "base64.hh"
#include "namespaces.hh"
#ifdef HAVE_P11KIT1
#include "pkcs11signers.hh"
#endif
#include "gss_context.hh"
#include "misc.hh"

using namespace boost::assign;

DNSCryptoKeyEngine* DNSCryptoKeyEngine::makeFromISCFile(DNSKEYRecordContent& drc, const char* fname)
{
  string sline, isc;
  FILE *fp=fopen(fname, "r");
  if(!fp) {
    throw runtime_error("Unable to read file '"+string(fname)+"' for generating DNS Private Key");
  }
  
  while(stringfgets(fp, sline)) {
    isc += sline;
  }
  fclose(fp);
  DNSCryptoKeyEngine* dke = makeFromISCString(drc, isc);
  if(!dke->checkKey()) {
    delete dke;
    throw runtime_error("Invalid DNS Private Key in file '"+string(fname));
  }
  return dke;
}

DNSCryptoKeyEngine* DNSCryptoKeyEngine::makeFromISCString(DNSKEYRecordContent& drc, const std::string& content)
{
  bool pkcs11=false;
  int algorithm = 0;
  string sline, key, value, raw;
  std::istringstream str(content);
  map<string, string> stormap;

  while(std::getline(str, sline)) {
    tie(key,value)=splitField(sline, ':');
    trim(value);
    if(pdns_iequals(key,"algorithm")) {
      algorithm = pdns_stou(value);
      stormap["algorithm"]=std::to_string(algorithm);
      continue;
    } else if (pdns_iequals(key,"pin")) {
      stormap["pin"]=value;
      continue;
    } else if (pdns_iequals(key,"engine")) {
      stormap["engine"]=value;
      pkcs11=true;
      continue;
    } else if (pdns_iequals(key,"slot")) {
      stormap["slot"]=value;
      continue;
    }  else if (pdns_iequals(key,"label")) {
      stormap["label"]=value;
      continue;
    }
    else if(pdns_iequals(key, "Private-key-format"))
      continue;
    raw.clear();
    B64Decode(value, raw);
    stormap[toLower(key)]=raw;
  }
  DNSCryptoKeyEngine* dpk;

  if (pkcs11) {
#ifdef HAVE_P11KIT1
    if (stormap.find("slot") == stormap.end())
      throw PDNSException("Cannot load PKCS#11 key, no Slot specified");
    // we need PIN to be at least empty
    if (stormap.find("pin") == stormap.end()) stormap["pin"] = "";
    dpk = PKCS11DNSCryptoKeyEngine::maker(algorithm); 
#else
    throw PDNSException("Cannot load PKCS#11 key without support for it");
#endif
  } else {
    dpk=make(algorithm);
  }
  dpk->fromISCMap(drc, stormap);
  return dpk;
}

std::string DNSCryptoKeyEngine::convertToISC() const
{
  typedef map<string, string> stormap_t;
  storvector_t stormap = this->convertToISCVector();
  ostringstream ret;
  ret<<"Private-key-format: v1.2\n";
  for(const stormap_t::value_type& value :  stormap) {
    if(value.first != "Algorithm" && value.first != "PIN" && 
       value.first != "Slot" && value.first != "Engine" &&
       value.first != "Label") 
      ret<<value.first<<": "<<Base64Encode(value.second)<<"\n";
    else
      ret<<value.first<<": "<<value.second<<"\n";
  }
  return ret.str();
}

DNSCryptoKeyEngine* DNSCryptoKeyEngine::make(unsigned int algo)
{
  makers_t& makers = getMakers();
  makers_t::const_iterator iter = makers.find(algo);
  if(iter != makers.end())
    return (iter->second)(algo);
  else {
    throw runtime_error("Request to create key object for unknown algorithm number "+std::to_string(algo));
  }
}

/**
 * Returns the supported DNSSEC algorithms with the name of the Crypto Backend used
 *
 * @return   A vector with pairs of (algorithm-number (int), backend-name (string))
 */
vector<pair<uint8_t, string>> DNSCryptoKeyEngine::listAllAlgosWithBackend()
{
  vector<pair<uint8_t, string>> ret;
  for (auto const& value : getMakers()) {
    shared_ptr<DNSCryptoKeyEngine> dcke(value.second(value.first));
    ret.push_back(make_pair(value.first, dcke->getName()));
  }
  return ret;
}

void DNSCryptoKeyEngine::report(unsigned int algo, maker_t* maker, bool fallback)
{
  getAllMakers()[algo].push_back(maker);
  if(getMakers().count(algo) && fallback) {
    return;
  }
  getMakers()[algo]=maker;
}

bool DNSCryptoKeyEngine::testAll()
{
  bool ret=true;

  for(const allmakers_t::value_type& value :  getAllMakers())
  {
    for(maker_t* creator :  value.second) {

      for(maker_t* signer :  value.second) {
        // multi_map<unsigned int, maker_t*> bestSigner, bestVerifier;
        
        for(maker_t* verifier :  value.second) {
          try {
            /* pair<unsigned int, unsigned int> res=*/ testMakers(value.first, creator, signer, verifier);
          }
          catch(std::exception& e)
          {
            cerr<<e.what()<<endl;
            ret=false;
          }
        }
      }
    }
  }
  return ret;
}

bool DNSCryptoKeyEngine::testOne(int algo)
{
  bool ret=true;

  for(maker_t* creator :  getAllMakers()[algo]) {

    for(maker_t* signer :  getAllMakers()[algo]) {
      // multi_map<unsigned int, maker_t*> bestSigner, bestVerifier;

      for(maker_t* verifier :  getAllMakers()[algo]) {
        try {
          /* pair<unsigned int, unsigned int> res=*/testMakers(algo, creator, signer, verifier);
        }
        catch(std::exception& e)
        {
          cerr<<e.what()<<endl;
          ret=false;
        }
      }
    }
  }
  return ret;
}
// returns times it took to sign and verify
pair<unsigned int, unsigned int> DNSCryptoKeyEngine::testMakers(unsigned int algo, maker_t* creator, maker_t* signer, maker_t* verifier)
{
  shared_ptr<DNSCryptoKeyEngine> dckeCreate(creator(algo));
  shared_ptr<DNSCryptoKeyEngine> dckeSign(signer(algo));
  shared_ptr<DNSCryptoKeyEngine> dckeVerify(verifier(algo));

  cerr<<"Testing algorithm "<<algo<<": '"<<dckeCreate->getName()<<"' ->'"<<dckeSign->getName()<<"' -> '"<<dckeVerify->getName()<<"' ";
  unsigned int bits;
  if(algo <= 10)
    bits=1024;
  else if(algo == 12 || algo == 13 || algo == 250) // ECC-GOST or ECDSAP256SHA256 or ED25519SHA512
    bits=256;
  else if(algo == 14) // ECDSAP384SHA384
    bits = 384;
  else
    throw runtime_error("Can't guess key size for algorithm "+std::to_string(algo));

  dckeCreate->create(bits);

  { // FIXME: this block copy/pasted from makeFromISCString
    DNSKEYRecordContent dkrc;
    int algorithm = 0;
    string sline, key, value, raw;
    std::istringstream str(dckeCreate->convertToISC());
    map<string, string> stormap;

    while(std::getline(str, sline)) {
      tie(key,value)=splitField(sline, ':');
      trim(value);
      if(pdns_iequals(key,"algorithm")) {
        algorithm = pdns_stou(value);
        stormap["algorithm"]=std::to_string(algorithm);
        continue;
      } else if (pdns_iequals(key,"pin")) {
        stormap["pin"]=value;
        continue;
      } else if (pdns_iequals(key,"engine")) {
        stormap["engine"]=value;
        continue;
      } else if (pdns_iequals(key,"slot")) {
        int slot = std::stoi(value);
        stormap["slot"]=std::to_string(slot);
        continue;
      }  else if (pdns_iequals(key,"label")) {
        stormap["label"]=value;
        continue;
      }
      else if(pdns_iequals(key, "Private-key-format"))
        continue;
      raw.clear();
      B64Decode(value, raw);
      stormap[toLower(key)]=raw;
    }
    dckeSign->fromISCMap(dkrc, stormap);
    if(!dckeSign->checkKey()) {
      throw runtime_error("Verification of key with creator "+dckeCreate->getName()+" with signer "+dckeSign->getName()+" and verifier "+dckeVerify->getName()+" failed");
    }
  }

  string message("Hi! How is life?");
  
  string signature;
  DTime dt; dt.set();
  for(unsigned int n = 0; n < 100; ++n)
    signature = dckeSign->sign(message);
  unsigned int udiffSign= dt.udiff()/100, udiffVerify;
  
  dckeVerify->fromPublicKeyString(dckeSign->getPublicKeyString());
  if (dckeVerify->getPublicKeyString().compare(dckeSign->getPublicKeyString())) {
    throw runtime_error("Comparison of public key loaded into verifier produced by signer failed");
  }
  dt.set();
  if(dckeVerify->verify(message, signature)) {
    udiffVerify = dt.udiff();
    cerr<<"Signature & verify ok, signature "<<udiffSign<<"usec, verify "<<udiffVerify<<"usec"<<endl;
  }
  else {
    throw runtime_error("Verification of creator "+dckeCreate->getName()+" with signer "+dckeSign->getName()+" and verifier "+dckeVerify->getName()+" failed");
  }
  return make_pair(udiffSign, udiffVerify);
}

DNSCryptoKeyEngine* DNSCryptoKeyEngine::makeFromPublicKeyString(unsigned int algorithm, const std::string& content)
{
  DNSCryptoKeyEngine* dpk=make(algorithm);
  dpk->fromPublicKeyString(content);
  return dpk;
}


DNSCryptoKeyEngine* DNSCryptoKeyEngine::makeFromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  
  for(makers_t::value_type& val :  getMakers())
  {
    DNSCryptoKeyEngine* ret=0;
    try {
      ret = val.second(val.first);
      ret->fromPEMString(drc, raw);
      return ret;
    }
    catch(...)
    {
      delete ret; // fine if 0
    }
  }
  return 0;
}


bool sharedDNSSECCompare(const shared_ptr<DNSRecordContent>& a, const shared_ptr<DNSRecordContent>& b)
{
  return a->serialize(DNSName("."), true, true) < b->serialize(DNSName("."), true, true);
}

/**
 * Returns the string that should be hashed to create/verify the RRSIG content
 *
 * @param qname               DNSName of the RRSIG's owner name.
 * @param rrc                 The RRSIGRecordContent we take the Type Covered and
 *                            original TTL fields from.
 * @param signRecords         A vector of DNSRecordContent shared_ptr's that are covered
 *                            by the RRSIG, where we get the RDATA from.
 * @param processRRSIGLabels  A boolean to trigger processing the RRSIG's "Labels"
 *                            field. This is usually only needed for validation
 *                            purposes, as the authoritative server correctly
 *                            sets qname to the wildcard.
 */
string getMessageForRRSET(const DNSName& qname, const RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& signRecords, bool processRRSIGLabels)
{
  sort(signRecords.begin(), signRecords.end(), sharedDNSSECCompare);

  string toHash;
  toHash.append(const_cast<RRSIGRecordContent&>(rrc).serialize(DNSName("."), true, true));
  toHash.resize(toHash.size() - rrc.d_signature.length()); // chop off the end, don't sign the signature!

  string nameToHash(qname.toDNSStringLC());

  if (processRRSIGLabels) {
    unsigned int rrsig_labels = rrc.d_labels;
    unsigned int fqdn_labels = qname.countLabels();

    if (rrsig_labels < fqdn_labels) {
      DNSName choppedQname(qname);
      while (choppedQname.countLabels() > rrsig_labels)
        choppedQname.chopOff();
      nameToHash = "\x01*" + choppedQname.toDNSStringLC();
    } else if (rrsig_labels > fqdn_labels) {
      // The RRSIG Labels field is a lie (or the qname is wrong) and the RRSIG
      // can never be valid
      return "";
    }
  }

  for(shared_ptr<DNSRecordContent>& add :  signRecords) {
    toHash.append(nameToHash);
    uint16_t tmp=htons(rrc.d_type);
    toHash.append((char*)&tmp, 2);
    tmp=htons(1); // class
    toHash.append((char*)&tmp, 2);
    uint32_t ttl=htonl(rrc.d_originalttl);
    toHash.append((char*)&ttl, 4);
    // for NSEC signatures, we should not lowercase the rdata section
    string rdata=add->serialize(DNSName("."), true, (add->getType() == QType::NSEC) ? false : true);  // RFC 6840, 5.1
    tmp=htons(rdata.length());
    toHash.append((char*)&tmp, 2);
    toHash.append(rdata);
  }
  
  return toHash;
}

DSRecordContent makeDSFromDNSKey(const DNSName& qname, const DNSKEYRecordContent& drc, int digest)
{
  string toHash;
  toHash.assign(qname.toDNSStringLC()); 
  toHash.append(const_cast<DNSKEYRecordContent&>(drc).serialize(DNSName(), true, true));
  
  DSRecordContent dsrc;
  if(digest==1) {
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(5)); // gives us SHA1
    dsrc.d_digest = dpk->hash(toHash);
  }
  else if(digest == 2) {
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(8)); // gives us SHA256
    dsrc.d_digest = dpk->hash(toHash);
  }
  else if(digest == 3) {
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(12)); // gives us GOST
    dsrc.d_digest = dpk->hash(toHash);
  }
  else if(digest == 4) {
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(14)); // gives us ECDSAP384
    dsrc.d_digest = dpk->hash(toHash);
  }
  else 
    throw std::runtime_error("Asked to a DS of unknown digest type " + std::to_string(digest)+"\n");
  
  dsrc.d_algorithm= drc.d_algorithm;
  dsrc.d_digesttype=digest;
  dsrc.d_tag=const_cast<DNSKEYRecordContent&>(drc).getTag();

  return dsrc;
}


DNSKEYRecordContent makeDNSKEYFromDNSCryptoKeyEngine(const DNSCryptoKeyEngine* pk, uint8_t algorithm, uint16_t flags)
{
  DNSKEYRecordContent drc;

  drc.d_protocol=3;
  drc.d_algorithm = algorithm;

  drc.d_flags=flags;
  drc.d_key = pk->getPublicKeyString();

  return drc;
}

int countLabels(const std::string& signQName)
{
  if(!signQName.empty()) {
    int count=1;
    for(string::const_iterator pos = signQName.begin(); pos != signQName.end() ; ++pos)
      if(*pos == '.' && pos+1 != signQName.end())
        count++;

    if(boost::starts_with(signQName, "*."))
      count--;
    return count;
  }
  return 0;
}

uint32_t getStartOfWeek()
{
  uint32_t now = time(0);
  now -= (now % (7*86400));
  return now;
}

string hashQNameWithSalt(const NSEC3PARAMRecordContent& ns3prc, const DNSName& qname)
{
  return hashQNameWithSalt(ns3prc.d_salt, ns3prc.d_iterations, qname);
}

string hashQNameWithSalt(const std::string& salt, unsigned int iterations, const DNSName& qname)
{
  unsigned int times = iterations;
  unsigned char hash[20];
  string toHash(qname.toDNSStringLC());

  for(;;) {
    toHash.append(salt);
    SHA1((unsigned char*)toHash.c_str(), toHash.length(), hash);
    toHash.assign((char*)hash, sizeof(hash));
    if(!times--)
      break;
  }
  return toHash;
}

DNSKEYRecordContent DNSSECPrivateKey::getDNSKEY() const
{
  return makeDNSKEYFromDNSCryptoKeyEngine(getKey(), d_algorithm, d_flags);
}

class DEREater
{
public:
  DEREater(const std::string& str) : d_str(str), d_pos(0)
  {}
  
  struct eof{};
  
  uint8_t getByte()
  {
    if(d_pos >= d_str.length()) {
      throw eof();
    }
    return (uint8_t) d_str[d_pos++];
  }
  
  uint32_t getLength()
  {
    uint8_t first = getByte();
    if(first < 0x80) {
      return first;
    }
    first &= ~0x80;
    
    uint32_t len=0;
    for(int n=0; n < first; ++n) {
      len *= 0x100;
      len += getByte();
    }
    return len;
  }
  
  std::string getBytes(unsigned int len)
  {
    std::string ret;
    for(unsigned int n=0; n < len; ++n)
      ret.append(1, (char)getByte());
    return ret;
  }
  
  std::string::size_type getOffset() 
  {
    return d_pos;
  }
private:
  const std::string& d_str;
  std::string::size_type d_pos;
};

void decodeDERIntegerSequence(const std::string& input, vector<string>& output)
{
  output.clear();
  DEREater de(input);
  if(de.getByte() != 0x30) 
    throw runtime_error("Not a DER sequence");
  
  unsigned int seqlen=de.getLength(); 
  unsigned int startseq=de.getOffset();
  unsigned int len;
  string ret;
  try {
    for(;;) {
      uint8_t kind = de.getByte();
      if(kind != 0x02) 
        throw runtime_error("DER Sequence contained non-INTEGER component: "+std::to_string(static_cast<unsigned int>(kind)) );
      len = de.getLength();
      ret = de.getBytes(len);
      output.push_back(ret);
    }
  }
  catch(DEREater::eof& eof)
  {
    if(de.getOffset() - startseq != seqlen)
      throw runtime_error("DER Sequence ended before end of data");
  }  
}

string calculateHMAC(const std::string& key, const std::string& text, TSIGHashEnum hasher) {

  const EVP_MD* md_type;
  unsigned int outlen;
  unsigned char hash[EVP_MAX_MD_SIZE];
  switch(hasher) {
    case TSIG_MD5:
      md_type = EVP_md5();
      break;
    case TSIG_SHA1:
      md_type = EVP_sha1();
      break;
    case TSIG_SHA224:
      md_type = EVP_sha224();
      break;
    case TSIG_SHA256:
      md_type = EVP_sha256();
      break;
    case TSIG_SHA384:
      md_type = EVP_sha384();
      break;
    case TSIG_SHA512:
      md_type = EVP_sha512();
      break;
    default:
      throw new PDNSException("Unknown hash algorithm requested from calculateHMAC()");
  }

  unsigned char* out = HMAC(md_type, reinterpret_cast<const unsigned char*>(key.c_str()), key.size(), reinterpret_cast<const unsigned char*>(text.c_str()), text.size(), hash, &outlen);
  if (out != NULL && outlen > 0) {
    return string((char*) hash, outlen);
  }

  return "";
}

string makeTSIGMessageFromTSIGPacket(const string& opacket, unsigned int tsigOffset, const DNSName& keyname, const TSIGRecordContent& trc, const string& previous, bool timersonly, unsigned int dnsHeaderOffset)
{
  string message;
  string packet(opacket);

  packet.resize(tsigOffset); // remove the TSIG record at the end as per RFC2845 3.4.1
  packet[(dnsHeaderOffset + sizeof(struct dnsheader))-1]--; // Decrease ARCOUNT because we removed the TSIG RR in the previous line.
  

  // Replace the message ID with the original message ID from the TSIG record.
  // This is needed for forwarded DNS Update as they get a new ID when forwarding (section 6.1 of RFC2136). The TSIG record stores the original ID and the
  // signature was created with the original ID, so we replace it here to get the originally signed message.
  // If the message is not forwarded, we simply override it with the same id.
  uint16_t origID = htons(trc.d_origID);
  packet.replace(0, 2, (char*)&origID, 2);

  if(!previous.empty()) {
    uint16_t len = htons(previous.length());
    message.append((char*)&len, 2);
    message.append(previous);
  }
  
  message.append(packet);

  vector<uint8_t> signVect;
  DNSPacketWriter dw(signVect, DNSName(), 0);
  if(!timersonly) {
    dw.xfrName(keyname, false);
    dw.xfr16BitInt(QClass::ANY); // class
    dw.xfr32BitInt(0);    // TTL
    // dw.xfrName(toLower(trc.d_algoName), false); //FIXME400 
    dw.xfrName(trc.d_algoName, false);
  }
  
  uint32_t now = trc.d_time; 
  dw.xfr48BitInt(now);
  dw.xfr16BitInt(trc.d_fudge); // fudge
  if(!timersonly) {
    dw.xfr16BitInt(trc.d_eRcode); // extended rcode
    dw.xfr16BitInt(trc.d_otherData.length()); // length of 'other' data
    //    dw.xfrBlob(trc->d_otherData);
  }
  const vector<uint8_t>& signRecord=dw.getRecordBeingWritten();
  message.append(signRecord.begin(), signRecord.end());
  return message;
}

void addTSIG(DNSPacketWriter& pw, TSIGRecordContent* trc, const DNSName& tsigkeyname, const string& tsigsecret, const string& tsigprevious, bool timersonly)
{
  TSIGHashEnum algo;
  if (!getTSIGHashEnum(trc->d_algoName, algo)) {
    throw PDNSException(string("Unsupported TSIG HMAC algorithm ") + trc->d_algoName.toString());
  }

  string toSign;
  if(!tsigprevious.empty()) {
    uint16_t len = htons(tsigprevious.length());
    toSign.append((char*)&len, 2);
    
    toSign.append(tsigprevious);
  }
  toSign.append(pw.getContent().begin(), pw.getContent().end());
  
  // now add something that looks a lot like a TSIG record, but isn't
  vector<uint8_t> signVect;
  DNSPacketWriter dw(signVect, DNSName(), 0);
  if(!timersonly) {
    dw.xfrName(tsigkeyname, false);
    dw.xfr16BitInt(QClass::ANY); // class
    dw.xfr32BitInt(0);    // TTL
    dw.xfrName(trc->d_algoName, false);
  }  
  uint32_t now = trc->d_time; 
  dw.xfr48BitInt(now);
  dw.xfr16BitInt(trc->d_fudge); // fudge
  
  if(!timersonly) {
    dw.xfr16BitInt(trc->d_eRcode); // extended rcode
    dw.xfr16BitInt(trc->d_otherData.length()); // length of 'other' data
    //    dw.xfrBlob(trc->d_otherData);
  }
  
  const vector<uint8_t>& signRecord=dw.getRecordBeingWritten();
  toSign.append(signRecord.begin(), signRecord.end());

  if (algo == TSIG_GSS) {
    if (!gss_add_signature(tsigkeyname, toSign, trc->d_mac)) {
      throw PDNSException(string("Could not add TSIG signature with algorithm 'gss-tsig' and key name '")+tsigkeyname.toString()+string("'"));
    }
  } else {
    trc->d_mac = calculateHMAC(tsigsecret, toSign, algo);
    //  d_trc->d_mac[0]++; // sabotage
  }
  pw.startRecord(tsigkeyname, QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  trc->toPacket(pw);
  pw.commit();
}

