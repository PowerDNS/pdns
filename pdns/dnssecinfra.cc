#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "iputils.hh"
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include "dnssecinfra.hh" 
#include "dnsseckeeper.hh"
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>
#include "base64.hh"
#include "sha.hh"
#include "namespaces.hh"
#ifdef HAVE_P11KIT1
#include "pkcs11signers.hh"
#endif

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
  return makeFromISCString(drc, isc);
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
      algorithm = atoi(value.c_str());
      stormap["algorithm"]=lexical_cast<string>(algorithm);
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
  BOOST_FOREACH(const stormap_t::value_type& value, stormap) {
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
    throw runtime_error("Request to create key object for unknown algorithm number "+lexical_cast<string>(algo));
  }
}

void DNSCryptoKeyEngine::report(unsigned int algo, maker_t* maker, bool fallback)
{
  getAllMakers()[algo].push_back(maker);
  if(getMakers().count(algo) && fallback) {
    return;
  }
  getMakers()[algo]=maker;
}

void DNSCryptoKeyEngine::testAll()
{
  BOOST_FOREACH(const allmakers_t::value_type& value, getAllMakers())
  {
    BOOST_FOREACH(maker_t* creator, value.second) {

      BOOST_FOREACH(maker_t* signer, value.second) {
        // multi_map<unsigned int, maker_t*> bestSigner, bestVerifier;
        
        BOOST_FOREACH(maker_t* verifier, value.second) {
          try {
            /* pair<unsigned int, unsigned int> res=*/ testMakers(value.first, creator, signer, verifier);
          }
          catch(std::exception& e)
          {
            cerr<<e.what()<<endl;
          }
        }
      }
    }
  }
}

void DNSCryptoKeyEngine::testOne(int algo)
{
  BOOST_FOREACH(maker_t* creator, getAllMakers()[algo]) {

    BOOST_FOREACH(maker_t* signer, getAllMakers()[algo]) {
      // multi_map<unsigned int, maker_t*> bestSigner, bestVerifier;

      BOOST_FOREACH(maker_t* verifier, getAllMakers()[algo]) {
        try {
          /* pair<unsigned int, unsigned int> res=*/testMakers(algo, creator, signer, verifier);
        }
        catch(std::exception& e)
        {
          cerr<<e.what()<<endl;
        }
      }
    }
  }
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
  else if(algo == 12 || algo == 13 || algo == 250) // GOST or nistp256 or ED25519
    bits=256;
  else 
    bits=384;
    
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
        algorithm = atoi(value.c_str());
        stormap["algorithm"]=lexical_cast<string>(algorithm);
        continue;
      } else if (pdns_iequals(key,"pin")) {
        stormap["pin"]=value;
        continue;
      } else if (pdns_iequals(key,"engine")) {
        stormap["engine"]=value;
        continue;
      } else if (pdns_iequals(key,"slot")) {
        int slot = atoi(value.c_str());
        stormap["slot"]=lexical_cast<string>(slot);
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
  }

  string message("Hi! How is life?");
  
  string signature;
  DTime dt; dt.set();
  for(unsigned int n = 0; n < 100; ++n)
    signature = dckeSign->sign(message);
  unsigned int udiffSign= dt.udiff()/100, udiffVerify;
  
  dckeVerify->fromPublicKeyString(dckeSign->getPublicKeyString());
  
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
  
  BOOST_FOREACH(makers_t::value_type& val, getMakers())
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
  return a->serialize("", true, true) < b->serialize("", true, true);
}

string getMessageForRRSET(const std::string& qname, const RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& signRecords) 
{
  sort(signRecords.begin(), signRecords.end(), sharedDNSSECCompare);

  string toHash;
  toHash.append(const_cast<RRSIGRecordContent&>(rrc).serialize("", true, true));
  toHash.resize(toHash.size() - rrc.d_signature.length()); // chop off the end, don't sign the signature!

  BOOST_FOREACH(shared_ptr<DNSRecordContent>& add, signRecords) {
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
  
  return toHash;
}

DSRecordContent makeDSFromDNSKey(const std::string& qname, const DNSKEYRecordContent& drc, int digest)
{
  string toHash;
  toHash.assign(toLower(simpleCompress(qname)));
  toHash.append(const_cast<DNSKEYRecordContent&>(drc).serialize("", true, true));
  
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
    throw std::runtime_error("Asked to a DS of unknown digest type " + lexical_cast<string>(digest)+"\n");
  
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
    toHash.assign((char*)hash, sizeof(hash));
    toHash.append(salt);
  }
  return string((char*)hash, sizeof(hash));
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
        throw runtime_error("DER Sequence contained non-INTEGER component: "+lexical_cast<string>((unsigned int)kind) );
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

string calculateMD5HMAC(const std::string& key, const std::string& text)
{
  std::string res;
  unsigned char hash[16];

  md5_hmac(reinterpret_cast<const unsigned char*>(key.c_str()), key.size(), reinterpret_cast<const unsigned char*>(text.c_str()), text.size(), hash);
  res.assign(reinterpret_cast<const char*>(hash), 16);

  return res;
}

string calculateSHAHMAC(const std::string& key, const std::string& text, TSIGHashEnum hasher)
{
  std::string res;
  unsigned char hash[64];

  switch(hasher) {
  case TSIG_SHA1:
  {
      sha1_hmac(reinterpret_cast<const unsigned char*>(key.c_str()), key.size(), reinterpret_cast<const unsigned char*>(text.c_str()), text.size(), hash);
      res.assign(reinterpret_cast<const char*>(hash), 20);
      break;
  };
  case TSIG_SHA224:
  {
      sha2_hmac(reinterpret_cast<const unsigned char*>(key.c_str()), key.size(), reinterpret_cast<const unsigned char*>(text.c_str()), text.size(), hash, 1);
      res.assign(reinterpret_cast<const char*>(hash), 28);
      break;
  };
  case TSIG_SHA256:
  {
      sha2_hmac(reinterpret_cast<const unsigned char*>(key.c_str()), key.size(), reinterpret_cast<const unsigned char*>(text.c_str()), text.size(), hash, 0);
      res.assign(reinterpret_cast<const char*>(hash), 32);
      break;
  };
  case TSIG_SHA384:
  {
      sha4_hmac(reinterpret_cast<const unsigned char*>(key.c_str()), key.size(), reinterpret_cast<const unsigned char*>(text.c_str()), text.size(), hash, 1);
      res.assign(reinterpret_cast<const char*>(hash), 48);
      break;
  };
  case TSIG_SHA512:
  {
      sha4_hmac(reinterpret_cast<const unsigned char*>(key.c_str()), key.size(), reinterpret_cast<const unsigned char*>(text.c_str()), text.size(), hash, 0);
      res.assign(reinterpret_cast<const char*>(hash), 64);
      break;
  };
  default:
    throw new PDNSException("Unknown hash algorithm requested for SHA");
  };

  return res;
}

string calculateHMAC(const std::string& key, const std::string& text, TSIGHashEnum hash) {
  if (hash == TSIG_MD5) return calculateMD5HMAC(key, text);

  // add other algorithms here

  return calculateSHAHMAC(key, text, hash);
}

string makeTSIGMessageFromTSIGPacket(const string& opacket, unsigned int tsigOffset, const string& keyname, const TSIGRecordContent& trc, const string& previous, bool timersonly, unsigned int dnsHeaderOffset)
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
  DNSPacketWriter dw(signVect, "", 0);
  if(!timersonly) {
    dw.xfrLabel(keyname, false);
    dw.xfr16BitInt(QClass::ANY); // class
    dw.xfr32BitInt(0);    // TTL
    dw.xfrLabel(toLower(trc.d_algoName), false);
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
  message.append(&*signRecord.begin(), &*signRecord.end());
  return message;
}


bool getTSIGHashEnum(const string &algoName, TSIGHashEnum& algoEnum)
{
  string normalizedName = toLowerCanonic(algoName);

  if (normalizedName == "hmac-md5.sig-alg.reg.int")
    algoEnum = TSIG_MD5;
  else if (normalizedName == "hmac-sha1")
    algoEnum = TSIG_SHA1;
  else if (normalizedName == "hmac-sha224")
    algoEnum = TSIG_SHA224;
  else if (normalizedName == "hmac-sha256")
    algoEnum = TSIG_SHA256;
  else if (normalizedName == "hmac-sha384")
    algoEnum = TSIG_SHA384;
  else if (normalizedName == "hmac-sha512")
    algoEnum = TSIG_SHA512;
  else {
     return false;
  }
  return true;
}


void addTSIG(DNSPacketWriter& pw, TSIGRecordContent* trc, const string& tsigkeyname, const string& tsigsecret, const string& tsigprevious, bool timersonly)
{
  TSIGHashEnum algo;
  if (!getTSIGHashEnum(trc->d_algoName, algo)) {
     L<<Logger::Error<<"Unsupported TSIG HMAC algorithm " << trc->d_algoName << endl;
     return;
  }

  string toSign;
  if(!tsigprevious.empty()) {
    uint16_t len = htons(tsigprevious.length());
    toSign.append((char*)&len, 2);
    
    toSign.append(tsigprevious);
  }
  toSign.append(&*pw.getContent().begin(), &*pw.getContent().end());
  
  // now add something that looks a lot like a TSIG record, but isn't
  vector<uint8_t> signVect;
  DNSPacketWriter dw(signVect, "", 0);
  if(!timersonly) {
    dw.xfrLabel(tsigkeyname, false);
    dw.xfr16BitInt(QClass::ANY); // class
    dw.xfr32BitInt(0);    // TTL
    dw.xfrLabel(trc->d_algoName, false);
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
  toSign.append(&*signRecord.begin(), &*signRecord.end());

  trc->d_mac = calculateHMAC(tsigsecret, toSign, algo);
  //  d_trc->d_mac[0]++; // sabotage
  pw.startRecord(tsigkeyname, QType::TSIG, 0, QClass::ANY, DNSPacketWriter::ADDITIONAL, false);
  trc->toPacket(pw);
  pw.commit();
}

