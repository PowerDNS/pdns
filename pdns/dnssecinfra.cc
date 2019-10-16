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

shared_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromISCFile(DNSKEYRecordContent& drc, const char* fname)
{
  string sline, isc;
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(fname, "r"), fclose);
  if(!fp) {
    throw runtime_error("Unable to read file '"+string(fname)+"' for generating DNS Private Key");
  }
  
  while(stringfgets(fp.get(), sline)) {
    isc += sline;
  }
  fp.reset();

  shared_ptr<DNSCryptoKeyEngine> dke = makeFromISCString(drc, isc);
  vector<string> checkKeyErrors;

  if(!dke->checkKey(&checkKeyErrors)) {
    string reason;
    if(checkKeyErrors.size()) {
      reason = " ("+boost::algorithm::join(checkKeyErrors, ", ")+")";
    }
    throw runtime_error("Invalid DNS Private Key in file '"+string(fname)+"'"+reason);
  }
  return dke;
}

shared_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromISCString(DNSKEYRecordContent& drc, const std::string& content)
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
    } else if (pdns_iequals(key,"publabel")) {
      stormap["publabel"]=value;
      continue;
    }
    else if(pdns_iequals(key, "Private-key-format"))
      continue;
    raw.clear();
    B64Decode(value, raw);
    stormap[toLower(key)]=raw;
  }
  shared_ptr<DNSCryptoKeyEngine> dpk;

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
  storvector_t stormap = this->convertToISCVector();
  ostringstream ret;
  ret<<"Private-key-format: v1.2\n";
  for(const stormap_t::value_type& value :  stormap) {
    if(value.first != "Algorithm" && value.first != "PIN" && 
       value.first != "Slot" && value.first != "Engine" &&
       value.first != "Label" && value.first != "PubLabel")
      ret<<value.first<<": "<<Base64Encode(value.second)<<"\n";
    else
      ret<<value.first<<": "<<value.second<<"\n";
  }
  return ret.str();
}

shared_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::make(unsigned int algo)
{
  const makers_t& makers = getMakers();
  makers_t::const_iterator iter = makers.find(algo);
  if(iter != makers.cend())
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
            testMakers(value.first, creator, signer, verifier);
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
          testMakers(algo, creator, signer, verifier);
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

void DNSCryptoKeyEngine::testMakers(unsigned int algo, maker_t* creator, maker_t* signer, maker_t* verifier)
{
  shared_ptr<DNSCryptoKeyEngine> dckeCreate(creator(algo));
  shared_ptr<DNSCryptoKeyEngine> dckeSign(signer(algo));
  shared_ptr<DNSCryptoKeyEngine> dckeVerify(verifier(algo));

  cerr<<"Testing algorithm "<<algo<<": '"<<dckeCreate->getName()<<"' ->'"<<dckeSign->getName()<<"' -> '"<<dckeVerify->getName()<<"' ";
  unsigned int bits;
  if(algo <= 10)
    bits=1024;
  else if(algo == DNSSECKeeper::ECCGOST || algo == DNSSECKeeper::ECDSA256 || algo == DNSSECKeeper::ED25519)
    bits = 256;
  else if(algo == DNSSECKeeper::ECDSA384)
    bits = 384;
  else if(algo == DNSSECKeeper::ED448)
    bits = 456;
  else
    throw runtime_error("Can't guess key size for algorithm "+std::to_string(algo));

  DTime dt; dt.set();
  for(unsigned int n = 0; n < 100; ++n)
    dckeCreate->create(bits);
  cerr<<"("<<dckeCreate->getBits()<<" bits) ";
  unsigned int udiffCreate = dt.udiff() / 100;

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
  dt.set();
  for(unsigned int n = 0; n < 100; ++n)
    signature = dckeSign->sign(message);
  unsigned int udiffSign= dt.udiff()/100, udiffVerify;
  
  dckeVerify->fromPublicKeyString(dckeSign->getPublicKeyString());
  if (dckeVerify->getPublicKeyString().compare(dckeSign->getPublicKeyString())) {
    throw runtime_error("Comparison of public key loaded into verifier produced by signer failed");
  }
  dt.set();
  bool verified;
  for(unsigned int n = 0; n < 100; ++n)
    verified = dckeVerify->verify(message, signature);

  if(verified) {
    udiffVerify = dt.udiff() / 100;
    cerr<<"Signature & verify ok, create "<<udiffCreate<<"usec, signature "<<udiffSign<<"usec, verify "<<udiffVerify<<"usec"<<endl;
  }
  else {
    throw runtime_error("Verification of creator "+dckeCreate->getName()+" with signer "+dckeSign->getName()+" and verifier "+dckeVerify->getName()+" failed");
  }
}

shared_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromPublicKeyString(unsigned int algorithm, const std::string& content)
{
  shared_ptr<DNSCryptoKeyEngine> dpk=make(algorithm);
  dpk->fromPublicKeyString(content);
  return dpk;
}


shared_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  
  for(const makers_t::value_type& val : getMakers())
  {
    shared_ptr<DNSCryptoKeyEngine> ret=nullptr;
    try {
      ret = val.second(val.first);
      ret->fromPEMString(drc, raw);
      return ret;
    }
    catch(...)
    {
    }
  }
  return 0;
}


static bool sharedDNSSECCompare(const shared_ptr<DNSRecordContent>& a, const shared_ptr<DNSRecordContent>& b)
{
  return a->serialize(g_rootdnsname, true, true) < b->serialize(g_rootdnsname, true, true);
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
  toHash.append(const_cast<RRSIGRecordContent&>(rrc).serialize(g_rootdnsname, true, true));
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
    string rdata=add->serialize(g_rootdnsname, true, (add->getType() == QType::NSEC) ? false : true);  // RFC 6840, 5.1
    tmp=htons(rdata.length());
    toHash.append((char*)&tmp, 2);
    toHash.append(rdata);
  }
  
  return toHash;
}

bool DNSCryptoKeyEngine::isAlgorithmSupported(unsigned int algo)
{
  const makers_t& makers = getMakers();
  makers_t::const_iterator iter = makers.find(algo);
  return iter != makers.cend();
}

static unsigned int digestToAlgorithmNumber(uint8_t digest)
{
  switch(digest) {
  case DNSSECKeeper::DIGEST_SHA1:
    return DNSSECKeeper::RSASHA1;
  case DNSSECKeeper::DIGEST_SHA256:
    return DNSSECKeeper::RSASHA256;
  case DNSSECKeeper::DIGEST_GOST:
    return DNSSECKeeper::ECCGOST;
  case DNSSECKeeper::DIGEST_SHA384:
    return DNSSECKeeper::ECDSA384;
  default:
    throw std::runtime_error("Unknown digest type " + std::to_string(digest));
  }
  return 0;
}

bool DNSCryptoKeyEngine::isDigestSupported(uint8_t digest)
{
  try {
    unsigned int algo = digestToAlgorithmNumber(digest);
    return isAlgorithmSupported(algo);
  }
  catch(const std::exception& e) {
    return false;
  }
}

DSRecordContent makeDSFromDNSKey(const DNSName& qname, const DNSKEYRecordContent& drc, uint8_t digest)
{
  string toHash;
  toHash.assign(qname.toDNSStringLC()); 
  toHash.append(const_cast<DNSKEYRecordContent&>(drc).serialize(DNSName(), true, true));
  
  DSRecordContent dsrc;
  try {
    unsigned int algo = digestToAlgorithmNumber(digest);
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(algo));
    dsrc.d_digest = dpk->hash(toHash);
  }
  catch(const std::exception& e) {
    throw std::runtime_error("Asked to create (C)DS record of unknown digest type " + std::to_string(digest));
  }
  
  dsrc.d_algorithm = drc.d_algorithm;
  dsrc.d_digesttype = digest;
  dsrc.d_tag = const_cast<DNSKEYRecordContent&>(drc).getTag();

  return dsrc;
}


static DNSKEYRecordContent makeDNSKEYFromDNSCryptoKeyEngine(const std::shared_ptr<DNSCryptoKeyEngine>& pk, uint8_t algorithm, uint16_t flags)
{
  DNSKEYRecordContent drc;

  drc.d_protocol=3;
  drc.d_algorithm = algorithm;

  drc.d_flags=flags;
  drc.d_key = pk->getPublicKeyString();

  return drc;
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

void incrementHash(std::string& raw) // I wonder if this is correct, cmouse? ;-)
{
  if(raw.empty())
    return;

  for(string::size_type pos=raw.size(); pos; ) {
    --pos;
    unsigned char c = (unsigned char)raw[pos];
    ++c;
    raw[pos] = (char) c;
    if(c)
      break;
  }
}

void decrementHash(std::string& raw) // I wonder if this is correct, cmouse? ;-)
{
  if(raw.empty())
    return;

  for(string::size_type pos=raw.size(); pos; ) {
    --pos;
    unsigned char c = (unsigned char)raw[pos];
    --c;
    raw[pos] = (char) c;
    if(c != 0xff)
      break;
  }
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

static string calculateHMAC(const std::string& key, const std::string& text, TSIGHashEnum hasher) {

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
      throw PDNSException("Unknown hash algorithm requested from calculateHMAC()");
  }

  unsigned char* out = HMAC(md_type, reinterpret_cast<const unsigned char*>(key.c_str()), key.size(), reinterpret_cast<const unsigned char*>(text.c_str()), text.size(), hash, &outlen);
  if (out == NULL || outlen == 0) {
    throw PDNSException("HMAC computation failed");
  }

  return string((char*) hash, outlen);
}

static bool constantTimeStringEquals(const std::string& a, const std::string& b)
{
  if (a.size() != b.size()) {
    return false;
  }
  const size_t size = a.size();
#if OPENSSL_VERSION_NUMBER >= 0x0090819fL
  return CRYPTO_memcmp(a.c_str(), b.c_str(), size) == 0;
#else
  const volatile unsigned char *_a = (const volatile unsigned char *) a.c_str();
  const volatile unsigned char *_b = (const volatile unsigned char *) b.c_str();
  unsigned char res = 0;

  for (size_t idx = 0; idx < size; idx++) {
    res |= _a[idx] ^ _b[idx];
  }

  return res == 0;
#endif
}

static string makeTSIGPayload(const string& previous, const char* packetBegin, size_t packetSize, const DNSName& tsigKeyName, const TSIGRecordContent& trc, bool timersonly)
{
  string message;

  if(!previous.empty()) {
    uint16_t len = htons(previous.length());
    message.append(reinterpret_cast<const char*>(&len), sizeof(len));
    message.append(previous);
  }

  message.append(packetBegin, packetSize);

  vector<uint8_t> signVect;
  DNSPacketWriter dw(signVect, DNSName(), 0);
  auto pos=signVect.size();
  if(!timersonly) {
    dw.xfrName(tsigKeyName, false);
    dw.xfr16BitInt(QClass::ANY); // class
    dw.xfr32BitInt(0);    // TTL
    dw.xfrName(trc.d_algoName.makeLowerCase(), false);
  }
  
  uint32_t now = trc.d_time; 
  dw.xfr48BitInt(now);
  dw.xfr16BitInt(trc.d_fudge); // fudge
  if(!timersonly) {
    dw.xfr16BitInt(trc.d_eRcode); // extended rcode
    dw.xfr16BitInt(trc.d_otherData.length()); // length of 'other' data
    //    dw.xfrBlob(trc->d_otherData);
  }
  message.append(signVect.begin()+pos, signVect.end());
  return message;
}

static string makeTSIGMessageFromTSIGPacket(const string& opacket, unsigned int tsigOffset, const DNSName& keyname, const TSIGRecordContent& trc, const string& previous, bool timersonly, unsigned int dnsHeaderOffset=0)
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

  return makeTSIGPayload(previous, packet.data(), packet.size(), keyname, trc, timersonly);
}

void addTSIG(DNSPacketWriter& pw, TSIGRecordContent& trc, const DNSName& tsigkeyname, const string& tsigsecret, const string& tsigprevious, bool timersonly)
{
  TSIGHashEnum algo;
  if (!getTSIGHashEnum(trc.d_algoName, algo)) {
    throw PDNSException(string("Unsupported TSIG HMAC algorithm ") + trc.d_algoName.toLogString());
  }

  string toSign = makeTSIGPayload(tsigprevious, reinterpret_cast<const char*>(pw.getContent().data()), pw.getContent().size(), tsigkeyname, trc, timersonly);

  if (algo == TSIG_GSS) {
    if (!gss_add_signature(tsigkeyname, toSign, trc.d_mac)) {
      throw PDNSException(string("Could not add TSIG signature with algorithm 'gss-tsig' and key name '")+tsigkeyname.toLogString()+string("'"));
    }
  } else {
    trc.d_mac = calculateHMAC(tsigsecret, toSign, algo);
    //  trc.d_mac[0]++; // sabotage
  }
  pw.startRecord(tsigkeyname, QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  trc.toPacket(pw);
  pw.commit();
}

bool validateTSIG(const std::string& packet, size_t sigPos, const TSIGTriplet& tt, const TSIGRecordContent& trc, const std::string& previousMAC, const std::string& theirMAC, bool timersOnly, unsigned int dnsHeaderOffset)
{
  uint64_t delta = std::abs((int64_t)trc.d_time - (int64_t)time(nullptr));
  if(delta > trc.d_fudge) {
    throw std::runtime_error("Invalid TSIG time delta " + std::to_string(delta) + " >  fudge " + std::to_string(trc.d_fudge));
  }

  TSIGHashEnum algo;
  if (!getTSIGHashEnum(trc.d_algoName, algo)) {
    throw std::runtime_error("Unsupported TSIG HMAC algorithm " + trc.d_algoName.toLogString());
  }

  TSIGHashEnum expectedAlgo;
  if (!getTSIGHashEnum(tt.algo, expectedAlgo)) {
    throw std::runtime_error("Unsupported TSIG HMAC algorithm expected " + tt.algo.toLogString());
  }

  if (algo != expectedAlgo) {
    throw std::runtime_error("Signature with TSIG key '"+tt.name.toLogString()+"' does not match the expected algorithm (" + tt.algo.toLogString() + " / " + trc.d_algoName.toLogString() + ")");
  }

  string tsigMsg;
  tsigMsg = makeTSIGMessageFromTSIGPacket(packet, sigPos, tt.name, trc, previousMAC, timersOnly, dnsHeaderOffset);

  if (algo == TSIG_GSS) {
    GssContext gssctx(tt.name);
    if (!gss_verify_signature(tt.name, tsigMsg, theirMAC)) {
      throw std::runtime_error("Signature with TSIG key '"+tt.name.toLogString()+"' failed to validate");
    }
  } else {
    string ourMac = calculateHMAC(tt.secret, tsigMsg, algo);

    if(!constantTimeStringEquals(ourMac, theirMAC)) {
      throw std::runtime_error("Signature with TSIG key '"+tt.name.toLogString()+"' failed to validate");
    }
  }

  return true;
}
