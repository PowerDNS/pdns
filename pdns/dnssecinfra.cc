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
#include <functional>
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
#include "dnssec.hh"
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

std::unique_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromISCFile(DNSKEYRecordContent& drc, const char* fname)
{
  string sline, isc;
  auto filePtr = pdns::UniqueFilePtr(fopen(fname, "r"));
  if(!filePtr) {
    throw runtime_error("Unable to read file '"+string(fname)+"' for generating DNS Private Key");
  }

  while(stringfgets(filePtr.get(), sline)) {
    isc += sline;
  }
  filePtr.reset();

  auto dke = makeFromISCString(drc, isc);
  auto checkKeyErrors = std::vector<std::string>{};

  if(!dke->checkKey(checkKeyErrors)) {
    string reason;
    if(!checkKeyErrors.empty()) {
      reason = " ("+boost::algorithm::join(checkKeyErrors, ", ")+")";
    }
    throw runtime_error("Invalid DNS Private Key in file '"+string(fname)+"'"+reason);
  }
  return dke;
}

std::unique_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromISCString(DNSKEYRecordContent& drc, const std::string& content)
{
  enum class KeyTypes : uint8_t { str, numeric, base64 };
  const std::map<std::string, KeyTypes> knownKeys = {
    { "algorithm", KeyTypes::numeric },
    { "modulus", KeyTypes::base64 },
    { "publicexponent", KeyTypes::base64 },
    { "privateexponent", KeyTypes::base64 },
    { "prime1", KeyTypes::base64 },
    { "prime2", KeyTypes::base64 },
    { "exponent1", KeyTypes::base64 },
    { "exponent2", KeyTypes::base64 },
    { "coefficient", KeyTypes::base64 },
    { "privatekey", KeyTypes::base64 },
    { "engine", KeyTypes::str },
    { "slot", KeyTypes::str },
    { "pin", KeyTypes::str },
    { "label", KeyTypes::str },
    { "publabel", KeyTypes::str },
    { "private-key-format", KeyTypes::str },
    { "flags", KeyTypes::numeric }
  };
  unsigned int algorithm = 0;
  string sline, key, value, raw;
  std::istringstream str(content);
  map<string, string> stormap;

  while (std::getline(str, sline)) {
    std::tie(key,value) = splitField(sline, ':');
    boost::trim(value);

    toLowerInPlace(key);
    const auto it = knownKeys.find(key);
    if (it != knownKeys.cend()) {
      if (it->second == KeyTypes::str) {
        stormap[key] = value;
      }
      else if (it->second == KeyTypes::base64) {
        try {
          raw.clear();
          B64Decode(value, raw);
          stormap[key] = raw;
        }
        catch (const std::exception& e) {
          throw std::runtime_error("Error while trying to base64 decode the value of the '" + key + "' key from the ISC map: " + e.what());
        }
      }
      else if (it->second == KeyTypes::numeric) {
        try {
          auto num = pdns::checked_stoi<unsigned int>(value);
          stormap[key] = std::to_string(num);
          if (key == "algorithm") {
            algorithm = num;
          }
        }
        catch (const std::exception& e) {
          throw std::runtime_error("Error while trying to parse the numeric value of the '" + key + "' key from the ISC map: " + e.what());
        }
      }
    }
    else {
      try {
        raw.clear();
        B64Decode(value, raw);
        stormap[key] = raw;
      }
      catch (const std::exception& e) {
        stormap[key] = value;
      }
    }
  }

  std::unique_ptr<DNSCryptoKeyEngine> dpk;

  if (stormap.count("engine")) {
#ifdef HAVE_P11KIT1
    if (stormap.count("slot") == 0) {
      throw PDNSException("Cannot load PKCS#11 key, no Slot specified");
    }
    // we need PIN to be at least empty
    if (stormap.count("pin") == 0) {
      stormap["pin"] = "";
    }
    dpk = PKCS11DNSCryptoKeyEngine::maker(algorithm);
#else
    throw PDNSException("Cannot load PKCS#11 key without support for it");
#endif
  } else {
    dpk = make(algorithm);
  }
  dpk->fromISCMap(drc, stormap);
  return dpk;
}

std::unique_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromPEMFile(DNSKEYRecordContent& drc, const uint8_t algorithm, std::FILE& inputFile, const std::string& filename)
{
  auto maker = DNSCryptoKeyEngine::make(algorithm);
  maker->createFromPEMFile(drc, inputFile, filename);
  return maker;
}

std::unique_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromPEMString(DNSKEYRecordContent& drc, uint8_t algorithm, const std::string& contents)
{
  auto maker = DNSCryptoKeyEngine::make(algorithm);
  maker->createFromPEMString(drc, contents);
  return maker;
}

std::string DNSCryptoKeyEngine::convertToISC() const
{
  storvector_t storvector = this->convertToISCVector();
  ostringstream ret;
  ret << "Private-key-format: v1.2\n";
  for (const storvector_t::value_type& value : storvector) {
    // clang-format off
    if(value.first != "Algorithm" && value.first != "PIN" &&
       value.first != "Slot" && value.first != "Engine" &&
       value.first != "Label" && value.first != "PubLabel") {
      ret << value.first << ": " << Base64Encode(value.second) << "\n";
    }
    else {
      ret << value.first << ": " << value.second << "\n";
    }
    // clang-format on
  }
  return ret.str();
}

std::unique_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::make(unsigned int algo)
{
  const makers_t& makers = getMakers();

  auto iter = makers.find(algo);
  if (iter != makers.cend()) {
    return (iter->second)(algo);
  }

  throw runtime_error("Request to create key object for unknown algorithm number " + std::to_string(algo));
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
    auto dcke = value.second(value.first);
    ret.emplace_back(value.first, dcke->getName());
  }
  return ret;
}

string DNSCryptoKeyEngine::listSupportedAlgoNames()
{
  set<unsigned int> algos;
  auto pairs = DNSCryptoKeyEngine::listAllAlgosWithBackend();
  for (const auto& pair : pairs) {
    algos.insert(pair.first);
  }
  string ret;
  bool first = true;
  for (auto algo : algos) {
    if (!first) {
      ret.append(" ");
    }
    else {
      first = false;
    }
    ret.append(DNSSEC::algorithm2name(algo));
    if (isAlgorithmSwitchedOff(algo)) {
      ret.append("(disabled)");
    }
  }
  ret.append("\n");
  return ret;
}

void DNSCryptoKeyEngine::report(unsigned int algo, maker_t* maker, bool fallback)
{
  getAllMakers()[algo].push_back(maker);
  if (getMakers().count(algo) != 0 && fallback) {
    return;
  }
  getMakers()[algo] = maker;
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

static map<string, string> ISCStringtoMap(const string& argStr)
{
  unsigned int algorithm = 0;
  string sline;
  string key;
  string value;
  string raw;
  std::istringstream str(argStr);
  map<string, string> stormap;

  while(std::getline(str, sline)) {
    std::tie(key,value)=splitField(sline, ':');
    boost::trim(value);
    if(pdns_iequals(key,"algorithm")) {
      pdns::checked_stoi_into(algorithm, value);
      stormap["algorithm"] = std::to_string(algorithm);
      continue;
    }
    if (pdns_iequals(key,"pin")) {
      stormap["pin"] = value;
      continue;
    }
    if (pdns_iequals(key,"engine")) {
      stormap["engine"] = value;
      continue;
    }
    if (pdns_iequals(key,"slot")) {
      int slot = std::stoi(value);
      stormap["slot"]=std::to_string(slot);
      continue;
    }
    if (pdns_iequals(key,"label")) {
      stormap["label"] = value;
      continue;
    }
    if(pdns_iequals(key, "Private-key-format")) {
      continue;
    }
    raw.clear();
    B64Decode(value, raw);
    stormap[toLower(key)] = raw;
  }
  return stormap;
}

bool DNSCryptoKeyEngine::testVerify(unsigned int algo, maker_t* verifier)
{
  const string message("Hi! How is life?");
  const string pubkey5 = "AwEAAe2srzo8UfPx5WwoRXTRdo0H8U4iYW6qneronwKlRtXrpOqgZWPtYGVZl1Q7JXqbxxH9aVK5iK6aYOVfxbwwGHejaY0NraqrxL60F5FhHGHg+zox1en8kEX2TcQHxoZaiK1iUgPkMrHJlX5yI5+p2V4qap5VPQsR/WfeFVudNsBEF/XRvg0Exh65fPI/e8sYNgAiflzdN9/5RM644r6viBdieuwUNwEV2HPizCBMssYzx2F29CqNseToqCKQlj1tghuGAsiiSKeosfDLlRPDe/uxtij0wqe0FNybj1oL3OG8Lq3xp8yXIG4CF59xmRDKdnGDmVycKzUWkVOZpesCsUU=";
  const string sig5 = "nMnMakbQiiCKIYsEiv4R75+8wvjQav2LPGIKucbqUZUz5sy1ovc2Pp7JVcOuyVyzQu5XH+CetDnTlqiEJWFHNU1jqEwwFK83GVOLABtvXSOvgmGwZGnHOouAchkrzgSSBoEh3+UUN3OsFZA21q6TZVRJBNBm7Ch/PxqSBkFS46ko/qLAUJ1p7/ymzwGNhuOfguHO3dAJ+LgcrNGLZQFDJ1aqT3kZ7LtXX2CQdd7EXgUs6VkE4Z3JN1RmPTk8kAJdZ4JLUR6lgu1dRlSPLGzqv+5d1yI7+h+B0LFNuDdQblDlBstO3LEs1KSaQld+TqVExpjj87oEg6wL/G/XOGabmQ==";

  const string pubkey7 = "AwEAAc4n7xPG6yJe6YAsg6oQ+7YjbL7wuDLCP4juOSaDsst2Mehc5eYdT7xJT2H9foTIq7ABkkp8Er1Bh6gDzB/0xvArARdH6DS3P5pUP6w5Zoz4Gu79y3pP6IsR3ZyhiQRSnht1ElnIGZzb1zpi7Y4Y8LZ18NYN2qdLasXx/h6hpRjdcF1s7svZKvfJdvCSgDHHD/JFtDGSOn6qt6i5UFSrObxMUMWbxfOsnqr/eXUQcF/aePdqDXO47yDaSH8sFZoglgvEDiOIkky9DV5VKamvVW8anxE5Vv7y4EPpZKXB3CgUW+NvaoasdgYPFmGM4EcnXh2EFFnSPDL6iwDubiL7s2k=";
  const string sig7 = "B04Oqmh/nF6BybBGsInauTXH6nlW3VhT2PeSzXVaxQ42QsbbXUgIKuzp2/R7diiEBzbbQ3Eg5vtHOKfEQDkArmOR1oU6yIkyrKHsJkpCvclCyaFiJXrwxkH+A2y8vB+loeDMJKJVwjn7fH9zwBI3Mk7SFuOgYXgzBUNhb5DeQ9RzRbxMcpSc8Cgtjn+QpmTNgL6olpBNsStYz9bSLXBk1EGhmZeBYhliw/2Fse75OoRxIuufKiN6sAD5bKQxp73QQUU+yunVuSeHJizNct8b4f9RXFe49wtZWt5rB0oYXG6zUv0Dq7xJHpUq6v1eB2wf2NucftCKwWu18r4TxkVC5A==";

  string b64pubkey;
  string b64sig;
  switch (algo) {
  case DNSSEC::RSASHA1:
    b64pubkey = pubkey5;
    b64sig = sig5;
    break;
  case DNSSEC::RSASHA1NSEC3SHA1:
    b64pubkey = pubkey7;
    b64sig = sig7;
    break;
  default:
    throw runtime_error("Verification of verifier called for unimplemented case");
  }

  string pubkey;
  string sig;
  B64Decode(b64pubkey, pubkey);
  B64Decode(b64sig, sig);
  auto dckeVerify = verifier(algo);
  dckeVerify->fromPublicKeyString(pubkey);

  auto ret = dckeVerify->verify(message, sig);
  return ret;
}

bool DNSCryptoKeyEngine::verifyOne(unsigned int algo)
{
  const auto& makers = getAllMakers();
  auto iter = makers.find(algo);
  // No algo found
  if (iter == makers.cend()) {
    return false;
  }
  // Algo found, but maker empty? Should not happen
  if (iter->second.empty()) {
    return false;
  }
  // Check that all maker->verify return true
  return std::all_of(iter->second.begin(), iter->second.end(), [algo](maker_t* verifier) {
    try {
      if (!testVerify(algo, verifier)) {
        return false;
      }
    }
    catch (std::exception& e) {
      return false;
    }
    return true;
  });
}

void DNSCryptoKeyEngine::testMakers(unsigned int algo, maker_t* creator, maker_t* signer, maker_t* verifier)
{
  auto dckeCreate = creator(algo);
  auto dckeSign = signer(algo);
  auto dckeVerify = verifier(algo);

  cout<<"Testing algorithm "<<algo<<"("<<DNSSEC::algorithm2name(algo)<<"): '"<<dckeCreate->getName()<<"' ->'"<<dckeSign->getName()<<"' -> '"<<dckeVerify->getName()<<"' ";
  unsigned int bits{};
  if(algo <= 10) {
    bits = 2048;
  }
  else if(algo == DNSSEC::ECCGOST || algo == DNSSEC::ECDSA256 || algo == DNSSEC::ED25519) {
    bits = 256;
  }
  else if(algo == DNSSEC::ECDSA384) {
    bits = 384;
  }
  else if(algo == DNSSEC::ED448) {
    bits = 456;
  }
  else {
    throw runtime_error("Can't guess key size for algorithm " + std::to_string(algo));
  }

  DTime dt; dt.set();
  for(unsigned int n = 0; n < 100; ++n)
    dckeCreate->create(bits);
  cout<<"("<<dckeCreate->getBits()<<" bits) ";
  unsigned int udiffCreate = dt.udiff() / 100;

  {
    DNSKEYRecordContent dkrc;
    auto stormap = ISCStringtoMap(dckeCreate->convertToISC());

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
    cout<<"Signature & verify ok, create "<<udiffCreate<<"us, signature "<<udiffSign<<"us, verify "<<udiffVerify<<"us"<<endl;
  }
  else {
    throw runtime_error("Verification of creator "+dckeCreate->getName()+" with signer "+dckeSign->getName()+" and verifier "+dckeVerify->getName()+" failed");
  }
}

std::unique_ptr<DNSCryptoKeyEngine> DNSCryptoKeyEngine::makeFromPublicKeyString(unsigned int algorithm, const std::string& content)
{
  auto dpk = make(algorithm);
  dpk->fromPublicKeyString(content);
  return dpk;
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
string getMessageForRRSET(const DNSName& qname, const RRSIGRecordContent& rrc, const sortedRecords_t& signRecords, bool processRRSIGLabels, bool includeRRSIG_RDATA)
{
  string toHash;

  // dnssec: signature = sign(RRSIG_RDATA | RR(1) | RR(2)... )
  // From RFC 4034
  // RRSIG_RDATA is the wire format of the RRSIG RDATA fields
  //             with the Signer's Name field in canonical form and
  //             the Signature field excluded;
  // zonemd: digest = hash( RR(1) | RR(2) | RR(3) | ... ), so skip RRSIG_RDATA

  if (includeRRSIG_RDATA) {
    toHash.append(rrc.serialize(g_rootdnsname, true, true));
    toHash.resize(toHash.size() - rrc.d_signature.length()); // chop off the end, don't sign the signature!
  }
  string nameToHash(qname.toDNSStringLC());

  if (processRRSIGLabels) {
    unsigned int rrsig_labels = rrc.d_labels;
    unsigned int fqdn_labels = qname.countLabels();

    if (rrsig_labels < fqdn_labels) {
      DNSName choppedQname(qname);
      for (auto nlabels = fqdn_labels; nlabels > rrsig_labels; --nlabels) {
        choppedQname.chopOff();
      }
      nameToHash = "\x01*" + choppedQname.toDNSStringLC();
    } else if (rrsig_labels > fqdn_labels) {
      // The RRSIG Labels field is a lie (or the qname is wrong) and the RRSIG
      // can never be valid
      return "";
    }
  }

  for (const shared_ptr<const DNSRecordContent>& add : signRecords) {
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

std::unordered_set<unsigned int> DNSCryptoKeyEngine::s_switchedOff;

bool DNSCryptoKeyEngine::isAlgorithmSwitchedOff(unsigned int algo)
{
  return s_switchedOff.count(algo) != 0;
}

void DNSCryptoKeyEngine::switchOffAlgorithm(unsigned int algo)
{
  s_switchedOff.insert(algo);
}

bool DNSCryptoKeyEngine::isAlgorithmSupported(unsigned int algo)
{
  if (isAlgorithmSwitchedOff(algo)) {
    return false;
  }
  const makers_t& makers = getMakers();
  auto iter = makers.find(algo);
  return iter != makers.cend();
}

static unsigned int digestToAlgorithmNumber(uint8_t digest)
{
  switch(digest) {
  case DNSSEC::DIGEST_SHA1:
    return DNSSEC::RSASHA1;
  case DNSSEC::DIGEST_SHA256:
    return DNSSEC::RSASHA256;
  case DNSSEC::DIGEST_GOST:
    return DNSSEC::ECCGOST;
  case DNSSEC::DIGEST_SHA384:
    return DNSSEC::ECDSA384;
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
  toHash.append(drc.serialize(DNSName(), true, true));

  DSRecordContent dsrc;
  try {
    unsigned int algo = digestToAlgorithmNumber(digest);
    auto dpk = DNSCryptoKeyEngine::make(algo);
    dsrc.d_digest = dpk->hash(toHash);
  }
  catch(const std::exception& e) {
    throw std::runtime_error("Asked to create (C)DS record of unknown digest type " + std::to_string(digest) + ": " + e.what());
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
  // coverity[store_truncates_time_t]
  uint32_t now = time(nullptr);
  now -= (now % (7*86400));
  return now;
}

string hashQNameWithSalt(const NSEC3PARAMRecordContent& ns3prc, const DNSName& qname)
{
  return hashQNameWithSalt(ns3prc.d_salt, ns3prc.d_iterations, qname);
}

string hashQNameWithSalt(const std::string& salt, unsigned int iterations, const DNSName& qname)
{
  // rfc5155 section 5
  unsigned int times = iterations;
  unsigned char hash[SHA_DIGEST_LENGTH];
  string toHash(qname.toDNSStringLC() + salt);

  for (;;) {
    /* so the first time we hash the (lowercased) qname plus the salt,
       then the result of the last iteration plus the salt */
    SHA1(reinterpret_cast<const unsigned char*>(toHash.c_str()), toHash.length(), hash);
    if (!times--) {
      /* we are done, just copy the result and return it */
      toHash.assign(reinterpret_cast<char*>(hash), sizeof(hash));
      break;
    }
    if (times == (iterations-1)) {
      /* first time, we need to replace the qname + salt with
         the hash plus salt, since the qname will not likely
         match the size of the hash */
      if (toHash.capacity() < (sizeof(hash) + salt.size())) {
        toHash.reserve(sizeof(hash) + salt.size());
      }
      toHash.assign(reinterpret_cast<char*>(hash), sizeof(hash));
      toHash.append(salt);
    }
    else {
      /* starting with the second iteration, the hash size does not change, so we don't need to copy the salt again */
      std::copy(reinterpret_cast<char*>(hash), reinterpret_cast<char*>(hash) + sizeof(hash), toHash.begin());
    }
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

const DNSKEYRecordContent& DNSSECPrivateKey::getDNSKEY() const
{
  return d_dnskey;
}

void DNSSECPrivateKey::computeDNSKEY()
{
  d_dnskey = makeDNSKEYFromDNSCryptoKeyEngine(getKey(), d_algorithm, d_flags);
}

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
  if (out == nullptr || outlen == 0) {
    throw PDNSException("HMAC computation failed");
  }

  return string((char*) hash, outlen);
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
    dw.xfrName(tsigKeyName.makeLowerCase(), false);
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
