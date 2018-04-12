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
#include <botan/auto_rng.h>
#include <botan/gost_3410.h>
#include <botan/gost_3411.h>
#include <botan/pubkey.h>
#include <botan/version.h>
#include "dnssecinfra.hh"

using namespace Botan;

/*  Государственный гимн Российской Федерации
    (Gosudarstvenny Gimn Rossiyskoy Federatsii)
    "The National Anthem of the Russian Federation"
    
 ~  Rossiya - svyashchennaya nasha derzhava,  ~
 ~  Rossiya - lyubimaya nasha strana.         ~
 ~  Moguchaya volya, velikaya slava -         ~
 ~  Tvoyo dostoyanye na vse vremena!          ~
 */

class GOSTDNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit GOSTDNSCryptoKeyEngine(unsigned int algorithm) : DNSCryptoKeyEngine(algorithm) {}
  ~GOSTDNSCryptoKeyEngine(){}
  void create(unsigned int bits) override;
  string getName() const override { return "Botan 2 GOST"; }
  storvector_t convertToISCVector() const override;
  std::string getPubKeyHash() const override;
  std::string sign(const std::string& msg) const override;
  std::string hash(const std::string& msg) const override;
  bool verify(const std::string& msg, const std::string& signature) const override;
  std::string getPublicKeyString() const override;
  int getBits() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& content) override;
  void fromPublicKeyString(const std::string& content) override;
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw) override
  {}

  static std::shared_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return std::make_shared<GOSTDNSCryptoKeyEngine>(algorithm);
  }

private:
  static EC_Group getParams()
  {
    return EC_Group("gost_256A");
  }

  shared_ptr<GOST_3410_PrivateKey> d_key;
  shared_ptr<GOST_3410_PublicKey> d_pubkey;
};

/*
 ~ Slav'sya, Otechestvo nashe svobodnoye, ~
 ~ Bratskikh narodov soyuz vekovoy,       ~
 ~ Predkami dannaya mudrost' narodnaya!   ~
 ~ Slav'sya, strana! My gordimsya toboy!  ~
*/


void GOSTDNSCryptoKeyEngine::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  d_key = std::make_shared<GOST_3410_PrivateKey>(rng, getParams());
}

int GOSTDNSCryptoKeyEngine::getBits() const
{
  return 256;
}

/*
 ~ Ot yuzhnykh morey do polyarnogo kraya ~
 ~ Raskinulis' nashi lesa i polya.       ~
 ~ Odna ty na svete! Odna ty takaya -    ~
 ~ Khranimaya Bogom rodnaya zemlya!      ~
*/

DNSCryptoKeyEngine::storvector_t GOSTDNSCryptoKeyEngine::convertToISCVector() const
{ 
  static const unsigned char asn1Prefix[]=
  {0x30, 0x45, 0x02, 0x01, 0x00, 0x30, 0x1c, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 
   0x13, 0x30, 0x12, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, 0x06, 0x07, 
   0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01, 0x04, 0x22, 0x04, 0x20}; // this is DER, fixed for a 32 byte key

  storvector_t storvect;
  storvect.push_back(make_pair("Algorithm", "12 (ECC-GOST)"));

  auto buffer = BigInt::encode(d_key->private_value());
  string gostasn1(reinterpret_cast<const char*>(asn1Prefix), sizeof(asn1Prefix));
  gostasn1.append(buffer.begin(), buffer.end());
  storvect.push_back(make_pair("GostAsn1", gostasn1));
  return storvect;
}

/*
 ~ Slav'sya, Otechestvo nashe svobodnoye, ~
 ~ Bratskikh narodov soyuz vekovoy,       ~
 ~ Predkami dannaya mudrost' narodnaya!   ~
 ~ Slav'sya, strana! My gordimsya toboy!  ~
*/

void GOSTDNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{ 
  drc.d_algorithm = pdns_stou(stormap["algorithm"]);
  string privateKey=stormap["gostasn1"];
  //cerr<<"PrivateKey.size() = "<<privateKey.size()<<endl;
  //cerr<<makeHexDump(string(privateKey.c_str(), 39))<<endl;
  string rawKey(privateKey.c_str()+39, privateKey.length()-39);
  
  for(size_t i = 0; i < rawKey.size() / 2; ++i)
  {
    std::swap(rawKey[i], rawKey[rawKey.size()-1-i]);
  }
  
  BigInt bigint((byte*)rawKey.c_str(), rawKey.size());
 
  AutoSeeded_RNG rng;
  d_key=std::make_shared<GOST_3410_PrivateKey>(rng, getParams(), bigint);
  
  //cerr<<"Is the just imported key on the curve? " << d_key->public_point().on_the_curve()<<endl;
  //cerr<<"Is the just imported key zero? " << d_key->public_point().is_zero()<<endl;
  
  const BigInt&x = d_key->private_value();
  auto buffer = BigInt::encode(x);
 // cerr<<"And out again! "<<makeHexDump(string((const char*)buffer.begin(), (const char*)buffer.end()))<<endl;
}
namespace {

BigInt decode_le(const byte msg[], size_t msg_len)
   {
   Botan::secure_vector<byte> msg_le(msg, msg + msg_len);

   for(size_t i = 0; i != msg_le.size() / 2; ++i)
      std::swap(msg_le[i], msg_le[msg_le.size()-1-i]);

   return BigInt(&msg_le[0], msg_le.size());
   }

}
void GOSTDNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  BigInt x, y;
  
  x=decode_le((const byte*)input.c_str(), input.length()/2);
  y=decode_le((const byte*)input.c_str() + input.length()/2, input.length()/2);

  auto params = getParams();
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(2,5,0)
  PointGFp point(params.get_curve(), x,y);
#else
  PointGFp point(params.point(x,y));
#endif
  d_pubkey = std::make_shared<GOST_3410_PublicKey>(params, point);
  d_key.reset();
}

std::string GOSTDNSCryptoKeyEngine::getPubKeyHash() const
{
  const BigInt&x = d_key->private_value();
  auto buffer = BigInt::encode(x);
  return string(buffer.begin(), buffer.end());
}

std::string GOSTDNSCryptoKeyEngine::getPublicKeyString() const
{
  std::shared_ptr<GOST_3410_PublicKey> pk = d_pubkey ? d_pubkey : d_key;
  const BigInt&x =pk->public_point().get_affine_x();
  const BigInt&y =pk->public_point().get_affine_y();
  
  size_t part_size = std::max(x.bytes(), y.bytes());
 
  std::vector<byte> bits(2*part_size);

  x.binary_encode(&bits[part_size - x.bytes()]);
  y.binary_encode(&bits[2*part_size - y.bytes()]);

  // Keys are stored in little endian format (WTF)
  for(size_t i = 0; i != part_size / 2; ++i)
  {
    std::swap(bits[i], bits[part_size-1-i]);
    std::swap(bits[part_size+i], bits[2*part_size-1-i]);
  }
 
  return string(bits.begin(), bits.end());
}

/*
 ~ Shirokiy prostor dlya mechty i dlya zhizni. ~ 
 ~ Gryadushchiye nam otkryvayut goda.          ~
 ~ Nam silu dayot nasha vernost' Otchizne.     ~
 ~ Tak bylo, tak yest' i tak budet vsegda!     ~  
 */

std::string GOSTDNSCryptoKeyEngine::sign(const std::string& msg) const
{
  AutoSeeded_RNG rng;
  PK_Signer signer(*d_key, rng, "Raw");
  signer.update(hash(msg));
  auto signature = signer.signature(rng);
  return string(signature.begin(), signature.end());
}

std::string GOSTDNSCryptoKeyEngine::hash(const std::string& orig) const
{
  GOST_34_11 hasher;
  auto result = hasher.process(orig);
  return string(result.begin(), result.end());
}


bool GOSTDNSCryptoKeyEngine::verify(const std::string& message, const std::string& signature) const
{
  std::shared_ptr<GOST_3410_PublicKey> pk = d_pubkey ? d_pubkey : d_key;
  PK_Verifier verifier(*pk, "Raw");
  verifier.update(hash(message));
  return verifier.check_signature(reinterpret_cast<const uint8_t*>(signature.c_str()), signature.size());
}

/*
 ~ Slav'sya, Otechestvo nashe svobodnoye, ~
 ~ Bratskikh narodov soyuz vekovoy,       ~
 ~ Predkami dannaya mudrost' narodnaya!   ~
 ~ Slav'sya, strana! My gordimsya toboy!  ~
*/


//////////////////////////////

namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
    DNSCryptoKeyEngine::report(12, &GOSTDNSCryptoKeyEngine::maker);
  }
} loaderBotan2;
}
