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
#ifndef PDNS_DNSSECINFRA_HH
#define PDNS_DNSSECINFRA_HH

#include "dnsrecords.hh"

#include <string>
#include <vector>
#include <map>
#include "misc.hh"

class UeberBackend;

// rules of the road: Algorithm must be set in 'make' for each KeyEngine, and will NEVER change!

class DNSCryptoKeyEngine
{
  public:
    explicit DNSCryptoKeyEngine(unsigned int algorithm) : d_algorithm(algorithm) {}
    virtual ~DNSCryptoKeyEngine() {};
    virtual string getName() const = 0;
    
    typedef std::map<std::string, std::string> stormap_t;
    typedef std::vector<std::pair<std::string, std::string > > storvector_t;
    virtual void create(unsigned int bits)=0;
    virtual storvector_t convertToISCVector() const =0;
    std::string convertToISC() const ;
    virtual std::string sign(const std::string& msg) const =0;
    virtual std::string hash(const std::string& msg) const
    {
       throw std::runtime_error("hash() function not implemented");
       return msg;
    }
    virtual bool verify(const std::string& msg, const std::string& signature) const =0;
    
    virtual std::string getPubKeyHash()const =0;
    virtual std::string getPublicKeyString()const =0;
    virtual int getBits() const =0;
    virtual unsigned int getAlgorithm() const
    {
      return d_algorithm;
    }
 
    virtual void fromISCMap(DNSKEYRecordContent& drc, stormap_t& stormap)=0;
    virtual void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
    {
      throw std::runtime_error("Can't import from PEM string");
    }
    virtual void fromPublicKeyString(const std::string& content) = 0;
    virtual bool checkKey(vector<string> *errorMessages = nullptr) const
    {
      return true;
    }
    static shared_ptr<DNSCryptoKeyEngine> makeFromISCFile(DNSKEYRecordContent& drc, const char* fname);
    static shared_ptr<DNSCryptoKeyEngine> makeFromISCString(DNSKEYRecordContent& drc, const std::string& content);
    static shared_ptr<DNSCryptoKeyEngine> makeFromPEMString(DNSKEYRecordContent& drc, const std::string& raw);
    static shared_ptr<DNSCryptoKeyEngine> makeFromPublicKeyString(unsigned int algorithm, const std::string& raw);
    static shared_ptr<DNSCryptoKeyEngine> make(unsigned int algorithm);
    static bool isAlgorithmSupported(unsigned int algo);
    static bool isDigestSupported(uint8_t digest);
    
    typedef shared_ptr<DNSCryptoKeyEngine> maker_t(unsigned int algorithm);
    
    static void report(unsigned int algorithm, maker_t* maker, bool fallback=false);
    static void testMakers(unsigned int algorithm, maker_t* creator, maker_t* signer, maker_t* verifier);
    static vector<pair<uint8_t, string>> listAllAlgosWithBackend();
    static bool testAll();
    static bool testOne(int algo);
  private:
    
    typedef std::map<unsigned int, maker_t*> makers_t;
    typedef std::map<unsigned int, vector<maker_t*> > allmakers_t;
    static makers_t& getMakers()
    {
      static makers_t s_makers;
      return s_makers;
    }
    static allmakers_t& getAllMakers()
    {
      static allmakers_t s_allmakers;
      return s_allmakers;
    }
  protected:
    const unsigned int d_algorithm;
};

struct DNSSECPrivateKey
{
  uint16_t getTag() const
  {
    return getDNSKEY().getTag();
  }
  
  const shared_ptr<DNSCryptoKeyEngine> getKey() const
  {
    return d_key;
  }
  
  void setKey(const shared_ptr<DNSCryptoKeyEngine> key)
  {
    d_key = key;
    d_algorithm = key->getAlgorithm();
  }
  DNSKEYRecordContent getDNSKEY() const;

  uint16_t d_flags;
  uint8_t d_algorithm;

private:
  shared_ptr<DNSCryptoKeyEngine> d_key;
};



struct CanonicalCompare: public std::binary_function<string, string, bool>  
{
  bool operator()(const std::string& a, const std::string& b) {
    std::vector<std::string> avect, bvect;

    stringtok(avect, a, ".");
    stringtok(bvect, b, ".");
    
    reverse(avect.begin(), avect.end());
    reverse(bvect.begin(), bvect.end());
    
    return avect < bvect;
  }
};

string getMessageForRRSET(const DNSName& qname, const RRSIGRecordContent& rrc, std::vector<std::shared_ptr<DNSRecordContent> >& signRecords, bool processRRSIGLabels = false);

DSRecordContent makeDSFromDNSKey(const DNSName& qname, const DNSKEYRecordContent& drc, uint8_t digest);

class DNSSECKeeper; 

uint32_t getStartOfWeek();

string hashQNameWithSalt(const NSEC3PARAMRecordContent& ns3prc, const DNSName& qname);
string hashQNameWithSalt(const std::string& salt, unsigned int iterations, const DNSName& qname);

void incrementHash(std::string& raw);
void decrementHash(std::string& raw);

void addRRSigs(DNSSECKeeper& dk, UeberBackend& db, const std::set<DNSName>& authMap, vector<DNSZoneRecord>& rrs);

void addTSIG(DNSPacketWriter& pw, TSIGRecordContent& trc, const DNSName& tsigkeyname, const string& tsigsecret, const string& tsigprevious, bool timersonly);
bool validateTSIG(const std::string& packet, size_t sigPos, const TSIGTriplet& tt, const TSIGRecordContent& trc, const std::string& previousMAC, const std::string& theirMAC, bool timersOnly, unsigned int dnsHeaderOffset=0);

uint64_t signatureCacheSize(const std::string& str);
#endif
