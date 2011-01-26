#ifndef PDNS_DNSSECINFRA_HH
#define PDNS_DNSSECINFRA_HH
#include "dnsrecords.hh"
#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>
#include <map>
#include "misc.hh"

class DNSPrivateKey
{
  public:
    virtual void create(unsigned int bits)=0;
    virtual std::string convertToISC(unsigned int algorithm) const =0;
    virtual std::string getPubKeyHash()const =0;
    virtual std::string sign(const std::string& hash) const =0;
    virtual std::string hash(const std::string& hash) const =0;
    virtual std::string getPublicKeyString()const =0;
    virtual int getBits() const =0;
    
    virtual void fromISCString(DNSKEYRecordContent& drc, const std::string& content)=0;
    virtual void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)=0;
    
    static DNSPrivateKey* makeFromISCFile(DNSKEYRecordContent& drc, const char* fname);
    static DNSPrivateKey* makeFromISCString(DNSKEYRecordContent& drc, const std::string& content);
    static DNSPrivateKey* makeFromPEMString(DNSKEYRecordContent& drc, const std::string& raw);
    static DNSPrivateKey* make(unsigned int algorithm);
    
    typedef DNSPrivateKey* maker_t(unsigned int algorithm);
    
    static void report(unsigned int algorithm, maker_t* maker);
  private:
    
    typedef std::map<unsigned int, maker_t*> makers_t;
    
    static makers_t& getMakers()
    {
      static makers_t s_makers;
      return s_makers;
    }
    // need some magic here to pick the right DNSPrivateKey supplier
};

struct DNSSECPrivateKey
{
  uint16_t getTag();
  
  const DNSPrivateKey* getKey() const
  {
    return d_key.get();
  }
  
  void setKey(const shared_ptr<DNSPrivateKey> key)
  {
    d_key = key;
  }
  DNSKEYRecordContent getDNSKEY() const;
  uint8_t d_algorithm;
  uint16_t d_flags;
  
private:
  shared_ptr<DNSPrivateKey> d_key;
};



struct CanonicalCompare: public binary_function<string, string, bool>  
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

bool sharedDNSSECCompare(const boost::shared_ptr<DNSRecordContent>& a, const shared_ptr<DNSRecordContent>& b);
string getHashForRRSET(const std::string& qname, const RRSIGRecordContent& rrc, std::vector<boost::shared_ptr<DNSRecordContent> >& signRecords);

DSRecordContent makeDSFromDNSKey(const std::string& qname, const DNSKEYRecordContent& drc, int digest=1);


int countLabels(const std::string& signQName);

class RSAContext;
class DNSSECKeeper; 
struct DNSSECPrivateKey;

bool getSignerApexFor(DNSSECKeeper& dk, const std::string& keyrepodir, const std::string& qname, std::string &signer);
void fillOutRRSIG(DNSSECPrivateKey& dpk, const std::string& signQName, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign);
uint32_t getCurrentInception();
void addSignature(DNSSECKeeper& dk, const std::string signQName, const std::string& wildcardname, uint16_t signQType, uint32_t signTTL, DNSPacketWriter::Place signPlace, 
  vector<shared_ptr<DNSRecordContent> >& toSign, vector<DNSResourceRecord>& outsigned);
int getRRSIGsForRRSET(DNSSECKeeper& dk, const std::string& signer, const std::string signQName, uint16_t signQType, uint32_t signTTL, 
		     vector<shared_ptr<DNSRecordContent> >& toSign, vector<RRSIGRecordContent> &rrc, bool ksk);

std::string hashQNameWithSalt(unsigned int times, const std::string& salt, const std::string& qname);
void decodeDERIntegerSequence(const std::string& input, vector<string>& output);
class DNSPacket;
void addRRSigs(DNSSECKeeper& dk, const std::string& signer, DNSPacket& p);


#endif
