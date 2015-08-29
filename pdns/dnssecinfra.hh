#ifndef PDNS_DNSSECINFRA_HH
#define PDNS_DNSSECINFRA_HH

#include "dnsrecords.hh"

#include <string>
#include <vector>
#include <map>
#include "misc.hh"
#include "ueberbackend.hh"

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
    virtual std::string hash(const std::string& msg) const =0;
    virtual bool verify(const std::string& msg, const std::string& signature) const =0;
    
    virtual std::string getPubKeyHash()const =0;
    virtual std::string getPublicKeyString()const =0;
    virtual int getBits() const =0;
 
    virtual void fromISCMap(DNSKEYRecordContent& drc, stormap_t& stormap)=0;
    virtual void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
    {
      throw std::runtime_error("Can't import from PEM string");
    }
    virtual void fromPublicKeyString(const std::string& content) = 0;
    
    static DNSCryptoKeyEngine* makeFromISCFile(DNSKEYRecordContent& drc, const char* fname);
    static DNSCryptoKeyEngine* makeFromISCString(DNSKEYRecordContent& drc, const std::string& content);
    static DNSCryptoKeyEngine* makeFromPEMString(DNSKEYRecordContent& drc, const std::string& raw);
    static DNSCryptoKeyEngine* makeFromPublicKeyString(unsigned int algorithm, const std::string& raw);
    static DNSCryptoKeyEngine* make(unsigned int algorithm);
    
    typedef DNSCryptoKeyEngine* maker_t(unsigned int algorithm);
    
    static void report(unsigned int algorithm, maker_t* maker, bool fallback=false);
    static std::pair<unsigned int, unsigned int> testMakers(unsigned int algorithm, maker_t* creator, maker_t* signer, maker_t* verifier);
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
  uint16_t getTag();
  
  const DNSCryptoKeyEngine* getKey() const
  {
    return d_key.get();
  }
  
  void setKey(const shared_ptr<DNSCryptoKeyEngine> key)
  {
    d_key = key;
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

bool sharedDNSSECCompare(const std::shared_ptr<DNSRecordContent>& a, const shared_ptr<DNSRecordContent>& b);
string getMessageForRRSET(const DNSName& qname, const RRSIGRecordContent& rrc, std::vector<std::shared_ptr<DNSRecordContent> >& signRecords);

DSRecordContent makeDSFromDNSKey(const DNSName& qname, const DNSKEYRecordContent& drc, int digest=1);


class RSAContext;
class DNSSECKeeper; 
struct DNSSECPrivateKey;

void fillOutRRSIG(DNSSECPrivateKey& dpk, const DNSName& signQName, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign);
uint32_t getStartOfWeek();
void addSignature(DNSSECKeeper& dk, UeberBackend& db, const DNSName& signer, const DNSName signQName, const DNSName& wildcardname, uint16_t signQType, uint32_t signTTL, DNSPacketWriter::Place signPlace,
  vector<shared_ptr<DNSRecordContent> >& toSign, vector<DNSResourceRecord>& outsigned, uint32_t origTTL);
int getRRSIGsForRRSET(DNSSECKeeper& dk, const DNSName& signer, const DNSName signQName, uint16_t signQType, uint32_t signTTL,
  vector<shared_ptr<DNSRecordContent> >& toSign, vector<RRSIGRecordContent> &rrc);

string hashQNameWithSalt(const NSEC3PARAMRecordContent& ns3prc, const DNSName& qname);
void decodeDERIntegerSequence(const std::string& input, vector<string>& output);
class DNSPacket;
void addRRSigs(DNSSECKeeper& dk, UeberBackend& db, const std::set<DNSName>& authMap, vector<DNSResourceRecord>& rrs);

string calculateHMAC(const std::string& key, const std::string& text, TSIGHashEnum hash);

string makeTSIGMessageFromTSIGPacket(const string& opacket, unsigned int tsigoffset, const DNSName& keyname, const TSIGRecordContent& trc, const string& previous, bool timersonly, unsigned int dnsHeaderOffset=0);
void addTSIG(DNSPacketWriter& pw, TSIGRecordContent* trc, const DNSName& tsigkeyname, const string& tsigsecret, const string& tsigprevious, bool timersonly);
uint64_t signatureCacheSize(const std::string& str);
#endif
