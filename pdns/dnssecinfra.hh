#ifndef PDNS_DNSSECINFRA_HH
#define PDNS_DNSSECINFRA_HH
#include "dnsrecords.hh"
#include <polarssl/rsa.h>
#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>
#include "misc.hh"


#define PDNSSEC_MI(x) mpi_init(&d_context.x, 0)
#define PDNSSEC_MC(x) PDNSSEC_MI(x); mpi_copy(&d_context.x, const_cast<mpi*>(&orig.d_context.x))
#define PDNSSEC_MF(x) mpi_free(&d_context.x, 0)

inline bool operator<(const mpi& a, const mpi& b)
{
  return mpi_cmp_mpi(&a, &b) < 0;
}

class DNSPrivateKey
{
  public:
    virtual void create(unsigned int bits)=0;
    virtual std::string convertToISC(unsigned int algorithm) const =0;
    virtual std::string getPubKeyHash()const =0;
    virtual std::string sign(const std::string& hash) const =0;
    virtual std::string getPublicKeyString()const =0;
    virtual int getBits() const =0;
    
  static DNSPrivateKey* fromISCFile(DNSKEYRecordContent& drc, const char* fname);
  static DNSPrivateKey* fromISCString(DNSKEYRecordContent& drc, const std::string& content);
  static DNSPrivateKey* fromPEMString(DNSKEYRecordContent& drc, const std::string& raw);
};

class RSADNSPrivateKey : public DNSPrivateKey
{
public:
  RSADNSPrivateKey()
  {
    memset(&d_context, 0, sizeof(d_context));
    PDNSSEC_MI(N); 
    PDNSSEC_MI(E); PDNSSEC_MI(D); PDNSSEC_MI(P); PDNSSEC_MI(Q); PDNSSEC_MI(DP); PDNSSEC_MI(DQ); PDNSSEC_MI(QP); PDNSSEC_MI(RN); PDNSSEC_MI(RP); PDNSSEC_MI(RQ);
  }

  ~RSADNSPrivateKey()
  {
    PDNSSEC_MF(N); 
    PDNSSEC_MF(E); PDNSSEC_MF(D); PDNSSEC_MF(P); PDNSSEC_MF(Q); PDNSSEC_MF(DP); PDNSSEC_MF(DQ); PDNSSEC_MF(QP); PDNSSEC_MF(RN); PDNSSEC_MF(RP); PDNSSEC_MF(RQ);
  }

  bool operator<(const RSADNSPrivateKey& rhs) const
  {
    return tie(d_context.N, d_context.E, d_context.D, d_context.P, d_context.Q, d_context.DP, d_context.DQ, d_context.QP)
    < tie(rhs.d_context.N, rhs.d_context.E, rhs.d_context.D, rhs.d_context.P, rhs.d_context.Q, rhs.d_context.DP, rhs.d_context.DQ, rhs.d_context.QP);
  }

  RSADNSPrivateKey(const RSADNSPrivateKey& orig) 
  {
    d_context.ver = orig.d_context.ver;
    d_context.len = orig.d_context.len;

    d_context.padding = orig.d_context.padding;
    d_context.hash_id = orig.d_context.hash_id;
    d_context.f_rng = orig.d_context.f_rng;
    d_context.p_rng = orig.d_context.p_rng;
    
    PDNSSEC_MC(N); 
    PDNSSEC_MC(E); PDNSSEC_MC(D); PDNSSEC_MC(P); PDNSSEC_MC(Q); PDNSSEC_MC(DP); PDNSSEC_MC(DQ); PDNSSEC_MC(QP); PDNSSEC_MC(RN); PDNSSEC_MC(RP); PDNSSEC_MC(RQ);
  }

  RSADNSPrivateKey& operator=(const RSADNSPrivateKey& orig) 
  {
    d_context.ver = orig.d_context.ver;
    d_context.len = orig.d_context.len;

    d_context.padding = orig.d_context.padding;
    d_context.hash_id = orig.d_context.hash_id;
    d_context.f_rng = orig.d_context.f_rng;
    d_context.p_rng = orig.d_context.p_rng;
    
    PDNSSEC_MF(N); 
    PDNSSEC_MF(E); PDNSSEC_MF(D); PDNSSEC_MF(P); PDNSSEC_MF(Q); PDNSSEC_MF(DP); PDNSSEC_MF(DQ); PDNSSEC_MF(QP); PDNSSEC_MF(RN); PDNSSEC_MF(RP); PDNSSEC_MF(RQ);
    
    PDNSSEC_MC(N); 
    PDNSSEC_MC(E); PDNSSEC_MC(D); PDNSSEC_MC(P); PDNSSEC_MC(Q); PDNSSEC_MC(DP); PDNSSEC_MC(DQ); PDNSSEC_MC(QP); PDNSSEC_MC(RN); PDNSSEC_MC(RP); PDNSSEC_MC(RQ);
    return *this;
  }

  const rsa_context& getConstContext() const
  {
    return d_context;
  }

  rsa_context& getContext() 
  {
    return d_context;
  }

  void create(unsigned int bits);
  std::string convertToISC(unsigned int algorithm) const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string getPublicKeyString() const;
  int getBits() const
  {
    return mpi_size(&d_context.N)*8;
  }
  static DNSPrivateKey* fromISCString(DNSKEYRecordContent& drc, const std::string& content);
  static DNSPrivateKey* fromPEMString(DNSKEYRecordContent& drc, const std::string& raw);

private:
  rsa_context d_context;
};

// see above
#undef PDNSSEC_MC
#undef PDNSSEC_MI
#undef PDNSSEC_MF

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


DNSKEYRecordContent getRSAKeyFromISC(rsa_context* rsa, const char* fname);
DNSKEYRecordContent getRSAKeyFromISCString(rsa_context* rsa, const std::string& content);
DNSKEYRecordContent getRSAKeyFromPEMString(rsa_context* rsa, const std::string& content);
void makeRSAPublicKeyFromDNS(rsa_context* rc, const DNSKEYRecordContent& dkrc);
bool sharedDNSSECCompare(const boost::shared_ptr<DNSRecordContent>& a, const shared_ptr<DNSRecordContent>& b);
string getHashForRRSET(const std::string& qname, const RRSIGRecordContent& rrc, std::vector<boost::shared_ptr<DNSRecordContent> >& signRecords);
DNSKEYRecordContent makeDNSKEYFromRSAKey(const rsa_context* rc, uint8_t algorithm, uint16_t flags);
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
