#ifndef PDNSDNSSECKEEPER_HH
#define PDNSDNSSECKEEPER_HH
#include <string>
#include <polarssl/rsa.h>
#include <string.h>
#include <vector>
#include <boost/logic/tribool.hpp>
#include "dnsrecords.hh"
#include "ueberbackend.hh"

#define PDNSSEC_MI(x) mpi_init(&d_context.x, 0)
#define PDNSSEC_MC(x) PDNSSEC_MI(x); mpi_copy(&d_context.x, const_cast<mpi*>(&orig.d_context.x))
#define PDNSSEC_MF(x) mpi_free(&d_context.x, 0)

inline bool operator<(const mpi& a, const mpi& b)
{
  return mpi_cmp_mpi(&a, &b) < 0;
}

class RSAContext
{
public:
  RSAContext()
  {
    memset(&d_context, 0, sizeof(d_context));
    PDNSSEC_MI(N); 
    PDNSSEC_MI(E); PDNSSEC_MI(D); PDNSSEC_MI(P); PDNSSEC_MI(Q); PDNSSEC_MI(DP); PDNSSEC_MI(DQ); PDNSSEC_MI(QP); PDNSSEC_MI(RN); PDNSSEC_MI(RP); PDNSSEC_MI(RQ);
  }

  ~RSAContext()
  {
    PDNSSEC_MF(N); 
    PDNSSEC_MF(E); PDNSSEC_MF(D); PDNSSEC_MF(P); PDNSSEC_MF(Q); PDNSSEC_MF(DP); PDNSSEC_MF(DQ); PDNSSEC_MF(QP); PDNSSEC_MF(RN); PDNSSEC_MF(RP); PDNSSEC_MF(RQ);
  }

  bool operator<(const RSAContext& rhs) const
  {
    return tie(d_context.N, d_context.E, d_context.D, d_context.P, d_context.Q, d_context.DP, d_context.DQ, d_context.QP)
    < tie(rhs.d_context.N, rhs.d_context.E, rhs.d_context.D, rhs.d_context.P, rhs.d_context.Q, rhs.d_context.DP, rhs.d_context.DQ, rhs.d_context.QP);
  }

  RSAContext(const RSAContext& orig) 
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

  RSAContext& operator=(const RSAContext& orig) 
  {
    d_context.ver = orig.d_context.ver;
    d_context.len = orig.d_context.len;

    d_context.padding = orig.d_context.padding;
    d_context.hash_id = orig.d_context.hash_id;
    d_context.f_rng = orig.d_context.f_rng;
    d_context.p_rng = orig.d_context.p_rng;

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
  std::string getPubKeyHash();
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
  
  RSAContext d_key;
  DNSKEYRecordContent getDNSKEY() const;
  uint8_t d_algorithm;
  uint16_t d_flags;
};

class DNSSECKeeper
{
public:
  struct KeyMetaData
  {
    unsigned int id;
    bool active;
    bool keyOrZone;
    string fname;
  }; 
  typedef std::vector<std::pair<DNSSECPrivateKey, KeyMetaData> > keyset_t;
private:
  UeberBackend d_db;
public:
  DNSSECKeeper() : d_db("key-only"){}
  bool haveActiveKSKFor(const std::string& zone);
  
  keyset_t getKeys(const std::string& zone, boost::tribool allOrKeyOrZone = boost::indeterminate);
  DNSSECPrivateKey getKeyById(const std::string& zone, unsigned int id);
  void addKey(const std::string& zname, bool keyOrZone, int algorithm=5, int bits=0, bool active=true);
  void addKey(const std::string& zname, bool keyOrZone, const DNSSECPrivateKey& dpk, bool active=true);
  void removeKey(const std::string& zname, unsigned int id);
  void activateKey(const std::string& zname, unsigned int id);
  void deactivateKey(const std::string& zname, unsigned int id);

  void secureZone(const std::string& fname, int algorithm);

  bool getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* n3p=0, bool* narrow=0);
  void setNSEC3PARAM(const std::string& zname, const NSEC3PARAMRecordContent& n3p, const bool& narrow=false);
  void unsetNSEC3PARAM(const std::string& zname);
};

#endif
