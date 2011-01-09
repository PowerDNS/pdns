#ifndef PDNS_DNSSECINFRA_HH
#define PDNS_DNSSECINFRA_HH
#include "dnsrecords.hh"
#include <polarssl/rsa.h>
#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>
#include "misc.hh"

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
void addSignature(DNSSECKeeper& dk, const std::string signQName, const std::string& wildcardname, uint16_t signQType, uint32_t signTTL, DNSPacketWriter::Place signPlace, vector<shared_ptr<DNSRecordContent> >& toSign, 
  uint16_t maxReplyLength, DNSPacketWriter& pw);
int getRRSIGsForRRSET(DNSSECKeeper& dk, const std::string signQName, uint16_t signQType, uint32_t signTTL, 
		     vector<shared_ptr<DNSRecordContent> >& toSign, vector<RRSIGRecordContent> &rrc, bool ksk);

std::string hashQNameWithSalt(unsigned int times, const std::string& salt, const std::string& qname);

#endif
