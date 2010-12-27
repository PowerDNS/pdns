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

void makeRSAPublicKeyFromDNS(rsa_context* rc, const DNSKEYRecordContent& dkrc);
bool sharedDNSSECCompare(const boost::shared_ptr<DNSRecordContent>& a, const shared_ptr<DNSRecordContent>& b);
string getSHA1HashForRRSET(const std::string& qname, const RRSIGRecordContent& rrc, std::vector<boost::shared_ptr<DNSRecordContent> >& signRecords);
DNSKEYRecordContent makeDNSKEYFromRSAKey(const rsa_context* rc, uint8_t algorithm, uint16_t flags);
DSRecordContent makeDSFromDNSKey(const std::string& qname, const DNSKEYRecordContent& drc, int digest=1);

bool getSignerFor(const std::string& keyrepodir, const std::string& qname, std::string &signer);
int countLabels(const std::string& signQName);

class RSAContext;

DNSKEYRecordContent getDNSKEYFor(const std::string& keyrepodir, const std::string& qname, bool withKSK, RSAContext* rc);
void fillOutRRSIG(const std::string& keyrepodir, const std::string& signQName, RRSIGRecordContent& rrc, const std::string& hash, vector<shared_ptr<DNSRecordContent> >& toSign, bool withKSK=false);
uint32_t getCurrentInception();
void addSignature(const std::string& keyrepodir, const std::string signQName, const std::string& wildcardname, uint16_t signQType, uint32_t signTTL, DNSPacketWriter::Place signPlace, vector<shared_ptr<DNSRecordContent> >& toSign, DNSPacketWriter& pw);
int getRRSIGForRRSET(const std::string& keyrepodir, const std::string signQName, uint16_t signQType, uint32_t signTTL, 
		     vector<shared_ptr<DNSRecordContent> >& toSign, RRSIGRecordContent &rrc, bool ksk);

std::string hashQNameWithSalt(unsigned int times, const std::string& salt, const std::string& qname);

#endif
