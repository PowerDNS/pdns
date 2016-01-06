#include "namespaces.hh"
#include "iputils.hh"
#include "dnsparser.hh"

vector<pair<vector<DNSRecord>, vector<DNSRecord> > >   getIXFRDeltas(const ComboAddress& master, const DNSName& zone, const DNSRecord& sr,
                                                                     const DNSName& tsigalgo=DNSName(), const DNSName& tsigname=DNSName(), const std::string& tsigsecret="");
