#include "namespaces.hh"
#include "iputils.hh"
#include "dnsparser.hh"

vector<pair<vector<DNSRecord>, vector<DNSRecord> > >   getIXFRDeltas(const ComboAddress& master, const DNSName& zone, 
                                                                     const DNSRecord& sr, const TSIGTriplet& tt=TSIGTriplet(),
                                                                     const ComboAddress* laddr=0, size_t maxReceivedBytes=0);
