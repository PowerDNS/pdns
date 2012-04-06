#ifndef TINYDNSBACKEND_HH
#define TINYDNSBACKEND_HH

#include <pdns/dnsbackend.hh>
#include <pdns/logger.hh>
#include <pdns/iputils.hh>
#include <pdns/dnspacket.hh>
#include <cdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "cdb.hh"
#include <pdns/lock.hh>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>

using namespace ::boost;
using namespace ::boost::multi_index;

struct TinyDomainInfo {
	uint32_t id;
	uint32_t notified_serial;
	string zone;

	bool operator<(const TinyDomainInfo& tdi) const
	{
		return zone < tdi.zone;
	}
};

struct TDI_SerialModifier {
	TDI_SerialModifier (const int newSerial) : d_newSerial(newSerial) {}

	void operator()(TinyDomainInfo& tdi)
	{
		tdi.notified_serial = d_newSerial;
	}

	private:
		int d_newSerial;
};


class TinyDNSBackend : public DNSBackend
{
public:
	// Methods for simple operation
	TinyDNSBackend(const string &suffix);
	void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
	bool list(const string &target, int domain_id);
	bool get(DNSResourceRecord &rr);
	void getAllDomains(vector<DomainInfo> *domains);

	//Master mode operation
	void getUpdatedMasters(vector<DomainInfo>* domains);
	void setNotified(uint32_t id, uint32_t serial);
private:
	vector<string> getLocations();

	//TypeDefs
	struct tag_zone{};
	struct tag_domainid{};
	typedef multi_index_container<
		TinyDomainInfo,
		indexed_by<
			hashed_unique<tag<tag_zone>, member<TinyDomainInfo, string, &TinyDomainInfo::zone> >,
			hashed_unique<tag<tag_domainid>, member<TinyDomainInfo, uint32_t, &TinyDomainInfo::id> >
		>
	> TDI_t;
	typedef map<string, TDI_t> TDI_suffix_t;
	typedef TDI_t::index<tag_zone>::type TDIByZone_t;
	typedef TDI_t::index<tag_domainid>::type TDIById_t;

	//data member variables
	uint64_t d_taiepoch;
	QType d_qtype;
	CDB *d_cdbReader;
	DNSPacket *d_dnspacket; // used for location and edns-client support.
	bool d_isWildcardQuery; // Indicate if the query received was a wildcard query.
	bool d_isAxfr; // Indicate if we received a list() and not a lookup().
	bool d_locations;
	bool d_timestamps;
	string d_suffix;
	

	// Statics
	static pthread_mutex_t s_domainInfoLock;
	static TDI_suffix_t s_domainInfo;
	static uint32_t s_lastId; // used to give a domain an id.
};

#endif // TINYDNSBACKEND_HH 
