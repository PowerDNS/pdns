#include <sstream>
#include <utility>
#include <string>
#include <ldap.h>
#include <stdlib.h>
#include <unistd.h>
#include <pdns/dns.hh>
#include <pdns/dnspacket.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/arguments.hh>
#include <pdns/logger.hh>
#include "powerldap.hh"


#ifndef LDAPBACKEND_HH
#define LDAPBACKEND_HH

using namespace std;


static string backendname="[LdapBackend]";

static char* attrany[] = {
	"ARecord",
	"NSRecord",
	"CNAMERecord",
	"PTRRecord",
	"MXRecord",
	"TXTRecord",
	"RPRecord",
	"AAAARecord",
	"LOCRecord",
	"NAPTRRecord",
	"AXFRRecord",
	NULL
};



class LdapBackend : public DNSBackend
{

private:

	int m_msgid;
	QType m_qtype;
	string m_qname;
	PowerLDAP* m_pldap;
	PowerLDAP::sentry_t m_result;

public:

	LdapBackend( const string &suffix="" );
	~LdapBackend();

	void lookup( const QType &qtype, const string &qdomain, DNSPacket *p=0, int zoneid=-1 );
	bool list( int domain_id );
	bool get( DNSResourceRecord &rr );
};

#endif /* LDAPBACKEND_HH */
