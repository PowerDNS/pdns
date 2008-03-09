/*
 *  PowerDNS LDAP Backend
 *  Copyright (C) 2003-2007 Norbert Sendetzky <norbert@linuxnetworks.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */



#include <algorithm>
#include <sstream>
#include <utility>
#include <string>
#include <cstdlib>
#include <cctype>
#include <inttypes.h>
#include <pdns/dns.hh>
#include <pdns/utility.hh>
#include <pdns/dnspacket.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/arguments.hh>
#include <pdns/logger.hh>
#include "powerldap.hh"
#include "utils.hh"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#ifndef LDAPBACKEND_HH
#define LDAPBACKEND_HH

using std::string;
using std::vector;



/*
 *  Known DNS RR types
 *  Types which aren't active are currently not supported by PDNS
 */

static const char* ldap_attrany[] = {
	"associatedDomain",
	"dNSTTL",
	"aRecord",
	"nSRecord",
	"cNAMERecord",
	"sOARecord",
	"pTRRecord",
	"hInfoRecord",
	"mXRecord",
	"tXTRecord",
	"rPRecord",
	"aFSDBRecord",
//	"SigRecord",
	"KeyRecord",
//	"gPosRecord",
	"aAAARecord",
	"lOCRecord",
	"sRVRecord",
	"nAPTRRecord",
	"kXRecord",
	"certRecord",
//	"a6Record",
//	"dNameRecord",
//	"aPLRecord",
	"dSRecord",
	"sSHFPRecord",
	"iPSecKeyRecord",
	"rRSIGRecord",
	"nSECRecord",
	"dNSKeyRecord",
	"dHCIDRecord",
	"sPFRecord",
	"modifyTimestamp",
	NULL
};



class LdapBackend : public DNSBackend
{
	bool m_getdn;
	bool m_qlog;
	int m_msgid;
	uint32_t m_ttl;
	uint32_t m_default_ttl;
	unsigned int m_axfrqlen;
	time_t m_last_modified;
	string m_myname;
	string m_qname;
	PowerLDAP* m_pldap;
	PowerLDAP::sentry_t m_result;
	PowerLDAP::sentry_t::iterator m_attribute;
	vector<string>::iterator m_value, m_adomain;
	vector<string> m_adomains;

	bool (LdapBackend::*m_list_fcnt)( const string&, int );
	void (LdapBackend::*m_lookup_fcnt)( const QType&, const string&, DNSPacket*, int );
	bool (LdapBackend::*m_prepare_fcnt)();

	bool list_simple( const string& target, int domain_id );
	bool list_strict( const string& target, int domain_id );

	void lookup_simple( const QType& qtype, const string& qdomain, DNSPacket* p, int zoneid );
	void lookup_strict( const QType& qtype, const string& qdomain, DNSPacket* p, int zoneid );
	void lookup_tree( const QType& qtype, const string& qdomain, DNSPacket* p, int zoneid );

	bool prepare();
	bool prepare_simple();
	bool prepare_strict();

	bool getDomainInfo( const string& domain, DomainInfo& di );

public:

	LdapBackend( const string &suffix="" );
	~LdapBackend();

	bool list( const string& target, int domain_id );
	void lookup( const QType& qtype, const string& qdomain, DNSPacket* p = 0, int zoneid = -1 );
	bool get( DNSResourceRecord& rr );
};

#endif /* LDAPBACKEND_HH */
