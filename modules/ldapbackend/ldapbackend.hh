/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 * originally authored by Norbert Sendetzky
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <algorithm>
#include <sstream>
#include <utility>
#include <string>
#include <cstdlib>
#include <cctype>
#include <inttypes.h>
#include "pdns/dns.hh"
#include "pdns/utility.hh"
#include "pdns/dnspacket.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/arguments.hh"
#include "pdns/logger.hh"
#include "powerldap.hh"
#include "utils.hh"



#ifndef LDAPBACKEND_HH
#define LDAPBACKEND_HH

using std::string;
using std::vector;

class LdapAuthenticator;

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
//  "SigRecord",
  "KeyRecord",
//  "gPosRecord",
  "aAAARecord",
  "lOCRecord",
  "sRVRecord",
  "nAPTRRecord",
  "kXRecord",
  "certRecord",
//  "a6Record",
//  "dNameRecord",
//  "aPLRecord",
  "dSRecord",
  "sSHFPRecord",
  "iPSecKeyRecord",
  "rRSIGRecord",
  "nSECRecord",
  "dNSKeyRecord",
  "dHCIDRecord",
  "nSEC3Record",
  "nSEC3PARAMRecord",
  "tLSARecord",
  "cDSRecord",
  "cDNSKeyRecord",
  "openPGPKeyRecord",
  "sPFRecord",
  "EUI48Record",
  "EUI64Record",
  "tKeyRecord",
  "uRIRecord",
  "cAARecord",
  "TYPE65226Record",
  "TYPE65534Record",
  "modifyTimestamp",
  NULL
};



class LdapBackend : public DNSBackend
{
    bool d_getdn;
    bool d_qlog;
    int d_msgid;
    uint32_t d_ttl;
    uint32_t d_default_ttl;
    unsigned int d_axfrqlen;
    time_t d_last_modified;
    string d_myname;
    DNSName d_qname;
    PowerLDAP* d_pldap;
    LdapAuthenticator *d_authenticator;
    PowerLDAP::sentry_t d_result;
    PowerLDAP::sentry_t::iterator d_attribute;
    vector<string>::iterator d_value;
    vector<DNSName>::iterator d_adomain;
    vector<DNSName> d_adomains;
    QType d_qtype;
    int d_reconnect_attempts;

    bool (LdapBackend::*d_list_fcnt)( const DNSName&, int );
    void (LdapBackend::*d_lookup_fcnt)( const QType&, const DNSName&, DNSPacket*, int );
    bool (LdapBackend::*d_prepare_fcnt)();

    bool list_simple( const DNSName& target, int domain_id );
    bool list_strict( const DNSName& target, int domain_id );

    void lookup_simple( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );
    void lookup_strict( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );
    void lookup_tree( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );

    bool prepare();
    bool prepare_simple();
    bool prepare_strict();

    bool reconnect();

  public:

    LdapBackend( const string &suffix="" );
    ~LdapBackend();

    // Native backend
    bool list( const DNSName& target, int domain_id, bool include_disabled=false ) override;
    void lookup( const QType& qtype, const DNSName& qdomain, DNSPacket* p = 0, int zoneid = -1 ) override;
    bool get( DNSResourceRecord& rr ) override;

    bool getDomainInfo( const DNSName& domain, DomainInfo& di, bool getSerial=true ) override;

    // Master backend
    void getUpdatedMasters( vector<DomainInfo>* domains ) override;
    void setNotified( uint32_t id, uint32_t serial ) override;
};

#endif /* LDAPBACKEND_HH */
