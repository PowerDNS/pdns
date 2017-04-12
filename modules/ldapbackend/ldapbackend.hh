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
#include <list>
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
  "ALIASRecord",
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
  "dNameRecord",
//  "aPLRecord",
  "dSRecord",
  "sSHFPRecord",
  "iPSecKeyRecord",
  "rRSIGRecord",
  "nSECRecord",
  "dNSKeyRecord",
  "dHCIDRecord",
  "sPFRecord",
  "TYPE65534Record",
  "EUI48Record",
  "EUI64Record",
  "TYPE65226Record",
  "modifyTimestamp",
  "objectClass",
  "PdnsRecordTTL",
  "PdnsRecordNoAuth",
  "PdnsRecordOrdername",
  NULL
};



class LdapBackend : public DNSBackend
{
    string m_myname;

    bool m_qlog;
    uint32_t m_default_ttl;
    int m_reconnect_attempts;

    bool m_getdn;
    int m_msgid;
    PowerLDAP::sentry_t m_result;
    bool m_dnssec;
    std::string m_metadata_searchdn;

    struct DNSResult {
      int domain_id;
      QType qtype;
      DNSName qname;
      uint32_t ttl;
      time_t lastmod;
      std::string value;
      bool auth;
      std::string ordername;

      DNSResult()
        : domain_id( -1 ), ttl( 0 ), lastmod( 0 ), value( "" ), auth( true ), ordername( "" )
      {
      }
    };
    std::list<DNSResult> m_results_cache;

    DNSName m_qname;
    QType m_qtype;

    PowerLDAP* m_pldap;
    LdapAuthenticator *m_authenticator;

    bool (LdapBackend::*m_list_fcnt)( const DNSName&, int );
    void (LdapBackend::*m_lookup_fcnt)( const QType&, const DNSName&, DNSPacket*, int );

    bool list_simple( const DNSName& target, int domain_id );
    bool list_strict( const DNSName& target, int domain_id );

    void lookup_simple( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );
    void lookup_strict( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );
    void lookup_tree( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );

    bool reconnect();

    // Extracts common attributes from the current result stored in m_result and sets them in the given DNSResult.
    // This will modify m_result by removing attributes that may interfere with the records extraction later.
    void extract_common_attributes( DNSResult &result );

    // Extract LDAP attributes for the current result stored in m_result and create a new DNSResult that will
    // be appended in the results cache. The result parameter is used as a template that will be copied for
    // each result extracted from the entry.
    // The given domain will be added as the qname attribute of the result.
    // The qtype parameter is used to filter extracted results.
    void extract_entry_results( const DNSName& domain, const DNSResult& result, QType qtype );

    // Returns the DN under which the metadata for the given domain can be found.
    // An empty string will be returned if nothing was found.
    std::string getDomainMetadataDN( const DNSName& name );

  public:

    LdapBackend( const string &suffix="" );
    ~LdapBackend();

    // Native backend
    bool list( const DNSName& target, int domain_id, bool include_disabled=false );
    void lookup( const QType& qtype, const DNSName& qdomain, DNSPacket* p = 0, int zoneid = -1 );
    bool get( DNSResourceRecord& rr );

    bool getDomainInfo( const DNSName& domain, DomainInfo& di );

    // Master backend
    void getUpdatedMasters( vector<DomainInfo>* domains );
    void setNotified( uint32_t id, uint32_t serial );

    // DNSSEC backend
    bool doesDNSSEC();

    bool getAllDomainMetadata( const DNSName& name, std::map<std::string, std::vector<std::string> >& meta );
    bool getDomainMetadata( const DNSName& name, const std::string& kind, std::vector<std::string>& meta );
    bool setDomainMetadata( const DNSName& name, const std::string& kind, const std::vector<std::string>& meta );

    bool getDomainKeys( const DNSName& name, unsigned int kind, std::vector<KeyData>& keys );
    bool addDomainKey( const DNSName& name, const KeyData& key, int64_t& id );
    bool activateDomainKey( const DNSName& name, unsigned int id );
    bool deactivateDomainKey( const DNSName& name, unsigned int id );
    bool removeDomainKey( const DNSName& name, unsigned int id );

    bool getTSIGKey( const DNSName& name, DNSName* algorithm, string* content );
    bool setTSIGKey( const DNSName& name, const DNSName& algorithm, const string& content );
    bool deleteTSIGKey( const DNSName& name );
    bool getTSIGKeys( std::vector<struct TSIGKey>& keys );

    bool getBeforeAndAfterNamesAbsolute( uint32_t domain_id, const std::string& qname, DNSName& unhashed, std::string& before, std::string& after );
    bool updateDNSSECOrderNameAndAuth( uint32_t domain_id, const DNSName& zonename, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype=QType::ANY );
};

#endif /* LDAPBACKEND_HH */
