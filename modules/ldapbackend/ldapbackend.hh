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

__attribute__ ((unused)) static const char* ldap_attrany[] = {
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
  "objectClass",
  "PdnsRecordTTL",
  "PdnsRecordNoAuth",
  "PdnsRecordOrdername",
  NULL
};



class LdapBackend : public DNSBackend
{
    string d_myname;

    bool d_qlog;
    uint32_t d_default_ttl;
    int d_reconnect_attempts;

    bool d_getdn;
    PowerLDAP::SearchResult::Ptr d_search;
    PowerLDAP::sentry_t d_result;
    bool d_in_list;
    bool d_dnssec;
    std::string d_metadata_searchdn;

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
    std::list<DNSResult> d_results_cache;

    DNSName d_qname;
    QType d_qtype;

    PowerLDAP* d_pldap;
    LdapAuthenticator *d_authenticator;

    bool (LdapBackend::*d_list_fcnt)( const DNSName&, int );
    void (LdapBackend::*d_lookup_fcnt)( const QType&, const DNSName&, DNSPacket*, int );

    bool list_simple( const DNSName& target, int domain_id );
    bool list_strict( const DNSName& target, int domain_id );

    void lookup_simple( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );
    void lookup_strict( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );
    void lookup_tree( const QType& qtype, const DNSName& qdomain, DNSPacket* p, int zoneid );

    bool reconnect();

    // Extracts common attributes from the current result stored in d_result and sets them in the given DNSResult.
    // This will modify d_result by removing attributes that may interfere with the records extraction later.
    void extract_common_attributes( DNSResult &result );

    // Extract LDAP attributes for the current result stored in d_result and create a new DNSResult that will
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
    bool list( const DNSName& target, int domain_id, bool include_disabled=false ) override;
    void lookup( const QType& qtype, const DNSName& qdomain, DNSPacket* p = 0, int zoneid = -1 ) override;
    bool get( DNSResourceRecord& rr ) override;

    bool getDomainInfo( const DNSName& domain, DomainInfo& di, bool getSerial=true ) override;

    // Master backend
    void getUpdatedMasters( vector<DomainInfo>* domains ) override;
    void setNotified( uint32_t id, uint32_t serial ) override;

    // DNSSEC backend
    bool doesDNSSEC() override;

    bool getAllDomainMetadata( const DNSName& name, std::map<std::string, std::vector<std::string> >& meta ) override;
    bool getDomainMetadata( const DNSName& name, const std::string& kind, std::vector<std::string>& meta ) override;
    bool setDomainMetadata( const DNSName& name, const std::string& kind, const std::vector<std::string>& meta ) override;

    bool getDomainKeys( const DNSName& name, std::vector<KeyData>& keys ) override;
    bool addDomainKey( const DNSName& name, const KeyData& key, int64_t& id ) override;
    bool activateDomainKey( const DNSName& name, unsigned int id ) override;
    bool deactivateDomainKey( const DNSName& name, unsigned int id ) override;
    bool removeDomainKey( const DNSName& name, unsigned int id ) override;

    bool updateDNSSECOrderNameAndAuth( uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype ) override;
};

#endif /* LDAPBACKEND_HH */
