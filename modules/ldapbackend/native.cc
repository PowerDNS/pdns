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
#include "exceptions.hh"
#include "ldapbackend.hh"
#include <cstdlib>


bool LdapBackend::list( const DNSName& target, int domain_id, bool include_disabled )
{
  try
  {
    m_qname = target;
    m_results_cache.clear();

    return (this->*m_list_fcnt)( target, domain_id );
  }
  catch( LDAPTimeout &lt )
  {
    L << Logger::Warning << m_myname << " Unable to get zone " << target << " from LDAP directory: " << lt.what() << endl;
    throw( DBException( "LDAP server timeout" ) );
  }
  catch( LDAPNoConnection &lnc )
  {
    L << Logger::Warning << m_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->list( target, domain_id );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    L << Logger::Error << m_myname << " Unable to get zone " << target << " from LDAP directory: " << le.what() << endl;
    throw( PDNSException( "LDAP server unreachable" ) );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    L << Logger::Error << m_myname << " Caught STL exception for target " << target << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }

  return false;
}


inline bool LdapBackend::list_simple( const DNSName& target, int domain_id )
{
  string dn;
  string filter;
  string qesc;

  dn = getArg( "basedn" );
  qesc = toLower( m_pldap->escape( target.toStringRootDot() ) );

  // search for SOARecord of target
  filter = strbind( ":target:", "&(associatedDomain=" + qesc + ")(sOARecord=*)", getArg( "filter-axfr" ) );
  m_msgid = m_pldap->search( dn, LDAP_SCOPE_SUBTREE, filter, (const char**) ldap_attrany );
  m_pldap->getSearchEntry( m_msgid, m_result, true );

  if( m_result.count( "dn" ) && !m_result["dn"].empty() )
  {
    if( !mustDo( "basedn-axfr-override" ) )
    {
      dn = m_result["dn"][0];
    }
    m_result.erase( "dn" );
  }

  // If we have any records associated with this entry let's parse them here
  m_result.erase( "associatedDomain" );
  DNSResult soa_result;
  soa_result.ttl = m_default_ttl;
  soa_result.lastmod = 0;
  this->extract_common_attributes( soa_result );
  this->extract_entry_results( m_qname, soa_result, QType(uint16_t(QType::ANY)) );

  filter = strbind( ":target:", "associatedDomain=*." + qesc, getArg( "filter-axfr" ) );
  L << Logger::Debug << m_myname << " Search = basedn: " << dn << ", filter: " << filter << endl;
  m_msgid = m_pldap->search( dn, LDAP_SCOPE_SUBTREE, filter, (const char**) ldap_attrany );

  while ( m_pldap->getSearchEntry( m_msgid, m_result, m_getdn ) ) {
    // Each search entry can result in multiple results if more than one
    // associatedDomain is present. However certain characteristics are
    // common to each result (the TTL and the last modification), so let's
    // just add them right now to the DNSResult. This will then be copied
    // for each item found in the entry.
    DNSResult result_template;
    result_template.ttl = m_default_ttl;
    result_template.lastmod = 0;
    this->extract_common_attributes( result_template );

    // Now on to the real stuff.
    // We can have more than one associatedDomain in the entry, so for each of them we have to check
    // that they are indeed under the domain we've been asked to list (nothing enforces this, so you
    // can have one associatedDomain set to "host.first-domain.com" and another one set to
    // "host.second-domain.com"). Better not return the latter I guess :)
    // We also have to generate one DNSResult per DNS-relevant attribute. As we've asked only for them
    // and the others above we've already cleaned it's just a matter of iterating over them.

    if ( ! m_result.count( "associatedDomain" ) )
      continue;

    unsigned int axfrqlen = m_qname.toStringRootDot().length();
    std::vector<std::string> associatedDomains;
    for ( auto i = m_result["associatedDomain"].begin(); i != m_result["associatedDomain"].end(); ++i ) {
      // Sanity checks: is this associatedDomain attribute under the requested domain?
      if ( i->size() >= axfrqlen && i->substr( i->size() - axfrqlen, axfrqlen ) == m_qname.toStringRootDot() )
        associatedDomains.push_back( *i );
    }
    // Same reason as above, we delete this attribute to prevent messing with the DNS records iteration
    m_result.erase( "associatedDomain" );

    std::string attrname, qstr;
    QType qt;

    for ( auto domain : associatedDomains ) {
      this->extract_entry_results( DNSName( domain ), result_template, QType(uint16_t(QType::ANY)) );
    }
  }

  return true;
}


bool LdapBackend::list_strict( const DNSName& target, int domain_id )
{
  if( target.isPartOf(DNSName("in-addr.arpa")) || target.isPartOf(DNSName(".ip6.arpa")) )
  {
    L << Logger::Warning << m_myname << " Request for reverse zone AXFR, but this is not supported in strict mode" << endl;
    return false;   // AXFR isn't supported in strict mode. Use simple mode and additional PTR records
  }

  return list_simple( target, domain_id );
}


void LdapBackend::lookup( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  try
  {
    m_qname = qname;

    if( m_qlog ) { L.log( "Query: '" + qname.toStringRootDot() + "|" + qtype.getName() + "'", Logger::Error ); }
    (this->*m_lookup_fcnt)( qtype, qname, dnspkt, zoneid );

    while ( m_pldap->getSearchEntry( m_msgid, m_result, m_getdn ) ) {
      // Same rationale as in LdapBackend::list_simple(), this template will
      // serve as the base for the results we'll cache.
      DNSResult result_template;
      result_template.ttl = m_default_ttl;
      result_template.lastmod = 0;
      result_template.domain_id = zoneid;
      this->extract_common_attributes( result_template );

      // If we have an associatedDomain attribute here this means that we're in strict mode and
      // that a reverse lookup was requested. We have to slightly tweak the result before extracting
      // the relevant information.
      if ( m_result.count( "associatedDomain" ) ) {
        m_result["pTRRecord"] = m_result["associatedDomain"];
        m_result.erase( "associatedDomain" );
      }

      std::string attrname, qstr;
      QType qt;

      this->extract_entry_results( m_qname, result_template, qtype );
    }
  }
  catch( LDAPTimeout &lt )
  {
    L << Logger::Warning << m_myname << " Unable to search LDAP directory: " << lt.what() << endl;
    throw( DBException( "LDAP server timeout" ) );
  }
  catch( LDAPNoConnection &lnc )
  {
    L << Logger::Warning << m_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->lookup( qtype, qname, dnspkt, zoneid );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    L << Logger::Error << m_myname << " Unable to search LDAP directory: " << le.what() << endl;
    throw( PDNSException( "LDAP server unreachable" ) );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    L << Logger::Error << m_myname << " Caught STL exception for qname " << qname << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}


void LdapBackend::lookup_simple( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  string filter, attr, qesc;
  const char** attributes = ldap_attrany + 1;   // skip associatedDomain
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", "PdnsDomainId", "PdnsRecordTTL", "PdnsRecordNoAuth", "PdnsRecordOrdername", NULL };

  std::string basedn = getArg( "basedn" );

  // If configured first search for the zone under which the records are to be found
  if ( mustDo( "lookup-zone-rebase" ) && zoneid >= 0 ) {
    std::string zoneFilter = "PdnsDomainId=" + std::to_string( zoneid );
    const char* zoneAttributes[] = { "objectClass", NULL };
    PowerLDAP::sentry_t result;
    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, zoneFilter, zoneAttributes );
    if ( !m_pldap->getSearchEntry( msgid, result, true ) ) {
      throw PDNSException( "No zone with ID "+std::to_string(zoneid)+" found" );
    }
    basedn = result["dn"][0];
    L<<Logger::Debug<< m_myname << " Searching for RR under " << basedn << std::endl;
  }

  qesc = toLower( m_pldap->escape( qname.toStringRootDot() ) );
  filter = "associatedDomain=" + qesc;

  if( qtype.getCode() != QType::ANY )
  {
    attr = qtype.getName() + "Record";
    filter = "&(" + filter + ")(" + attr + "=*)";
    attronly[0] = attr.c_str();
    attributes = attronly;
  }

  filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

  L << Logger::Debug << m_myname << " Search = basedn: " << basedn << ", filter: " << filter << ", qtype: " << qtype.getName() << ", domain_id: " << zoneid << endl;
  m_msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );
}


void LdapBackend::lookup_strict( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  int len;
  vector<string> parts;
  string filter, attr, qesc;
  const char** attributes = ldap_attrany + 1;   // skip associatedDomain
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", "PdnsDomainId", "PdnsRecordTTL", "PdnsRecordNoAuth", "PdnsRecordOrdername", NULL };


  qesc = toLower( m_pldap->escape( qname.toStringRootDot() ) );
  stringtok( parts, qesc, "." );
  len = qesc.length();

  if( parts.size() == 6 && len > 13 && qesc.substr( len - 13, 13 ) == ".in-addr.arpa" )   // IPv4 reverse lookups
  {
    filter = "aRecord=" + ptr2ip4( parts );
    attronly[0] = "associatedDomain";
    attributes = attronly;
  }
  else if( parts.size() == 34 && len > 9 && ( qesc.substr( len - 9, 9 ) == ".ip6.arpa" ) )   // IPv6 reverse lookups
  {
    filter = "aAAARecord=" + ptr2ip6( parts );
    attronly[0] = "associatedDomain";
    attributes = attronly;
  }
  else   // IPv4 and IPv6 lookups
  {
    filter = "associatedDomain=" + qesc;
    if( qtype.getCode() != QType::ANY )
    {
      attr = qtype.getName() + "Record";
      filter = "&(" + filter + ")(" + attr + "=*)";
      attronly[0] = attr.c_str();
      attributes = attronly;
    }
  }

  filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

  L << Logger::Debug << m_myname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
  m_msgid = m_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attributes );
}


void LdapBackend::lookup_tree( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  string filter, attr, qesc, dn;
  const char** attributes = ldap_attrany + 1;   // skip associatedDomain
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", "PdnsRecordTTL", "PdnsRecordNoAuth", "PdnsRecordOrdername", NULL };
  vector<string> parts;


  qesc = toLower( m_pldap->escape( qname.toStringRootDot() ) );
  filter = "associatedDomain=" + qesc;

  if( qtype.getCode() != QType::ANY )
  {
    attr = qtype.getName() + "Record";
    filter = "&(" + filter + ")(" + attr + "=*)";
    attronly[0] = attr.c_str();
    attributes = attronly;
  }

  filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

  stringtok( parts, toLower( qname.toString() ), "." );
  for(auto i = parts.crbegin(); i != parts.crend(); i++ )
  {
    dn = "dc=" + *i + "," + dn;
  }

  L << Logger::Debug << m_myname << " Search = basedn: " << dn + getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
  m_msgid = m_pldap->search( dn + getArg( "basedn" ), LDAP_SCOPE_BASE, filter, attributes );
}


bool LdapBackend::get( DNSResourceRecord &rr )
{
  if ( m_results_cache.empty() )
    return false;

  DNSResult result = m_results_cache.front();
  m_results_cache.pop_front();
  rr.qtype = result.qtype;
  rr.qname = result.qname;
  rr.ttl = result.ttl;
  rr.last_modified = 0;
  rr.content = result.value;
  rr.auth = result.auth;
  if ( result.domain_id > 0 )
    rr.domain_id = result.domain_id;

  L << Logger::Debug << m_myname << " Record = qname: " << rr.qname << ", qtype: " << (rr.qtype).getName() << ", ttl: " << rr.ttl << ", content: " << rr.content << ", auth: " << rr.auth << ", domain_id: " << rr.domain_id << endl;
  return true;
}


bool LdapBackend::getDomainInfo( const DNSName& domain, DomainInfo& di )
{
  string filter;
  SOAData sd;
  int msgid;
  PowerLDAP::sentry_t result;
  const char* attronly[] = {
    "sOARecord",
    "PdnsDomainId",
    "PdnsDomainNotifiedSerial",
    "PdnsDomainLastCheck",
    "PdnsDomainMaster",
    "PdnsDomainType",
    NULL
  };

  L<<Logger::Debug<< m_myname << " Getting domain info for " << domain << std::endl;

  try
  {
    // search for SOARecord of domain
    filter = "(&(associatedDomain=" + toLower( m_pldap->escape( domain.toStringRootDot() ) ) + ")(SOARecord=*))";
    m_msgid = m_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
    m_pldap->getSearchEntry( msgid, result );
  }
  catch( LDAPTimeout &lt )
  {
    L << Logger::Warning << m_myname << " Unable to search LDAP directory: " << lt.what() << endl;
    throw( DBException( "LDAP server timeout" ) );
  }
  catch( LDAPNoConnection &lnc )
  {
    L << Logger::Warning << m_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->getDomainInfo( domain, di );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    L << Logger::Error << m_myname << " Unable to search LDAP directory: " << le.what() << endl;
    throw( PDNSException( "LDAP server unreachable" ) );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    throw( DBException( "STL exception" ) );
  }

  if( result.count( "sOARecord" ) && !result["sOARecord"].empty() )
  {
    sd.serial = 0;
    fillSOAData( result["sOARecord"][0], sd );

    if ( result.count( "PdnsDomainId" ) && !result["PdnsDomainId"].empty() )
      di.id = std::stoi( result["PdnsDomainId"][0] );
    else
      di.id = 0;

    di.serial = sd.serial;
    di.zone = domain;

    if( result.count( "PdnsDomainLastCheck" ) && !result["PdnsDomainLastCheck"].empty() )
      di.last_check = pdns_stou( result["PdnsDomainLastCheck"][0] );
    else
      di.last_check = 0;

    if ( result.count( "PdnsDomainNotifiedSerial" ) && !result["PdnsDomainNotifiedSerial"].empty() )
      di.notified_serial = pdns_stou( result["PdnsDomainNotifiedSerial"][0] );
    else
      di.notified_serial = 0;

    if ( result.count( "PdnsDomainMaster" ) && !result["PdnsDomainMaster"].empty() )
      di.masters = result["PdnsDomainMaster"];

    if ( result.count( "PdnsDomainType" ) && !result["PdnsDomainType"].empty() ) {
      string kind = result["PdnsDomainType"][0];
      if ( kind == "master" )
        di.kind = DomainInfo::Master;
      else if ( kind == "slave" )
        di.kind = DomainInfo::Slave;
      else
        di.kind = DomainInfo::Native;
    }
    else {
      di.kind = DomainInfo::Native;
    }

    di.backend = this;

    return true;
  }

  return false;
}

// vim: ts=2 sw=2 sts=2 et
