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
    d_in_list = true;
    d_qname = target;
    d_qtype = QType::ANY;
    d_results_cache.clear();

    return (this->*d_list_fcnt)( target, domain_id );
  }
  catch( LDAPTimeout &lt )
  {
    g_log << Logger::Warning << d_myname << " Unable to get zone " << target << " from LDAP directory: " << lt.what() << endl;
    throw DBException( "LDAP server timeout" );
  }
  catch( LDAPNoConnection &lnc )
  {
    g_log << Logger::Warning << d_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->list( target, domain_id );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Unable to get zone " << target << " from LDAP directory: " << le.what() << endl;
    throw PDNSException( "LDAP server unreachable" );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    g_log << Logger::Error << d_myname << " Caught STL exception for target " << target << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }

  return false;
}



bool LdapBackend::list_simple( const DNSName& target, int domain_id )
{
  string dn;
  string filter;
  string qesc;


  dn = getArg( "basedn" );
  qesc = toLower( d_pldap->escape( target.toStringRootDot() ) );

  // search for SOARecord of target
  filter = strbind( ":target:", "&(associatedDomain=" + qesc + ")(sOARecord=*)", getArg( "filter-axfr" ) );
  PowerLDAP::SearchResult::Ptr search = d_pldap->search( dn, LDAP_SCOPE_SUBTREE, filter, (const char**) ldap_attrany );
  if ( !search->getNext( d_result, true ) )
    return false;

  if( d_result.count( "dn" ) && !d_result["dn"].empty() )
  {
    if( !mustDo( "basedn-axfr-override" ) )
    {
      dn = d_result["dn"][0];
    }
  }

  // If we have any records associated with this entry let's parse them here
  DNSResult soa_result;
  soa_result.ttl = d_default_ttl;
  soa_result.lastmod = 0;
  this->extract_common_attributes( soa_result );
  this->extract_entry_results( d_qname, soa_result, QType(uint16_t(QType::ANY)) );

  filter = strbind( ":target:", "associatedDomain=*." + qesc, getArg( "filter-axfr" ) );
  g_log << Logger::Debug << d_myname << " Search = basedn: " << dn << ", filter: " << filter << endl;
  d_search = d_pldap->search( dn, LDAP_SCOPE_SUBTREE, filter, (const char**) ldap_attrany );

  return true;
}


bool LdapBackend::list_strict( const DNSName& target, int domain_id )
{
  if( target.isPartOf(DNSName("in-addr.arpa")) || target.isPartOf(DNSName("ip6.arpa")) )
  {
    g_log << Logger::Warning << d_myname << " Request for reverse zone AXFR, but this is not supported in strict mode" << endl;
    return false;   // AXFR isn't supported in strict mode. Use simple mode and additional PTR records
  }

  return list_simple( target, domain_id );
}



void LdapBackend::lookup( const QType &qtype, const DNSName &qname, int zoneid, DNSPacket *dnspkt )
{
  try
  {
    d_in_list = false;
    d_qname = qname;
    d_qtype = qtype;
    d_results_cache.clear();

    if( d_qlog ) { g_log.log( "Query: '" + qname.toStringRootDot() + "|" + qtype.getName() + "'", Logger::Error ); }
    (this->*d_lookup_fcnt)( qtype, qname, dnspkt, zoneid );
  }
  catch( LDAPTimeout &lt )
  {
    g_log << Logger::Warning << d_myname << " Unable to search LDAP directory: " << lt.what() << endl;
    throw DBException( "LDAP server timeout" );
  }
  catch( LDAPNoConnection &lnc )
  {
    g_log << Logger::Warning << d_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->lookup( qtype, qname, zoneid, dnspkt );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Unable to search LDAP directory: " << le.what() << endl;
    throw PDNSException( "LDAP server unreachable" );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    g_log << Logger::Error << d_myname << " Caught STL exception for qname " << qname << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}



void LdapBackend::lookup_simple( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  string filter, attr, qesc;
  const char** attributes = ldap_attrany + 1;   // skip associatedDomain
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", "PdnsRecordTTL", "PdnsRecordAuth", "PdnsRecordOrdername", NULL };


  qesc = toLower( d_pldap->escape( qname.toStringRootDot() ) );
  filter = "associatedDomain=" + qesc;

  if( qtype.getCode() != QType::ANY )
  {
    attr = qtype.getName() + "Record";
    filter = "&(" + filter + ")(" + attr + "=*)";
    attronly[0] = attr.c_str();
    attributes = attronly;
  }

  filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

  g_log << Logger::Debug << d_myname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
  d_search = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attributes );
}



void LdapBackend::lookup_strict( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  int len;
  vector<string> parts;
  string filter, attr, qesc;
  const char** attributes = ldap_attrany + 1;   // skip associatedDomain
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", "PdnsRecordTTL", "PdnsRecordAuth", "PdnsRecordOrdername", NULL };


  qesc = toLower( d_pldap->escape( qname.toStringRootDot() ) );
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
  }

  if( qtype.getCode() != QType::ANY )
  {
    attr = qtype.getName() + "Record";
    filter = "&(" + filter + ")(" + attr + "=*)";
    attronly[0] = attr.c_str();
    attributes = attronly;
  }

  filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

  g_log << Logger::Debug << d_myname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
  d_search = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attributes );
}



void LdapBackend::lookup_tree( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  string filter, attr, qesc, dn;
  const char** attributes = ldap_attrany + 1;   // skip associatedDomain
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", "PdnsRecordTTL", "PdnsRecordAuth", "PdnsRecordOrdername", NULL };
  vector<string> parts;


  qesc = toLower( d_pldap->escape( qname.toStringRootDot() ) );
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

  g_log << Logger::Debug << d_myname << " Search = basedn: " << dn + getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
  d_search = d_pldap->search( dn + getArg( "basedn" ), LDAP_SCOPE_BASE, filter, attributes );
}


bool LdapBackend::get( DNSResourceRecord &rr )
{
  if ( d_results_cache.empty() ) {
    while ( d_results_cache.empty() ) {
      bool exhausted = false;
      bool valid_entry_found = false;

      while ( !valid_entry_found && !exhausted ) {
        try {
          exhausted = !d_search->getNext( d_result, true );
        }
        catch( LDAPException &le )
        {
          g_log << Logger::Error << d_myname << " Failed to get next result: " << le.what() << endl;
          throw PDNSException( "Get next result impossible" );
        }

        if ( !exhausted ) {
          if ( !d_in_list ) {
            // All entries are valid here
            valid_entry_found = true;
          }
          else {
            // If we're called after list() then the entry *must* contain
            // associatedDomain, otherwise let's just skip it
            if ( d_result.count( "associatedDomain" ) )
              valid_entry_found = true;
          }
        }
      }

      if ( exhausted ) {
        break;
      }

      DNSResult result_template;
      result_template.ttl = d_default_ttl;
      result_template.lastmod = 0;
      this->extract_common_attributes( result_template );

      std::vector<std::string> associatedDomains;

      if ( d_result.count( "associatedDomain" ) ) {
        if ( d_in_list ) {
          // We can have more than one associatedDomain in the entry, so for each of them we have to check
          // that they are indeed under the domain we've been asked to list (nothing enforces this, so you
          // can have one associatedDomain set to "host.first-domain.com" and another one set to
          // "host.second-domain.com"). Better not return the latter I guess :)
          // We also have to generate one DNSResult per DNS-relevant attribute. As we've asked only for them
          // and the others above we've already cleaned it's just a matter of iterating over them.

          unsigned int axfrqlen = d_qname.toStringRootDot().length();
          for ( auto i = d_result["associatedDomain"].begin(); i != d_result["associatedDomain"].end(); ++i ) {
            // Sanity checks: is this associatedDomain attribute under the requested domain?
            if ( i->size() >= axfrqlen && i->substr( i->size() - axfrqlen, axfrqlen ) == d_qname.toStringRootDot() )
              associatedDomains.push_back( *i );
          }
        }
        else {
          // This was a lookup in strict mode, so we add the reverse lookup
          // information manually.
          d_result["pTRRecord"] = d_result["associatedDomain"];
        }
      }

      if ( d_in_list ) {
        for ( const auto& domain : associatedDomains )
          this->extract_entry_results( DNSName( domain ), result_template, QType(uint16_t(QType::ANY)) );
      }
      else {
        this->extract_entry_results( d_qname, result_template, QType(uint16_t(QType::ANY)) );
      }
    }

    if ( d_results_cache.empty() )
      return false;
  }

  DNSResult result = d_results_cache.back();
  d_results_cache.pop_back();
  rr.qtype = result.qtype;
  rr.qname = result.qname;
  rr.ttl = result.ttl;
  rr.last_modified = 0;
  rr.content = result.value;
  rr.auth = result.auth;

  g_log << Logger::Debug << d_myname << " Record = qname: " << rr.qname << ", qtype: " << (rr.qtype).getName() << ", ttl: " << rr.ttl << ", content: " << rr.content << endl;
  return true;
}


bool LdapBackend::getDomainInfo( const DNSName& domain, DomainInfo& di, bool getSerial )
{
  string filter;
  SOAData sd;
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

  try
  {
    // search for SOARecord of domain
    filter = "(&(associatedDomain=" + toLower( d_pldap->escape( domain.toStringRootDot() ) ) + ")(SOARecord=*))";
    d_search = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
    if (!d_search->getNext( result )) {
      return false;
    }
  }
  catch( LDAPTimeout &lt )
  {
    g_log << Logger::Warning << d_myname << " Unable to search LDAP directory: " << lt.what() << endl;
    throw DBException( "LDAP server timeout" );
  }
  catch( LDAPNoConnection &lnc )
  {
    g_log << Logger::Warning << d_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->getDomainInfo( domain, di );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Unable to search LDAP directory: " << le.what() << endl;
    throw PDNSException( "LDAP server unreachable" );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    throw DBException( "STL exception" );
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
    di.zone = DNSName(domain);

    if( result.count( "PdnsDomainLastCheck" ) && !result["PdnsDomainLastCheck"].empty() )
      di.last_check = pdns_stou( result["PdnsDomainLastCheck"][0] );
    else
      di.last_check = 0;

    if ( result.count( "PdnsDomainNotifiedSerial" ) && !result["PdnsDomainNotifiedSerial"].empty() )
      di.notified_serial = pdns_stou( result["PdnsDomainNotifiedSerial"][0] );
    else
      di.notified_serial = 0;

    if ( result.count( "PdnsDomainMaster" ) && !result["PdnsDomainMaster"].empty() ) {
      for(const auto &m : result["PdnsDomainMaster"])
        di.masters.emplace_back(m, 53);
    }

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
