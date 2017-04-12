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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "exceptions.hh"
#include "ldapauthenticator_p.hh"
#include "ldapbackend.hh"
#include <cstdlib>

unsigned int ldap_host_index = 0;

LdapBackend::LdapBackend( const string &suffix )
{
  string hoststr;
  unsigned int i, idx;
  vector<string> hosts;


  try
  {
    d_msgid = 0;
    d_qname.clear();
    d_pldap = NULL;
    d_authenticator = NULL;
    d_ttl = 0;
    d_axfrqlen = 0;
    d_last_modified = 0;
    d_qlog = arg().mustDo( "query-logging" );
    d_default_ttl = arg().asNum( "default-ttl" );
    d_myname = "[LdapBackend]";

    setArgPrefix( "ldap" + suffix );

    d_getdn = false;
    d_reconnect_attempts = getArgAsNum( "reconnect-attempts" );
    d_list_fcnt = &LdapBackend::list_simple;
    d_lookup_fcnt = &LdapBackend::lookup_simple;
    d_prepare_fcnt = &LdapBackend::prepare_simple;

    if( getArg( "method" ) == "tree" )
    {
      d_lookup_fcnt = &LdapBackend::lookup_tree;
    }

    if( getArg( "method" ) == "strict" || mustDo( "disable-ptrrecord" ) )
    {
      d_list_fcnt = &LdapBackend::list_strict;
      d_lookup_fcnt = &LdapBackend::lookup_strict;
      d_prepare_fcnt = &LdapBackend::prepare_strict;
    }

    stringtok( hosts, getArg( "host" ), ", " );
    idx = ldap_host_index++ % hosts.size();
    hoststr = hosts[idx];

    for( i = 1; i < hosts.size(); i++ )
    {
      hoststr += " " + hosts[ ( idx + i ) % hosts.size() ];
    }

    g_log << Logger::Info << d_myname << " LDAP servers = " << hoststr << endl;

    d_pldap = new PowerLDAP( hoststr.c_str(), LDAP_PORT, mustDo( "starttls" ), getArgAsNum( "timeout" ) );
    d_pldap->setOption( LDAP_OPT_DEREF, LDAP_DEREF_ALWAYS );

    string bindmethod = getArg( "bindmethod" );
    if ( bindmethod == "gssapi" ) {
      setenv( "KRB5CCNAME", getArg( "krb5-ccache" ).c_str(), 1 );
      d_authenticator = new LdapGssapiAuthenticator( getArg( "krb5-keytab" ), getArg( "krb5-ccache" ), getArgAsNum( "timeout" ) );
    }
    else {
      d_authenticator = new LdapSimpleAuthenticator( getArg( "binddn" ), getArg( "secret" ), getArgAsNum( "timeout" ) );
    }
    d_pldap->bind( d_authenticator );

    g_log << Logger::Notice << d_myname << " Ldap connection succeeded" << endl;
    return;
  }
  catch( LDAPTimeout &lt )
  {
    g_log << Logger::Error << d_myname << " Ldap connection to server failed because of timeout" << endl;
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Ldap connection to server failed: " << le.what() << endl;
  }
  catch( std::exception &e )
  {
    g_log << Logger::Error << d_myname << " Caught STL exception: " << e.what() << endl;
  }

  if( d_pldap != NULL ) { delete( d_pldap ); }
  throw PDNSException( "Unable to connect to ldap server" );
}



LdapBackend::~LdapBackend()
{
  delete( d_pldap );
  delete( d_authenticator );
  g_log << Logger::Notice << d_myname << " Ldap connection closed" << endl;
}



bool LdapBackend::reconnect()
{
  int attempts = d_reconnect_attempts;
  bool connected = false;
  while ( !connected && attempts > 0 ) {
    g_log << Logger::Debug << d_myname << " Reconnection attempts left: " << attempts << endl;
    connected = d_pldap->connect();
    if ( !connected )
      Utility::usleep( 250 );
    --attempts;
  }

  if ( connected )
    d_pldap->bind( d_authenticator );

  return connected;
}



bool LdapBackend::list( const DNSName& target, int domain_id, bool include_disabled )
{
  try
  {
    d_qname = target;
    d_qtype = QType::ANY;
    d_axfrqlen = target.toStringRootDot().length();
    d_adomain = d_adomains.end();   // skip loops in get() first time

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



inline bool LdapBackend::list_simple( const DNSName& target, int domain_id )
{
  string dn;
  string filter;
  string qesc;


  dn = getArg( "basedn" );
  qesc = toLower( d_pldap->escape( target.toStringRootDot() ) );

  // search for SOARecord of target
  filter = strbind( ":target:", "&(associatedDomain=" + qesc + ")(sOARecord=*)", getArg( "filter-axfr" ) );
  d_msgid = d_pldap->search( dn, LDAP_SCOPE_SUBTREE, filter, (const char**) ldap_attrany );
  d_pldap->getSearchEntry( d_msgid, d_result, true );

  if( d_result.count( "dn" ) && !d_result["dn"].empty() )
  {
    if( !mustDo( "basedn-axfr-override" ) )
    {
      dn = d_result["dn"][0];
    }
    d_result.erase( "dn" );
  }

  prepare();
  filter = strbind( ":target:", "associatedDomain=*." + qesc, getArg( "filter-axfr" ) );
  DLOG( g_log << Logger::Debug << d_myname << " Search = basedn: " << dn << ", filter: " << filter << endl );
  d_msgid = d_pldap->search( dn, LDAP_SCOPE_SUBTREE, filter, (const char**) ldap_attrany );

  return true;
}



inline bool LdapBackend::list_strict( const DNSName& target, int domain_id )
{
  if( target.isPartOf(DNSName("in-addr.arpa")) || target.isPartOf(DNSName("ip6.arpa")) )
  {
    g_log << Logger::Warning << d_myname << " Request for reverse zone AXFR, but this is not supported in strict mode" << endl;
    return false;   // AXFR isn't supported in strict mode. Use simple mode and additional PTR records
  }

  return list_simple( target, domain_id );
}



void LdapBackend::lookup( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  try
  {
    d_axfrqlen = 0;
    d_qname = qname;
    d_adomain = d_adomains.end();   // skip loops in get() first time
    d_qtype = qtype;

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
      this->lookup( qtype, qname, dnspkt, zoneid );
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
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", NULL };


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

  DLOG( g_log << Logger::Debug << d_myname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl );
  d_msgid = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attributes );
}



void LdapBackend::lookup_strict( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  int len;
  vector<string> parts;
  string filter, attr, qesc;
  const char** attributes = ldap_attrany + 1;   // skip associatedDomain
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", NULL };


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
    if( qtype.getCode() != QType::ANY )
    {
      attr = qtype.getName() + "Record";
      filter = "&(" + filter + ")(" + attr + "=*)";
      attronly[0] = attr.c_str();
      attributes = attronly;
    }
  }

  filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

  DLOG( g_log << Logger::Debug << d_myname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl );
  d_msgid = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attributes );
}



void LdapBackend::lookup_tree( const QType &qtype, const DNSName &qname, DNSPacket *dnspkt, int zoneid )
{
  string filter, attr, qesc, dn;
  const char** attributes = ldap_attrany + 1;   // skip associatedDomain
  const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", NULL };
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

  DLOG( g_log << Logger::Debug << d_myname << " Search = basedn: " << dn + getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl );
  d_msgid = d_pldap->search( dn + getArg( "basedn" ), LDAP_SCOPE_BASE, filter, attributes );
}


inline bool LdapBackend::prepare()
{
  d_adomains.clear();
  d_ttl = d_default_ttl;
  d_last_modified = 0;

  if( d_result.count( "dNSTTL" ) && !d_result["dNSTTL"].empty() )
  {
    char* endptr;

    d_ttl = (uint32_t) strtol( d_result["dNSTTL"][0].c_str(), &endptr, 10 );
    if( *endptr != '\0' )
    {
      g_log << Logger::Warning << d_myname << " Invalid time to live for " << d_qname << ": " << d_result["dNSTTL"][0] << endl;
      d_ttl = d_default_ttl;
    }
    d_result.erase( "dNSTTL" );
  }

  if( d_result.count( "modifyTimestamp" ) && !d_result["modifyTimestamp"].empty() )
  {
    if( ( d_last_modified = str2tstamp( d_result["modifyTimestamp"][0] ) ) == 0 )
    {
      g_log << Logger::Warning << d_myname << " Invalid modifyTimestamp for " << d_qname << ": " << d_result["modifyTimestamp"][0] << endl;
    }
    d_result.erase( "modifyTimestamp" );
  }

  if( !(this->*d_prepare_fcnt)() )
  {
    return false;
  }

  d_adomain = d_adomains.begin();
  d_attribute = d_result.begin();
  d_value = d_attribute->second.begin();

  return true;
}



inline bool LdapBackend::prepare_simple()
{
  if( !d_axfrqlen )   // request was a normal lookup()
  {
    d_adomains.push_back( d_qname );
  }
  else   // request was a list() for AXFR
  {
    if( d_result.count( "associatedDomain" ) )
    {
      for(auto i = d_result["associatedDomain"].begin(); i != d_result["associatedDomain"].end(); i++ ) {
        if( i->size() >= d_axfrqlen && i->substr( i->size() - d_axfrqlen, d_axfrqlen ) == d_qname.toStringRootDot() /* ugh */ ) {
          d_adomains.push_back( DNSName(*i) );
        }
      }
      d_result.erase( "associatedDomain" );
    }
  }

  return true;
}



inline bool LdapBackend::prepare_strict()
{
  if( !d_axfrqlen )   // request was a normal lookup()
  {
    d_adomains.push_back( d_qname );
    if( d_result.count( "associatedDomain" ) )
    {
      d_result["PTRRecord"] = d_result["associatedDomain"];
      d_result.erase( "associatedDomain" );
    }
  }
  else   // request was a list() for AXFR
  {
    if( d_result.count( "associatedDomain" ) )
    {
      for(auto i = d_result["associatedDomain"].begin(); i != d_result["associatedDomain"].end(); i++ ) {
        if( i->size() >= d_axfrqlen && i->substr( i->size() - d_axfrqlen, d_axfrqlen ) == d_qname.toStringRootDot() /* ugh */ ) {
          d_adomains.push_back( DNSName(*i) );
        }
      }
      d_result.erase( "associatedDomain" );
    }
  }

  return true;
}



bool LdapBackend::get( DNSResourceRecord &rr )
{
  QType qt;
  vector<string> parts;
  string attrname, qstr;


  try
  {
    do
    {
      while( d_adomain != d_adomains.end() )
      {
        while( d_attribute != d_result.end() )
        {
          attrname = d_attribute->first;
          qstr = attrname.substr( 0, attrname.length() - 6 );   // extract qtype string from ldap attribute name
          qt = const_cast<char*>(toUpper( qstr ).c_str());

          while( d_value != d_attribute->second.end() )
          {
            if(d_qtype != qt && d_qtype != QType::ANY) {
              d_value++;
              continue;
            }


            rr.qtype = qt;
            rr.qname = *d_adomain;
            rr.ttl = d_ttl;
            rr.last_modified = d_last_modified;
            rr.content = *d_value;
            d_value++;

            DLOG( g_log << Logger::Debug << d_myname << " Record = qname: " << rr.qname << ", qtype: " << (rr.qtype).getName() << ", ttl: " << rr.ttl << ", content: " << rr.content << endl );
            return true;
          }

          d_attribute++;
          d_value = d_attribute->second.begin();
        }
        d_adomain++;
        d_attribute = d_result.begin();
        d_value = d_attribute->second.begin();
      }
    }
    while( d_pldap->getSearchEntry( d_msgid, d_result, d_getdn ) && prepare() );

  }
  catch( LDAPTimeout &lt )
  {
    g_log << Logger::Warning << d_myname << " Search failed: " << lt.what() << endl;
    throw DBException( "LDAP server timeout" );
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Search failed: " << le.what() << endl;
    throw PDNSException( "LDAP server unreachable" );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    g_log << Logger::Error << d_myname << " Caught STL exception for " << d_qname << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }

  return false;
}
 
 
 
void LdapBackend::getUpdatedMasters( vector<DomainInfo>* domains )
{
  string filter;
  int msgid=0;
  PowerLDAP::sentry_t result;
  const char* attronly[] = {
    "associatedDomain",
    NULL
  };

  try
  {
    // First get all domains on which we are master.
    filter = strbind( ":target:", "&(SOARecord=*)(PdnsDomainId=*)", getArg( "filter-axfr" ) );
    msgid = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
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
      this->getUpdatedMasters( domains );
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

  while( d_pldap->getSearchEntry( msgid, result ) ) {
    if( !result.count( "associatedDomain" ) || result["associatedDomain"].empty() )
      continue;

    DomainInfo di;
    if ( !getDomainInfo( DNSName( result["associatedDomain"][0] ), di ) )
      continue;

    if( di.notified_serial < di.serial )
      domains->push_back( di );
  }
}



void LdapBackend::setNotified( uint32_t id, uint32_t serial )
{
  string filter;
  int msgid;
  PowerLDAP::sresult_t results;
  PowerLDAP::sentry_t entry;
  const char* attronly[] = { "associatedDomain", NULL };

  try
  {
    // Try to find the notified domain
    filter = strbind( ":target:", "PdnsDomainId=" + std::to_string( id ), getArg( "filter-axfr" ) );
    msgid = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
    d_pldap->getSearchResults( msgid, results, true );
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
      this->setNotified( id, serial );
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

  if ( results.empty() )
    throw PDNSException( "No results found when trying to update domain notified_serial for ID " + std::to_string( id ) );

  entry = results.front();
  string dn = entry["dn"][0];
  string serialStr = std::to_string( serial );
  LDAPMod *mods[2];
  LDAPMod mod;
  char *vals[2];

  mod.mod_op = LDAP_MOD_REPLACE;
  mod.mod_type = (char*)"PdnsDomainNotifiedSerial";
  vals[0] = const_cast<char*>( serialStr.c_str() );
  vals[1] = NULL;
  mod.mod_values = vals;

  mods[0] = &mod;
  mods[1] = NULL;

  try
  {
    d_pldap->modify( dn, mods );
  }
  catch( LDAPNoConnection &lnc )
  {
    g_log << Logger::Warning << d_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->setNotified( id, serial );
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
    d_msgid = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
    d_pldap->getSearchEntry( d_msgid, result );
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
      for(const auto& m : result["PdnsDomainMaster"])
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





class LdapFactory : public BackendFactory
{
  public:

    LdapFactory() : BackendFactory( "ldap" ) {}

    void declareArguments( const string &suffix="" )
    {
      declare( suffix, "host", "One or more LDAP server with ports or LDAP URIs (separated by spaces)","ldap://127.0.0.1:389/" );
      declare( suffix, "starttls", "Use TLS to encrypt connection (unused for LDAP URIs)", "no" );
      declare( suffix, "basedn", "Search root in ldap tree (must be set)","" );
      declare( suffix, "basedn-axfr-override", "Override base dn for AXFR subtree search", "no" );
      declare( suffix, "bindmethod", "Bind method to use (simple or gssapi)", "simple" );
      declare( suffix, "binddn", "User dn for non anonymous binds","" );
      declare( suffix, "secret", "User password for non anonymous binds", "" );
      declare( suffix, "krb5-keytab", "The keytab to use for GSSAPI authentication", "" );
      declare( suffix, "krb5-ccache", "The credentials cache used for GSSAPI authentication", "" );
      declare( suffix, "timeout", "Seconds before connecting to server fails", "5" );
      declare( suffix, "method", "How to search entries (simple, strict or tree)", "simple" );
      declare( suffix, "filter-axfr", "LDAP filter for limiting AXFR results", "(:target:)" );
      declare( suffix, "filter-lookup", "LDAP filter for limiting IP or name lookups", "(:target:)" );
      declare( suffix, "disable-ptrrecord", "Deprecated, use ldap-method=strict instead", "no" );
      declare( suffix, "reconnect-attempts", "Number of attempts to re-establish a lost LDAP connection", "5" );
    }


    DNSBackend* make( const string &suffix="" )
    {
      return new LdapBackend( suffix );
    }
};





class LdapLoader
{
   LdapFactory factory;

  public:

   LdapLoader()
   {
     BackendMakers().report( &factory );
     g_log << Logger::Info << "[ldapbackend] This is the ldap backend version " VERSION
#ifndef REPRODUCIBLE
       << " (" __DATE__ " " __TIME__ ")"
#endif
       << " reporting" << endl;
   }
};


static LdapLoader ldaploader;
