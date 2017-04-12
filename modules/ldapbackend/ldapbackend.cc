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
    m_msgid = 0;
    m_qname.clear();
    m_pldap = NULL;
    m_authenticator = NULL;
    m_qlog = arg().mustDo( "query-logging" );
    m_default_ttl = arg().asNum( "default-ttl" );
    m_myname = "[LdapBackend]";

    setArgPrefix( "ldap" + suffix );

    m_dnssec = mustDo( "dnssec" );
    if ( m_dnssec ) {
      m_metadata_searchdn = getArg( "metadata-searchdn" );
      if ( m_metadata_searchdn.empty() )
        throw( PDNSException( "Please set 'ldap-metadata-searchdn' to use DNSSEC" ) );
    }

    m_getdn = false;
    m_reconnect_attempts = getArgAsNum( "reconnect-attempts" );
    m_list_fcnt = &LdapBackend::list_simple;
    m_lookup_fcnt = &LdapBackend::lookup_simple;

    if( getArg( "method" ) == "tree" )
    {
      m_lookup_fcnt = &LdapBackend::lookup_tree;
    }

    if( getArg( "method" ) == "strict" || mustDo( "disable-ptrrecord" ) )
    {
      m_list_fcnt = &LdapBackend::list_strict;
      m_lookup_fcnt = &LdapBackend::lookup_strict;
    }

    stringtok( hosts, getArg( "host" ), ", " );
    idx = ldap_host_index++ % hosts.size();
    hoststr = hosts[idx];

    for( i = 1; i < hosts.size(); i++ )
    {
      hoststr += " " + hosts[ ( idx + i ) % hosts.size() ];
    }

    L << Logger::Info << m_myname << " LDAP servers = " << hoststr << endl;

    m_pldap = new PowerLDAP( hoststr.c_str(), LDAP_PORT, mustDo( "starttls" ) );
    m_pldap->setOption( LDAP_OPT_DEREF, LDAP_DEREF_ALWAYS );

    string bindmethod = getArg( "bindmethod" );
    if ( bindmethod == "gssapi" ) {
      setenv( "KRB5CCNAME", getArg( "krb5-ccache" ).c_str(), 1 );
      m_authenticator = new LdapGssapiAuthenticator( getArg( "krb5-keytab" ), getArg( "krb5-ccache" ), getArgAsNum( "timeout" ) );
    }
    else {
      m_authenticator = new LdapSimpleAuthenticator( getArg( "binddn" ), getArg( "secret" ), getArgAsNum( "timeout" ) );
    }
    m_pldap->bind( m_authenticator );

    L << Logger::Notice << m_myname << " Ldap connection succeeded" << endl;
    return;
  }
  catch( LDAPTimeout &lt )
  {
    L << Logger::Error << m_myname << " Ldap connection to server failed because of timeout" << endl;
  }
  catch( LDAPException &le )
  {
    L << Logger::Error << m_myname << " Ldap connection to server failed: " << le.what() << endl;
  }
  catch( std::exception &e )
  {
    L << Logger::Error << m_myname << " Caught STL exception: " << e.what() << endl;
  }

  if( m_pldap != NULL ) { delete( m_pldap ); }
  throw( PDNSException( "Unable to connect to ldap server" ) );
}



LdapBackend::~LdapBackend()
{
  delete( m_pldap );
  delete( m_authenticator );
  L << Logger::Notice << m_myname << " Ldap connection closed" << endl;
}



bool LdapBackend::reconnect()
{
  int attempts = m_reconnect_attempts;
  bool connected = false;
  while ( !connected && attempts > 0 ) {
    L << Logger::Debug << m_myname << " Reconnection attempts left: " << attempts << endl;
    connected = m_pldap->connect();
    if ( !connected )
      Utility::usleep( 250 );
    --attempts;
  }

  if ( connected )
    m_pldap->bind( m_authenticator );

  return connected;
}


void LdapBackend::extract_common_attributes( DNSResult &result ) {
  if ( m_result.count( "dNSTTL" ) && !m_result["dNSTTL"].empty() ) {
    char *endptr;
    uint32_t ttl = (uint32_t) strtol( m_result["dNSTTL"][0].c_str(), &endptr, 10 );

    if ( *endptr != '\0' ) {
      // NOTE: this will not give the entry for which the TTL was off.
      // TODO: improve this.
      //   - Check how m_getdn is used, because if it's never false then we
      //     might as well use it.
      L << Logger::Warning << m_myname << " Invalid time to live for " << m_qname << ": " << m_result["dNSTTL"][0] << endl;
    }
    else {
      result.ttl = ttl;
    }

    // We have to erase the attribute, otherwise this will mess up the records retrieval later.
    m_result.erase( "dNSTTL" );
  }

  if ( m_result.count( "modifyTimestamp" ) && !m_result["modifyTimestamp"].empty() ) {
    time_t tstamp = 0;
    if ( ( tstamp = str2tstamp( m_result["modifyTimestamp"][0] ) ) == 0 ) {
      // Same note as above, we don't know which entry failed here
      L << Logger::Warning << m_myname << " Invalid modifyTimestamp for " << m_qname << ": " << m_result["modifyTimestamp"][0] << endl;
    }
    else {
      result.lastmod = tstamp;
    }

    // Here too we have to erase this attribute.
    m_result.erase( "modifyTimestamp" );
  }

  if ( m_result.count( "PdnsDomainId" ) && !m_result["PdnsDomainId"].empty() ) {
    result.domain_id = pdns_stou( m_result["PdnsDomainId"][0] );
  }
}


void LdapBackend::extract_entry_results( const DNSName& domain, const DNSResult& result_template, QType qtype ) {
  std:: string attrname, qstr;
  QType qt;

  for ( auto attribute : m_result ) {
    // Find if we're dealing with a record attribute
    if ( attribute.first.length() > 6 && attribute.first.compare( attribute.first.length() - 6, 6, "Record" ) == 0 ) {
      attrname = attribute.first;
      // extract qtype string from ldap attribute name by removing the 'Record' suffix.
      qstr = attrname.substr( 0, attrname.length() - 6 );
      qt = toUpper( qstr );

      for ( auto value : attribute.second ) {
        if(qtype != qt && qtype != QType::ANY) {
          continue;
        }

        DNSResult local_result = result_template;
        local_result.qtype = qt;
        local_result.qname = domain;
        local_result.value = value;
        local_result.auth = true;

        // Now let's see if we have some PDNS record data

        // TTL
        if ( m_result.count( "PdnsRecordTTL" ) && !m_result["PdnsRecordTTL"].empty() ) {
          for ( auto rdata : m_result["PdnsRecordTTL"] ) {
            std::string qtype;
            std::size_t pos = rdata.find_first_of( '|', 0 );
            if ( pos == std::string::npos )
              continue;

            qtype = rdata.substr( 0, pos );
            if ( qtype != QType( local_result.qtype ).getName() )
              continue;

            local_result.ttl = pdns_stou( rdata.substr( pos + 1 ) );
          }
        }

        // Not authoritative
        if ( m_result.count( "PdnsRecordNoAuth" ) && !m_result["PdnsRecordNoAuth"].empty() ) {
          for ( auto rdata : m_result["PdnsRecordNoAuth"] ) {
            if ( rdata == QType( local_result.qtype ).getName() )
              local_result.auth = false;
          }
        }

        // Ordername
        if ( m_result.count( "PdnsRecordOrdername" ) && !m_result["PdnsRecordOrdername"].empty() ) {
          std::string defaultOrdername;

          for ( auto rdata : m_result["PdnsRecordOrdername"] ) {
            std::string qtype;
            std::size_t pos = rdata.find_first_of( '|', 0 );
            if ( pos == std::string::npos ) {
              // This is the default ordername for all records in this entry
              defaultOrdername = rdata;
              continue;
            }

            qtype = rdata.substr( 0, pos );
            if ( qtype != QType( local_result.qtype ).getName() )
              continue;

            local_result.ordername = rdata.substr( pos + 1 );
          }

          if ( local_result.ordername.empty() && !defaultOrdername.empty() )
            local_result.ordername = defaultOrdername;
        }

        m_results_cache.push_back( local_result );
      }
    }
  }
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
      declare( suffix, "lookup-zone-rebase", "Whether or not to search for a zone record under the zone entry", "no" );
      // DNSSEC related settings
      declare( suffix, "dnssec", "Enable DNSSEC lookups in the backend", "no" );
      declare( suffix, "metadata-searchdn", "The DN under which the metadata for a given domain can be found", "" );
      declare( suffix, "metadata-searchfilter", "The filter that will return the domain DN for the metadata searches", "(&(objectClass=organizationalUnit)(ou=:domain:))" );
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
     L << Logger::Info << "[ldapbackend] This is the ldap backend version " VERSION
#ifndef REPRODUCIBLE
       << " (" __DATE__ " " __TIME__ ")"
#endif
       << " reporting" << endl;
   }
};


static LdapLoader ldaploader;
