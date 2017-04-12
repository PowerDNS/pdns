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


void LdapBackend::getUpdatedMasters( vector<DomainInfo>* domains )
{
  string filter;
  int msgid;
  PowerLDAP::sentry_t result;
  const char* attronly[] = {
    "associatedDomain",
    NULL
  };

  try
  {
    // First get all domains on which we are master.
    filter = strbind( ":target:", "&(SOARecord=*)(PdnsDomainId=*)", getArg( "filter-axfr" ) );
    msgid = m_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
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
      this->getUpdatedMasters( domains );
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

  while( m_pldap->getSearchEntry( msgid, result ) ) {
    if( !result.count( "associatedDomain" ) || result["associatedDomain"].empty() )
      continue;

    DomainInfo di;
    if ( !getDomainInfo( result["associatedDomain"][0], di ) )
      continue;

    di.backend = this;

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
    msgid = m_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
    m_pldap->getSearchResults( msgid, results, true );
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
      this->setNotified( id, serial );
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
    m_pldap->modify( dn, mods );
  }
  catch( LDAPNoConnection &lnc )
  {
    L << Logger::Warning << m_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->setNotified( id, serial );
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
}

// vim: ts=2 sw=2 sts=2 et
