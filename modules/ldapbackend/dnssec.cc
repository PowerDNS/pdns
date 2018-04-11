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


std::string LdapBackend::getDomainMetadataDN( const DNSName &name )
{
  std::string dn;
  std::string filter = strbind( ":domain:", d_pldap->escape( name.toStringRootDot() ), getArg( "metadata-searchfilter" ) );
  const char* attributes[] = { "objectClass", NULL };
  PowerLDAP::sentry_t result;

  try {
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( d_metadata_searchdn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( search->getNext( result, true ) ) {
      if ( result.count( "dn" ) && !result["dn"].empty() )
        dn = result["dn"][0];
    }

    g_log<<Logger::Debug<< d_myname << " getDomainMetadataDN will return " << dn << endl;
    return dn;
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
      return this->getDomainMetadataDN( name );
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
    g_log << Logger::Error << d_myname << " Caught STL exception searching for domain " << name << " under the metadata DN: " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::getDomainMetadata( const DNSName& name, const std::string& kind, std::vector<std::string>& meta )
{
  g_log<<Logger::Debug<< d_myname << " Getting metadata " << kind << " for domain " << name << endl;

  if ( !d_dnssec && isDnssecDomainMetadata( kind ) )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;
  std::string filter = "(&(objectClass=PdnsMetadata)(cn=" + d_pldap->escape( kind ) + "))";
  const char* attributes[] = { "PdnsMetadataValue", NULL };
  PowerLDAP::sentry_t result;

  try {
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    // We're supposed to get just one entry
    if ( search->getNext( result, d_getdn ) ) {
      if ( result.count( "PdnsMetadataValue" ) && !result["PdnsMetadataValue"].empty() ) {
        for ( const auto& value : result["PdnsMetadataValue"] )
          meta.push_back( value );
      }
    }

    return true;
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
      return this->getDomainMetadata( name, kind, meta );
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
    g_log << Logger::Error << d_myname << " Caught STL exception retrieving metadata for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}

bool LdapBackend::getAllDomainMetadata( const DNSName& name, std::map<std::string, std::vector<std::string> >& meta )
{
  g_log<<Logger::Debug<< d_myname << " Getting all metadata for domain " << name << endl;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  std::string filter = "objectClass=PdnsMetadata";
  const char* attributes[] = { "cn", "PdnsMetadataValue", NULL };
  PowerLDAP::sentry_t result;

  try {
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );
    meta.clear();

    while ( search->getNext( result, false ) ) {
      meta[ result["cn"][0] ] = result["PdnsMetadataValue"];
    }

    return true;
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
      return this->getAllDomainMetadata( name, meta );
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
    g_log << Logger::Error << d_myname << " Caught STL exception retrieving metadata for all domains" << endl;
    throw DBException( "STL exception" );
  }
}

bool LdapBackend::setDomainMetadata( const DNSName& name, const std::string& kind, const std::vector<std::string>& meta )
{
  g_log<<Logger::Debug<< d_myname << " Setting metadata " << kind << " for domain " << name << endl;

  if ( !d_dnssec && isDnssecDomainMetadata( kind ) )
    return false;

  // We won't create the root entry here as this is left to the discretion of the LDAP admin,
  // so just bail out. Maybe throw an exception?
  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  try {
    bool ret = false;
    std::string filter = "(&(objectClass=PdnsMetadata)(cn=" + d_pldap->escape( kind ) + "))";
    const char* attributes[] = { "cn", NULL };
    PowerLDAP::sentry_t result;

    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );
    bool exists = search->getNext( result, true );

    if ( !exists ) {
      // OK, this metadata entry doesn't exist. Let's just create it, yay!
      if ( !meta.empty() ) {
        g_log<<Logger::Debug<< d_myname << " Creating metadata " << kind << " for domain " << name << endl;

        std::string escaped_kind = d_pldap->escape( kind );
        std::string dn = "cn=" + escaped_kind + "," + basedn;

        std::vector<char*> vals( meta.size() + 1 );
        for ( int i = 0; i < meta.size(); ++i )
          vals[i] = (char*)( meta.at( i ).c_str() );
        vals[meta.size()] = NULL;

        LDAPMod objectClassMod;
        objectClassMod.mod_op = LDAP_MOD_ADD;
        objectClassMod.mod_type = (char*)"objectClass";
        char* objectClassValues[] = { (char*)"top", (char*)"PdnsMetadata", NULL };
        objectClassMod.mod_values = objectClassValues;

        LDAPMod cnMod;
        cnMod.mod_op = LDAP_MOD_ADD;
        cnMod.mod_type = (char*)"cn";
        char* cnValues[] = { (char*)( escaped_kind.c_str() ), NULL };
        cnMod.mod_values = cnValues;

        LDAPMod valueMod;
        valueMod.mod_op = LDAP_MOD_ADD;
        valueMod.mod_type = (char*)"PdnsMetadataValue";
        valueMod.mod_values = vals.data();

        LDAPMod* mods[4];
        mods[0] = &objectClassMod;
        mods[1] = &cnMod;
        mods[2] = &valueMod;
        mods[3] = NULL;

        d_pldap->add( dn, mods );
      }
      ret = true;
    }
    else {
      if ( meta.empty() ) {
        g_log<<Logger::Debug<< d_myname << " Deleting metadata " << kind << " for domain " << name << endl;
        d_pldap->del( result["dn"][0] );
      }
      else {
        g_log<<Logger::Debug<< d_myname << " Replacing metadata " << kind << " for domain " << name << endl;

        std::vector<char*> vals( meta.size() + 1 );
        for ( int i = 0; i < meta.size(); ++i )
          vals[i] = (char*)( meta.at( i ).c_str() );
        vals[meta.size()] = NULL;

        LDAPMod mod;
        mod.mod_op = LDAP_MOD_REPLACE;
        mod.mod_type = (char*)"PdnsMetadataValue";
        mod.mod_values = vals.data();

        LDAPMod* mods[2];
        mods[0] = &mod;
        mods[1] = NULL;

        d_pldap->modify( result["dn"][0], mods );
      }
      ret = true;
    }

    return ret;
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
      return this->setDomainMetadata( name, kind, meta );
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
    g_log << Logger::Error << d_myname << " Caught STL exception setting metadata for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}
