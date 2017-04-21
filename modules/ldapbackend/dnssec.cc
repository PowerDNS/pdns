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


bool LdapBackend::doesDNSSEC()
{
  return m_dnssec;
}


std::string LdapBackend::getDomainMetadataDN( const DNSName &name )
{
  std::string dn;
  std::string filter = strbind( ":domain:", m_pldap->escape( name.toStringRootDot() ), getArg( "metadata-searchfilter" ) );
  const char* attributes[] = { "objectClass", NULL };
  PowerLDAP::sentry_t result;

  try {
    int msgid = m_pldap->search( m_metadata_searchdn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( m_pldap->getSearchEntry( msgid, result, true ) ) {
      if ( result.count( "dn" ) && !result["dn"].empty() )
        dn = result["dn"][0];
    }

    L<<Logger::Debug<< m_myname << " getDomainMetadataDN will return " << dn << endl;
    return dn;
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
      return this->getDomainMetadataDN( name );
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
    L << Logger::Error << m_myname << " Caught STL exception searching for domain " << name << " under the metadata DN: " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}


bool LdapBackend::getDomainMetadata( const DNSName& name, const std::string& kind, std::vector<std::string>& meta )
{
  L<<Logger::Debug<< m_myname << " Getting metadata " << kind << " for domain " << name << endl;

  if ( !m_dnssec && isDnssecDomainMetadata( kind ) )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;
  std::string filter = "(&(objectClass=PdnsMetadata)(cn=" + m_pldap->escape( kind ) + "))";
  const char* attributes[] = { "PdnsMetadataValue", NULL };
  PowerLDAP::sentry_t result;

  try {
    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    // We're supposed to get just one entry
    if ( m_pldap->getSearchEntry( msgid, result, m_getdn ) ) {
      if ( result.count( "PdnsMetadataValue" ) && !result["PdnsMetadataValue"].empty() ) {
        for ( auto value : result["PdnsMetadataValue"] )
          meta.push_back( value );
      }
    }

    return true;
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
      return this->getDomainMetadata( name, kind, meta );
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
    L << Logger::Error << m_myname << " Caught STL exception retrieving metadata for domain " << name << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}


bool LdapBackend::getAllDomainMetadata( const DNSName& name, std::map<std::string, std::vector<std::string> >& meta )
{
  L<<Logger::Debug<< m_myname << " Getting all metadata for domain " << name << endl;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  std::string filter = "objectClass=PdnsMetadata";
  const char* attributes[] = { "cn", "PdnsMetadataValue", NULL };
  PowerLDAP::sentry_t result;

  try {
    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );
    meta.clear();

    while ( m_pldap->getSearchEntry( msgid, result, false ) ) {
      meta[ result["cn"][0] ] = result["PdnsMetadataValue"];
    }

    return true;
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
      return this->getAllDomainMetadata( name, meta );
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
    L << Logger::Error << m_myname << " Caught STL exception retrieving metadata for all domains" << endl;
    throw( DBException( "STL exception" ) );
  }
}


bool LdapBackend::setDomainMetadata( const DNSName& name, const std::string& kind, const std::vector<std::string>& meta )
{
  L<<Logger::Debug<< m_myname << " Setting metadata " << kind << " for domain " << name << endl;

  if ( !m_dnssec && isDnssecDomainMetadata( kind ) )
    return false;

  // We won't create the root entry here as this is left to the discretion of the LDAP admin,
  // so just bail out. Maybe throw an exception?
  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  try {
    bool ret = false;
    std::string filter = "(&(objectClass=PdnsMetadata)(cn=" + m_pldap->escape( kind ) + "))";
    const char* attributes[] = { "cn", NULL };
    PowerLDAP::sentry_t result;

    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );
    bool exists = m_pldap->getSearchEntry( msgid, result, true );

    if ( !exists ) {
      // OK, this metadata entry doesn't exist. Let's just create it, yay!
      if ( !meta.empty() ) {
        L<<Logger::Debug<< m_myname << " Creating metadata " << kind << " for domain " << name << endl;

        std::string escaped_kind = m_pldap->escape( kind );
        std::string dn = "cn=" + escaped_kind + "," + basedn;

        char* vals[meta.size() + 1];
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
        valueMod.mod_values = vals;

        LDAPMod* mods[4];
        mods[0] = &objectClassMod;
        mods[1] = &cnMod;
        mods[2] = &valueMod;
        mods[3] = NULL;

        m_pldap->add( dn, mods );
      }
      ret = true;
    }
    else {
      if ( meta.empty() ) {
        L<<Logger::Debug<< m_myname << " Deleting metadata " << kind << " for domain " << name << endl;
        m_pldap->del( result["dn"][0] );
      }
      else {
        L<<Logger::Debug<< m_myname << " Replacing metadata " << kind << " for domain " << name << endl;

        char* vals[meta.size() + 1];
        for ( int i = 0; i < meta.size(); ++i )
          vals[i] = (char*)( meta.at( i ).c_str() );
        vals[meta.size()] = NULL;

        LDAPMod mod;
        mod.mod_op = LDAP_MOD_REPLACE;
        mod.mod_type = (char*)"PdnsMetadataValue";
        mod.mod_values = vals;

        LDAPMod* mods[2];
        mods[0] = &mod;
        mods[1] = NULL;

        m_pldap->modify( result["dn"][0], mods );
      }
      ret = true;
    }

    return ret;
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
      return this->setDomainMetadata( name, kind, meta );
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
    L << Logger::Error << m_myname << " Caught STL exception setting metadata for domain " << name << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}


bool LdapBackend::getDomainKeys( const DNSName& name, unsigned int kind, std::vector<KeyData>& keys )
{
  if ( !m_dnssec )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  L<<Logger::Debug<< m_myname << " Retrieving zone keys for " << name << std::endl;

  try {
    PowerLDAP::sentry_t result;
    std::string filter = "objectClass=PdnsDomainKey";
    const char* attributes[] = {
      "PdnsKeyId",
      "PdnsKeyFlags",
      "PdnsKeyContent",
      "PdnsKeyActive",
      NULL
    };

    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    while ( m_pldap->getSearchEntry( msgid, result, false ) ) {
      KeyData kd;
      kd.id = pdns_stou( result["PdnsKeyId"][0] );
      kd.flags = pdns_stou( result["PdnsKeyFlags"][0] );
      kd.content = result["PdnsKeyContent"][0];
      if ( result.count( "PdnsKeyActive" ) )
        kd.active = true;
      else
        kd.active = false;

      L<<Logger::Debug<< m_myname << " Found key with ID " << kd.id << std::endl;
      keys.push_back( kd );
    }

    return true;
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
      return this->getDomainKeys( name, kind, keys );
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
    L << Logger::Error << m_myname << " Caught STL exception retrieving key for domain " << name << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}


bool LdapBackend::addDomainKey( const DNSName& name, const KeyData& key, int64_t& id )
{
  if ( !m_dnssec )
    return false;

  L<<Logger::Debug<< m_myname << " Adding domain key for " << name << std::endl;

  // Same as in setDomainMetadata, we don't create the required entries
  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  try {
    // Prepare all the elements first. As LDAP doesn't have the concept of transaction
    // we risk ending up with two keys with the same ID if there are insertions between
    // the moment we get the list of keys and the moment we insert. So better not dawdle
    // between those.

    LDAPMod objectClassMod;
    objectClassMod.mod_op = LDAP_MOD_ADD;
    objectClassMod.mod_type = (char*)"objectClass";
    char* objectClassValues[] = { (char*)"top", (char*)"PdnsDomainKey", NULL };
    objectClassMod.mod_values = objectClassValues;

    LDAPMod keyidMod;
    keyidMod.mod_op = LDAP_MOD_ADD;
    keyidMod.mod_type = (char*)"PdnsKeyId";

    LDAPMod keyflagsMod;
    keyflagsMod.mod_op = LDAP_MOD_ADD;
    keyflagsMod.mod_type = (char*)"PdnsKeyFlags";
    std::string keyflagsStr = std::to_string( key.flags );
    char* keyflagsValues[] = { (char*)keyflagsStr.c_str(), NULL };
    keyflagsMod.mod_values = keyflagsValues;

    LDAPMod keycontentMod;
    keycontentMod.mod_op = LDAP_MOD_ADD;
    keycontentMod.mod_type = (char*)"PdnsKeyContent";
    std::string escaped_keycontent = m_pldap->escape( key.content );
    char* keycontentValues[] = { (char*)escaped_keycontent.c_str(), NULL };
    keycontentMod.mod_values = keycontentValues;

    LDAPMod keyactiveMod;
    keyactiveMod.mod_op = LDAP_MOD_ADD;
    keyactiveMod.mod_type = (char*)"PdnsKeyActive";
    char* keyactiveValues[] = { (char*)"1", NULL };
    keyactiveMod.mod_values = keyactiveValues;

    /*
       Search for all the keys
    */
    int64_t maxId = 0;
    PowerLDAP::sentry_t keysearch_result;
    const char* keysearch_attributes[] = { "PdnsKeyId", NULL };
    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, "objectClass=PdnsDomainKey", keysearch_attributes );
    while ( m_pldap->getSearchEntry( msgid, keysearch_result, false ) ) {
      int64_t currentId = std::stoll( keysearch_result["PdnsKeyId"][0] );
      if ( currentId >= maxId )
        maxId = currentId + 1;
    }

    std::string maxIdStr = std::to_string( maxId );
    char* keyidValues[] = { (char*)maxIdStr.c_str(), NULL };
    keyidMod.mod_values = keyidValues;

    LDAPMod *mods[5];
    mods[0] = &objectClassMod;
    mods[1] = &keyidMod;
    mods[2] = &keyflagsMod;
    mods[3] = &keycontentMod;
    if ( key.active )
      mods[4] = &keyactiveMod;
    else
      mods[4] = NULL;
    mods[5] = NULL;

    std::string dn = "PdnsKeyId=" + maxIdStr + "," + basedn;
    L<<Logger::Debug<< m_myname << " Will create entry for the key at " << dn << std::endl;
    m_pldap->add( dn, mods );
    id = maxId;

    return true;
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
      return this->addDomainKey( name, key, id );
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
    L << Logger::Error << m_myname << " Caught STL exception adding key for domain " << name << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}


bool LdapBackend::activateDomainKey( const DNSName& name, unsigned int id )
{
  if ( !m_dnssec )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  L<<Logger::Debug<< m_myname << " Activating key " << id << " on domain " << name << std::endl;

  try {
    PowerLDAP::sentry_t result;
    std::string filter = "(&(objectClass=PdnsDomainKey)(PdnsKeyId=" + std::to_string( id ) + "))";
    const char* attributes[] = { "PdnsKeyActive", NULL };
    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( !m_pldap->getSearchEntry( msgid, result, true ) ) {
      L<<Logger::Warning<< m_myname << " No key with this ID found" << std::endl;
      return false;
    }

    std::string dn = result["dn"][0];

    if ( !result.count( "PdnsKeyActive" ) ) {
      LDAPMod mod;
      mod.mod_op = LDAP_MOD_ADD;
      mod.mod_type = (char*)"PdnsKeyActive";
      char* modValues[] = { (char*)"1", NULL };
      mod.mod_values = modValues;

      LDAPMod* mods[2];
      mods[0] = &mod;
      mods[1] = NULL;

      m_pldap->modify( dn, mods );
    }

    return true;
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
      return this->activateDomainKey( name, id );
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
    L << Logger::Error << m_myname << " Caught STL exception activating key for domain " << name << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}


bool LdapBackend::deactivateDomainKey( const DNSName& name, unsigned int id )
{
  if ( !m_dnssec )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  L<<Logger::Debug<< m_myname << " Deactivating key " << id << " on domain " << name << std::endl;

  try {
    PowerLDAP::sentry_t result;
    std::string filter = "(&(objectClass=PdnsDomainKey)(PdnsKeyId=" + std::to_string( id ) + "))";
    const char* attributes[] = { "PdnsKeyActive", NULL };
    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( !m_pldap->getSearchEntry( msgid, result, true ) ) {
      L<<Logger::Warning<< m_myname << " No key with this ID found" << std::endl;
      return false;
    }

    std::string dn = result["dn"][0];

    if ( result.count( "PdnsKeyActive" ) ) {
      LDAPMod mod;
      mod.mod_op = LDAP_MOD_DELETE;
      mod.mod_type = (char*)"PdnsKeyActive";

      LDAPMod* mods[2];
      mods[0] = &mod;
      mods[1] = NULL;

      m_pldap->modify( dn, mods );
    }

    return true;
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
      return this->deactivateDomainKey( name, id );
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
    L << Logger::Error << m_myname << " Caught STL exception deactivating key for domain " << name << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}


bool LdapBackend::removeDomainKey( const DNSName& name, unsigned int id )
{
  if ( !m_dnssec )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  L<<Logger::Debug<< m_myname << " Removing key " << id << " on domain " << name << std::endl;

  try {
    PowerLDAP::sentry_t result;
    std::string filter = "(&(objectClass=PdnsDomainKey)(PdnsKeyId=" + std::to_string( id ) + "))";
    const char* attributes[] = { "PdnsKeyActive", NULL };
    int msgid = m_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( !m_pldap->getSearchEntry( msgid, result, true ) ) {
      L<<Logger::Warning<< m_myname << " No key with this ID found" << std::endl;
      return true; // Eh, it's already not there, so everybody's happy, right?
    }

    std::string dn = result["dn"][0];
    m_pldap->del( dn );
    return true;
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
      return this->removeDomainKey( name, id );
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
    L << Logger::Error << m_myname << " Caught STL exception removing key for domain " << name << ": " << e.what() << endl;
    throw( DBException( "STL exception" ) );
  }
}

// vim: ts=2 sw=2 sts=2 et
