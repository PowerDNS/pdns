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
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>
#include <inttypes.h>
#include <errno.h>
#include <lber.h>
#include <ldap.h>




#ifndef POWERLDAP_HH
#define POWERLDAP_HH

using std::list;
using std::map;
using std::string;
using std::vector;

class LdapAuthenticator;

class PowerLDAP
{
    LDAP* d_ld;
    bool d_sort_supported;
    bool d_vlv_supported;
    string d_hosts;
    int d_port;
    bool d_tls;
  
    const string getError( int rc = -1 );
    int waitResult( int msgid = LDAP_RES_ANY, int timeout = 0, LDAPMessage** result = NULL );
    void ensureConnect();
    
  public:
    typedef map<string, vector<string> > sentry_t;
    typedef vector<sentry_t> sresult_t;
  
    class SearchResult {
        LDAP* d_ld;
        int d_msgid;
        bool d_finished;
        int d_status;
        std::string d_error;

        SearchResult( const SearchResult& other );
        SearchResult& operator=( const SearchResult& other );

      public:
	typedef std::unique_ptr<SearchResult> Ptr;

        SearchResult( int msgid, LDAP* ld );
        ~SearchResult();

        bool finished() const;
        bool successful() const;
        int status() const;
        std::string error() const;

        bool consumeAll();
        bool getNext( PowerLDAP::sentry_t& entry, bool dn = false, int timeout = 5 );
        void getAll( PowerLDAP::sresult_t& results, bool dn = false, int timeout = 5 );
    };

    PowerLDAP( const string& hosts = "ldap://127.0.0.1/", uint16_t port = LDAP_PORT, bool tls = false );
    ~PowerLDAP();
  
    bool connect();
  
    void getOption( int option, int* value );
    void setOption( int option, int value );
  
    void bind( LdapAuthenticator *authenticator );
    void bind( const string& ldapbinddn = "", const string& ldapsecret = "", int method = LDAP_AUTH_SIMPLE, int timeout = 5 );
    void simpleBind( const string& ldapbinddn = "", const string& ldapsecret = "" );
    SearchResult::Ptr search( const string& base, int scope, const string& filter, const char** attr = 0 );
    SearchResult::Ptr sorted_search( const string& base, int scope, const string& filter, const string& sort, const char** attr = 0, unsigned int limit = 0 );
    void add( const string &dn, LDAPMod *mods[] );
    void modify( const string& dn, LDAPMod *mods[], LDAPControl **scontrols = 0, LDAPControl **ccontrols = 0 );
    void del( const string& dn );
  
    bool getSearchEntry( int msgid, sentry_t& entry, bool dn = false, int timeout = 5 );
    void getSearchResults( int msgid, sresult_t& result, bool dn = false, int timeout = 5 );
  
    static const string escape( const string& tobe );
};



#endif
