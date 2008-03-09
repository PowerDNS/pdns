#include "powerldap.hh"
#include <pdns/misc.hh>
#include <sys/time.h>



PowerLDAP::PowerLDAP( const string& hosts, uint16_t port, bool tls )
{
	int err;

#ifdef HAVE_LDAP_INITIALIZE
	if( ( err = ldap_initialize( &d_ld, hosts.c_str() ) ) != LDAP_SUCCESS )
	{
		string ldapuris;
		vector<string> uris;
		stringtok( uris, hosts );

		for( size_t i = 0; i < uris.size(); i++ )
		{
			ldapuris += " ldap://" + uris[i];
		}

		if( ( err = ldap_initialize( &d_ld, ldapuris.c_str() ) ) != LDAP_SUCCESS )
		{
				throw LDAPException( "Error initializing LDAP connection to '" + ldapuris + ": " + getError( err ) );
		}
	}
#else
	if( ( d_ld = ldap_init( hosts.c_str(), port ) ) == NULL )
	{
		throw LDAPException( "Error initializing LDAP connection to '" + hosts + "': " + string( strerror( errno ) ) );
	}
#endif

	int protocol = LDAP_VERSION3;
	if( ldap_set_option( d_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol ) != LDAP_OPT_SUCCESS )
	{
		protocol = LDAP_VERSION2;
		if( ldap_set_option( d_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol ) != LDAP_OPT_SUCCESS )
		{
			ldap_unbind_ext( d_ld, NULL, NULL );
			throw LDAPException( "Couldn't set protocol version to LDAPv3 or LDAPv2" );
		}
	}

	if( tls && ( err = ldap_start_tls_s( d_ld, NULL, NULL ) ) != LDAP_SUCCESS )
	{
		ldap_unbind_ext( d_ld, NULL, NULL );
		throw LDAPException( "Couldn't perform STARTTLS: " + getError( err ) );
	}
}


PowerLDAP::~PowerLDAP()
{
	ldap_unbind_ext( d_ld, NULL, NULL );
}


void PowerLDAP::setOption( int option, int value )
{
	if( ldap_set_option( d_ld, option, (void*) &value ) != LDAP_OPT_SUCCESS )
	{
		throw( LDAPException( "Unable to set option" ) );
	}
}


void PowerLDAP::getOption( int option, int *value )
{
	if( ldap_get_option( d_ld, option, (void*) value ) != LDAP_OPT_SUCCESS )
	{
		throw( LDAPException( "Unable to get option" ) );
	}
}


void PowerLDAP::bind( const string& ldapbinddn, const string& ldapsecret, int method, int timeout )
{
	int msgid;

#ifdef HAVE_LDAP_SASL_BIND
	int rc;
	struct berval passwd;

	passwd.bv_val = (char *)ldapsecret.c_str();
	passwd.bv_len = strlen( passwd.bv_val );

	if( ( rc = ldap_sasl_bind( d_ld, ldapbinddn.c_str(), LDAP_SASL_SIMPLE, &passwd, NULL, NULL, &msgid ) ) != LDAP_SUCCESS )
	{
		throw LDAPException( "Failed to bind to LDAP server: " + getError( rc ) );
	}
#else
	if( ( msgid = ldap_bind( d_ld, ldapbinddn.c_str(), ldapsecret.c_str(), method ) ) == -1 )
	{
		throw LDAPException( "Failed to bind to LDAP server: " + getError( msgid ) );
	}
#endif

	waitResult( msgid, timeout, NULL );
}


/**
 * Depricated, use PowerLDAP::bind() instead
 */

void PowerLDAP::simpleBind( const string& ldapbinddn, const string& ldapsecret )
{
	this->bind( ldapbinddn, ldapsecret, LDAP_AUTH_SIMPLE, 30 );
}


int PowerLDAP::search( const string& base, int scope, const string& filter, const char** attr )
{
	int msgid, rc;

	if( ( rc = ldap_search_ext( d_ld, base.c_str(), scope, filter.c_str(), const_cast<char**> (attr), 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &msgid ) ) != LDAP_SUCCESS )
	{
		throw LDAPException( "Starting LDAP search: " + getError( rc ) );
	}

	return msgid;
}


/**
 * Function waits for a result, returns its type and optionally stores the result.
 * If the result is returned, the caller is responsible for freeing it with
 * ldap_msgfree!
 */

int PowerLDAP::waitResult( int msgid, int timeout, LDAPMessage** result )
{
	struct timeval tv;
	LDAPMessage* res;


	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	int rc = ldap_result( d_ld, msgid, LDAP_MSG_ONE, &tv, &res );

	switch( rc )
	{
		case -1:
			throw LDAPException( "Error waiting for LDAP result: " + getError() );
		case 0:
			throw LDAPTimeout();
	}

	if( result == NULL )
	{
		ldap_msgfree( res );
		return rc;
	}

	*result = res;
	return rc;
}


bool PowerLDAP::getSearchEntry( int msgid, sentry_t& entry, bool dn, int timeout )
{
	int i;
	char* attr;
	BerElement* ber;
	struct berval** berval;
	vector<string> values;
	LDAPMessage* result;
	LDAPMessage* object;


	if( ( i = waitResult( msgid, timeout, &result ) ) == LDAP_RES_SEARCH_RESULT )
	{
		ldap_msgfree( result );
		return false;
	}

	if( i != LDAP_RES_SEARCH_ENTRY )
	{
		ldap_msgfree( result );
		throw LDAPException( "Search returned an unexpected result" );
	}

	if( ( object = ldap_first_entry( d_ld, result ) ) == NULL )
	{
		ldap_msgfree( result );
		throw LDAPException( "Couldn't get first result entry: " + getError() );
	}

	entry.clear();

	if( dn )
	{
		attr = ldap_get_dn( d_ld, object );
		values.push_back( string( attr ) );
		ldap_memfree( attr );
		entry["dn"] = values;
	}

	if( ( attr = ldap_first_attribute( d_ld, object, &ber ) ) != NULL )
	{
		do
		{
			if( ( berval = ldap_get_values_len( d_ld, object, attr ) ) != NULL )
			{
				values.clear();
				for( i = 0; i < ldap_count_values_len( berval ); i++ )
				{
					values.push_back( berval[i]->bv_val );   // use berval[i]->bv_len for non string values?
				}

				entry[attr] = values;
				ldap_value_free_len( berval );
			}
			ldap_memfree( attr );
		}
		while( ( attr = ldap_next_attribute( d_ld, object, ber ) ) != NULL );

		ber_free( ber, 0 );
	}

	ldap_msgfree( result );
	return true;
}


void PowerLDAP::getSearchResults( int msgid, sresult_t& result, bool dn, int timeout )
{
	sentry_t entry;

	result.clear();
	while( getSearchEntry( msgid, entry, dn, timeout ) )
	{
		result.push_back( entry );
	}
}


const string PowerLDAP::getError( int rc )
{
	if( rc == -1 ) { getOption( LDAP_OPT_ERROR_NUMBER, &rc ); }

	return string( ldap_err2string( rc ) );;
}


const string PowerLDAP::escape( const string& str )
{
	string a;
	string::const_iterator i;

	for( i = str.begin(); i != str.end(); i++ )
	{
		if( *i == '*' || *i == '\\' ) {
			a += '\\';
		}
		a += *i;
	}

	return a;
}
