#include <map>
#include <string>
#include <vector>
#include <exception>
#include <stdexcept>
#include <lber.h>
#include <ldap.h>


#ifndef POWERLDAP_HH
#define POWERLDAP_HH

using std::map;
using std::string;
using std::vector;


extern int errno;



class LDAPException : public std::runtime_error
{
public:
	explicit LDAPException( const string &str ) : std::runtime_error( str ) {}
};


class LDAPTimeout : public LDAPException
{
public:
	explicit LDAPTimeout() : LDAPException( "Timeout" ) {}
};


class PowerLDAP
{
	LDAP* d_ld;

	const string getError( int rc = -1 );
	int waitResult( int msgid = LDAP_RES_ANY, int timeout = 0, LDAPMessage** result = NULL );

public:
	typedef map<string, vector<string> > sentry_t;
	typedef vector<sentry_t> sresult_t;

	PowerLDAP( const string& host = "127.0.0.1", u_int16_t port = LDAP_PORT, bool tls = false );
	~PowerLDAP();

	void getOption( int option, int* value );
	void setOption( int option, int value );

	void simpleBind( const string& ldapbinddn = "", const string& ldapsecret = "" );
	int search( const string& base, int scope, const string& filter, const char** attr = 0 );

	bool getSearchEntry( int msgid, sentry_t& entry, bool dn = false, int timeout = 5 );
	void getSearchResults( int msgid, sresult_t& result, bool dn = false, int timeout = 5 );

	static const string escape( const string& tobe );
};

#endif
