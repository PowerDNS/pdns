#include "powerldap.hh"



PowerLDAP::PowerLDAP( const string& host, u_int16_t port, bool tls ) : d_timeout( 5 )
{
	int protocol = LDAP_VERSION3;

	if( ( d_ld = ldap_init( host.c_str(), port ) ) == NULL )
	{
		throw LDAPException( "Error initializing LDAP connection: " + string( strerror( errno ) ) );
	}

	if( ldap_set_option( d_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol ) != LDAP_OPT_SUCCESS )
	{
		protocol = LDAP_VERSION2;
		if( ldap_set_option( d_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol ) != LDAP_OPT_SUCCESS )
		{
			ldap_unbind( d_ld );
			throw LDAPException( "Couldn't set protocol version to LDAPv3 or LDAPv2" );
		}
	}

	if( tls && ldap_start_tls_s( d_ld, NULL, NULL ) != LDAP_SUCCESS )
	{
		ldap_unbind( d_ld );
		throw( LDAPException( "Couldn't perform STARTTLS" ) );
	}
}


PowerLDAP::~PowerLDAP()
{
	ldap_unbind( d_ld );
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


void PowerLDAP::simpleBind( const string& ldapbinddn, const string& ldapsecret )
{
	int err;
	if( ( err = ldap_simple_bind_s( d_ld, ldapbinddn.c_str(), ldapsecret.c_str() ) ) != LDAP_SUCCESS )
	{
		throw LDAPException( "Failed to bind to LDAP server: " + getError( err ) );
	}
}


/** Function waits for a result, returns its type and optionally stores the result
    in retresult. If returned via retresult, the caller is responsible for freeing
    it with ldap_msgfree! */
int PowerLDAP::waitResult(int msgid,LDAPMessage **retresult)
{
  struct timeval tv;
  tv.tv_sec=d_timeout;
  tv.tv_usec=0;
  LDAPMessage *result;

  int rc=ldap_result(d_ld,msgid,0,&tv,&result);
  if(rc==-1)
    throw LDAPException("Error waiting for LDAP result: "+getError());
  if(!rc)
    throw LDAPTimeout();
  
  if(retresult)
    *retresult=result;
  
  if(rc==LDAP_RES_SEARCH_ENTRY || LDAP_RES_SEARCH_RESULT) // no error in that case
    return rc;
  
  int err;
  if((err=ldap_result2error(d_ld, result,0))!=LDAP_SUCCESS) {
    ldap_msgfree(result);
    throw LDAPException("LDAP Server reported error: "+getError(err));
  }
  
  if(!retresult)
    ldap_msgfree(result);
  
  return rc;
}


int PowerLDAP::search(const string& base, int scope, const string& filter, const char **attr)
{
  int msgid;

  if( ( msgid = ldap_search( d_ld, base.c_str(), scope, filter.c_str(),const_cast<char **>(attr),0 ) ) == -1 )
    throw LDAPException("Starting LDAP search: "+getError());

  return msgid;
}

bool PowerLDAP::getSearchEntry(int msgid, sentry_t &entry, bool withdn)
{
  entry.clear();
  int rc=waitResult(msgid,&d_searchresult);

  if(rc==LDAP_RES_SEARCH_RESULT) {
    ldap_msgfree(d_searchresult);
    return false;
  }

  if(rc!=LDAP_RES_SEARCH_ENTRY)
    throw LDAPException("Search returned non-answer result");

  d_searchentry=ldap_first_entry(d_ld, d_searchresult);

  // we now have an entry in d_searchentry

  if( withdn == true )
  {
    vector<string> dnresult;
    char* dn = ldap_get_dn( d_ld, d_searchentry );
    dnresult.push_back( dn );
    ldap_memfree( dn );
    entry["dn"] = dnresult;
  }

  BerElement *ber;

  for(char *attr = ldap_first_attribute( d_ld, d_searchresult, &ber ); attr ; attr=ldap_next_attribute(d_ld, d_searchresult, ber)) {
    struct berval **bvals=ldap_get_values_len(d_ld,d_searchentry,attr);
    vector<string> rvalues;
    if(bvals) {
      for(struct berval** bval=bvals;*bval;++bval)
        rvalues.push_back((*bval)->bv_val);
    }
    entry[attr]=rvalues;
    ldap_value_free_len(bvals);
    ldap_memfree(attr);
  }

  ber_free(ber,0);
  ldap_msgfree(d_searchresult);
  
  return true;
}

void PowerLDAP::getSearchResults(int msgid, sresult_t &result, bool withdn)
{
  result.clear();
  sentry_t entry;
  while(getSearchEntry(msgid, entry, withdn))
    result.push_back(entry);
}


const string PowerLDAP::getError( int rc )
{
	int ld_errno = rc;

	if( ld_errno == -1 )
	{
		getOption( LDAP_OPT_ERROR_NUMBER, &ld_errno );
	}

	return ldap_err2string( ld_errno );
}


const string PowerLDAP::escape(const string &name)
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i) {
    if(*i=='*' || *i=='\\')
      a+='\\';
    a+=*i;
  }
  return a;
}
