#include "powerldap.hh"
#include <iostream>

#include <map>
#include <vector>
#include <exception>
#include <stdexcept>
#include <string>



PowerLDAP::PowerLDAP( const string &host, u_int16_t port ) : d_host( host ), d_port( port ), d_timeout( 1 )
{
	int protocol = LDAP_VERSION3;

	if( ( d_ld = ldap_init( d_host.c_str(), d_port ) ) == NULL )
	{
		throw LDAPException( "Error initializing LDAP connection: " + string( strerror( errno ) ) );
	}

	if( ldap_set_option( d_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol ) != LDAP_OPT_SUCCESS )
	{
		protocol = LDAP_VERSION2;
		if( ldap_set_option( d_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol ) != LDAP_OPT_SUCCESS )
		{
			throw LDAPException( "Couldn't set protocol version neiher to LDAPv3 nor to LDAPv2" );
		}
	}
}


void PowerLDAP::simpleBind(const string &ldapbinddn, const string& ldapsecret)
{
  int err;
  if( ( err = ldap_simple_bind_s( d_ld, ldapbinddn.c_str(), ldapsecret.c_str() ) ) != LDAP_SUCCESS ) {
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


int PowerLDAP::search(const string& base, const string& filter, const char **attr)
{
  int msgid;

  if( ( msgid = ldap_search( d_ld, base.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(),const_cast<char **>(attr),0 ) ) == -1 )
    throw LDAPException("Starting LDAP search: "+getError());

  return msgid;
}

bool PowerLDAP::getSearchEntry(int msgid, sentry_t &entry)
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

void PowerLDAP::getSearchResults(int msgid, sresult_t &result)
{
  result.clear();
  sentry_t entry;
  while(getSearchEntry(msgid, entry))
    result.push_back(entry);
}

PowerLDAP::~PowerLDAP()
{
  ldap_unbind( d_ld );
}

const string PowerLDAP::getError(int rc)
{
  int ld_errno=rc;
  if(ld_errno==-1)
    ldap_get_option(d_ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
  return ldap_err2string(ld_errno);
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


#ifdef TESTDRIVER
int main(int argc, char **argv)
{
	int msgid, k, n;

	try
	{
		for(int k=0;k<30;++k)
		{
    		PowerLDAP ldap;
//			ldap.simpleBind("uid=ahu,ou=people,dc=snapcount","wuhwuh"); // anon
			ldap.simpleBind("",""); // anon

			for(int n=0;n<30;n++)
			{
				PowerLDAP::sresult_t ret;
				const char *attr[]={"uid","userPassword",0};

//				msgid = ldap.search("ou=people,dc=snapcount","uid=ahu",attr);
				msgid = ldap.search("o=linuxnetworks,c=de","objectclass=*",0);

				ldap.getSearchResults(msgid, ret);
//				cout<<ret.size()<<" records"<<endl;

				for(PowerLDAP::sresult_t::const_iterator h=ret.begin();h!=ret.end();++h)
				{
					for(PowerLDAP::sentry_t::const_iterator i=h->begin();i!=h->end();++i)
					{
//						cout<<"attr: "<<i->first<<endl;
						for(vector<string>::const_iterator j=i->second.begin();j!=i->second.end();++j)
						{
//							cout<<"\t"<<*j<<endl;
						}
					}
//					cout<<endl;
				}
			}
		}
	}
	catch(exception &e)
	{
		cerr<<"Fatal: "<<e.what()<<endl;
	}
}
#endif
