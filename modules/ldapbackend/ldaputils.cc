#include "ldaputils.hh"
#include <sys/time.h>

void ldapSetOption( LDAP *conn, int option, void *value )
{
  if( ldap_set_option( conn, option, value ) != LDAP_OPT_SUCCESS )
  {
    throw LDAPException( "Unable to set option" );
  }
}

void ldapGetOption( LDAP *conn, int option, void *value )
{
  if( ldap_get_option( conn, option, value ) != LDAP_OPT_SUCCESS )
  {
    throw LDAPException( "Unable to get option" );
  }
}

std::string ldapGetError( LDAP *conn, int code )
{
  if ( code == -1 )
    ldapGetOption( conn, LDAP_OPT_ERROR_NUMBER, &code );
  return std::string( ldap_err2string( code ) );
}

int ldapWaitResult( LDAP *conn, int msgid, int timeout, LDAPMessage** result )
{
  struct timeval tv;
  LDAPMessage* res;


  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  int rc = ldap_result( conn, msgid, LDAP_MSG_ONE, &tv, &res );

  if ( rc == -1 || rc == 0 )
    return rc;

  if( result == NULL )
  {
    ldap_msgfree( res );
    return rc;
  }

  *result = res;
  return rc;
}
