/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2006 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

// Utility class win32 implementation.

#include "utility.hh"
#include <iostream>
#include <mmsystem.h>

// Closes a socket.
int Utility::closesocket( Utility::sock_t socket )
{
  return ::closesocket( socket );
}


// Drops the program's privileges.
void Utility::dropPrivs( int uid, int gid )
{
}


// Returns the current process id.
Utility::pid_t Utility::getpid( void )
{
  return GetCurrentProcessId();
}


// Returns a monotonic clock
int Utility::gettimeofday( struct timeval *tv, void *tz )
{
  if ( tv == NULL )
    return -1;

  DWORD ticks = timeGetTime();
  tv->tv_sec  = 86400 + static_cast< long >( ticks / 1000 );
  tv->tv_usec = static_cast< long >( ticks % 1000 );

  return 0;
}


// Converts an address from dot and numbers format to binary data.
int Utility::inet_aton( const char *cp, struct in_addr *inp )
{
  if ( cp == NULL )
    return 0;

  if (( inp->s_addr = inet_addr( cp )) == -1 )
    return 0;

  return 1;
}


// The inet_ntop() function converts an address from network format (usually a struct in_addr or some other binary form, in network byte order) to presentation format.
const char *Utility::inet_ntop( int af, const char *src, char *dst, size_t size )
{
  if ( af == AF_INET )
    return inet_ntop4( src, dst, size );
  else if ( af == AF_INET6 )
    return inet_ntop6( src, dst, size );
    
  return NULL;
}


// Converts an address from presentation format to network format.
int Utility::inet_pton( int af, const char *src, void *dst )
{
  if ( af == AF_INET )
    return inet_pton4( src, dst );
  else if ( af == AF_INET6 )
    return inet_pton6( src, dst );

  // TODO: Implement this.
  return 0;
}


// Converts an ipv4 address from www.xxx.yyy.zzz format to binary data.
int Utility::inet_pton4( const char *src, void *dst )
{
  struct in_addr tmp;

  if ( inet_aton( src, &tmp ) == -1 )
    return 0;

  memcpy( dst, &tmp, sizeof( struct in_addr ));

  return 1;
}


const char *Utility::inet_ntop4( const char *src, char *dst, size_t size )
{
  char *temp = inet_ntoa( *( reinterpret_cast< const struct in_addr * >( src )));

  if ( temp == NULL )
    return NULL;

  memcpy( dst, temp, size );

  return reinterpret_cast< const char * >( dst );
}

#define NS_IN6ADDRSZ  16
#define NS_INT16SZ    2
#define NS_INADDRSZ   4

const char *
Utility::inet_ntop6( const char *src, char *dst, size_t size )
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct { int base, len; } best, cur;
	uint16_t words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 && (best.len == 6 ||
		    (best.len == 7 && words[7] != 0x0001) ||
		    (best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		tp += sprintf(tp, "%x", words[i]);
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == 
	    (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
	  // errno = ENOSPC;
	  return (NULL);
	}
	strcpy(dst, tmp);
	return (dst);
}



/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	(1) does not touch `dst' unless it's returning 1.
 *	(2) :: in a full address is silently ignored.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */
int
Utility::inet_pton6( const char *src, void *dst )
{
	static const char xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	u_char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit;
	u_int val;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return (0);
			}
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
		    inet_pton4(curtok, tp) > 0) {
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		if (tp == endp)
			return (0);
		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, NS_IN6ADDRSZ);
	return (1);
}
#undef NS_IN6ADDRSZ
#undef NS_INT16SZ
#undef NS_INADDRSZ


// Returns a random number.
long int Utility::random( void )
{
  return rand();
}


// Retrieves a gid using a groupname.
int Utility::makeGidNumeric( const std::string & group )
{
  return 0;
}


// Retrieves an uid using a username.
int Utility::makeUidNumeric( const std::string & username )
{
  return 0;
}


// Sets the socket into blocking mode.
bool Utility::setBlocking( Utility::sock_t socket )
{
  unsigned long tmp = 0;

  if ( ioctlsocket( socket, FIONBIO, &tmp ) == SOCKET_ERROR )
    return false;

  return true;
}


// Sets the socket into non-blocking mode.
bool Utility::setNonBlocking( Utility::sock_t socket )
{
  unsigned long tmp = 1;

  if( ioctlsocket( socket, FIONBIO, &tmp ) == SOCKET_ERROR )
    return false;

  return true;
}


// Sleeps for a number of seconds.
unsigned int Utility::sleep( unsigned int seconds )
{
  Sleep( seconds * 1000 );
  return 0;
}


// Sets the random seed.
void Utility::srandom( unsigned int seed )
{
  srand( seed );
}


// Compares two string, ignoring the case.
int Utility::strcasecmp( const char *s1, const char *s2 )
{
  return strcmp( s1, s2 );
}


// Sleeps for a number of microseconds.
void Utility::usleep( unsigned long usec )
{
  Sleep( usec / 1000 );
}


// Writes a vector.
int Utility::writev( Utility::sock_t socket, const Utility::iovec *vector, size_t count )
{
  unsigned int i;
  int res;
  int nbytes = 0;

  for ( i = 0; i < count; i++ )
  {
    res = send( socket, reinterpret_cast< const char * >(  vector[ i ].iov_base ), vector[ i ].iov_len, 0 );
    if ( res == -1 )
      return -1;

    nbytes += res;
  }

  return nbytes;
}

