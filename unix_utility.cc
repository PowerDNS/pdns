/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2005 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "utility.hh"
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h> 
#include "ahuexception.hh"
#include "logger.hh"
#include "misc.hh"
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#ifdef NEED_INET_NTOP_PROTO
extern "C" {
const char *inet_ntop(int af, const void *src, char *dst, size_t cnt);
}
#endif


using namespace std;

// Closes a socket.
int Utility::closesocket( Utility::sock_t socket )
{
  int ret=::close(socket);
  if(ret < 0)
    throw AhuException("Error closing socket: "+stringerror());
  return ret;
}

bool Utility::setNonBlocking(sock_t sock)
{
  int flags=fcntl(sock,F_GETFL,0);    
  if(flags<0 || fcntl(sock, F_SETFL,flags|O_NONBLOCK) <0)
    return false;
  return true;
}

bool Utility::setBlocking(sock_t sock)
{
  int flags=fcntl(sock,F_GETFL,0);    
  if(flags<0 || fcntl(sock, F_SETFL,flags&(~O_NONBLOCK)) <0)
    return false;
  return true;
}

const char *Utility::inet_ntop(int af, const char *src, char *dst, size_t size)
{
  return ::inet_ntop(af,src,dst,size);
}

unsigned int Utility::sleep(unsigned int sec)
{
  return ::sleep(sec);
}

void Utility::usleep(unsigned long usec)
{
  ::usleep(usec);
}


// Drops the program's privileges.
void Utility::dropPrivs( int uid, int gid )
{
  if(gid) {
    if(setgid(gid)<0) {
      theL()<<Logger::Error<<"Unable to set effective group id to "<<gid<<": "<<stringerror()<<endl;
      exit(1);
    }
    else
      theL()<<Logger::Error<<"Set effective group id to "<<gid<<endl;

  }

  if(uid) {
    if(setuid(uid)<0) {
      theL()<<Logger::Error<<"Unable to set effective user id to "<<uid<<":  "<<stringerror()<<endl;
      exit(1);
    }
    else
      theL()<<Logger::Error<<"Set effective user id to "<<uid<<endl;
  }
}


// Returns the current process id.
Utility::pid_t Utility::getpid( void )
{
  return ::getpid();
}


// Returns the current time.
int Utility::gettimeofday( struct timeval *tv, void *tz )
{
  return ::gettimeofday(tv,0);
}


// Converts an address from dot and numbers format to binary data.
int Utility::inet_aton( const char *cp, struct in_addr *inp )
{
  return ::inet_aton(cp,inp);

}


// Converts an address from presentation format to network format.
int Utility::inet_pton( int af, const char *src, void *dst )
{
  return ::inet_pton(af, src, dst);
}

// Retrieves a gid using a groupname.
int Utility::makeGidNumeric(const string &group)
{
  int newgid;
  if(!(newgid=atoi(group.c_str()))) {
    struct group *gr=getgrnam(group.c_str());
    if(!gr) {
      theL()<<Logger::Error<<"Unable to look up gid of group '"<<group<<"': "<<strerror(errno)<<endl;
      exit(1);
    }
    newgid=gr->gr_gid;
  }
  return newgid;
}


// Retrieves an uid using a username.
int Utility::makeUidNumeric(const string &username)
{
  int newuid;
  if(!(newuid=atoi(username.c_str()))) {
    struct passwd *pw=getpwnam(username.c_str());
    if(!pw) {
      theL()<<Logger::Error<<"Unable to look up uid of user '"<<username<<"': "<<strerror(errno)<<endl;
      exit(1);
    }
    newuid=pw->pw_uid;
  }
  return newuid;
}


// Returns a random number.
long int Utility::random( void )
{
  return rand();
}

// Sets the random seed.
void Utility::srandom( unsigned int seed )
{
  ::srandom(seed);
}

// Compares two string, ignoring the case.
int Utility::strcasecmp( const char *s1, const char *s2 )
{
  return ::strcasecmp( s1, s2 );
}


// Writes a vector.
int Utility::writev(int socket, const iovec *vector, size_t count )
{
  return ::writev(socket,vector,count);
}

