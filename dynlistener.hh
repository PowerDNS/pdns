/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef PDNS_DYNLISTENER
#define PDNS_DYNLISTENER

#include <string>
#include <vector>
#include <pthread.h>
#include <sys/types.h>
#include <errno.h>
#include <iostream>
#include <sstream>

#ifndef WIN32
#include <unistd.h>
#include <sys/un.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <netinet/in.h>
#endif // WIN32

using namespace std;

class DynListener
{
public:
  DynListener(const string &pname="");
  ~DynListener();
  void go();
  void theListener();
  static void *theListenerHelper(void *p);

  typedef string g_funk_t(const vector<string> &parts, Utility::pid_t ppid); // guido!
  typedef map<string,g_funk_t *> g_funkdb_t;
  
  void registerFunc(const string &name, g_funk_t *gf);
  void registerRestFunc(g_funk_t *gf);
private:
  DynListener(const DynListener &);
  DynListener& operator=(const DynListener &); 
  void sendLine(const string &line);
  string getLine();

#ifndef WIN32
  struct sockaddr_un d_remote;
#else
  HANDLE m_pipeHandle;
#endif // WIN32
  
  Utility::socklen_t d_addrlen;

  int d_s;
  int d_client;
  pthread_t d_tid;
  bool d_udp;
  pid_t d_ppid;
  
  string d_socketname;
  g_funkdb_t d_funcdb;
  g_funk_t* d_restfunc;

};
#endif /* PDNS_DYNLISTENER */
