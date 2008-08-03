/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2008 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

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
#include "iputils.hh"
#include <boost/utility.hpp>
#ifndef WIN32
#include <unistd.h>
#include <sys/un.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <netinet/in.h>
#endif // WIN32

using namespace std;

class DynListener : public boost::noncopyable
{
public:
  explicit DynListener(const string &pname="");
  explicit DynListener(const ComboAddress& addr);
  ~DynListener();
  void go();
  void theListener();
  static void *theListenerHelper(void *p);

  typedef string g_funk_t(const vector<string> &parts, Utility::pid_t ppid); // guido!
  typedef map<string,g_funk_t *> g_funkdb_t;
  
  static void registerFunc(const string &name, g_funk_t *gf);
  static void registerRestFunc(g_funk_t *gf);
private:
  void sendLine(const string &line);
  string getLine();

  void listenOnUnixDomain(const std::string& fname);
  void listenOnTCP(const ComboAddress&);
  void createSocketAndBind(int family, struct sockaddr*local, size_t len);

#ifndef WIN32
  struct sockaddr_un d_remote;
#else
  HANDLE m_pipeHandle;
#endif // WIN32
  
  Utility::socklen_t d_addrlen;
  NetmaskGroup d_tcprange;
  int d_s;
  int d_client;
  pthread_t d_tid;
  bool d_nonlocal;
  bool d_tcp;
  pid_t d_ppid;
  
  string d_socketname;
  ComboAddress d_socketaddress;
  static g_funkdb_t s_funcdb;
  static g_funk_t* s_restfunc;
};
#endif /* PDNS_DYNLISTENER */
