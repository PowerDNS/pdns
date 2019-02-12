/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
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
#include <unistd.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "namespaces.hh"

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
  typedef struct { g_funk_t *func; string args; string usage; } g_funkwithusage_t;
  typedef map<string,g_funkwithusage_t> g_funkdb_t;
  
  static void registerFunc(const string &name, g_funk_t *gf, const string &usage="", const string &args="");
  static void registerRestFunc(g_funk_t *gf);
  static g_funk_t* getFunc(const string& fname) { return s_funcdb[fname].func; } 
private:
  void sendlines(const string &lines);
  string getHelp();
  string getLine();

  void listenOnUnixDomain(const std::string& fname);
  void listenOnTCP(const ComboAddress&);
  void createSocketAndBind(int family, struct sockaddr*local, size_t len);

  NetmaskGroup d_tcprange;
  int d_s{-1};
  int d_client{-1};
  pthread_t d_tid{0};
  bool d_nonlocal;
  bool d_tcp{false};
  pid_t d_ppid{0};
  
  string d_socketname;
  ComboAddress d_socketaddress;
  static g_funkdb_t s_funcdb;
  static g_funk_t* s_restfunc;
  bool testLive(const string& fname);
};
#endif /* PDNS_DYNLISTENER */
