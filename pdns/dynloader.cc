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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <climits>
#include <string>
#include <map>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>


#include <sys/stat.h>
#include "pdnsexception.hh"
#include "misc.hh"
#include "dynmessenger.hh"
#include "arguments.hh"
#include "statbag.hh"
#include "misc.hh"
#include "namespaces.hh"
#include "namespaces.hh"

ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
}

StatBag S;

int main(int argc, char **argv)
{
  string s_programname="pdns";

  ::arg().set("config-dir","Location of configuration directory (pdns.conf)")=SYSCONFDIR;
  ::arg().set("socket-dir",string("Where the controlsocket will live, ")+LOCALSTATEDIR+"/pdns when unset and not chrooted" )="";
  ::arg().set("remote-address","Remote address to query");
  ::arg().set("remote-port","Remote port to query")="53000";
  ::arg().set("secret","Secret needed to connect to remote PowerDNS");

  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  ::arg().setCmd("no-config","Don't parse configuration file");
  ::arg().set("chroot","")="";
  ::arg().setCmd("help","Provide a helpful message");
  ::arg().laxParse(argc,argv);

  if(::arg().mustDo("help")) {
    cout<<"syntax:"<<endl<<endl;
    cout<<::arg().helpstring(::arg()["help"])<<endl;
    cout<<"In addition, 'pdns_control help' can be used to retrieve a list\nof available commands from PowerDNS"<<endl;
    exit(0);
  }

  const vector<string>commands=::arg().getCommands();

  if(commands.empty()) {
    cerr<<"No command passed"<<endl;
    return 0;
  }

  if(::arg()["config-name"]!="") 
    s_programname+="-"+::arg()["config-name"];

  string configname=::arg()["config-dir"]+"/"+s_programname+".conf";
  cleanSlashes(configname);

  if(!::arg().mustDo("no-config")) {
    ::arg().laxFile(configname.c_str());
    ::arg().laxParse(argc,argv); // reparse so the commandline still wins
  }

  string socketname=::arg()["socket-dir"];
  if (::arg()["socket-dir"].empty()) {
    if (::arg()["chroot"].empty())
      socketname = std::string(LOCALSTATEDIR) + "/pdns";
    else
      socketname = ::arg()["chroot"] + "/";
  } else if (!::arg()["socket-dir"].empty() && !::arg()["chroot"].empty()) {
    socketname = ::arg()["chroot"] + ::arg()["socket-dir"];
  }

  socketname += "/" + s_programname + ".controlsocket";
  cleanSlashes(socketname);
  
  try {
    string command=commands[0];
    shared_ptr<DynMessenger> D;
    if(::arg()["remote-address"].empty())
      D=shared_ptr<DynMessenger>(new DynMessenger(socketname));
    else {
      uint16_t port;
      try {
        port = static_cast<uint16_t>(pdns_stou(::arg()["remote-port"]));
      }
      catch(...) {
        cerr<<"Unable to convert '"<<::arg()["remote-port"]<<"' to a port number for connecting to remote PowerDNS\n";
        exit(99);
      }
      
      D=shared_ptr<DynMessenger>(new DynMessenger(ComboAddress(::arg()["remote-address"], port), ::arg()["secret"]));
    }

    string message;
    for(vector<string>::const_iterator i=commands.begin();i!=commands.end();++i) {
      if(i!=commands.begin())
        message+=" ";
      message+=*i;
    }
    
    if(command=="show") {
      message="SHOW ";
      for(unsigned int n=1;n<commands.size();n++) {
        message+=commands[n];
        message+=" ";
      }
    }
    else if(command=="list") {
      message="SHOW *";
      command="show";
    }
    else if(command=="quit" || command=="QUIT") {
      message="QUIT";
    }
    else if(command=="status" || command=="STATUS") {
      message="STATUS";
    }
    else if(command=="version" || command=="VERSION") {
      message="VERSION";
    }
    
    
    if(D->send(message)<0) {
      cerr<<"Error sending command"<<endl;
      return 1;
    }
    
    string resp=D->receive();
    if(resp.compare(0, 7, "Unknown") == 0) {
      cerr<<resp<<endl;
      return 1;
    }
    
    cout<<resp<<endl;
  }
  catch(TimeoutException &ae) {
    cerr<<"Timeout error: "<<ae.reason<<endl;
    return 2;
  }
  catch(PDNSException &ae) {
    cerr<<"Fatal error: "<<ae.reason<<endl;
    return 1;
  }
  catch(const std::runtime_error& e) {
    cerr<<"Runtime error: "<<e.what()<<endl;
    return 2;
  }
  return 0;
}


