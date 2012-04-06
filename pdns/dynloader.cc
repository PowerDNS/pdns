/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2008  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <errno.h>
#include <climits>
#include <string>
#include <map>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>
#include <boost/shared_ptr.hpp>

#include <sys/stat.h>
#include "ahuexception.hh"
#include "misc.hh"
#include "dynmessenger.hh"
#include "arguments.hh"
#include "config.h"
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
  string localdir;

  ::arg().set("config-dir","Location of configuration directory (pdns.conf)")=SYSCONFDIR;
  ::arg().set("socket-dir","Where the controlsocket will live")=LOCALSTATEDIR;
  ::arg().set("remote-address","Remote address to query");
  ::arg().set("remote-port","Remote port to query")="53000";
  ::arg().set("secret","Secret needed to connect to remote PowerDNS");

  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  ::arg().set("chroot","")="";
  ::arg().setCmd("help","Provide a helpful message");
  ::arg().laxParse(argc,argv);

  if(::arg().mustDo("help")) {
    cerr<<"syntax:"<<endl<<endl;
    cerr<<::arg().helpstring(::arg()["help"])<<endl;
    exit(99);
  }

  if(::arg()["config-name"]!="") 
    s_programname+="-"+::arg()["config-name"];

  string configname=::arg()["config-dir"]+"/"+s_programname+".conf";
  cleanSlashes(configname);
  
  ::arg().laxFile(configname.c_str());
  string socketname=::arg()["socket-dir"]+"/"+s_programname+".controlsocket";
  if(::arg()["chroot"].empty())
    localdir="/tmp";
  else
    localdir=dirname(strdup(socketname.c_str()));

  const vector<string>&commands=::arg().getCommands();

  if(commands.empty()) {
    cerr<<"No command passed"<<endl;
    return 0;
  }

  try {
    string command=commands[0];
    shared_ptr<DynMessenger> D;
    if(::arg()["remote-address"].empty())
      D=shared_ptr<DynMessenger>(new DynMessenger(localdir,socketname));
    else {
      uint16_t port;
      try {
        port  = lexical_cast<uint16_t>(::arg()["remote-port"]);
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
    
    cout<<resp<<endl;
  }
  catch(AhuException &ae) {
    cerr<<"Fatal error: "<<ae.reason<<endl;
    return 1;
  }
  return 0;
}


