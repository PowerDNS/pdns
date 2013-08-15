/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

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

#include "utility.hh"
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <errno.h>
#include <climits>
#include <string>
#include <map>
#include <sys/types.h>

#include <sys/stat.h>
#include "pdnsexception.hh"
#include "misc.hh"
#include "dynmessenger.hh"
#include "arguments.hh"
#include "statbag.hh"
#include "misc.hh"
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

  arg().set("config-dir","Location of configuration directory (pdns.conf)")="./";
  arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  arg().laxParse(argc,argv);

  if(arg()["config-name"]!="") 
    s_programname+="-"+arg()["config-name"];

  string configname=arg()["config-dir"]+"/"+s_programname+".conf";
  cleanSlashes(configname);
  
  arg().laxFile(configname.c_str());

  const vector<string>&commands=arg().getCommands();

  if(commands.empty()) {
    cerr<<"No command passed"<<endl;
    return 0;
  }

  try {
    string command=commands[0];

    DynMessenger D( "", s_programname );

    string message;
    for(vector<string>::const_iterator i=commands.begin();i!=commands.end();++i) {
      if(i!=commands.begin())
              message+=" ";
      message+=*i;
    }
    
    if( command=="show") {
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
    
    
    if(D.send(message)<0) {
      cerr<<"Error sending command"<<endl;
      return 1;
    }
    
    string resp=D.receive();
    
    cout<<resp<<endl;
  }
  catch(PDNSException &ae) {
    cerr<<"Fatal error: "<<ae.reason<<endl;
    return 1;
  }
  return 0;
}



