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
#include "rec_channel.hh"
#include <iostream>
#include "pdnsexception.hh"
#include "arguments.hh"

#include "namespaces.hh"

ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
}

static void initArguments(int argc, char** argv)
{
  arg().set("config-dir","Location of configuration directory (recursor.conf)")=SYSCONFDIR;

  arg().set("socket-dir",string("Where the controlsocket will live, ")+LOCALSTATEDIR+"/pdns-recursor when unset and not chrooted" )="";
  arg().set("chroot","switch to chroot jail")="";
  arg().set("process","When controlling multiple recursors, the target process number")="";
  arg().set("timeout", "Number of seconds to wait for the recursor to respond")="5";
  arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  arg().setCmd("help","Provide this helpful message");
  arg().setCmd("version","Show the version of this program");

  arg().laxParse(argc,argv);  
  if(arg().mustDo("help") || arg().getCommands().empty()) {
    cout<<"syntax: rec_control [options] command, options as below: "<<endl<<endl;
    cout<<arg().helpstring(arg()["help"])<<endl;
    cout<<"In addition, 'rec_control help' can be used to retrieve a list\nof available commands from PowerDNS"<<endl;
    exit(arg().mustDo("help") ? 0 : 99);
  }

  if(arg().mustDo("version")) {
    cout<<"rec_control version "<<VERSION<<endl;
    exit(0);
  }

  string configname=::arg()["config-dir"]+"/recursor.conf";
  if (::arg()["config-name"] != "")
    configname=::arg()["config-dir"]+"/recursor-"+::arg()["config-name"]+".conf";
  
  cleanSlashes(configname);

  arg().laxFile(configname.c_str());

  arg().laxParse(argc,argv);   // make sure the commandline wins

  if (::arg()["socket-dir"].empty()) {
    if (::arg()["chroot"].empty())
      ::arg().set("socket-dir") = std::string(LOCALSTATEDIR) + "/pdns-recursor";
    else
      ::arg().set("socket-dir") = ::arg()["chroot"] + "/";
  } else if (!::arg()["chroot"].empty()) {
    ::arg().set("socket-dir") = ::arg()["chroot"] + "/" + ::arg()["socket-dir"];
  }
}

int main(int argc, char** argv)
try
{
  initArguments(argc, argv);
  RecursorControlChannel rccS;
  string sockname="pdns_recursor";

  if (arg()["config-name"] != "")
    sockname+="-"+arg()["config-name"];

  if(!arg()["process"].empty())
    sockname+="."+arg()["process"];

  sockname.append(".controlsocket");

  rccS.connect(arg()["socket-dir"], sockname);

  const vector<string>&commands=arg().getCommands();
  string command;
  for(unsigned int i=0; i< commands.size(); ++i) {
    if(i>0)
      command+=" ";
    command+=commands[i];
  }
  rccS.send(command, nullptr, arg().asNum("timeout"));
  string receive=rccS.recv(0, arg().asNum("timeout"));
  if(receive.compare(0, 7, "Unknown") == 0) {
    cerr<<receive<<endl;
    return 1;
  }
  cout<<receive;
  return 0;
}
catch(PDNSException& ae)
{
  cerr<<"Fatal: "<<ae.reason<<"\n";
  return 1;
}
