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
#include <iomanip>
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
#include "arguments.hh"
#include "dynmessenger.hh"
#include "logger.hh"
#include "logging.hh"
#include "misc.hh"
#include "namespaces.hh"
#include "pdnsexception.hh"
#include "statbag.hh"

bool g_slogStructured{false};
static Logger::Urgency s_logUrgency;

ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
}

StatBag S;

static void pdnsControlLoggerBackend(const Logging::Entry& entry)
{
  static thread_local std::stringstream buf;

  // First map SL priority to syslog's Urgency
  Logger::Urgency urg = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (urg > s_logUrgency) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Not that lower Urgency means higher number.
    return;
  }
  buf.str("");
  buf << "msg=" << std::quoted(entry.message);
  if (entry.error) {
    buf << " error=" << std::quoted(entry.error.value());
  }

  if (entry.name) {
    buf << " subsystem=" << std::quoted(entry.name.value());
  }
  buf << " level=" << std::quoted(std::to_string(entry.level));
  if (entry.d_priority != 0) {
    buf << " prio=" << std::quoted(Logr::Logger::toString(entry.d_priority));
  }
  std::array<char, 64> timebuf{};
  buf << " ts=" << std::quoted(Logging::toTimestampStringMilli(entry.d_timestamp, timebuf));
  for (auto const& value : entry.values) {
    buf << " ";
    buf << value.first << "=" << std::quoted(value.second);
  }

  g_log << urg << buf.str() << endl;
}

int main(int argc, char **argv)
{
  string programname="pdns";

  ::arg().set("config-dir","Location of configuration directory (pdns.conf)")=SYSCONFDIR;
  // Note pdns_server defaults to 4, but pdnsutil defaults to 3.
  ::arg().set("loglevel","Amount of logging. Higher is more.")="4";
  ::arg().setSwitch("logging-structured", "Produce structured log messages") = "no";
  ::arg().set("socket-dir",string("Where the controlsocket will live, ")+LOCALSTATEDIR+"/pdns when unset and not chrooted" )="";
  ::arg().set("remote-address","Remote address to query");
  ::arg().set("remote-port","Remote port to query")="53000";
  ::arg().set("secret","Secret needed to connect to remote PowerDNS");

  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
  ::arg().setCmd("no-config","Don't parse configuration file");
  ::arg().set("chroot","")="";
  ::arg().setCmd("help","Provide a helpful message");
  ::arg().laxParse(argc,argv);

  s_logUrgency = (Logger::Urgency)(::arg().asNum("loglevel"));

  g_slogStructured = ::arg().mustDo("logging-structured");
  if (g_slogStructured) {
    g_slog = Logging::Logger::create(pdnsControlLoggerBackend);
    auto log = g_slog->withName("config");
    ::arg().setSLog(log);
  }

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
    programname+="-"+::arg()["config-name"];

  string configname=::arg()["config-dir"]+"/"+programname+".conf";
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

  socketname += "/" + programname + ".controlsocket";
  cleanSlashes(socketname);

  try {
    string command = commands[0];
    shared_ptr<DynMessenger> D;
    if(::arg()["remote-address"].empty())
      D = std::make_shared<DynMessenger>(socketname);
    else {
      uint16_t port;
      try {
        pdns::checked_stoi_into(port, ::arg()["remote-port"]);
      }
      catch (...) {
        cerr << "Unable to convert '" << ::arg()["remote-port"] << "' to a port number for connecting to remote PowerDNS\n";
        exit(99);
      }

      D = std::make_shared<DynMessenger>(ComboAddress(::arg()["remote-address"], port), ::arg()["secret"]);
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
    else if(command=="quit" || command=="QUIT" || command == "stop" || command == "STOP") {
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
