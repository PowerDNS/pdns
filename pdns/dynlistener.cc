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
#include <cstring>
#include <string>
#include <map>
#include <sys/types.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <unistd.h>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>

#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <sstream>
#include <csignal>

#include <sys/stat.h>
#include <fcntl.h>
#include <thread>

#include "misc.hh"
#include "dns.hh"
#include "arguments.hh"
#include "dnsbackend.hh"
#include "dynlistener.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "statbag.hh"
#include "threadname.hh"

extern StatBag S;

DynListener::g_funkdb_t DynListener::s_funcdb;
DynListener::g_funk_t* DynListener::s_restfunc;
std::string DynListener::s_exitfuncname;

DynListener::~DynListener()
{
  if(!d_socketname.empty())
    unlink(d_socketname.c_str());
}

void DynListener::createSocketAndBind(int family, struct sockaddr*local, size_t len)
{
  d_s=socket(family, SOCK_STREAM,0);
  setCloseOnExec(d_s);

  if(d_s < 0) {
    if (family == AF_UNIX) {
      SLOG(g_log<<Logger::Error<<"Unable to create control socket at '"<<((struct sockaddr_un*)local)->sun_path<<"', reason: "<<stringerror()<<endl,
           d_slog->error(Logr::Error, errno, "Unable to create control socket", "path", Logging::Loggable(reinterpret_cast<struct sockaddr_un*>(local)->sun_path)));
    }
    else {
      SLOG(g_log<<Logger::Error<<"Unable to create control socket on '"<<((ComboAddress *)local)->toStringWithPort()<<"', reason: "<<stringerror()<<endl,
           d_slog->error(Logr::Error, errno, "Unable to create control socket", "socket", Logging::Loggable(reinterpret_cast<ComboAddress*>(local)->toStringWithPort())));
    }
    exit(1);
  }
  
  int tmp=1;
  if(setsockopt(d_s,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
    throw PDNSException(string("Setsockopt failed on control socket: ")+stringerror());
    
  if(bind(d_s, local, len) < 0) {
    if (family == AF_UNIX) {
      SLOG(g_log<<Logger::Critical<<"Unable to bind to control socket at '"<<((struct sockaddr_un*)local)->sun_path<<"', reason: "<<stringerror()<<endl,
           d_slog->error(Logr::Critical, errno, "Unable to bind to control socket", "path", Logging::Loggable(reinterpret_cast<struct sockaddr_un*>(local)->sun_path)));
    }
    else {
      SLOG(g_log<<Logger::Critical<<"Unable to bind to control socket on '"<<((ComboAddress *)local)->toStringWithPort()<<"', reason: "<<stringerror()<<endl,
           d_slog->error(Logr::Critical, errno, "Unable to bind to control socket", "socket", Logging::Loggable(reinterpret_cast<ComboAddress*>(local)->toStringWithPort())));
    }
    exit(1);
  }
}

/* this does a simplistic check, if we can connect, we consider it live. If we can't connect because
   of access denied, we must consider it dead, nothing we can do about it.
*/
bool DynListener::testLive(const string& fname)
{
  struct sockaddr_un addr;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if(fd < 0) { // we'll have bigger issues down the road
    return false;
  }

  if (makeUNsockaddr(fname, &addr)) {
    SLOG(g_log<<Logger::Critical<<"Unable to open controlsocket, path '"<<fname<<"' is not a valid UNIX socket path."<<endl,
         d_slog->info(Logr::Critical, "Unable to open control socket, for it is not a valid UNIX socket path", "path", Logging::Loggable(fname)));
    exit(1);
  }

  int status = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
  close(fd);
  return status==0;
}

void DynListener::listenOnUnixDomain(const string& fname)
{
  if(testLive(fname)) {
    SLOG(g_log<<Logger::Critical<<"Previous controlsocket '"<<fname<<"' is in use"<<endl,
         d_slog->info(Logr::Critical, "Previous control socket is in use", "path", Logging::Loggable(fname)));
    exit(1);
  }
  int err=unlink(fname.c_str());
  if(err < 0 && errno!=ENOENT) {
    SLOG(g_log<<Logger::Critical<<"Unable to remove (previous) controlsocket at '"<<fname<<"': "<<stringerror()<<endl,
         d_slog->error(Logr::Critical, errno, "Unable to remove (previous) control socket", "path", Logging::Loggable(fname)));
    exit(1);
  }

  struct sockaddr_un local;
  if (makeUNsockaddr(fname, &local)) {
    SLOG(g_log<<Logger::Critical<<"Unable to bind to controlsocket, path '"<<fname<<"' is not a valid UNIX socket path."<<endl,
         d_slog->info(Logr::Critical, "Unable to bind to control socket, for it is not a valid UNIX socket path", "path", Logging::Loggable(fname)));
    exit(1);
  }
  
  createSocketAndBind(AF_UNIX, (struct sockaddr*)& local, sizeof(local));
  d_socketname=fname;
  if(!arg()["setgid"].empty()) {
    if(chmod(fname.c_str(),0660)<0) {
      SLOG(g_log<<Logger::Error<<"Unable to change group access mode of controlsocket at '"<<fname<<"', reason: "<<stringerror()<<endl,
           d_slog->error(Logr::Error, errno, "Unable to change group access mode of control socket", "path", Logging::Loggable(fname)));
    }
    if(chown(fname.c_str(),static_cast<uid_t>(-1), strToGID(arg()["setgid"]))<0) {
      SLOG(g_log<<Logger::Error<<"Unable to change group ownership of controlsocket at '"<<fname<<"', reason: "<<stringerror()<<endl,
           d_slog->error(Logr::Error, errno, "Unable to change group ownership of control socket", "path", Logging::Loggable(fname)));
    }
  }
  
  listen(d_s, 10);
  
  SLOG(g_log<<Logger::Warning<<"Listening on controlsocket in '"<<fname<<"'"<<endl,
       d_slog->info(Logr::Warning, "Listening on control socket", "path", Logging::Loggable(fname)));
  d_nonlocal=true;
}

void DynListener::listenOnTCP(const ComboAddress& local)
{
  if (local.isIPv4()) {
    createSocketAndBind(AF_INET, (struct sockaddr*)& local, local.getSocklen());
  } else if (local.isIPv6()) {
    createSocketAndBind(AF_INET6, (struct sockaddr*)& local, local.getSocklen());
  }
  listen(d_s, 10);

  d_socketaddress=local;
  SLOG(g_log<<Logger::Warning<<"Listening on controlsocket on '"<<local.toStringWithPort()<<"'"<<endl,
       d_slog->info(Logr::Warning, "Listening on control socket", "socket", Logging::Loggable(local.toStringWithPort())));
 
  d_nonlocal=true;

  if(!::arg()["tcp-control-range"].empty()) {
    d_tcprange.toMasks(::arg()["tcp-control-range"]);
    SLOG(g_log<<Logger::Warning<<"Only allowing TCP control from: "<<d_tcprange.toString()<<endl,
         d_slog->info(Logr::Warning, "Only allowing TCP control from", "source", Logging::Loggable(d_tcprange)));
  }
}


DynListener::DynListener(Logr::log_t slog, const ComboAddress& local) :
  d_tcp(true)
{
  d_slog = slog;
  listenOnTCP(local);
}

DynListener::DynListener(Logr::log_t slog, const string &progname)
{
  d_slog = slog;

  if(!progname.empty()) {
    string socketname = ::arg()["socket-dir"];
    if (::arg()["socket-dir"].empty()) {
      if (::arg()["chroot"].empty())
        socketname = std::string(LOCALSTATEDIR) + "/pdns";
      else
        socketname = ::arg()["chroot"];
    } else if (!::arg()["socket-dir"].empty() && !::arg()["chroot"].empty()) {
      socketname = ::arg()["chroot"] + ::arg()["socket-dir"];
    }
    socketname += "/";
    cleanSlashes(socketname);
    
    if(mkdir(socketname.c_str(),0700) == 0) { // make /var directory, if needed
      SLOG(g_log<<Logger::Warning<<"Created local state directory '"<<socketname<<"'"<<endl,
           d_slog->info(Logr::Warning, "Created local state directory", "path", Logging::Loggable(socketname)));
    }
    else if(errno!=EEXIST) {
      SLOG(g_log<<Logger::Critical<<"Unable to create socket directory ("<<socketname<<") and it does not exist yet"<<endl,
           d_slog->error(Logr::Critical, errno, "Unable to create socket directory", "path", Logging::Loggable(socketname)));
      exit(1);
    }
    
    socketname+=progname+".controlsocket";
    listenOnUnixDomain(socketname);
  }
  else
    d_nonlocal=false; // we listen on stdin!
}

void DynListener::go()
{
  d_ppid=getpid();
  std::thread listener([this](){theListener();});
  listener.detach();
}

string DynListener::getLine()
{
  vector<char> mesg;
  mesg.resize(1024000);

  ComboAddress remote;
  socklen_t remlen=remote.getSocklen();

  if(d_nonlocal) {
    for(;;) {
      d_client = accept(d_s, reinterpret_cast<sockaddr *>(&remote), &remlen);
      if(d_client<0) {
        if(errno!=EINTR) {
          SLOG(g_log<<Logger::Error<<"Unable to accept controlsocket connection ("<<d_s<<"): "<<stringerror()<<endl,
               d_slog->error(Logr::Error, errno, "Unable to accept control socket connection", "socket", Logging::Loggable(d_s)));
        }
        continue;
      }

      if(d_tcp && !d_tcprange.match(&remote)) { // checks if the remote is within the permitted range.
        SLOG(g_log<<Logger::Error<<"Access denied to remote "<<remote.toString()<<" because not allowed"<<endl,
             d_slog->info(Logr::Error, "Access denied, not within allowed range", "remote", Logging::Loggable(remote)));
        writen2(d_client, "Access denied to "+remote.toString()+"\n");
        close(d_client);
        continue;
      }

      std::shared_ptr<FILE> fp=std::shared_ptr<FILE>(fdopen(dup(d_client), "r"), fclose);
      if(d_tcp) {
        if (fgets(mesg.data(), static_cast<int>(mesg.size()), fp.get()) == nullptr) {
          SLOG(g_log<<Logger::Error<<"Unable to receive password from controlsocket ("<<d_client<<"): "<<stringerror()<<endl,
                d_slog->error(Logr::Error, errno, "Unable to receive password from control socket", "socket", Logging::Loggable(d_client)));
          close(d_client);
          continue;
        }
        string password(mesg.data());
        boost::trim(password);
        if(password.empty() || password!=arg()["tcp-control-secret"]) {
          SLOG(g_log<<Logger::Error<<"Wrong password on TCP control socket"<<endl,
               d_slog->info(Logr::Error, "Wrong password on control socket"));
          writen2(d_client, "Wrong password");

          close(d_client);
          continue;
        }
      }
      errno=0;
      if (fgets(mesg.data(), static_cast<int>(mesg.size()), fp.get()) == nullptr) {
        if (errno) {
          SLOG(g_log<<Logger::Error<<"Unable to receive line from controlsocket ("<<d_client<<"): "<<stringerror()<<endl,
               d_slog->error(Logr::Error, errno, "Unable to receive line from control socket", "socket", Logging::Loggable(d_client)));
        }
        close(d_client);
        continue;
      }
      
      if (strlen(mesg.data()) == mesg.size()) {
        SLOG(g_log<<Logger::Error<<"Line on controlsocket ("<<d_client<<") was too long"<<endl,
             d_slog->info(Logr::Error, "Line too long on control socket", "socket", Logging::Loggable(d_client)));
        close(d_client);
        continue;
      }
      break;
    }
  }
  else {
    if (isatty(0) != 0) {
      if (write(1, "% ", 2) != 2) {
        throw PDNSException("Writing to console: " + stringerror());
      }
    }

    ssize_t len = read(0, mesg.data(), mesg.size());
    if (len < 0) {
      throw PDNSException("Reading from the control pipe: " + stringerror());
    }

    if (len == 0) {
      // File descriptor has been closed. We translate this into an exit
      // request, but if it did not succeed and we are back attempting to
      // read data, there's not much we can do but throw up.
      static bool firstTime = true;
      if (!firstTime) {
        throw PDNSException("Guardian exited - going down as well");
      }
      firstTime = false;
    }

    if (static_cast<size_t>(len) == mesg.size()) {
      throw PDNSException("Line on control console was too long");
    }

    mesg[len] = 0;
  }

  return mesg.data();
}

void DynListener::sendlines(const string &l)
{
  if(d_nonlocal) {
    unsigned int sent=0;
    int ret;
    while(sent < l.length()) {
      ret=send(d_client, l.c_str()+sent, l.length()-sent, 0); 

      if(ret<0 || !ret) {
        SLOG(g_log<<Logger::Error<<"Error sending data to pdns_control: "<<stringerror()<<endl,
             d_slog->error(Logr::Error, errno, "Error sending data to pdns_control"));
        break;
      }
      sent+=ret;
    }
    close(d_client);
  } else {
    string lines=l;
    if(!lines.empty() && lines[lines.length()-1] != '\n')
      lines.append("\n");
    lines.append(1, '\0');
    lines.append(1, '\n');
    if((unsigned int)write(1, lines.c_str(), lines.length()) != lines.length()) {
      SLOG(g_log<<Logger::Error<<"Error sending data to console: "<<stringerror()<<endl,
           d_slog->error(Logr::Error, errno, "Error sending data to console"));
    }
  }
}

void DynListener::registerExitFunc(const string &name, g_funk_t *gf) // NOLINT(readability-identifier-length)
{
  g_funkwithusage_t funk = {gf, "", "quit daemon"};
  s_exitfuncname = name;
  s_funcdb[s_exitfuncname] = std::move(funk);
}

void DynListener::registerFunc(const string &name, g_funk_t *gf, const string &usage, const string &args)
{
  g_funkwithusage_t e = {gf, args, usage};
  s_funcdb[name] = std::move(e);
}

void DynListener::registerRestFunc(g_funk_t *gf)
{
  s_restfunc=gf;
}

void DynListener::theListener()
{
  setThreadName("pdns/ctrlListen");

  try {
    signal(SIGPIPE,SIG_IGN);

    for(;;) {
      string line=getLine();
      if (line.empty()) {
        line = s_exitfuncname;
      }
      boost::trim_right(line);

      vector<string>parts;
      stringtok(parts,line," ");
      if(parts.empty()) {
        sendlines("Empty line");
        continue;
      }

      try {
        parts[0] = toUpper( parts[0] );
        if(s_funcdb.count(parts[0]))
          sendlines((*(s_funcdb[parts[0]].func))(parts,d_ppid,d_slog));
        else if (parts[0] == "HELP")
          sendlines(getHelp());
        else if(s_restfunc)
          sendlines((*s_restfunc)(parts,d_ppid,d_slog));
        else
          sendlines("Unknown command: '"+parts[0]+"'");
      }
      catch(PDNSException &AE) {
        SLOG(g_log<<Logger::Error<<"Non-fatal error in control listener command '"<<line<<"': "<<AE.reason<<endl,
             d_slog->error(Logr::Error, AE.reason, "Non-fatal error in control listener command", "input", Logging::Loggable(line)));
      }
      catch(string &E) {
        SLOG(g_log<<Logger::Error<<"Non-fatal error 2 in control listener command '"<<line<<"': "<<E<<endl,
             d_slog->error(Logr::Error, E, "Non-fatal error 2 in control listener command", "input", Logging::Loggable(line)));
      }
      catch(std::exception& e) {
        SLOG(g_log<<Logger::Error<<"Non-fatal STL error in control listener command '"<<line<<"': "<<e.what()<<endl,
             d_slog->error(Logr::Error, e.what(), "Non-fatal STL error in control listener command", "input", Logging::Loggable(line)));
      }
      catch(...) {
        SLOG(g_log<<Logger::Error<<"Non-fatal error in control listener command '"<<line<<"': unknown exception occurred"<<endl,
             d_slog->error(Logr::Error, "unknown exception occurred", "Non-fatal error in control listener command", "input", Logging::Loggable(line)));
      }
    }
  }
  catch(PDNSException &AE) {
    SLOG(g_log<<Logger::Error<<"Fatal error in control listener: "<<AE.reason<<endl,
         d_slog->error(Logr::Error, AE.reason, "Fatal error in control listener"));
  }
  catch(string &E) {
    SLOG(g_log<<Logger::Error<<"Fatal error 2 in control listener: "<<E<<endl,
         d_slog->error(Logr::Error, E, "Fatal error 2 in control listener"));
  }
  catch(std::exception& e) {
    SLOG(g_log<<Logger::Error<<"Fatal STL error in control listener: "<<e.what()<<endl,
         d_slog->error(Logr::Error, e.what(), "Fatal STL error in control listener"));
  }
  catch(...) {
    SLOG(g_log<<Logger::Error<<"Fatal: unknown exception in control listener occurred"<<endl,
         d_slog->error(Logr::Error, "unknown exception occurred", "Fatal error in control listener"));
  }
}


string DynListener::getHelp()
{
  vector<string> funcs;
  string rest;

  // s_restfunc, when in guardian mode, is the function that
  // can pass commands on to the guarded instance
  // we just pass it HELP and merge it with our own list
  if(s_restfunc)
  {
    vector<string> parts;
    parts.push_back("HELP");
    rest=((*s_restfunc)(parts,d_ppid,d_slog));
    boost::split(funcs, rest, boost::is_any_of("\n"));
  }

  const boost::format fmter("%|-32| %||");

  for(g_funkdb_t::const_iterator i=s_funcdb.begin();i!=s_funcdb.end();++i) {
    funcs.push_back(str(boost::format(fmter) % (toLower(i->first)+" "+i->second.args) % i->second.usage));
  }
  sort(funcs.begin(), funcs.end());

  // hack: this removes the duplicate quit method
  funcs.resize(unique(funcs.begin(), funcs.end()) - funcs.begin());
  return boost::join(funcs, "\n");
}
