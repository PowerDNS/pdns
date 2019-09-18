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
#include "remotebackend.hh"

PipeConnector::PipeConnector(std::map<std::string,std::string> optionsMap): d_pid(-1)  {
  if (optionsMap.count("command") == 0) {
    g_log<<Logger::Error<<"Cannot find 'command' option in connection string"<<endl;
    throw PDNSException();
  }
  this->command = optionsMap.find("command")->second;
  this->options = optionsMap;
  d_timeout=2000;

  if (optionsMap.find("timeout") != optionsMap.end()) {
     d_timeout = std::stoi(optionsMap.find("timeout")->second);
  }

  d_fd1[0] = d_fd1[1] = -1;
  d_fd2[0] = d_fd2[1] = -1;
}

PipeConnector::~PipeConnector(){
  int status;
  // just in case...
  if (d_pid == -1) return;

  if(!waitpid(d_pid, &status, WNOHANG)) {
    kill(d_pid, 9);
    waitpid(d_pid, &status, 0);
  }

  if (d_fd1[1]) {
    close(d_fd1[1]);
  }
}

void PipeConnector::launch() {
  // no relaunch
  if (d_pid > 0 && checkStatus()) return;

  std::vector <std::string> v;
  split(v, command, is_any_of(" "));

  std::vector<const char *>argv(v.size()+1);
  argv[v.size()]=0;

  for (size_t n = 0; n < v.size(); n++)
    argv[n]=v[n].c_str();

  signal(SIGPIPE, SIG_IGN);

  if(access(argv[0],X_OK)) // check before fork so we can throw
    throw PDNSException("Command '"+string(argv[0])+"' cannot be executed: "+stringerror());

  if(pipe(d_fd1)<0 || pipe(d_fd2)<0)
    throw PDNSException("Unable to open pipe for coprocess: "+string(strerror(errno)));

  if((d_pid=fork())<0)
    throw PDNSException("Unable to fork for coprocess: "+stringerror());
  else if(d_pid>0) { // parent speaking
    close(d_fd1[0]);
    setCloseOnExec(d_fd1[1]);
    close(d_fd2[1]);
    setCloseOnExec(d_fd2[0]);
    if(!(d_fp=std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(d_fd2[0],"r"), fclose)))
      throw PDNSException("Unable to associate a file pointer with pipe: "+stringerror());
    if (d_timeout)
      setbuf(d_fp.get(),0); // no buffering please, confuses poll
  }
  else if(!d_pid) { // child
    signal(SIGCHLD, SIG_DFL); // silence a warning from perl
    close(d_fd1[1]);
    close(d_fd2[0]);

    if(d_fd1[0]!= 0) {
      dup2(d_fd1[0], 0);
      close(d_fd1[0]);
    }

    if(d_fd2[1]!= 1) {
      dup2(d_fd2[1], 1);
      close(d_fd2[1]);
    }

    // stdin & stdout are now connected, fire up our coprocess!

    if(execv(argv[0], const_cast<char * const *>(argv.data()))<0) // now what
      exit(123);

    /* not a lot we can do here. We shouldn't return because that will leave a forked process around.
       no way to log this either - only thing we can do is make sure that our parent catches this soonest! */
  }

  Json::array parameters;
  Json msg = Json(Json::object{
    { "method", "initialize" },
    { "parameters", Json(options) },
  });

  this->send(msg);
  msg = nullptr;
  if (this->recv(msg)==false) {
    g_log<<Logger::Error<<"Failed to initialize coprocess"<<std::endl;
  }
}

int PipeConnector::send_message(const Json& input)
{
   auto line = input.dump();
   launch();

   line.append(1,'\n');

   unsigned int sent=0;
   int bytes;

   // writen routine - socket may not accept al data in one go
   while(sent<line.size()) {
     bytes=write(d_fd1[1],line.c_str()+sent,line.length()-sent);
     if(bytes<0)
       throw PDNSException("Writing to coprocess failed: "+std::string(strerror(errno)));

     sent+=bytes;
   }
   return sent;
}

int PipeConnector::recv_message(Json& output)
{
   std::string receive;
   std::string err;
   std::string s_output;
   launch();

   while(1) {
     receive.clear();
     if(d_timeout) {
       int ret=waitForData(fileno(d_fp.get()), 0, d_timeout * 1000);
       if(ret<0) 
         throw PDNSException("Error waiting on data from coprocess: "+stringerror());
       if(!ret)
         throw PDNSException("Timeout waiting for data from coprocess");
     }

     if(!stringfgets(d_fp.get(), receive))
       throw PDNSException("Child closed pipe");
  
      s_output.append(receive);
      // see if it can be parsed
      output = Json::parse(s_output, err);
      if (output != nullptr) return s_output.size();
   }
   return 0;
}

bool PipeConnector::checkStatus()
{
  int status;
  int ret=waitpid(d_pid, &status, WNOHANG);
  if(ret<0)
    throw PDNSException("Unable to ascertain status of coprocess "+itoa(d_pid)+" from "+itoa(getpid())+": "+string(strerror(errno)));
  else if(ret) {
    if(WIFEXITED(status)) {
      int exitStatus=WEXITSTATUS(status);
      throw PDNSException("Coprocess exited with code "+itoa(exitStatus));
    }
    if(WIFSIGNALED(status)) {
      int sig=WTERMSIG(status);
      string reason="CoProcess died on receiving signal "+itoa(sig);
#ifdef WCOREDUMP
      if(WCOREDUMP(status))
        reason+=". Dumped core";
#endif

      throw PDNSException(reason);
    }
  }
  return true;
}
