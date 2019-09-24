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
#include "coprocess.hh"
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "pdns/utility.hh"
#include <sys/un.h>
#include "pdns/misc.hh"
#include "pdns/pdnsexception.hh"
#include <sys/stat.h>
#include <unistd.h>
#include <boost/algorithm/string.hpp>
#include <vector>

CoProcess::CoProcess(const string &command,int timeout, int infd, int outfd): d_infd(infd), d_outfd(outfd), d_timeout(timeout)
{
  split(d_params, command, is_any_of(" "));

  d_argv.resize(d_params.size()+1);
  d_argv[d_params.size()]=nullptr;

  for (size_t n = 0; n < d_params.size(); n++) {
    d_argv[n]=d_params[n].c_str();
  }
  d_pid = 0;
}

void CoProcess::launch()
{
  signal(SIGPIPE, SIG_IGN);

  if(access(d_argv[0],X_OK)) // check before fork so we can throw
    throw PDNSException("Command '"+string(d_argv[0])+"' cannot be executed: "+stringerror());

  if(pipe(d_fd1)<0 || pipe(d_fd2)<0)
    throw PDNSException("Unable to open pipe for coprocess: "+string(strerror(errno)));

  if((d_pid=fork())<0)
    throw PDNSException("Unable to fork for coprocess: "+stringerror());
  else if(d_pid>0) { // parent speaking
    // no need to keep this around
    d_argv.clear();
    close(d_fd1[0]);
    setCloseOnExec(d_fd1[1]);
    close(d_fd2[1]);
    setCloseOnExec(d_fd2[0]);

    if (d_timeout) {
      setNonBlocking(d_fd2[0]);
    }
  }
  else if(!d_pid) { // child
    signal(SIGCHLD, SIG_DFL); // silence a warning from perl
    close(d_fd1[1]);
    close(d_fd2[0]);

    if(d_fd1[0]!= d_infd) {
      dup2(d_fd1[0], d_infd);
      close(d_fd1[0]);
    }

    if(d_fd2[1]!= d_outfd) {
      dup2(d_fd2[1], d_outfd);
      close(d_fd2[1]);
    }

    // stdin & stdout are now connected, fire up our coprocess!
    if(execv(d_argv[0], const_cast<char * const *>(d_argv.data()))<0) // now what
      exit(123);

    /* not a lot we can do here. We shouldn't return because that will leave a forked process around.
       no way to log this either - only thing we can do is make sure that our parent catches this soonest! */
  }
}

CoProcess::~CoProcess()
{
  int status;
  if(d_pid){
    if(!waitpid(d_pid, &status, WNOHANG)) {
      kill(d_pid, 9);
      waitpid(d_pid, &status, 0);
    }
  }
  
  close(d_fd1[1]);
  close(d_fd2[0]);
}

void CoProcess::checkStatus()
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
}

void CoProcess::send(const string &snd)
{
  checkStatus();
  string line(snd);
  line.append(1,'\n');
  
  unsigned int sent=0;
  int bytes;

  // writen routine - socket may not accept al data in one go
  while(sent<line.size()) {
    bytes=write(d_fd1[1],line.c_str()+sent,line.length()-sent);
    if(bytes<0)
      throw PDNSException("Writing to coprocess failed: "+string(strerror(errno)));

    sent+=bytes;
  }
}

void CoProcess::receive(string &receive)
{
  receive.clear();

  // we might still have some remaining data from our last read
  if (!d_remaining.empty()) {
    receive = std::move(d_remaining);
  }

  size_t lastPos = 0;
  size_t eolPos;
  while ((eolPos = receive.find('\n', lastPos)) == std::string::npos) {
    size_t existingSize = receive.size();
    lastPos = existingSize;
    receive.resize(existingSize + 4096);
    ssize_t got = read(d_fd2[0], &receive.at(existingSize), 4096);
    if (got == 0) {
      throw PDNSException("Child closed pipe");
    }
    else if (got < 0) {
      receive.resize(existingSize);
      int saved = errno;
      if (saved == EINTR) {
        continue;
      }
      if (saved == EAGAIN) {
        if(d_timeout) {
          int ret = waitForData(d_fd2[0], 0, d_timeout * 1000);
          if(ret<0)
            throw PDNSException("Error waiting on data from coprocess: "+string(strerror(saved)));
          if(!ret)
            throw PDNSException("Timeout waiting for data from coprocess");
        }
      }
      else {
        throw PDNSException("Error reading from child's pipe:" + string(strerror(saved)));
      }
    } else {
      receive.resize(existingSize + static_cast<size_t>(got));
    }
  }

  if (eolPos != receive.size() - 1) {
    /* we have some data remaining after the first '\n', let's keep it for later */
    d_remaining.append(receive, eolPos + 1, receive.size() - eolPos - 1);
  }

  receive.resize(eolPos);
  trim_right(receive);
}

void CoProcess::sendReceive(const string &snd, string &rcv)
{
  checkStatus();
  send(snd);
  receive(rcv);

}

UnixRemote::UnixRemote(const string& path, int timeout) 
{
  d_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if(d_fd < 0)
    throw PDNSException("Unable to create UNIX domain socket: "+string(strerror(errno)));

  struct sockaddr_un remote;
  if (makeUNsockaddr(path, &remote))
    throw PDNSException("Unable to create UNIX domain socket: Path '"+path+"' is not a valid UNIX socket path.");

  // fcntl(fd, F_SETFL, O_NONBLOCK, &sock);

  if(connect(d_fd, (struct sockaddr*)&remote, sizeof(remote)) < 0)
    unixDie("Unable to connect to remote '"+path+"' using UNIX domain socket");

  d_fp = fdopen(d_fd, "r");
}

UnixRemote::~UnixRemote()
{
  fclose(d_fp);
}

void UnixRemote::send(const string& line)
{
  string nline(line);
  nline.append(1, '\n');
  writen2(d_fd, nline);
}

void UnixRemote::receive(string& line)
{
  line.clear();
  stringfgets(d_fp, line);
  trim_right(line);
}

void UnixRemote::sendReceive(const string &snd, string &rcv)
{
  //  checkStatus();
  send(snd);
  receive(rcv);
}

bool isUnixSocket(const string& fname)
{
  struct stat st;
  if(stat(fname.c_str(), &st) < 0)
    return false; // not a unix socket in any case ;-)

  return (st.st_mode & S_IFSOCK) == S_IFSOCK;
}


#ifdef TESTDRIVER
main()
{
  try {
    CoProcess cp("./irc.pl");
    string reply;
    cp.sendReceive("www.trilab.com", reply);
    cout<<"Answered: '"<<reply<<"'"<<endl;
  }
  catch(PDNSException &ae) {
    cerr<<ae.reason<<endl;
  }
  
}
#endif
