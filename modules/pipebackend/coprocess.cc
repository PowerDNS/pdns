#include "coprocess.hh"
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <pdns/misc.hh>
#include <pdns/ahuexception.hh>
#include <sys/stat.h>
#include <unistd.h>
#include <boost/algorithm/string.hpp>
#include <vector>

CoProcess::CoProcess(const string &command,int timeout, int infd, int outfd)
{
  vector <string> v;
  split(v, command, is_any_of(" "));

  const char *argv[v.size()+1];
  argv[v.size()]=0;

  for (size_t n = 0; n < v.size(); n++)
    argv[n]=v[n].c_str();
  // we get away with not copying since nobody resizes v 
  launch(argv, timeout, infd, outfd);
}

void CoProcess::launch(const char **argv, int timeout, int infd, int outfd)
{
  d_timeout=timeout;
  d_infd=infd;
  d_outfd=outfd;

  signal(SIGPIPE, SIG_IGN);

  if(access(argv[0],X_OK)) // check before fork so we can throw
    throw AhuException("Command '"+string(argv[0])+"' cannot be executed: "+stringerror());

  if(pipe(d_fd1)<0 || pipe(d_fd2)<0)
    throw AhuException("Unable to open pipe for coprocess: "+string(strerror(errno)));

  if((d_pid=fork())<0)
    throw AhuException("Unable to fork for coprocess: "+stringerror());
  else if(d_pid>0) { // parent speaking
    close(d_fd1[0]);
    Utility::setCloseOnExec(d_fd1[1]);
    close(d_fd2[1]);
    Utility::setCloseOnExec(d_fd2[0]);
    if(!(d_fp=fdopen(d_fd2[0],"r")))
      throw AhuException("Unable to associate a file pointer with pipe: "+stringerror());
    setbuf(d_fp,0); // no buffering please, confuses select
  }
  else if(!d_pid) { // child
    signal(SIGCHLD, SIG_DFL); // silence a warning from perl
    close(d_fd1[1]);
    close(d_fd2[0]);

    if(d_fd1[0]!= infd) {
      dup2(d_fd1[0], infd);
      close(d_fd1[0]);
    }

    if(d_fd2[1]!= outfd) {
      dup2(d_fd2[1], outfd);
      close(d_fd2[1]);
    }

    // stdin & stdout are now connected, fire up our coprocess!

    if(execv(argv[0], const_cast<char * const *>(argv))<0) // now what
      exit(123);

    /* not a lot we can do here. We shouldn't return because that will leave a forked process around.
       no way to log this either - only thing we can do is make sure that our parent catches this soonest! */
  }
}

CoProcess::~CoProcess()
{
  int status;
  if(!waitpid(d_pid, &status, WNOHANG)) {
    kill(d_pid, 9);
    waitpid(d_pid, &status, 0);
  }
  
  close(d_fd1[1]);
  fclose(d_fp);
}

void CoProcess::checkStatus()
{
  int status;
  int ret=waitpid(d_pid, &status, WNOHANG);
  if(ret<0) 
    throw AhuException("Unable to ascertain status of coprocess "+itoa(d_pid)+" from "+itoa(getpid())+": "+string(strerror(errno)));
  else if(ret) {
    if(WIFEXITED(status)) {
      int ret=WEXITSTATUS(status);
      throw AhuException("Coprocess exited with code "+itoa(ret));
    }
    if(WIFSIGNALED(status)) {
      int sig=WTERMSIG(status);
      string reason="CoProcess died on receiving signal "+itoa(sig);
#ifdef WCOREDUMP
      if(WCOREDUMP(status)) 
        reason+=". Dumped core";
#endif
      
      throw AhuException(reason);
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
      throw AhuException("Writing to coprocess failed: "+string(strerror(errno)));

    sent+=bytes;
  }
}

void CoProcess::receive(string &receive)
{
  receive.clear();
    
  if(d_timeout) {
    struct timeval tv={tv_sec: d_timeout/1000, tv_usec: (d_timeout % 1000) * 1000,};
    fd_set rds;
    FD_ZERO(&rds);
    FD_SET(fileno(d_fp),&rds);
    int ret=select(fileno(d_fp)+1,&rds,0,0,&tv);
    if(ret<0)
      throw AhuException("Error waiting on data from coprocess: "+stringerror());
    if(!ret)
      throw AhuException("Timeout waiting for data from coprocess");
  }

  if(!stringfgets(d_fp, receive))
    throw AhuException("Child closed pipe");
  
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
  d_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
  if(d_fd < 0)
    throw AhuException("Unable to create UNIX domain socket: "+string(strerror(errno)));

  struct sockaddr_un remote;
  memset(&remote, 0, sizeof(remote));
  remote.sun_family = AF_UNIX;
  memset(remote.sun_path, 0, sizeof(remote.sun_path));
  path.copy(remote.sun_path, sizeof(remote.sun_path), 0);

  // fcntl(fd, F_SETFL, O_NONBLOCK, &sock);

  if(connect(d_fd, (struct sockaddr*)&remote, sizeof(remote)) < 0)
    unixDie("Unable to connect to remote '"+path+"' using UNIX domain socket");

  d_fp = fdopen(d_fd, "r");
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
  catch(AhuException &ae) {
    cerr<<ae.reason<<endl;
  }
  
}
#endif
