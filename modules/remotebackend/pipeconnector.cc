#include <sys/types.h>
#include <sys/wait.h>
#include "remotebackend.hh"

PipeConnector::PipeConnector(std::map<std::string,std::string> options) {
  if (options.count("command") == 0) {
    L<<Logger::Error<<"Cannot find 'command' option in connection string"<<endl;
    throw new AhuException();
  }
  this->command = options.find("command")->second;
  this->options = options;
  d_timeout=2000;

  if (options.find("timeout") != options.end()) {
     d_timeout = boost::lexical_cast<int>(options.find("timeout")->second);
  }

  d_pid = -1;
  d_fp = NULL;
  launch();
}

PipeConnector::~PipeConnector(){
  int status;
  // just in case...
  if (d_pid == -1) return;

  if(!waitpid(d_pid, &status, WNOHANG)) {
    kill(d_pid, 9);
    waitpid(d_pid, &status, 0);
  }

  close(d_fd1[1]);
  if (d_fp != NULL) fclose(d_fp);
}

void PipeConnector::launch() {
  // no relaunch
  if (d_pid > 0 && checkStatus()) return;

  std::vector <std::string> v;
  split(v, command, is_any_of(" "));

  const char *argv[v.size()+1];
  argv[v.size()]=0;

  for (size_t n = 0; n < v.size(); n++)
    argv[n]=v[n].c_str();

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

    if(d_fd1[0]!= 0) {
      dup2(d_fd1[0], 0);
      close(d_fd1[0]);
    }

    if(d_fd2[1]!= 1) {
      dup2(d_fd2[1], 1);
      close(d_fd2[1]);
    }

    // stdin & stdout are now connected, fire up our coprocess!

    if(execv(argv[0], const_cast<char * const *>(argv))<0) // now what
      exit(123);

    /* not a lot we can do here. We shouldn't return because that will leave a forked process around.
       no way to log this either - only thing we can do is make sure that our parent catches this soonest! */
  }

  rapidjson::Value val;
  rapidjson::Document init,res;
  init.SetObject();
  val = "initialize";

  init.AddMember("method",val, init.GetAllocator());
  val.SetObject();
  init.AddMember("parameters", val, init.GetAllocator());

  for(std::map<std::string,std::string>::iterator i = options.begin(); i != options.end(); i++) {
    val = i->second.c_str();
    init["parameters"].AddMember(i->first.c_str(), val, init.GetAllocator());
  }

  this->send(init);
  if (this->recv(res)==false) {
    L<<Logger::Error<<"Failed to initialize coprocess"<<std::endl;
  }
}

int PipeConnector::send_message(const rapidjson::Document &input)
{
   std::string line;
   line = makeStringFromDocument(input);
   launch();

   line.append(1,'\n');

   unsigned int sent=0;
   int bytes;

   // writen routine - socket may not accept al data in one go
   while(sent<line.size()) {
     bytes=write(d_fd1[1],line.c_str()+sent,line.length()-sent);
     if(bytes<0)
       throw AhuException("Writing to coprocess failed: "+std::string(strerror(errno)));

     sent+=bytes;
   }
   return sent;
}

int PipeConnector::recv_message(rapidjson::Document &output) 
{
   std::string receive;
   rapidjson::GenericReader<rapidjson::UTF8<> , rapidjson::MemoryPoolAllocator<> > r;
   std::string tmp;
   std::string s_output;
   launch();

   while(1) {
     receive.clear();
     if(d_timeout) {
       struct timeval tv;
       tv.tv_sec = d_timeout/1000;
       tv.tv_usec = (d_timeout % 1000) * 1000;
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
  
      s_output.append(receive);
      rapidjson::StringStream ss(s_output.c_str());
      output.ParseStream<0>(ss); 
      if (output.HasParseError() == false)
        return s_output.size();
   }
   return 0;
}

bool PipeConnector::checkStatus()
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
  return true;
}
