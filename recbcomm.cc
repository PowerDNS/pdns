#include "recbcomm.hh"

SyncresCommunicator::SyncresCommunicator()
{
  int sv[2];
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv)<0)
    throw AhuException("Unable to create socket for talking with recursing module: "+stringerror());

  if((d_pid=fork())<0)
    throw AhuException("Unable to fork for coprocess: "+stringerror());
  else if(d_pid>0) { // parent speaking
    close(sv[1]);
    d_fd=sv[0];
  }
  else if(!d_pid) { // child
    close(sv[0]);
    const char *argv[3];
    argv[0]="./syncres";
    argv[1]=strdup(itoa(sv[1]).c_str());
    argv[2]=0;
    if(execv(argv[0], const_cast<char * const *>(argv))<0) // now what
      exit(123);
    // we gone 
  }
  pthread_create(&d_tid,0,threadHelper,this);  


}

void *SyncresCommunicator::threadHelper(void *self)
{
  ((SyncresCommunicator *)self)->thread();
}

void SyncresCommunicator::thread()
{
  char rline[1024];
  string line;

  //   it can receive: 
  //        
  //        cache inserts (1 line + content lines, terminated with an empty line)
  //        cache lookups (1 line)
  //        packets (1 line + content lines, terminated with an empty line)


  for(;;) {
    int res=read(d_fd,rline,sizeof(rline));
    if(res<=0) {
      L<<Logger::Critical<<"Communications with syncres died!"<<endl;
      exit(1);
    }
    line.assign(rline,res);
    cout<<"Received line: '"<<line<<"'"<<endl;
  }
}

void SyncresCommunicator::giveQuestion(DNSPacket *p)
{
  string line;
  
  // -> www.powerdns.com A 1 1234 123
  line=p->qdomain+" "+itoa(p->qtype.getCode())+" "+itoa(p->getSocket())+" "+itoa(p->d.id)+"\n";
  if(write(d_fd,line.c_str(),line.size())<0)
    throw AhuException("Unable to write line to recursion module: "+stringerror());

}
