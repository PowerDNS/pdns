#include "recbcomm.hh"
#include "nameserver.hh"
#include "packetcache.hh"
#include "packethandler.hh"

SyncresCommunicator::SyncresCommunicator()
{
  int sv[2];
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv)<0)
    throw AhuException("Unable to create socket for talking with recursing module: "+stringerror());

  if((d_pid=fork())<0)
    throw AhuException("Unable to fork for coprocess: "+stringerror());
  else if(d_pid>0) { // parent speaking
    d_fd=sv[0];
  }
  else if(!d_pid) { // child
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
  return 0;
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
  //        think about the negcache!!
  FILE *fp=fdopen(d_fd,"rw");
  setbuf(fp,0); // no buffering please, confuses select
  DNSPacket *P=0;
  string content, tuple;
  int entryttl;
  PacketHandler PH;
  DNSBackend *B=PH.getBackend();
  for(;;) {
    char *res=fgets(rline,sizeof(rline),fp);
    if(!res) {
      L<<Logger::Critical<<"Communications with syncres died!";
      if(!feof(fp))
	L<<" Error: "<<stringerror();
      L<<endl;
      exit(1);
    }
    line.assign(rline);
    stripLine(line);
    cout<<"Received line: '"<<line<<"' ("<<(void *)P<<", "<<tuple.empty()<<")"<<endl;
    vector<string>parts;
    stringtok(parts,line," ");
    if(!parts.empty()) {
      if(!P && tuple.empty()) {  //                 qdom   qt s  id   fl  remote         port rcode
	if(parts[0]=="P:") { // Received line: 'P: ds9a.nl 1 5 19803 22 104.250.255.191 5300 0'
	  P=new DNSPacket;
	  P->setQuestion(0,parts[1],atoi(parts[2].c_str()));
	  P->setSocket(atoi(parts[3].c_str()));
	  P->d.id=atoi(parts[4].c_str());
	  *((char *)&P->d+2)=atoi(parts[5].c_str()); // spoof in flags
	  P->setRA(true);
	  struct sockaddr_in toaddr;
	  struct in_addr inp;
	  Utility::inet_aton(parts[6].c_str(),&inp);
	  toaddr.sin_addr.s_addr=inp.s_addr;
	  
	  toaddr.sin_port=htons(atoi(parts[7].c_str())); // hmf
	  toaddr.sin_family=AF_INET;
	  P->setRemote((sockaddr *)&toaddr,sizeof(toaddr));

	  P->setRcode(atoi(parts[8].c_str()));
	}
	if(parts[0]=="Q:") { // Received line: 'Q: lwn.net. 5'     // question
	  extern PacketCache PC;
	  QType qt;
	  qt=atoi(parts[2].c_str());

	  B->lookup(qt,parts[1]);
	  DNSResourceRecord rr;
	  content="";
	  while(B->get(rr)) 
	    content+=rr.serialize()+"\n";
	  if(content.empty()) 
	    PC.getKey(toLower(parts[1])+"|S|"+qt.getName(),content); // lwn.net.|S|NS
	  else
	    L<<Logger::Error<<"Authoritive data!"<<endl;

	  if(content.empty())
	    L<<Logger::Error<<"no hit ("<<toLower(parts[1])+"|S|"+qt.getName()<<")"<<endl;
	  else
	    L<<Logger::Error<<"hit: "<<content<<endl;

	  content+="\n";
	  write(d_fd,content.c_str(),content.size());

	}
	if(parts[0]=="A:") { // Received line: 'A: powerdns.com. 6 1000'   // cache push
	  L<<Logger::Error<<"Start of cache push"<<endl;

	  tuple=toLower(parts[1])+"|S|";
	  QType qt; qt=atoi(parts[2].c_str());
	  tuple+=qt.getName();
	  entryttl=atoi(parts[3].c_str());
	  content="";
	}
      }
      else {
	if(P) {
	L<<Logger::Error<<"Got part of packet to send out"<<endl;
	DNSResourceRecord rr;
	rr.unSerialize(line.substr(1));
	rr.d_place=(DNSResourceRecord::Place)(line[0]-'0');
	P->addRecord(rr);
	}
	else if(!tuple.empty()) {
	  L<<Logger::Error<<"Got cache content line"<<endl;
	  content+=line+"\n";
	}
      }

    }
    else {
      if(P) {
	L<<Logger::Error<<"Sending packet"<<endl;
	P->wrapup();
	UDPNameserver::send(P);
	delete P;
	P=0;
      }
      if(!tuple.empty()) {
	extern PacketCache PC;
	PC.insert(tuple,content,entryttl);
	L<<Logger::Error<<"Inserting in cache done ("<<tuple<<", "<<entryttl<<", '"<<content<<"')"<<endl;
	tuple="";

      }
    }
  }
}

void SyncresCommunicator::giveQuestion(DNSPacket *p)
{
  string line;
  
  // -> www.powerdns.com A 1 1234 123
  line=p->qdomain+" "+itoa(p->qtype.getCode())+" "+itoa(p->getSocket())+" "+itoa(p->d.id)+" ";
  line+= itoa(*(((char*)&p->d)+2)) +" "+p->getRemote()+" "+itoa(p->getRemotePort())+"\n"; // first part are the flags (ick)
  if(write(d_fd,line.c_str(),line.size())<0)
    throw AhuException("Unable to write line to recursion module: "+stringerror());
  L<<Logger::Error<<"Gave question to syncres"<<endl;
}
