#include <fstream>
#include <iostream>
#include <string>
#include <set>
#include <utility>
#include "dnspacket.hh"
#include "qtype.hh"
#include "dns.hh"
#include "logger.hh"
#include "statbag.hh"
#include "arguments.hh"
#include "ws.hh"
#include "argtng.hh"
using namespace std;
Logger L;
StatBag S;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

class QGen
{
  struct OutstandingQuestion
  {
    string qname;
    QType qtype;
    u_int16_t id;
    double timeSent;
    bool operator< (const OutstandingQuestion &rhs) const
    {
      if(qname < rhs.qname)
	return true;
      if(qname > rhs.qname)
	return false;
      return id < rhs.id;
    }
    bool operator==(const OutstandingQuestion &rhs) const
    {
      return qname==rhs.qname && id==rhs.id && qtype==rhs.qtype;
    }
  };

  multiset<OutstandingQuestion> d_questions;
  multiset<OutstandingQuestion> d_unanswered;

  vector<string> d_new;

  struct sockaddr_in d_toaddr;
  ifstream d_in;

  unsigned int d_port;
  unsigned int d_numqueries;
  unsigned int d_maxOutstanding;
  unsigned int d_maxToRead;
  unsigned int d_timeout;
  unsigned int d_answeredOK;
  unsigned int d_delayed;
  unsigned int d_unmatched;
  unsigned int d_maxBurst;
  unsigned int d_servfail;
  unsigned int d_nxdomain;
  time_t d_laststats;
  int d_clientsock;
  string d_server;
  Ewma d_ewma;

  void unixDie(const string &why);
  int fillAndSendQuestions();
  void processAnswers();
  void pruneUnanswered();

  static bool tooOld(const OutstandingQuestion &oq);
  void printStats(bool force=false);

public:
  void sendQuestion(const string& qname, QType qtype);
  QGen(const string &server, unsigned int port, const string &fileName,
       unsigned int maxOutstanding, unsigned int maxBurst, unsigned int maxToRead, unsigned int timeout);
  void start();

};

void QGen::unixDie(const string &why)
{
  cerr<<"Fatal error, "<<why<<": "<<strerror(errno)<<endl;
  exit(1);
}


QGen::QGen(const string &server,
	   unsigned int port,
	   const string &fileName,
	   unsigned int maxOutstanding,
	   unsigned int maxBurst,
	   unsigned int maxToRead,
	   unsigned int timeout) : d_in(fileName.c_str())
{
  d_answeredOK = d_numqueries = d_delayed = d_unmatched = d_servfail = d_nxdomain = 0;

  if(!d_in)
    unixDie("unable to open '"+fileName+"'");

  d_maxOutstanding = maxOutstanding;
  d_maxToRead = maxToRead;
  d_maxBurst=maxBurst;
  d_timeout=timeout;
  struct in_addr inp;
  Utility::inet_aton(server.c_str(),&inp);
  d_toaddr.sin_addr.s_addr=inp.s_addr;

  d_toaddr.sin_port=htons(port);
  d_toaddr.sin_family=AF_INET;

  d_clientsock=socket(AF_INET, SOCK_DGRAM,0);
  if(d_clientsock<0) 
    throw AhuException("Making a socket for resolver: "+stringerror());
  
  struct sockaddr_in sin;
  memset((char *)&sin,0, sizeof(sin));
  
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port=0;

  if (bind(d_clientsock, (struct sockaddr *)&sin, sizeof(sin))<0) 
    unixDie("binding to socket");

}

void QGen::pruneUnanswered()
{
  double now=getTime();

  for(multiset<OutstandingQuestion>::iterator i=d_questions.begin();i!=d_questions.end();) 
    if(now-i->timeSent > d_timeout) {
      cerr<<"No answer received to question for "<<i->qname<<endl;
      cout<<i->qname<<" "<<i->qtype.getName()<<" NO ANSWER"<<endl;
      d_unanswered.insert(*i);
      d_questions.erase(i++);

    }
    else
      ++i;

}

int QGen::fillAndSendQuestions()
{
  unsigned int wantToRead=d_maxOutstanding-d_questions.size();
  string line;
  int burst(d_maxBurst);
  while(!d_in.eof() && wantToRead-- && burst--) {
    getline(d_in,line);
    chomp(line,"\r\n\t ");
    vector<string> words;
    stringtok(words,line," \t\n");

    if(!line.empty()) {
      int a,b,c,d;
      if(line.find_first_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")==string::npos && 
	 sscanf(line.c_str(),"%d.%d.%d.%d",&a,&b,&c,&d)==4) {
	ostringstream ostr;
	ostr<<d<<"."<<c<<"."<<b<<"."<<a<<".in-addr.arpa";
	sendQuestion(ostr.str(),QType(QType::PTR));

      }
      else
	sendQuestion(words[0],(words.size() > 1) ? QType(QType::chartocode(words[1].c_str())) : QType(QType::A));
    }
  }
  return d_questions.size();
}

void QGen::sendQuestion(const string& qname, QType qtype)
{
  DNSPacket p;
  p.setQuestion(Opcode::Query,qname,qtype.getCode());
  // set p.d.id here?
  p.setRD(true);

  p.wrapup();

  if(sendto(d_clientsock, p.getData(), p.len, 0, (struct sockaddr*)(&d_toaddr), sizeof(d_toaddr))<0) 
    unixDie("error sending packet");

  OutstandingQuestion oq;
  oq.id=p.d.id;
  oq.qname=qname;
  oq.qtype=qtype;
  oq.timeSent=getTime();
  
  d_questions.insert(oq);
  d_numqueries++;
  //  cout<<"Sent packet with question "<<qname<<" and id "<<p.d.id<<": "<<d_questions.size()<<endl;
}

void QGen::printStats(bool force)
{
  if(!force && time(0)==d_laststats )
    return;
  d_laststats=time(0);
  cerr.precision(2);
  cerr.setf(ios::fixed);
  cerr<<"Sent "<<d_numqueries<<", "<<d_answeredOK<<" OK, ";
  cerr<<d_questions.size()<<" outstanding, ";
  cerr<<d_servfail<<" failed, ";

  cerr<<d_nxdomain<<" NXDOMAIN, ";
  cerr<<d_unanswered.size()<<" unanswered, "<<d_delayed<<" delayed, "<<d_unmatched<<" unmatched, "<<d_ewma.get1()<<"/s"<<endl;
  d_ewma.submit(d_answeredOK + d_delayed + d_nxdomain + d_servfail);

}

void QGen::start()
{

  while(fillAndSendQuestions()) {
    printStats();
    processAnswers();
    pruneUnanswered();
  }

  time_t end=time(0)+60;
  while(time(0)<end && !d_unanswered.empty()) {
    processAnswers();
    printStats();
  }
  printStats(1);
}

void QGen::processAnswers()
{
  unsigned char buf[1500];
  struct sockaddr_in fromaddr;
  socklen_t addrlen=sizeof(fromaddr);
  unsigned int len;
  bool first(true);

  while(waitForData(d_clientsock, first ? 1 : 0) > 0) {
    first=false;
    len=recvfrom(d_clientsock, reinterpret_cast<char *>(buf), sizeof(buf)-1,0,(struct sockaddr*)(&fromaddr), &addrlen);

    DNSPacket p;
    vector<DNSResourceRecord> answers;
    try {
      if(p.parse((char *)buf, len)<0) {
	cerr<<"resolver: unable to parse packet of "+itoa(len)+" bytes"<<endl;
	continue;
      }
      
      answers= p.getAnswers();
    }
    catch(...) {
      cerr<<"Got an error parsing packet"<<endl;
      continue;
    }
    
    OutstandingQuestion oq;
    oq.qname=p.qdomain;
    oq.id=p.d.id;
    oq.qtype=p.qtype;
    multiset<OutstandingQuestion>::const_iterator i=d_questions.find(oq);
    if(i==d_questions.end()) {
      if(d_unanswered.count(oq)) {
	d_delayed++;
	cerr<<"Delayed answer for "<<p.qdomain<<" came in anyhow"<<endl;
	d_unanswered.erase(oq);
      }
      else {
	d_unmatched++;
	cerr<<"Unmatched answer, question: "<<p.qdomain<<endl;
	cout<<p.qdomain<<"\tMATCH_ERROR"<<endl;
      }
    }
    else {
      if(p.d.rcode==RCode::ServFail) {
	d_servfail++;
	d_questions.erase(oq);
	cout<<p.qdomain<<"\tSERVFAIL"<<endl;
	continue;
      }
      
      if(p.d.rcode==RCode::NXDomain) {
	d_nxdomain++;
	d_questions.erase(oq);
	cout<<p.qdomain<<" "<<p.qtype.getName()<<" NXDOMAIN"<<endl;
	continue;
      }

      bool gotOne(false);
      for(vector<DNSResourceRecord>::const_iterator j=answers.begin();j!=answers.end();++j)
	if(j->d_place==DNSResourceRecord::ANSWER) {
	  gotOne=true;
	  cout<<p.qdomain<<" "<<p.qtype.getName()<<" OK ";
	  if(j->qtype.getCode()==QType::MX)
	    cout<<j->priority<<"|"<<j->content;
	  else
	    cout<<j->content;
	  cout<<"\n";
	}

      //      if(!gotOne)
      //	cout<<p.qdomain<<" "<<p.qtype.getName()<<" NO RECORD"<<endl;

      d_answeredOK++;
      d_questions.erase(i);
    }

  }
}

int main(int argc, char **argv)
try
{
  ArgTng at;
  at.add("questions");
  at.add("server",IpAddress(),"127.0.0.1");
  at.add("port",Numeric(),"5300");
  at.add("max-burst",Numeric(),"50");
  at.add("max-outstanding",Numeric(),"200");
  at.add("max-questions",Numeric(),"0");
  at.add("timeout",Numeric(),"30");
  at.parse(argc, argv);
  at.constraints();
  arg().set("no-shuffle","Don't change")="off";

  string fileName=at.get("questions");
  string server=at.get("server");
  unsigned int port=at.getInt("port");
  unsigned int maxBurst=at.getInt("max-burst");
  unsigned int maxOutstanding=at.getInt("max-outstanding");
  unsigned int maxToRead=at.getInt("max-questions");
  unsigned int timeout=at.getInt("timeout");

  // parse commandline here

  QGen qg(server, port, fileName, maxOutstanding, maxBurst, maxToRead, timeout);
  qg.start();

}
catch(runtime_error &re)
{
  cerr<<"Fatal: "<<re.what()<<endl;
}
catch(exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
/*
catch(...)
{
  cerr<<"Unknown fatal exception"<<endl;
}
*/
