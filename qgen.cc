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
  unsigned int d_answeredOK;
  unsigned int d_delayed;
  unsigned int d_unmatched;
  time_t d_laststats;
  int d_clientsock;
  string d_server;
  Ewma d_ewma;

  void unixDie(const string &why);
  int fillAndSendQuestions();
  void processAnswers();
  void pruneUnanswered();
  void sendQuestion(const string& qname, QType qtype);
  static bool tooOld(const OutstandingQuestion &oq);
  void printStats(bool force=false);

public:
  QGen(const string &server, unsigned int port, const string &fileName,
       unsigned int maxOutstanding, unsigned int maxToRead);
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
	   unsigned int maxToRead) : d_in(fileName.c_str())
{
  d_answeredOK = d_numqueries = d_delayed = d_unmatched =0;

  if(!d_in)
    unixDie("unable to open '"+fileName+"'");

  d_maxOutstanding = maxOutstanding;
  d_maxToRead = maxToRead;

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
    if(now-i->timeSent > 5) {
      cout<<"No answer received to question for "<<i->qname<<endl;
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
  int burst=50;

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
  cout<<"Sent "<<d_numqueries<<" questions, "<<d_answeredOK<<" OK answers, ";
  cout<<d_unanswered.size()<<" unanswered, "<<d_delayed<<" delayed, "<<d_unmatched<<" unmatched, "<<d_ewma.get1()<<"/s"<<endl;
  d_ewma.submit(d_answeredOK);

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

    /*
    cout<<"Packet: "<<p.d.id<<", "<<p.qdomain<<", rcode="<<p.d.rcode<<", ";
    if(answers.empty())
      cout<<"NO ANSWER"<<endl;
    else cout<<answers[0].content<<endl;
    */

    OutstandingQuestion oq;
    oq.qname=p.qdomain;
    oq.id=p.d.id;
    oq.qtype=p.qtype;
    multiset<OutstandingQuestion>::const_iterator i=d_questions.find(oq);
    if(i==d_questions.end()) {
      if(d_unanswered.count(oq)) {
	d_delayed++;
	d_answeredOK++;
	cout<<"Delayed answer for "<<p.qdomain<<" came in anyhow"<<endl;
	d_unanswered.erase(oq);
      }
      else {
	d_unmatched++;
	cout<<"Unmatched answer, question: "<<p.qdomain<<endl;
      }
    }
    else {
      for(vector<DNSResourceRecord>::const_iterator j=answers.begin();j!=answers.end();++j)
	cout<<p.qdomain<<"\t"<<j->content<<endl;
      d_answeredOK++;
      d_questions.erase(i);
    }

  }
}

int main(int argc, char **argv)
{
  string fileName="./questions";
  string server="127.0.0.1";
  unsigned int port=53;
  unsigned int maxOutstanding=500;
  unsigned int maxToRead=1000000;

  // parse commandline here

  QGen qg(server, port, fileName, maxOutstanding, maxToRead);
  qg.start();
}
