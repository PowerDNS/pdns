// -*- sateh-c -*- 
// File    : pdnsbackend.cc
// Version : $Id: pipebackend.cc,v 1.4 2002/12/16 13:04:27 ahu Exp $ 
//

#include <string>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include "coprocess.hh"

using namespace std;

#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pipebackend.hh"

static const char *kBackendId = "[PIPEBackend]";

CoWrapper::CoWrapper(const string &command, int timeout)
{
   d_cp=0;
   d_command=command;
   d_timeout=timeout;
   launch(); // let exceptions fall through - if initial launch fails, we want to die
   // I think
}

void CoWrapper::launch()
{
   if(d_cp)
      return;

   d_cp=new CoProcess(d_command, d_timeout); 
   d_cp->send("HELO\t1");
   string banner;
   d_cp->receive(banner); 
   L<<Logger::Error<<"Backend launched with banner: "<<banner<<endl;
}

void CoWrapper::send(const string &line)
{
   launch();
   try {
      d_cp->send(line);
      return;
   }
   catch(AhuException &ae) {
      delete d_cp;
      d_cp=0;
      throw;
   }
}
void CoWrapper::receive(string &line)
{
   launch();
   try {
      d_cp->receive(line);
      return;
   }
   catch(AhuException &ae) {
      L<<Logger::Warning<<kBackendId<<" unable to receive data from coprocess. "<<ae.reason<<endl;
      delete d_cp;
      d_cp=0;
      throw;
   }
}

PipeBackend::PipeBackend(const string &suffix)
{
  setArgPrefix("pipe"+suffix);
   try {
      d_coproc=new CoWrapper(getArg("command"), getArgAsNum("timeout"));
      d_regex=getArg("regex").empty() ? 0 : new Regex(getArg("regex"));
      d_regexstr=getArg("regex");
   }
   catch(const ArgException &A) {
      L<<Logger::Error<<kBackendId<<" Fatal argument error: "<<A.reason<<endl;
      throw;
   }
   catch(...) {
      throw;
   }
}

void PipeBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p,  int zoneId)
{
   try {
      d_disavow=false;
      if(d_regex && !d_regex->match(qname+";"+qtype.getName())) { 
         if(arg().mustDo("query-logging"))
            L<<Logger::Error<<"Query for '"<<qname<<"' type '"<<qtype.getName()<<"' failed regex '"<<d_regexstr<<"'"<<endl;
         d_disavow=true; // don't pass to backend
      } else {
         ostringstream query;
         // type    qname           qclass  qtype   id      ip-address
         query<<"Q\t"<<qname<<"\tIN\t"<<qtype.getName()<<"\t"<<zoneId<<"\t"<<(pkt_p ? pkt_p->getRemote() : "0.0.0.0");
         if(arg().mustDo("query-logging"))
            L<<Logger::Error<<"Query: '"<<query.str()<<"'"<<endl;
         d_coproc->send(query.str());
      }
   }
   catch(AhuException &ae) {
      L<<Logger::Error<<kBackendId<<" Error from coprocess: "<<ae.reason<<endl;
      throw; // hop
   }
   d_qtype=qtype;
   d_qname=qname;
}

bool PipeBackend::list(int inZoneId)
{
   try {
      d_disavow=false;
      ostringstream query;
// The question format:

// type    qname           qclass  qtype   id      ip-address

      query<<"AXFR\t"<<inZoneId;

      d_coproc->send(query.str());
   }
   catch(AhuException &ae) {
      L<<Logger::Error<<kBackendId<<" Error from coprocess: "<<ae.reason<<endl;
      throw;
   }
   d_qname=itoa(inZoneId);
   return true;
}

//! For the dynamic loader
DNSBackend *PipeBackend::maker()
{
   try {
      return new PipeBackend();
   }
   catch(...) {
      L<<Logger::Error<<kBackendId<<" Unable to instantiate a pipebackend!"<<endl;
      return 0;
   }
}

PipeBackend::~PipeBackend()
{
   delete d_regex;
}

bool PipeBackend::get(DNSResourceRecord &r)
{
   if(d_disavow) // this query has been blocked
      return false;

   string line;

   // The answer format:
   // DATA    qname           qclass  qtype   ttl     id      content 

   for(;;) {
      d_coproc->receive(line);
      vector<string>parts;
      stringtok(parts,line,"\t");
      if(parts.empty()) {
         L<<Logger::Error<<kBackendId<<" coprocess returned emtpy line in query for "<<d_qname<<endl;
         throw AhuException("Format error communicating with coprocess");
      }
      else if(parts[0]=="END") {
         return false;
      }
      else if(parts[0]=="LOG") {
         L<<Logger::Error<<"Coprocess: "<<line.substr(4)<<endl;
         continue;
      }
      else if(parts[0]=="DATA") { // yay
         if(parts.size()<7) {
            L<<Logger::Error<<kBackendId<<" coprocess returned incomplete or empty line in data section for query for "<<d_qname<<endl;
            throw AhuException("Format error communicating with coprocess in data section");
            // now what?
         }
         r.qname=parts[1];
         r.qtype=parts[3];
         r.ttl=atoi(parts[4].c_str());
         r.domain_id=atoi(parts[5].c_str());

	 if(parts[3]!="MX")
	   r.content=parts[6];
	 else {
	   if(parts.size()<8) {
            L<<Logger::Error<<kBackendId<<" coprocess returned incomplete MX line in data section for query for "<<d_qname<<endl;
            throw AhuException("Format error communicating with coprocess in data section of MX record");
	   }
	   
	   r.priority=atoi(parts[6].c_str());
	   r.content=parts[7];
	 }
         break;
      }
      else
         throw AhuException("Coprocess backend sent incorrect response '"+line+"'");
   }   
   return true;
}

//
// Magic class that is activated when the dynamic library is loaded
//

class PipeFactory : public BackendFactory
{
   public:
      PipeFactory() : BackendFactory("pipe") {}

      void declareArguments(const string &suffix="")
      {
         declare(suffix,"command","Command to execute for piping questions to","");
         declare(suffix,"timeout","Number of milliseconds to wait for an answer","1000");
         declare(suffix,"regex","Regular exception of queries to pass to coprocess","");
      }

      DNSBackend *make(const string &suffix="")
      {
         return new PipeBackend(suffix);
      }
};

class PipeLoader
{
   public:
      PipeLoader()
      {
         BackendMakers().report(new PipeFactory);
         
         L<<Logger::Notice<<kBackendId<<" This is the pipebackend version "VERSION" ("__DATE__", "__TIME__") reporting"<<endl;
      }  
};

static PipeLoader pipeloader;

