// -*- sateh-c -*- 
// File    : pdnsbackend.cc
// Version : $Id$ 
//

#include <string>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include "coprocess.hh"

#include "pdns/namespaces.hh"

#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/pdnsexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <boost/lexical_cast.hpp>
#include "pipebackend.hh"

static const char *kBackendId = "[PIPEBackend]";

CoWrapper::CoWrapper(const string &command, int timeout)
{
   d_cp=0;
   d_command=command;
   d_timeout=timeout;
   d_abiVersion = ::arg().asNum("pipebackend-abi-version");
   launch(); // let exceptions fall through - if initial launch fails, we want to die
   // I think
}

CoWrapper::~CoWrapper()
{
  if(d_cp)
    delete d_cp;
}


void CoWrapper::launch()
{
   if(d_cp)
      return;

   if(isUnixSocket(d_command))
     d_cp = new UnixRemote(d_command, d_timeout);
   else
     d_cp = new CoProcess(d_command, d_timeout); 
   d_cp->send("HELO\t"+lexical_cast<string>(d_abiVersion));
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
   catch(PDNSException &ae) {
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
   catch(PDNSException &ae) {
      L<<Logger::Warning<<kBackendId<<" unable to receive data from coprocess. "<<ae.reason<<endl;
      delete d_cp;
      d_cp=0;
      throw;
   }
}

PipeBackend::PipeBackend(const string &suffix)
{
   signal(SIGCHLD, SIG_IGN);
   setArgPrefix("pipe"+suffix);
   try {
     d_coproc=shared_ptr<CoWrapper>(new CoWrapper(getArg("command"), getArgAsNum("timeout")));
     d_regex=getArg("regex").empty() ? 0 : new Regex(getArg("regex"));
     d_regexstr=getArg("regex");
     d_abiVersion = ::arg().asNum("pipebackend-abi-version");
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
         if(::arg().mustDo("query-logging"))
            L<<Logger::Error<<"Query for '"<<qname<<"' type '"<<qtype.getName()<<"' failed regex '"<<d_regexstr<<"'"<<endl;
         d_disavow=true; // don't pass to backend
      } else {
         ostringstream query;
         string localIP="0.0.0.0";
         string remoteIP="0.0.0.0";
         Netmask realRemote("0.0.0.0/0");
         if (pkt_p) {
            localIP=pkt_p->getLocal();
            realRemote = pkt_p->getRealRemote();
            remoteIP = pkt_p->getRemote();
         }
         // pipebackend-abi-version = 1
         // type    qname           qclass  qtype   id      remote-ip-address
         query<<"Q\t"<<qname<<"\tIN\t"<<qtype.getName()<<"\t"<<zoneId<<"\t"<<remoteIP;

         // add the local-ip-address if pipebackend-abi-version is set to 2
         if (d_abiVersion >= 2)
            query<<"\t"<<localIP;
         if(d_abiVersion >= 3)
           query <<"\t"<<realRemote.toString(); 

         if(::arg().mustDo("query-logging"))
            L<<Logger::Error<<"Query: '"<<query.str()<<"'"<<endl;
         d_coproc->send(query.str());
      }
   }
   catch(PDNSException &ae) {
      L<<Logger::Error<<kBackendId<<" Error from coprocess: "<<ae.reason<<endl;
      throw; // hop
   }
   d_qtype=qtype;
   d_qname=qname;
}

bool PipeBackend::list(const string &target, int inZoneId, bool include_disabled)
{
   try {
      d_disavow=false;
      ostringstream query;
// The question format:

// type    qname           qclass  qtype   id      ip-address
      if (d_abiVersion >= 4)
        query<<"AXFR\t"<<inZoneId<<"\t"<<target;
      else
        query<<"AXFR\t"<<inZoneId;

      d_coproc->send(query.str());
   }
   catch(PDNSException &ae) {
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
   unsigned int extraFields = 0;
   if(d_abiVersion >= 3)
     extraFields = 2;
     
   for(;;) {
      d_coproc->receive(line);
      vector<string>parts;
      stringtok(parts,line,"\t");
      if(parts.empty()) {
         L<<Logger::Error<<kBackendId<<" coprocess returned emtpy line in query for "<<d_qname<<endl;
         throw PDNSException("Format error communicating with coprocess");
      }
      else if(parts[0]=="FAIL") {
         throw DBException("coprocess returned a FAIL");
      }
      else if(parts[0]=="END") {
         return false;
      }
      else if(parts[0]=="LOG") {
         L<<Logger::Error<<"Coprocess: "<<line.substr(4)<<endl;
         continue;
      }
      else if(parts[0]=="DATA") { // yay
         if(parts.size() < 7 + extraFields) {
            L<<Logger::Error<<kBackendId<<" coprocess returned incomplete or empty line in data section for query for "<<d_qname<<endl;
            throw PDNSException("Format error communicating with coprocess in data section");
            // now what?
         }
         
         if(d_abiVersion >= 3) {
           r.scopeMask = atoi(parts[1].c_str());
           r.auth = atoi(parts[2].c_str());
         } else {
           r.scopeMask = 0;
           r.auth = 1;
         }
         r.qname=parts[1+extraFields];
         r.qtype=parts[3+extraFields];
         r.ttl=atoi(parts[4+extraFields].c_str());
         r.domain_id=atoi(parts[5+extraFields].c_str());
         
         if(r.qtype.getCode() != QType::MX && r.qtype.getCode() != QType::SRV) {
           r.content.clear();
           for(unsigned int n= 6 + extraFields; n < parts.size(); ++n) {
             if(n!=6+extraFields)
               r.content.append(1,' ');
             r.content.append(parts[n]);
           }
         }
         else {
           if(parts.size()< 8 + extraFields) {
            L<<Logger::Error<<kBackendId<<" coprocess returned incomplete MX/SRV line in data section for query for "<<d_qname<<endl;
            throw PDNSException("Format error communicating with coprocess in data section of MX/SRV record");
           }
           
           r.priority=atoi(parts[6+extraFields].c_str());
           r.content=parts[7+extraFields];
         }
         break;
      }
      else
         throw PDNSException("Coprocess backend sent incorrect response '"+line+"'");
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
         declare(suffix,"timeout","Number of milliseconds to wait for an answer","2000");
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
         L << Logger::Info << kBackendId <<" This is the pipe backend version " VERSION " reporting" << endl;
      }  
};

static PipeLoader pipeloader;

