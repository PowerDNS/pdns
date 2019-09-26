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
#include <string>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include "coprocess.hh"

#include "pdns/namespaces.hh"

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pipebackend.hh"

static const char *kBackendId = "[PIPEBackend]";

CoWrapper::CoWrapper(const string &command, int timeout, int abiVersion)
{
   d_command=command;
   d_timeout=timeout;
   d_abiVersion = abiVersion;
   launch(); // let exceptions fall through - if initial launch fails, we want to die
   // I think
}

CoWrapper::~CoWrapper()
{
}

void CoWrapper::launch()
{
   if(d_cp)
      return;

   if(d_command.empty())
     throw ArgException("pipe-command is not specified");

   if(isUnixSocket(d_command)) {
     d_cp = std::unique_ptr<CoRemote>(new UnixRemote(d_command, d_timeout));
   }
   else {
     auto coprocess = std::unique_ptr<CoProcess>(new CoProcess(d_command, d_timeout));
     coprocess->launch();
     d_cp = std::move(coprocess);
   }

   d_cp->send("HELO\t"+std::to_string(d_abiVersion));
   string banner;
   d_cp->receive(banner);
   g_log<<Logger::Error<<"Backend launched with banner: "<<banner<<endl;
}

void CoWrapper::send(const string &line)
{
   launch();
   try {
      d_cp->send(line);
      return;
   }
   catch(PDNSException &ae) {
      d_cp.reset();
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
      g_log<<Logger::Warning<<kBackendId<<" Unable to receive data from coprocess. "<<ae.reason<<endl;
      d_cp.reset();
      throw;
   }
}

PipeBackend::PipeBackend(const string &suffix)
{
   d_disavow=false;
   signal(SIGCHLD, SIG_IGN);
   setArgPrefix("pipe"+suffix);
   try {
     launch();
   }
   catch(const ArgException &A) {
      g_log<<Logger::Error<<kBackendId<<" Unable to launch, fatal argument error: "<<A.reason<<endl;
      throw;
   }
   catch(...) {
      throw;
   }
}

void PipeBackend::launch()
{
  if(d_coproc)
    return;

  try {
    if (!getArg("regex").empty()) {
      d_regex = std::unique_ptr<Regex>(new Regex(getArg("regex")));
    }
    d_regexstr=getArg("regex");
    d_abiVersion = getArgAsNum("abi-version");
    d_coproc=unique_ptr<CoWrapper> (new CoWrapper(getArg("command"), getArgAsNum("timeout"), getArgAsNum("abi-version")));
  }

  catch(const ArgException &A) {
    cleanup();
    throw;
  }
}

/*
 * Cleans up the co-process wrapper
 */
void PipeBackend::cleanup()
{
  d_coproc.reset(0);
  d_regex.reset();
  d_regexstr = string();
  d_abiVersion = 0;
}

void PipeBackend::lookup(const QType& qtype,const DNSName& qname, int zoneId, DNSPacket *pkt_p)
{
  try {
    launch();
    d_disavow=false;
    if(d_regex && !d_regex->match(qname.toStringRootDot())) {
      if(::arg().mustDo("query-logging"))
        g_log<<Logger::Error<<"Query for '"<<qname<<"' failed regex '"<<d_regexstr<<"'"<<endl;
      d_disavow=true; // don't pass to backend
    } else {
      ostringstream query;
      string localIP="0.0.0.0";
      string remoteIP="0.0.0.0";
      Netmask realRemote("0.0.0.0/0");
      if (pkt_p) {
        localIP=pkt_p->getLocal().toString();
        realRemote = pkt_p->getRealRemote();
        remoteIP = pkt_p->getRemote().toString();
      }
      // abi-version = 1
      // type    qname           qclass  qtype   id      remote-ip-address
      query<<"Q\t"<<qname.toStringRootDot()<<"\tIN\t"<<qtype.getName()<<"\t"<<zoneId<<"\t"<<remoteIP;

      // add the local-ip-address if abi-version is set to 2
      if (d_abiVersion >= 2)
        query<<"\t"<<localIP;
      if(d_abiVersion >= 3)
        query <<"\t"<<realRemote.toString(); 

      if(::arg().mustDo("query-logging"))
        g_log<<Logger::Error<<"Query: '"<<query.str()<<"'"<<endl;
      d_coproc->send(query.str());
    }
  }
  catch(PDNSException &pe) {
    g_log<<Logger::Error<<kBackendId<<" Error from coprocess: "<<pe.reason<<endl;
    d_disavow = true;
  }
  d_qtype=qtype;
  d_qname=qname;
}

bool PipeBackend::list(const DNSName& target, int inZoneId, bool include_disabled)
{
  try {
    launch();
    d_disavow=false;
    ostringstream query;
    // The question format:

    // type    qname           qclass  qtype   id      ip-address
    if (d_abiVersion >= 4)
      query<<"AXFR\t"<<inZoneId<<"\t"<<target.toStringRootDot();
    else
      query<<"AXFR\t"<<inZoneId;

    d_coproc->send(query.str());
  }
  catch(PDNSException &ae) {
    g_log<<Logger::Error<<kBackendId<<" Error from coprocess: "<<ae.reason<<endl;
  }
  d_qname=DNSName(itoa(inZoneId)); // why do we store a number here??
  return true;
}

string PipeBackend::directBackendCmd(const string &query) {
  if (d_abiVersion < 5)
    return "not supported on ABI version " + std::to_string(d_abiVersion) + " (use ABI version 5 or later)\n";

  try {
    launch();
    ostringstream oss;
    oss<<"CMD\t"<<query;
    d_coproc->send(oss.str());
  }
  catch(PDNSException &ae) {
    g_log<<Logger::Error<<kBackendId<<" Error from coprocess: "<<ae.reason<<endl;
    cleanup();
  }

  ostringstream oss;
  while(true) {
    string line;
    d_coproc->receive(line);
    if (line == "END") break;
    oss << line << std::endl;
  };

  return oss.str();
}

//! For the dynamic loader
DNSBackend *PipeBackend::maker()
{
   try {
      return new PipeBackend();
   }
   catch(...) {
      g_log<<Logger::Error<<kBackendId<<" Unable to instantiate a pipebackend!"<<endl;
      return 0;
   }
}

PipeBackend::~PipeBackend()
{
  cleanup();
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

  try{
    launch();
    for(;;) {
      d_coproc->receive(line);
      vector<string>parts;
      stringtok(parts,line,"\t");
      if(parts.empty()) {
        g_log<<Logger::Error<<kBackendId<<" Coprocess returned empty line in query for "<<d_qname<<endl;
        throw PDNSException("Format error communicating with coprocess");
      }
      else if(parts[0]=="FAIL") {
        throw DBException("coprocess returned a FAIL");
      }
      else if(parts[0]=="END") {
        return false;
      }
      else if(parts[0]=="LOG") {
        g_log<<Logger::Error<<"Coprocess: "<<line.substr(4)<<endl;
        continue;
      }
      else if(parts[0]=="DATA") { // yay
        if(parts.size() < 7 + extraFields) {
          g_log<<Logger::Error<<kBackendId<<" Coprocess returned incomplete or empty line in data section for query for "<<d_qname<<endl;
          throw PDNSException("Format error communicating with coprocess in data section");
          // now what?
        }

         if(d_abiVersion >= 3) {
           r.scopeMask = std::stoi(parts[1]);
           r.auth = (parts[2] == "1");
         } else {
           r.scopeMask = 0;
           r.auth = 1;
         }
         r.qname=DNSName(parts[1+extraFields]);
         r.qtype=parts[3+extraFields];
         r.ttl=pdns_stou(parts[4+extraFields]);
         r.domain_id=std::stoi(parts[5+extraFields]);

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
            g_log<<Logger::Error<<kBackendId<<" Coprocess returned incomplete MX/SRV line in data section for query for "<<d_qname<<endl;
            throw PDNSException("Format error communicating with coprocess in data section of MX/SRV record");
          }

          r.content=parts[6+extraFields]+" "+parts[7+extraFields];
        }
        break;
      }
      else
        throw PDNSException("Coprocess backend sent incorrect response '"+line+"'");
    }
  }
  catch (DBException &dbe) {
    g_log<<Logger::Error<<kBackendId<<" "<<dbe.reason<<endl;
    throw;
  }
  catch (PDNSException &pe) {
    g_log<<Logger::Error<<kBackendId<<" "<<pe.reason<<endl;
    cleanup();
    throw;
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
         declare(suffix,"regex","Regular expression of queries to pass to coprocess","");
         declare(suffix,"abi-version","Version of the pipe backend ABI","1");
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
         g_log << Logger::Info << kBackendId <<" This is the pipe backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
      }  
};

static PipeLoader pipeloader;

