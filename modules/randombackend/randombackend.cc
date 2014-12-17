/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2008  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "pdns/utility.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/version.hh"
#include <boost/algorithm/string.hpp>

/* FIRST PART */
class RandomBackend : public DNSBackend
{
public:
  RandomBackend(const string &suffix="") 
  {
    setArgPrefix("random"+suffix);
    d_ourname=getArg("hostname");
  }

  bool list(const string &target, int id, bool include_disabled) {
    return false; // we don't support AXFR
  }
    
  void lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId)
  {
    if((type.getCode()!=QType::ANY && type.getCode()!=QType::A) || !pdns_iequals(qdomain, d_ourname))  // we only know about random.example.com A by default
      d_answer="";                                                  // no answer
    else {
      ostringstream os;
      os<<Utility::random()%256<<"."<<Utility::random()%256<<"."<<Utility::random()%256<<"."<<Utility::random()%256;
      d_answer=os.str();                                           // our random ip address
    }

  }

  bool get(DNSResourceRecord &rr)
  {
    if(!d_answer.empty()) {
      rr.qname=d_ourname;                                           // fill in details
      rr.qtype=QType::A;                                            // A record
      rr.ttl=5;                                                 // 5 seconds
      rr.auth = 1;  // it may be random.. but it is auth!
      rr.content=d_answer;

      d_answer="";                                                  // this was the last answer
      
      return true;
    }
    return false;                                                   // no more data
  }
  
private:
  string d_answer;
  string d_ourname;
};

/* SECOND PART */

class RandomFactory : public BackendFactory
{
public:
  RandomFactory() : BackendFactory("random") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"hostname","Hostname which is to be random","random.example.com");
  }
  DNSBackend *make(const string &suffix="")
  {
    return new RandomBackend(suffix);
  }
};

/* THIRD PART */

class RandomLoader
{
public:
  RandomLoader()
  {
    BackendMakers().report(new RandomFactory);
    L << Logger::Info << "[randombackend] This is the random backend version " VERSION " reporting" << endl;
  }  
};

static RandomLoader randomLoader;

