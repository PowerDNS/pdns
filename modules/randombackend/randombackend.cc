/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2015  PowerDNS.COM BV

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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
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
    d_ourname=DNSName(getArg("hostname"));
    d_want_A=false;
    d_want_SOA=false;
  }

  bool list(const DNSName &target, int id, bool include_disabled) {
    return false; // we don't support AXFR
  }

  void lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId)
  {
    if(qdomain == d_ourname){
        switch (type.getCode()) {
          case QType::A:
            d_want_A = true;
            break;
          case QType::SOA:
            d_want_SOA = true;
            break;
          case QType::ANY:
            d_want_A = true;
            d_want_SOA = true;
            break;
        }
    } else { // We know nothing
      d_want_A = false;
      d_want_SOA = false;
    }
  }

  bool get(DNSResourceRecord &rr)
  {
    // fill in details
    rr.qname=d_ourname;
    rr.ttl=5;   // 5 seconds
    rr.auth=1;  // it may be random.. but it is auth!

    if(d_want_A) {
      rr.qtype=QType::A;
      ostringstream os;
      os<<Utility::random()%256<<"."<<Utility::random()%256<<"."<<Utility::random()%256<<"."<<Utility::random()%256;
      rr.content=os.str();
      d_want_A=false;
      return true;
    }

    if(d_want_SOA) {
      rr.qtype=QType::SOA;
      rr.content="ns1." + d_ourname.toString() + " hostmaster." + d_ourname.toString() + " 1234567890 86400 7200 604800 300";
      d_want_SOA=false;
      return true;
    }

    return false;
  }

private:
  DNSName d_ourname;
  bool d_want_A;
  bool d_want_SOA;
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
    L << Logger::Info << "[randombackend] This is the random backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }  
};

static RandomLoader randomLoader;
