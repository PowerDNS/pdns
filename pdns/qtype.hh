/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef QTYPE_HH
#define QTYPE_HH
/* (C) 2002 POWERDNS.COM BV */
// $Id$
#include <string>
#include <vector>
#include <utility>
#include "namespaces.hh"

/** The QType class is meant to deal easily with the different kind of resource types, like 'A', 'NS',
 *  'CNAME' etcetera. These types have both a name and a number. This class can seamlessly move between
 *   them. Use it like this:

\code
   QType t;
   t="CNAME";
   cout<<t.getCode()<<endl; // prints '5'
   t=6;
   cout<<t.getName()<<endl; // prints 'SOA'
\endcode

*/



class QType
{
public:
  QType(); //!< Naked constructor
  explicit QType(uint16_t); //!< convert from an integer to a QType
  QType(const QType& orig) : code(orig.code)
  {
  }
  QType &operator=(uint16_t);  //!< Assigns integers to us
  QType &operator=(const char *); //!< Assings strings to us
  QType &operator=(const string &); //!< Assings strings to us
  QType &operator=(const QType&rhs)  //!< Assings strings to us
  {
    code=rhs.code;
    return *this;
  }

  bool operator<(const QType& rhs) const 
  {
    return code < rhs.code;
  }

  template<class Archive>
  void serialize(Archive &ar, const unsigned int version)
  {
    ar & code;
  }

  bool operator==(const QType &) const; //!< equality operator

  const string getName() const; //!< Get a string representation of this type
  uint16_t getCode() const; //!< Get the integer representation of this type

  static int chartocode(const char *p); //!< convert a character string to a code
// more solaris fun
#undef DS   
  enum typeenum {A=1,NS=2,CNAME=5,SOA=6, MR=9, PTR=12,HINFO=13,MX=15,TXT=16,RP=17,AFSDB=18,KEY=25,AAAA=28,LOC=29,SRV=33,NAPTR=35, KX=36, 
		 CERT=37,OPT=41, DS=43, SSHFP=44, IPSECKEY=45, RRSIG=46, NSEC=47, DNSKEY=48, DHCID=49, NSEC3=50, NSEC3PARAM=51,
		 TLSA=52, SPF=99, TSIG=250, AXFR=252, IXFR=251, ANY=255, URL=256, MBOXFW=257, CURL=258, ADDR=259, DLV=32769} types;
  typedef pair<string,uint16_t> namenum; 
  static vector<namenum> names;
private:
  uint16_t code;
  void insert(const char *p, int n);


  static bool uninit;
};

struct QClass
{
	enum QClassEnum {IN=1, CHAOS=3};
};
#endif
