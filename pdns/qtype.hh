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

using namespace std;

/** The QType class is meant to deal easily with the different kind of resource types, like 'A', 'NS',
 *  'CNAME' etcetera. These types have both a name and a number. This class can seemlessly move between
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
  explicit QType(int); //!< convert from an integer to a QType
  QType(const char *p);  //!< convert from a char* to a QType
  QType(const QType& orig) : code(orig.code)
  {
  }
  QType &operator=(int);  //!< Assigns integers to us
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

  bool operator==(const QType &) const; //!< equality operator

  const string getName() const; //!< Get a string representation of this type
  int getCode() const; //!< Get the integer representation of this type

  static int chartocode(const char *p); //!< convert a character string to a code
  
  enum typeenum {A=1,NS=2,CNAME=5,SOA=6, MR=9, PTR=12,HINFO=13,MX=15,TXT=16,RP=17,AAAA=28,LOC=29,SRV=33,NAPTR=35, SPF=99, AXFR=252, IXFR=254, ANY=255} types;
private:
  short int code;
  typedef pair<string,int> namenum; 
  void insert(const char *p, int n);

  static vector<namenum> names;
  static bool uninit;
};


#endif
