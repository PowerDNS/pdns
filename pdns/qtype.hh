/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef QTYPE_HH
#define QTYPE_HH
/* (C) 2002 POWERDNS.COM BV */
// $Id: qtype.hh,v 1.5 2003/04/05 19:31:52 ahu Exp $
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
  QType(char *p);  //!< convert from a char* to a QType

  QType &operator=(int);  //!< Assigns integers to us
  QType &operator=(const char *); //!< Assings strings to us
  QType &operator=(const string &); //!< Assings strings to us
  bool operator==(const QType &) const; //!< equality operator

  string getName() const; //!< Get a string representation of this type
  int getCode() const; //!< Get the integer representation of this type

  static int chartocode(const char *p); //!< convert a character string to a code
  
  enum {A=1,NS=2,CNAME=5,SOA=6,PTR=12,HINFO=13,MX=15,TXT=16,RP=17,AAAA=28,LOC=29,SRV=33,NAPTR=35,AXFR=252, IXFR=254, ANY=255} types;
private:
  short int code;
  typedef pair<string,int> namenum; 
  void insert(char *p, int n);

  static vector<namenum> names;
  static bool uninit;
};


#endif
