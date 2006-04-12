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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef PDNS_HUFFMAN
#define PDNS_HUFFMAN
#include <string>
#include <bitset>
#include <map>
#include <sstream>
#include <vector>
#include "../../ahuexception.hh"

using namespace std;

class HuffmanCodec
{
public:
  HuffmanCodec();
  void encode(const string &in, string &out);
  void decode(const string &compressed, string &out);
  void passthrough(bool);
  string decode(const string &in) {
    string tmp;
    decode(in,tmp);
    return tmp;
  }
private:
  void bitify(const string &full, string &out);
  void unbitify(const string &in, string &full);
  void set(char c,const string &code);
  map<char,string> d_dict;
  vector<map<string,char> >d_rdict;
  size_t d_min, d_max;
  string d_last_compressed;
  string d_last_out;
  bool d_passthrough;
};
#endif /* PDNS_HUFFMAN */
