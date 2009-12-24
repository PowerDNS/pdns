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
#include <string>
#include "huffman.hh"
#include <bitset>
#include <map>
#include <sstream>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <algorithm>
#include <utility>

void HuffmanCodec::set(char c,const string &code)
{
  d_dict[c]=code;
}

HuffmanCodec::HuffmanCodec()
{
  d_dict.clear();
  set('6',"0000");
  set('5',"0001");
  set(0,"0010");
  set('3',"0011");
  set('4',"0100");
  set('s',"0101");
  set('n',"011");
  set('c',"100000");
  set('u',"100001");
  set('-',"1000100");
  set('1',"1000101");
  set('f',"1000110");
  set('j',"10001110");
  set('9',"1000111100");
  set('*',"100011110100");
  set('q',"100011110101");
  set('7',"10001111011");
  set('8',"100011111");
  set('o',"10010");
  set('t',"10011");
  set('e',"1010");
  set('a',"10110");
  set('r',"10111");
  set('d',"110000");
  set('2',"1100010");
  set('k',"1100011");
  set('.',"110010");
  set('v',"1100110");
  set('w',"1100111");
  set('i',"1101");
  set('l',"111000");
  set('p',"1110010");
  set('b',"1110011");
  set('z',"111010000");
  set('y',"111010001");
  set('x',"11101001");
  set('h',"1110101");
  set('m',"1110110");
  set('g',"1110111");
  set('0',"1111");

  d_min=10000;
  d_max=0;
  d_rdict.resize(128);
  for(map<char,string>::const_iterator i=d_dict.begin();i!=d_dict.end();++i) {
    d_min=min(d_min,i->second.length());
    d_max=max(d_max,i->second.length());

    (d_rdict[i->second.length()])[i->second]=i->first;
  }
  d_last_compressed=d_last_out="";
  d_passthrough=false;
}

void HuffmanCodec::passthrough(bool shoulddo)
{
  d_passthrough=shoulddo;
}


//       Bitify input: 1001101110101001000101
//Decode got offered: '1001101110101001'


void HuffmanCodec::decode(const string &compressed, string &out)
{
  if(d_passthrough) {
    out=compressed;
    return;
  }
  if(compressed==d_last_compressed) {
    out=d_last_out;
    return;
  }
  string full;

  out="";
  unbitify(compressed, full);
  //  cout<<"Decode got offered: '"<<full<<"'"<<endl;

  unsigned int pos=0;
  size_t cleft=full.length();
  size_t mlen;
  out.reserve(full.length()/5);
  while(cleft) {
    map<string,char>::const_iterator i;

    for(mlen=d_min;mlen<=cleft && mlen<=d_max;++mlen) {
      if(d_rdict[mlen].empty())
        continue;

      i=d_rdict[mlen].find(full.substr(pos,mlen));

      if(i!=d_rdict[mlen].end()) { // match 
        if(!i->second) {
          d_last_compressed=compressed;
          d_last_out=out;
          return;
        }

        out.append(1,i->second);

        pos+=mlen;
        cleft-=mlen;
        break;
      }
    }
  }
  if(cleft)
    throw AhuException("Unable to parse huffman symbol "+full.substr(pos));
  d_last_compressed=compressed;
  d_last_out=out;
}

void HuffmanCodec::encode(const string &in, string &out)
{
  if(d_passthrough) {
    out=in;
    return;
  }
  string full;
  for(string::const_iterator i=in.begin();i!=in.end();++i) {
    map<char,string>::const_iterator j=d_dict.find(tolower(*i));
    if(j==d_dict.end()) {
      string c;
      char cc=tolower(*i);
      c.append(1,cc);
      throw AhuException("Trying to huffman encode an unknown symbol '"+c+"'");
    }
    full.append(j->second);
  }
  full.append(d_dict[0]);
  bitify(full,out);
  //  cout<<"full: "<<full<<endl;
}

void HuffmanCodec::bitify(const string &full, string &out)
{
  unsigned char bitpos=0;
  unsigned char curbyte=0;
  //  cout<<"Bitify input: "<<full<<endl;
  for(string::const_iterator i=full.begin();i!=full.end();++i) {
    curbyte|= (*i=='1')<<(7-bitpos);
    if(bitpos++==7) {
      out.append(1,curbyte);
      bitpos=0;
      curbyte=0;
    }
  }
  out.append(1,curbyte);
}

void HuffmanCodec::unbitify(const string &in, string &full) 
{
  bitset<8> byte;
  ostringstream os;
  full.reserve(in.length()*8);
  for(string::const_iterator i=in.begin();i!=in.end();++i) {
    byte=*i;
    os<<byte;
  }
  full.append(os.str());
}

#if 0
int main(int argc, char **argv)
{
  string in(argv[1]);
  string compressed;

  try {
    HuffmanCodec hc;
    //  hc.initDictionary(dict);
    //    cout<<"in: "<<in.length()<<endl;
    hc.encode(in,compressed);
    // cout<<"compressed: "<<compressed.length()<<endl;
    //    cout<<"Compressed: '"<<compressed<<"'"<<endl;
    
    string out;
    hc.decode(compressed,out);
    
    cout<<"'"<<out<<"'"<<endl;
  }
  catch(AhuException &ae) {
    cerr<<"Fatal error: "<<ae.reason<<endl;
  }
}
#endif
