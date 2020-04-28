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
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <iostream>
#include "base32.hh"
#include "namespaces.hh"

/* based on freebsd:src/contrib/opie/libopie/btoe.c extract: get bit ranges from a char* */
/* NOTE: length should not exceed 8; all callers inside PowerDNS only pass length=5 though */
static unsigned char extract_bits(const char *s, int start, int length)
{
  uint16_t x;
  unsigned char cl, cc;

  if(!length)
    return 0;

  cl = s[start / 8];
  if(start / 8 < (start + length-1)/8)
    cc = s[start / 8 + 1];
  else
    cc = 0;

  x = (uint16_t) (cl << 8 | cc);
  x = x >> (16 - (length + (start % 8)));
  x = (x & (0xffff >> (16 - length)));
  return (x);
}

/* same, set bit ranges in a char* */
static void set_bits(char* s, int x, int start, int length)
{
  unsigned char cl, cc, cr;
  uint32_t y;
  int shift;

  shift = ((8 - ((start + length) % 8)) % 8);
  y = (uint32_t) x << shift;
  cl = (y >> 16) & 0xff;
  cc = (y >> 8) & 0xff;
  cr = y & 0xff;
  if (shift + length > 16) {
    s[start / 8] |= cl;
    s[start / 8 + 1] |= cc;
    s[start / 8 + 2] |= cr;
  } 
  else {
    if (shift + length > 8) {
      s[start / 8] |= cc;
      s[start / 8 + 1] |= cr;
    } else {
      s[start / 8] |= cr;
    }
  }
}

/* convert a base32 hex character to its decoded equivalent */
static int unbase32hex(char c)
{
  if(c >= '0' && c<='9')
    return c-'0';
  if(c >= 'a' && c<='z') 
    return 10 + (c-'a');
  if(c >= 'A' && c<='Z') 
    return 10 + (c-'A');
  if(c=='=')
    return '=';
  return -1;
}

/* convert a binary string to base32hex */
string toBase32Hex(const std::string& input)
{
  static const char base32hex[] = "0123456789abcdefghijklmnopqrstuv=";
  string ret;
  ret.reserve(4+ 8*input.length()/5); // optimization
  // process input in groups of 5 8-bit chunks, emit 8 5-bit chunks 
  for(string::size_type offset = 0 ; offset < input.length(); offset+=5) {
    int todo = input.length() - offset;
    int stuffing; // how much '=' to add at the end
    
    switch(todo) {
    case 1:
      stuffing = 6; break;
    case 2:
      stuffing = 4; break;
    case 3:
      stuffing = 3; break;
    case 4:
      stuffing = 1; break;
    default: // ->  0 or more than 5, no stuffing
      stuffing = 0; break;
    }
   
    for(int n=0; n < 8 - stuffing; ++n)
      ret.append(1, base32hex[extract_bits(input.c_str()+offset, n*5, 5)]);
    ret.append(stuffing, '=');
  }

  return ret;
}

// convert base32hex encoded string to normal string
string fromBase32Hex(const std::string& input)
{
  string ret;
  char block[5]={0,0,0,0,0};  // we process 5 8-bit chunks at a time
  string::size_type n, toWrite=0;
  for(n = 0; n < input.length(); ++n) {
    int c=unbase32hex(input[n]);
    if(c == '=' || c < 0) // stop at stuffing or error
      break;
    set_bits(block, c , (n % 8) * 5, 5);
    if(++toWrite == 8) {
      ret.append(block, sizeof(block));
      memset(block, 0, sizeof(block));
      toWrite = 0;
    }
  }
  ret.append(block, (toWrite*5)/8); 

  return ret;
}

#if 0
int main(int argc, char **argv)
{
  if(argc!=3 || (argc==3 && strcmp(argv[1],"from") && strcmp(argv[1],"to"))) {
    printf("syntax: base32 from|to string\n");
    exit(0);
  }
  if(!strcmp(argv[1],"to")) {
    printf("input: '%s'\noutput: '%s'\n",
           argv[2], 
           toBase32Hex(argv[2]).c_str());
  }
  else {
    cout<<"input: '"<<argv[2]<<"'\noutput: '"<<fromBase32Hex(argv[2])<<"'\n";
  }
}
#endif
