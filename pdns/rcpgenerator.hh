/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2009  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/


#ifndef PDNS_RCPGENERATOR_HH
#define PDNS_RCPGENERATOR_HH
#include <inttypes.h>
#include <string>
#include <stdexcept>
#if !defined SOLARIS8 && !defined WIN32

#elif defined WIN32
# include "utility.hh"
#endif

#include "namespaces.hh"

class RecordTextException : public runtime_error
{
public:
  RecordTextException(const string& str) : runtime_error(str)
  {}
};

class RecordTextReader
{
public:
  RecordTextReader(const string& str, const string& zone="");
  void xfr64BitInt(uint64_t& val);
  void xfr48BitInt(uint64_t& val);
  void xfr32BitInt(uint32_t& val);
  void xfr16BitInt(uint16_t& val);
  void xfr8BitInt(uint8_t& val);

  void xfrType(uint16_t& val);
  void xfrIP(uint32_t& val);
  void xfrTime(uint32_t& val);

  void xfrLabel(string& val, bool compress=false);
  void xfrText(string& val, bool multi=false);
  void xfrHexBlob(string& val, bool keepReading=false);
  void xfrBase32HexBlob(string& val);

  void xfrBlob(string& val, int len=-1);

  bool eof();
private:
  string d_string;
  string d_zone;
  string::size_type d_pos;
  string::size_type d_end;
  void skipSpaces();
};

class RecordTextWriter
{
public:
  RecordTextWriter(string& str);
  void xfr48BitInt(const uint64_t& val);
  void xfr32BitInt(const uint32_t& val);
  void xfr16BitInt(const uint16_t& val);
  void xfr8BitInt(const uint8_t& val);
  void xfrIP(const uint32_t& val);
  void xfrTime(const uint32_t& val);
  void xfrBase32HexBlob(const string& val);

  void xfrType(const uint16_t& val);
  void xfrLabel(const string& val, bool compress=false);
  void xfrText(const string& val, bool multi=false);
  void xfrBlob(const string& val, int len=-1);
  void xfrHexBlob(const string& val, bool keepReading=false);

private:
  string& d_string;
};


#endif
