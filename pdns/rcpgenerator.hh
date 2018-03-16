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
#ifndef PDNS_RCPGENERATOR_HH
#define PDNS_RCPGENERATOR_HH
#include <inttypes.h>
#include <string>
#include <stdexcept>

#include "namespaces.hh"
#include "dnsname.hh"
#include "iputils.hh"

class RecordTextException : public runtime_error
{
public:
  RecordTextException(const string& str) : runtime_error(str)
  {}
};

class RecordTextReader
{
public:
  RecordTextReader(const string& str, const DNSName& zone=DNSName(""));
  void xfr64BitInt(uint64_t& val);
  void xfr48BitInt(uint64_t& val);
  void xfr32BitInt(uint32_t& val);
  void xfr16BitInt(uint16_t& val);
  void xfr8BitInt(uint8_t& val);

  void xfrType(uint16_t& val);
  void xfrIP(uint32_t& val);
  void xfrIP6(std::string& val);
  void xfrCAWithoutPort(uint8_t version, ComboAddress &val);
  void xfrCAPort(ComboAddress &val);
  void xfrTime(uint32_t& val);

  void xfrName(DNSName& val, bool compress=false, bool noDot=false);
  void xfrText(string& val, bool multi=false, bool lenField=true);
  void xfrUnquotedText(string& val, bool lenField=true);
  void xfrHexBlob(string& val, bool keepReading=false);
  void xfrBase32HexBlob(string& val);

  void xfrBlobNoSpaces(string& val, int len=-1);
  void xfrBlob(string& val, int len=-1);

  const string getRemaining() const {
    return d_string.substr(d_pos);
  }

  bool eof();
private:
  string d_string;
  DNSName d_zone;
  string::size_type d_pos;
  string::size_type d_end;
  void skipSpaces();
};

class RecordTextWriter
{
public:
  RecordTextWriter(string& str, bool noDot=false);
  void xfr48BitInt(const uint64_t& val);
  void xfr32BitInt(const uint32_t& val);
  void xfr16BitInt(const uint16_t& val);
  void xfr8BitInt(const uint8_t& val);
  void xfrIP(const uint32_t& val);
  void xfrIP6(const std::string& val);
  void xfrCAWithoutPort(uint8_t version, ComboAddress &val);
  void xfrCAPort(ComboAddress &val);
  void xfrTime(const uint32_t& val);
  void xfrBase32HexBlob(const string& val);

  void xfrType(const uint16_t& val);
  void xfrName(const DNSName& val, bool compress=false, bool noDot=false);
  void xfrText(const string& val, bool multi=false, bool lenField=true);
  void xfrUnquotedText(const string& val, bool lenField=true);
  void xfrBlobNoSpaces(const string& val, int len=-1);
  void xfrBlob(const string& val, int len=-1);
  void xfrHexBlob(const string& val, bool keepReading=false);
  bool eof() { return true; };

  const string getRemaining() const {
     return "";
  }
private:
  string& d_string;
  bool d_nodot;
};
#endif
