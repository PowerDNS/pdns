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
#ifndef ZONEPARSER_HH
#define ZONEPARSER_HH
#include <string>
#include <map>
#include <vector>
#include <time.h>

using namespace std;

class ZoneParser
{
 public:
  struct Record
  {
    string name;
    string qtype;
    string content;
    int ttl;
    int prio;
  };
  ZoneParser() : d_ttl(3600) {}
  ~ZoneParser();
  void parse(const string &fname,const string &origin, unsigned int domain_id);
  void parse(const string &fname,const string &origin, vector<Record>&records);
  
  typedef void callback_t(unsigned int domain_id, const string &domain, const string &qtype, const string &content, int ttl, int prio);
  void setCallback(callback_t *callback);
  callback_t *d_callback;
  bool parseLine(const vector<string>&words, vector<Record> &);
  bool eatLine(const string& line, vector<Record>&);
  void setDirectory(const string &dir);
  static string canonic(const string& dom);
    
private:
  unsigned int zoneNumber(const string &str);
  string d_filename;
  string d_dir;
  unsigned int d_lineno;
  void soaCanonic(string &content);
  bool isNumber(const string &);
  bool isType(const string &);
  bool isClass(const string &);
  string d_origin;
  time_t d_ttl;
  void cutOff(string &line, const string &delim);
  void fillRec(const string &qname, const string &qtype, const string &content, int ttl, int prio, vector<Record>&rec);
  string expandWord(const string &line, int value);
};


#endif /* BINDPARSER_HH */
