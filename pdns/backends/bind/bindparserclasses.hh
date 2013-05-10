/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2007  PowerDNS.COM BV

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
#ifndef BINDPARSER_HH
#define BINDPARSER_HH
#include <string>
#include <map>
#include <vector>
#include <set>

#include "namespaces.hh"

class BindDomainInfo
{
public:
  BindDomainInfo() : d_dev(0), d_ino(0)
  {}

  void clear()
  {
    name=filename=type="";
    masters.clear();
    alsoNotify.clear();
    d_dev=0;
    d_ino=0;
  }
  string name;
  string viewName;
  string filename;
  vector<string> masters;
  set<string> alsoNotify;
  string type;

  dev_t d_dev;
  ino_t d_ino;

  bool operator<(const BindDomainInfo& b) const
  {
    return make_pair(d_dev, d_ino) < make_pair(b.d_dev, b.d_ino);
  }
};

extern const char *bind_directory;
extern FILE *yyin;
class BindParser
{
 public:
  BindParser() : d_dir("."), d_verbose(false)
  {
    yyin=0;
    extern int include_stack_ptr;
    include_stack_ptr=0;

    bind_directory=d_dir.c_str();
  }
  ~BindParser()
  {
    if(yyin) {
      fclose(yyin);
      yyin=0;
    }
  }
  void parse(const string &fname);
  void commit(BindDomainInfo DI);
  void setDirectory(const string &dir);
  const string &getDirectory();
  const vector<BindDomainInfo>& getDomains();
  void setVerbose(bool verbose);
  void addAlsoNotify(const string &host);
  set<string> & getAlsoNotify() { return this->alsoNotify; }
private:
  string d_dir;
  bool d_verbose;
  typedef map<string,string> zonedomain_t;
  set<string> alsoNotify;
  vector<BindDomainInfo> d_zonedomains;
};

#endif /* BINDPARSER_HH */
