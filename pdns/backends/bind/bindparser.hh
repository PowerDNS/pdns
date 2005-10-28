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
#ifndef BINDPARSER_HH
#define BINDPARSER_HH
#include <string>
#include <map>
#include <vector>

using namespace std;

class BindDomainInfo 
{
public:
  void clear() 
  {
    name=filename=master=type="";
  }
  string name;
  string filename;
  string master;
  string type;
};

extern const char *bind_directory;
class BindParser
{
 public:
  BindParser() : d_dir("."), d_verbose(false) 
  {
    extern int include_stack_ptr;
    include_stack_ptr=0;
 
    bind_directory=d_dir.c_str(); 
  }
  void parse(const string &fname);
  void commit(BindDomainInfo DI);
  void setDirectory(const string &dir);
  const string &getDirectory();
  const vector<BindDomainInfo>& getDomains();
  void setVerbose(bool verbose);
private:
  string d_dir;
  bool d_verbose;
  typedef map<string,string> zonedomain_t;

  vector<BindDomainInfo> d_zonedomains;
};

#endif /* BINDPARSER_HH */
