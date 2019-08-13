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
#ifndef ARGUMENTS_HH
#define ARGUMENTS_HH

#include <map>
#include <set>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include "misc.hh"
#include "pdnsexception.hh"
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "namespaces.hh"

typedef PDNSException ArgException;

/** This class helps parsing argc and argv into a map of parameters. We have 3 kinds of formats:


    -w           this leads to a key/value pair of "w"/void

    --port=25    "port"/"25"

    --daemon     "daemon"/void

    We do not support "--port 25" syntax.

    It can also read from a file. This file can contain '#' to delimit comments.

    Some sample code:

    \code

    ArgvMap R;
  
    R.set("port")="25";  // use this to specify default parameters
    R.file("./default.conf"); // parse configuration file
    
    R.parse(argc, argv); // read the arguments from main()
    
    cout<<"Will we be a daemon?: "<<R.isset("daemon")<<endl;
    cout<<"Our port will be "<<R["port"]<<endl;
    
    map<string,string>::const_iterator i;
    cout<<"via iterator"<<endl;
    for(i=R.begin();i!=R.end();i++)
    cout<<i->first<<"="<<i->second<<endl;
    \endcode
*/



class ArgvMap
{
public:
  ArgvMap();
  void parse(int &argc, char **argv, bool lax=false); //!< use this to parse from argc and argv
  void laxParse(int &argc, char **argv) //!< use this to parse from argc and argv
  {
    parse(argc,argv,true);
  }
  void preParse(int &argc, char **argv, const string &arg); //!< use this to preparse a single var
  bool preParseFile(const char *fname, const string &arg, const string& theDefault=""); //!< use this to preparse a single var in configuration

  bool file(const char *fname, bool lax=false); //!< Parses a file with parameters
  bool file(const char *fname, bool lax, bool included); 
  bool laxFile(const char *fname) 
  {
    return file(fname,true);
  }
  bool parseFile(const char *fname, const string& arg, bool lax); //<! parse one line
  typedef map<string,string> param_t; //!< use this if you need to know the content of the map
  bool parmIsset(const string &var); //!< Checks if a parameter is set to *a* value
  bool mustDo(const string &var); //!< if a switch is given, if we must do something (--help)
  int asNum(const string &var, int def=0); //!< return a variable value as a number or the default if the variable is empty
  mode_t asMode(const string &var); //!< return value interpreted as octal number
  uid_t asUid(const string &var); //!< return user id, resolves if necessary
  gid_t asGid(const string &var); //!< return group id, resolves if necessary
  double asDouble(const string &var); //!< return a variable value as a number
  string &set(const string &); //!< Gives a writable reference and allocates space for it
  string &set(const string &, const string &); //!< Does the same but also allows one to specify a help message
  void setCmd(const string &, const string &); //!< Add a command flag
  string &setSwitch(const string &, const string &); //!< Add a switch flag
  string helpstring(string prefix=""); //!< generates the --help
  string configstring(bool current=false); //!< generates the --mkconfig
  bool contains(const string &var, const string &val);
  bool isEmpty(const string &var); //!< checks if variable has value

  vector<string>list();
  string getHelp(const string &item);

  const param_t::const_iterator begin(); //!< iterator semantics
  const param_t::const_iterator end(); //!< iterator semantics
  const string &operator[](const string &); //!< iterator semantics
  const vector<string>&getCommands();
  void gatherIncludes(std::vector<std::string> &extraConfigs);
private:
  void parseOne(const string &unparsed, const string &parseOnly="", bool lax=false);
  typedef map<string,string> params_t;
  params_t params;
  map<string,string> helpmap;
  map<string,string> d_typeMap;
  vector<string> d_cmds;
  std::set<string> d_cleared;
};

extern ArgvMap &arg();

#endif /* ARGUMENTS_HH */
