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
#ifndef ARGUMENTS_HH
#define ARGUMENTS_HH

#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include "misc.hh"
#include "ahuexception.hh"

using namespace std;

typedef AhuException ArgException;

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
    
    cout<<"Will we be a deamon?: "<<R.isset("daemon")<<endl;
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
  bool preParseFile(const char *fname, const string &arg); //!< use this to preparse a single var in configuration

  bool file(const char *fname, bool lax=false); //!< Parses a file with parameters
  bool laxFile(const char *fname) 
  {
    return file(fname,true);
  }
  typedef map<string,string> param_t; //!< use this if you need to know the content of the map
  bool parmIsset(const string &var); //!< Checks if a parameter is set to *a* value
  bool mustDo(const string &var); //!< if a switch is given, if we must do something (--help)
  int asNum(const string &var); //!< return a variable value as a number
  double asDouble(const string &var); //!< return a variable value as a number
  string &set(const string &); //!< Gives a writable reference and allocates space for it
  string &set(const string &, const string &); //!< Does the same but also allows to specify a help message
  void setCmd(const string &, const string &); //!< Add a command flag
  string &setSwitch(const string &, const string &); //!< Add a command flag
  string helpstring(string prefix=""); //!< generates the --help
  string configstring(); //!< generates the --mkconfig
  bool contains(const string &var, const string &val);

  vector<string>list();
  string getHelp(const string &item);

  const param_t::const_iterator begin(); //!< iterator semantics
  const param_t::const_iterator end(); //!< iterator semantics
  const string &operator[](const string &); //!< iterator semantics
  const vector<string>&getCommands();
private:
  void parseOne(const string &unparsed, const string &parseOnly="", bool lax=false);
  map<string,string> params;
  map<string,string> helpmap;
  map<string,string> d_typeMap;
  vector<string> d_cmds;
};

extern ArgvMap &arg();

#endif /* ARGUMENTS_HH */
