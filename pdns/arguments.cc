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
#include "arguments.hh"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/compare.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "namespaces.hh"
#include "logger.hh"
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

const ArgvMap::param_t::const_iterator ArgvMap::begin()
{
  return params.begin();
}

const ArgvMap::param_t::const_iterator ArgvMap::end()
{
  return params.end();
}

string & ArgvMap::set(const string &var)
{
  return params[var];
}

bool ArgvMap::mustDo(const string &var)
{
  return ((*this)[var]!="no") && ((*this)[var]!="off");
}

vector<string>ArgvMap::list()
{
  vector<string> ret;
  for(map<string,string>::const_iterator i=params.begin();i!=params.end();++i)
    ret.push_back(i->first);
  return ret;
}

string ArgvMap::getHelp(const string &item)
{
  return helpmap[item];
}

string & ArgvMap::set(const string &var, const string &help)
{
  helpmap[var]=help;
  d_typeMap[var]="Parameter";
  return set(var);
}

void ArgvMap::setCmd(const string &var, const string &help)
{
  helpmap[var]=help;
  d_typeMap[var]="Command";
  set(var)="no";
}

string & ArgvMap::setSwitch(const string &var, const string &help)
{
  helpmap[var]=help;
  d_typeMap[var]="Switch";
  return set(var);
}


bool ArgvMap::contains(const string &var, const string &val)
{
  params_t::const_iterator param = params.find(var);
  if(param == params.end() || param->second.empty())  {
    return false;
  }
  vector<string> parts;
  vector<string>::const_iterator i;
  
  stringtok( parts, param->second, ", \t" );
  for( i = parts.begin(); i != parts.end(); i++ ) {
    if( *i == val ) {
      return true;
    }
  }

  return false;
}

string ArgvMap::helpstring(string prefix)
{
  if(prefix=="no")
    prefix="";
  
  string help;
  
  for(map<string,string>::const_iterator i=helpmap.begin();
      i!=helpmap.end();
      i++)
    {
      if(!prefix.empty() && i->first.find(prefix) != 0) // only print items with prefix
        continue;

      help+="  --";
      help+=i->first;
      
      string type=d_typeMap[i->first];

      if(type=="Parameter")
        help+="=...";
      else if(type=="Switch")
        {
          help+=" | --"+i->first+"=yes";
          help+=" | --"+i->first+"=no";
        }
      

      help+="\n\t";
      help+=i->second;
      help+="\n";

    }
  return help;
}

string ArgvMap::configstring(bool current)
{
  string help;

  if (current)
    help="# Autogenerated configuration file based on running instance\n";
  else
    help="# Autogenerated configuration file template\n";
  
  for(map<string,string>::const_iterator i=helpmap.begin(); i!=helpmap.end(); i++) {
    if(d_typeMap[i->first]=="Command")
      continue;

    help+="#################################\n";
    help+="# ";
    help+=i->first;
    help+="\t";
    help+=i->second;
    help+="\n#\n";
    if (current) {
      help+=i->first+"="+params[i->first]+"\n\n";
    } else {
      help+="# "+i->first+"="+params[i->first]+"\n\n";
    }
  }
  return help;
}

const string & ArgvMap::operator[](const string &arg)
{
  if(!parmIsset(arg))
    throw ArgException(string("Undefined but needed argument: '")+arg+"'");

  return params[arg];
}

mode_t ArgvMap::asMode(const string &arg) 
{
  mode_t mode;
  const char *cptr_orig;
  char *cptr_ret = NULL;

  if(!parmIsset(arg))
   throw ArgException(string("Undefined but needed argument: '")+arg+"'");

  cptr_orig = params[arg].c_str();
  mode = static_cast<mode_t>(strtol(cptr_orig, &cptr_ret, 8));
  if (mode == 0 && cptr_ret == cptr_orig) 
    throw ArgException("'" + arg + string("' contains invalid octal mode"));
   return mode;
}

gid_t ArgvMap::asGid(const string &arg)
{
  gid_t gid;
  const char *cptr_orig;
  char *cptr_ret = NULL;

  if(!parmIsset(arg))
   throw ArgException(string("Undefined but needed argument: '")+arg+"'");

  cptr_orig = params[arg].c_str();
  gid = static_cast<gid_t>(strtol(cptr_orig, &cptr_ret, 0));
  if (gid == 0 && cptr_ret == cptr_orig) {
    // try to resolve
    struct group *group = getgrnam(params[arg].c_str());
    if (group == NULL)
     throw ArgException("'" + arg + string("' contains invalid group"));
    gid = group->gr_gid;
   }
   return gid;
}

uid_t ArgvMap::asUid(const string &arg)
{
  uid_t uid;
  const char *cptr_orig;
  char *cptr_ret = NULL;

  if(!parmIsset(arg))
   throw ArgException(string("Undefined but needed argument: '")+arg+"'");

  cptr_orig = params[arg].c_str();
  uid = static_cast<uid_t>(strtol(cptr_orig, &cptr_ret, 0));
  if (uid == 0 && cptr_ret == cptr_orig) {
    // try to resolve
    struct passwd *pwent = getpwnam(params[arg].c_str());
    if (pwent == NULL)
     throw ArgException("'" + arg + string("' contains invalid group"));
    uid = pwent->pw_uid;
   }
   return uid;
}

int ArgvMap::asNum(const string &arg, int def)
{
  int retval;
  const char *cptr_orig;
  char *cptr_ret = NULL;

  if(!parmIsset(arg))
    throw ArgException(string("Undefined but needed argument: '")+arg+"'");

  // use default for empty values
  if (params[arg].empty())
   return def;

  cptr_orig = params[arg].c_str();
  retval = static_cast<int>(strtol(cptr_orig, &cptr_ret, 0));
  if (!retval && cptr_ret == cptr_orig)
   throw ArgException("'"+arg+"' value '"+string(cptr_orig) + string( "' is not a valid number"));

  return retval;
}

bool ArgvMap::isEmpty(const string &arg) 
{
   if(!parmIsset(arg))
    return true;
   return params[arg].empty();
}

double ArgvMap::asDouble(const string &arg)
{
  double retval;
  const char *cptr_orig;
  char *cptr_ret = NULL;

  if(!parmIsset(arg))
    throw ArgException(string("Undefined but needed argument: '")+arg+"'");

  if (params[arg].empty())
   return 0.0;

  cptr_orig = params[arg].c_str();
  retval = strtod(cptr_orig, &cptr_ret);
 
  if (retval == 0 && cptr_ret == cptr_orig)
   throw ArgException("'"+arg+string("' is not valid double"));

  return retval;
}

ArgvMap::ArgvMap()
{

}

bool ArgvMap::parmIsset(const string &var)
{
  return (params.find(var)!=params.end());
}

void ArgvMap::parseOne(const string &arg, const string &parseOnly, bool lax)
{
  string var, val;
  string::size_type pos;
  bool incremental = false;

  if(arg.find("--") == 0 && (pos=arg.find("+="))!=string::npos) // this is a --port+=25 case
  {
    var=arg.substr(2,pos-2);
    val=arg.substr(pos+2);
    incremental = true;
  }
  else if(arg.find("--") == 0 && (pos=arg.find("="))!=string::npos)  // this is a --port=25 case
  {
    var=arg.substr(2,pos-2);
    val=arg.substr(pos+1);
  }
  else if(arg.find("--") == 0 && (arg.find("=")==string::npos))  // this is a --daemon case
  {
    var=arg.substr(2);
    val="";
  }
  else if(arg[0]=='-')
  {
    var=arg.substr(1);
    val="";
  }
  else // command
    d_cmds.push_back(arg);
 
  boost::trim(var);

  if(var!="" && (parseOnly.empty() || var==parseOnly)) {
    pos=val.find_first_not_of(" \t");  // strip leading whitespace
    if(pos && pos!=string::npos)
      val=val.substr(pos);
    if(parmIsset(var))
    {
      if(incremental)
      {
        if(params[var].empty())
        {
          if(!d_cleared.count(var))
            throw ArgException("Incremental parameter '"+var+"' without a parent");
          params[var]=val;
        }
        else
          params[var]+=", " + val;
      }
      else
      {
        params[var]=val;
        d_cleared.insert(var);
      }
    }
    else if(!lax)
      throw ArgException("Trying to set unknown parameter '"+var+"'");
  }
}

const vector<string>&ArgvMap::getCommands()
{
  return d_cmds;
}

void ArgvMap::parse(int &argc, char **argv, bool lax)
{
  d_cmds.clear();
  d_cleared.clear();
  for(int n=1;n<argc;n++) {
    parseOne(argv[n],"",lax);
  }
}

void ArgvMap::preParse(int &argc, char **argv, const string &arg)
{
  for(int n=1;n<argc;n++) {
    string varval=argv[n];
    if(varval.find("--"+arg) == 0)
      parseOne(argv[n]);
  }
}

bool ArgvMap::parseFile(const char *fname, const string& arg, bool lax) {
  string line;
  string pline;
  string::size_type pos;

  ifstream f(fname);
  if(!f)
    return false;

  while(getline(f,pline)) {
    trim_right(pline);
    
    if(!pline.empty() && pline[pline.size()-1]=='\\') {
      line+=pline.substr(0,pline.length()-1);
      continue;
    }
    else
      line+=pline;

    // strip everything after a #
    if((pos=line.find("#"))!=string::npos) {
      // make sure it's either first char or has whitespace before
      // fixes issue #354
      if (pos == 0 || std::isspace(line[pos-1]))
        line=line.substr(0,pos);
    }

    // strip trailing spaces
    trim_right(line);

    // strip leading spaces
    if((pos=line.find_first_not_of(" \t\r\n"))!=string::npos)
      line=line.substr(pos);

    // gpgsql-basic-query=sdfsdfs dfsdfsdf sdfsdfsfd

    parseOne( string("--") + line, arg, lax );
    line="";
  }

  return true;
}


bool ArgvMap::preParseFile(const char *fname, const string &arg, const string& theDefault)
{
  params[arg]=theDefault;

  return parseFile(fname, arg, false);
}

bool ArgvMap::file(const char *fname, bool lax)
{
   return file(fname,lax,false);
}

bool ArgvMap::file(const char *fname, bool lax, bool included)
{
  if (!parmIsset("include-dir"))  // inject include-dir
    set("include-dir","Directory to include configuration files from");

  if(!parseFile(fname, "", lax)) {
    g_log << Logger::Warning << "Unable to open " << fname << std::endl;
    return false;
  }

  // handle include here (avoid re-include)
  if (!included && !params["include-dir"].empty()) {
    std::vector<std::string> extraConfigs;
    gatherIncludes(extraConfigs); 
    for(const std::string& fn :  extraConfigs) {
      if (!file(fn.c_str(), lax, true)) {
        g_log << Logger::Error << fn << " could not be parsed" << std::endl;
        throw ArgException(fn + " could not be parsed");
      }
    }
  }

  return true;
}

void ArgvMap::gatherIncludes(std::vector<std::string> &extraConfigs) {
  extraConfigs.clear();
  if (params["include-dir"].empty()) return; // nothing to do
    struct stat st;
    DIR *dir;
    struct dirent *ent;

    // stat
    if (stat(params["include-dir"].c_str(), &st)) {
       g_log << Logger::Error << params["include-dir"] << " does not exist!" << std::endl;
       throw ArgException(params["include-dir"] + " does not exist!");
    }

    // wonder if it's accessible directory
    if (!S_ISDIR(st.st_mode)) {
       g_log << Logger::Error << params["include-dir"] << " is not a directory" << std::endl;
       throw ArgException(params["include-dir"] + " is not a directory");
    }

    if (!(dir = opendir(params["include-dir"].c_str()))) {
       g_log << Logger::Error << params["include-dir"] << " is not accessible" << std::endl;
       throw ArgException(params["include-dir"] + " is not accessible");
    }

    while((ent = readdir(dir)) != NULL) {
      if (ent->d_name[0] == '.') continue; // skip any dots
      if (boost::ends_with(ent->d_name, ".conf")) {
        // build name
        std::ostringstream namebuf;
        namebuf << params["include-dir"].c_str() << "/" << ent->d_name; // FIXME: Use some path separator
        // ensure it's readable file
        if (stat(namebuf.str().c_str(), &st) || !S_ISREG(st.st_mode)) {
          g_log << Logger::Error << namebuf.str() << " is not a file" << std::endl;
          closedir(dir);
          throw ArgException(namebuf.str() + " does not exist!");
        }
        extraConfigs.push_back(namebuf.str());
      }
    }
    std::sort(extraConfigs.begin(), extraConfigs.end(), CIStringComparePOSIX()); 
    closedir(dir);
}
