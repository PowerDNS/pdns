#include "json.hh"
#include "namespaces.hh"
#include <stdio.h>
#include <boost/circular_buffer.hpp>
#include <boost/tokenizer.hpp>
#include "namespaces.hh"
#include "misc.hh"
#include <boost/foreach.hpp>

std::string escapeJSON( const std::string & name)
{
  std::string a;
  
  for( std::string::const_iterator i = name.begin(); i != name.end(); ++i ) 
  {
    if( *i == '\"' || *i == '\\' )
      a += '\\';
                
    a += *i;
  }
  return a;
}
                        

string returnJSONObject(const map<string, string>& items)
{
  ostringstream ostr;
  typedef map<string, string> map_t;
  ostr<<"{";
  for(map_t::const_iterator val = items.begin(); val != items.end(); ++val)
  {
    if(val != items.begin()) ostr<<", ";
    ostr << "\"" << val->first <<"\": \""<<escapeJSON(val->second)<<"\"\n";
  }
  ostr<<"}";
  return ostr.str();
}

string makeLogGrepJSON(map<string, string>& varmap, const string& fname, const string& prefix)
{
  FILE* ptr = fopen(fname.c_str(), "r");
  if(!ptr) {
    return "[]";
  }
  boost::shared_ptr<FILE> fp(ptr, fclose);

  string line;
  string needle=varmap["needle"];
  trim_right(needle);

  boost::replace_all(needle, "%20", " ");  
  boost::replace_all(needle, "%22", "\"");    

  boost::tokenizer<boost::escaped_list_separator<char> > t(needle, boost::escaped_list_separator<char>("\\", " ", "\""));
  vector<string> matches(t.begin(), t.end());
  matches.push_back(prefix);
  
  boost::circular_buffer<string> lines(200);
  while(stringfgets(fp.get(), line)) {
    vector<string>::const_iterator iter;
    for(iter = matches.begin(); iter != matches.end(); ++iter) {
      if(!strcasestr(line.c_str(), iter->c_str()))
        break;
    }
    if(iter == matches.end()) { 
      trim_right(line);
      lines.push_front(line);
    }
  }
  bool first=true;
  string ret="[";
  if(!lines.empty()) {
    BOOST_FOREACH(const string& line, lines) {
      if(!first) {
        ret += ",\n";
      }
      else first=false;
      ret += "[\"" + escapeJSON(line)+"\"]";
    }
  }
  ret+="]";
  return ret;
}
