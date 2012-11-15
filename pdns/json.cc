#include "json.hh"
#include "namespaces.hh"

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
