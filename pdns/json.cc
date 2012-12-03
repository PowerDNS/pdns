#include "json.hh"
#include "namespaces.hh"
#include <stdio.h>
#include <boost/circular_buffer.hpp>
#include <boost/tokenizer.hpp>
#include "namespaces.hh"
#include "misc.hh"
#include <boost/foreach.hpp>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

using namespace rapidjson;                        

string makeStringFromDocument(Document& doc)
{
  StringBuffer output;
  Writer<StringBuffer> w(output);
  doc.Accept(w);
  return string(output.GetString(), output.Size());
}

string returnJSONObject(const map<string, string>& items)
{
  Document doc;
  doc.SetObject();
  typedef map<string, string> items_t;
  BOOST_FOREACH(const items_t::value_type& val, items) {
    doc.AddMember(val.first.c_str(), val.second.c_str(), doc.GetAllocator());
  }
  return makeStringFromDocument(doc);
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

  Document doc;
  doc.SetArray();
  if(!lines.empty()) {
    BOOST_FOREACH(const string& line, lines) {
      doc.PushBack(line.c_str(), doc.GetAllocator());
    }
  }
  return makeStringFromDocument(doc);
}
