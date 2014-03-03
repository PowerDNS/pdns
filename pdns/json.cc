#include "json.hh"
#include "namespaces.hh"
#include "misc.hh"
#include <boost/foreach.hpp>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

using namespace rapidjson;

int intFromJson(const Value& container, const char* key)
{
  if (!container.IsObject()) {
    throw JsonException("Container was not an object.");
  }
  const Value& val = container[key];
  if (val.IsInt()) {
    return val.GetInt();
  } else if (val.IsString()) {
    return atoi(val.GetString());
  } else {
    throw JsonException("Key '" + string(key) + "' not an Integer or not present");
  }
}

int intFromJson(const Value& container, const char* key, const int default_value)
{
  if (!container.IsObject()) {
    throw JsonException("Container was not an object.");
  }
  const Value& val = container[key];
  if (val.IsInt()) {
    return val.GetInt();
  } else if (val.IsString()) {
    return atoi(val.GetString());
  } else {
    // TODO: check if value really isn't present
    return default_value;
  }
}

string stringFromJson(const Value& container, const char* key)
{
  if (!container.IsObject()) {
    throw JsonException("Container was not an object.");
  }
  const Value& val = container[key];
  if (val.IsString()) {
    return val.GetString();
  } else {
    throw JsonException("Key '" + string(key) + "' not present or not a String");
  }
}

string stringFromJson(const Value& container, const char* key, const string& default_value)
{
  if (!container.IsObject()) {
    throw JsonException("Container was not an object.");
  }
  const Value& val = container[key];
  if (val.IsString()) {
    return val.GetString();
  } else {
    // TODO: check if value really isn't present
    return default_value;
  }
}

bool boolFromJson(const rapidjson::Value& container, const char* key)
{
  if (!container.IsObject()) {
    throw JsonException("Container was not an object.");
  }
  const Value& val = container[key];
  if (val.IsBool()) {
    return val.GetBool();
  } else {
    throw JsonException("Key '" + string(key) + "' not present or not a Bool");
  }
}

bool boolFromJson(const rapidjson::Value& container, const char* key, const bool default_value)
{
  if (!container.IsObject()) {
    throw JsonException("Container was not an object.");
  }
  const Value& val = container[key];
  if (val.IsBool()) {
    return val.GetBool();
  } else {
    return default_value;
  }
}

string makeStringFromDocument(const Document& doc)
{
  StringBuffer output;
  Writer<StringBuffer> w(output);
  doc.Accept(w);
  return string(output.GetString(), output.Size());
}

string returnJsonObject(const map<string, string>& items)
{
  Document doc;
  doc.SetObject();
  typedef map<string, string> items_t;
  BOOST_FOREACH(const items_t::value_type& val, items) {
    doc.AddMember(val.first.c_str(), val.second.c_str(), doc.GetAllocator());
  }
  return makeStringFromDocument(doc);
}

string returnJsonError(const string& error)
{
  Document doc;
  doc.SetObject();
  Value jerror(error.c_str(), doc.GetAllocator()); // copy
  doc.AddMember("error", jerror, doc.GetAllocator());
  return makeStringFromDocument(doc);
}
