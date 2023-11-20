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

#include <fstream>
#include <regex>
#include <unistd.h>
#include <cstdio>
#include <libgen.h>

#include "namespaces.hh"
#include "arguments.hh"
#include "misc.hh"
#include "cxxsettings.hh"
#include "cxxsettings-private.hh"
#include "logger.hh"
#include "logging.hh"

::rust::Vec<::rust::String> pdns::settings::rec::getStrings(const std::string& name)
{
  ::rust::Vec<::rust::String> vec;
  to_yaml(vec, arg()[name]);
  return vec;
}

::rust::Vec<ForwardZone> pdns::settings::rec::getForwardZones(const string& name)
{
  ::rust::Vec<ForwardZone> vec;
  const auto recurse = name == "forward-zones-recurse";
  to_yaml(vec, arg()[name], recurse);
  return vec;
}

::rust::Vec<AuthZone> pdns::settings::rec::getAuthZones(const string& name)
{
  ::rust::Vec<AuthZone> vec;
  to_yaml(vec, arg()[name]);
  return vec;
}

void pdns::settings::rec::oldStyleForwardsFileToBridgeStruct(const std::string& file, ::rust::Vec<ForwardZone>& vec)
{
  auto filePtr = std::unique_ptr<FILE, decltype(&fclose)>(fopen(file.c_str(), "r"), fclose);
  if (!filePtr) {
    throw PDNSException("Error opening forward-zones-file '" + file + "': " + stringerror());
  }

  string line;
  int linenum = 0;
  while (linenum++, stringfgets(filePtr.get(), line)) {
    boost::trim(line);
    if (line.length() == 0 || line.at(0) == '#') { // Comment line, skip to the next line
      continue;
    }
    auto [domain, instructions] = splitField(line, '=');
    instructions = splitField(instructions, '#').first; // Remove EOL comments
    boost::trim(domain);
    boost::trim(instructions);
    if (domain.empty() || instructions.empty()) {
      throw PDNSException("Error parsing line " + std::to_string(linenum) + " of " + file);
    }
    bool allowNotify = false;
    bool recurse = false;
    for (; !domain.empty(); domain.erase(0, 1)) {
      switch (domain[0]) {
      case '+':
        recurse = true;
        continue;
      case '^':
        allowNotify = true;
        continue;
      }
      break;
    }
    if (domain.empty()) {
      throw PDNSException("Error parsing line " + std::to_string(linenum) + " of " + file);
    }
    ::rust::Vec<::rust::String> addresses;
    stringtok(addresses, instructions, ",; ");
    ForwardZone forwardzone{domain, std::move(addresses), recurse, allowNotify};
    vec.push_back(std::move(forwardzone));
  }
}

void pdns::settings::rec::oldStyleAllowFileToBridgeStruct(const std::string& file, ::rust::Vec<::rust::String>& vec)
{
  string line;
  ifstream ifs(file);
  if (!ifs) {
    int err = errno;
    throw runtime_error("Could not open '" + file + "': " + stringerror(err));
  }

  while (getline(ifs, line)) {
    auto pos = line.find('#');
    if (pos != string::npos) {
      line.resize(pos);
    }
    boost::trim(line);
    if (line.empty()) {
      continue;
    }
    vec.emplace_back(line);
  }
}

static void mergeYamlSubFile(const std::string& configname, Recursorsettings& settings, bool allowabsent, Logr::log_t log)
{
  auto file = ifstream(configname);
  if (!file.is_open()) {
    if (allowabsent) {
      return;
    }
    throw runtime_error("Cannot open " + configname);
  }
  SLOG(g_log << Logger::Notice << "Processing YAML settings from " << configname << endl,
       log->info(Logr::Notice, "Processing YAML settings", "path", Logging::Loggable(configname)));
  auto data = string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  pdns::rust::settings::rec::merge(settings, data);
}

static void possiblyConvertACLFile(const string& includeDir, const string& apiDir, const std::string& filename, Logr::log_t log)
{
  auto path = includeDir;
  path.append("/").append(filename).append(".conf");
  auto file = ifstream(path);
  if (!file.is_open()) {
    // Not an error, file just is not there
    return;
  }
  rust::vec<rust::string> result;
  std::string line;
  while (getline(file, line)) {
    auto pos = line.find('#');
    if (pos != string::npos) {
      line.resize(pos);
    }
    boost::trim(line);
    if (line.empty()) {
      continue;
    }
    auto plusis = line.find("+=");
    if (plusis != string::npos) {
      auto val = line.substr(plusis + 2);
      boost::trim(val);
      result.emplace_back(val);
    }
  }

  rust::string key = "allow_from";
  rust::string filekey = "allow_from_file";
  if (filename == "allow-notify-from") {
    key = "allow_notify_from";
    filekey = "allow_notify_from_file";
  }
  const auto yaml = pdns::rust::settings::rec::allow_from_to_yaml_string_incoming(key, filekey, result);

  string yamlfilename = apiDir;
  yamlfilename.append("/").append(filename).append(".yml");
  string tmpfilename = yamlfilename + ".tmp";
  ofstream ofconf(tmpfilename);
  if (!ofconf) {
    int err = errno;
    log->error(Logr::Error, err, "Cannot open for file for writing YAML", "to", Logging::Loggable(tmpfilename));
    throw runtime_error("YAML Conversion");
  }
  ofconf << "# Generated by pdns-recursor REST API, DO NOT EDIT" << endl;
  ofconf << yaml << endl;
  ofconf.close();
  if (ofconf.bad()) {
    log->error(Logr::Error, "Error writing YAML", "to", Logging::Loggable(tmpfilename));
    unlink(tmpfilename.c_str());
    throw runtime_error("YAML Conversion");
  }
  if (rename(path.c_str(), (path + ".converted").c_str()) != 0) {
    int err = errno;
    log->error(Logr::Error, err, "Rename failed", "file", Logging::Loggable(path), "to", Logging::Loggable(path + ".converted"));
    unlink(tmpfilename.c_str());
    throw runtime_error("YAML Conversion");
  }

  if (rename(tmpfilename.c_str(), yamlfilename.c_str()) != 0) {
    int err = errno;
    log->error(Logr::Error, err, "Rename failed", "file", Logging::Loggable(tmpfilename), "to", Logging::Loggable(yamlfilename));
    if (rename((path + ".converted").c_str(), path.c_str()) != 0) {
      err = errno;
      log->error(Logr::Error, err, "Rename failed", "file", Logging::Loggable(path + ".converted"), "to", Logging::Loggable(path));
    }
    throw runtime_error("YAML Conversion");
  }
  log->info(Logr::Notice, "Converted to YAML", "file", Logging::Loggable(path), "to", Logging::Loggable(yamlfilename));
}

static void fileCopy(const string& src, const string& dst, Logr::log_t log)
{
  ifstream ifconf(src);
  if (!ifconf) {
    log->info(Logr::Error, "Cannot open for file for reading", "file", Logging::Loggable(src));
    throw runtime_error("YAML Conversion");
  }
  ofstream ofconf(dst);
  if (!ofconf) {
    log->info(Logr::Error, "Cannot open for file for writing YAML", "to", Logging::Loggable(dst));
    throw runtime_error("YAML Conversion");
  }
  for (;;) {
    auto character = ifconf.get();
    if (ifconf.eof()) {
      break;
    }
    if (ifconf.bad()) {
      int err = errno;
      log->error(Logr::Error, err, "Error reading", "to", Logging::Loggable(src));
      throw runtime_error("YAML Conversion");
    }
    ofconf.put(static_cast<char>(character));
    if (ofconf.bad()) {
      int err = errno;
      log->error(Logr::Error, err, "Error writing YAML", "to", Logging::Loggable(dst));
      throw runtime_error("YAML Conversion");
    }
  }
  ifconf.close();
  ofconf.close();
  if (ofconf.bad()) {
    log->error(Logr::Error, "Error writing YAML", "to", Logging::Loggable(dst));
    throw runtime_error("YAML Conversion");
  }
}

static void possiblyConvertForwardsandAuths(const std::string& includeDir, const std::string& apiDir, Logr::log_t log)
{
  std::vector<std::string> forwAndAuthFiles{};
  ::arg().gatherIncludes(includeDir, "..conf", forwAndAuthFiles);
  pdns::rust::settings::rec::Recursorsettings settings{};
  for (const auto& file : forwAndAuthFiles) {
    auto yaml = pdns::settings::rec::oldStyleSettingsFileToYaml(file, false);
    pdns::rust::settings::rec::merge(settings, yaml);
  }
  const string yamlAPiZonesFile = apiDir + "/apizones";

  for (auto& zone : settings.recursor.auth_zones) {
    const std::string origName(zone.file);
    std::string newName(zone.file);
    newName.replace(0, includeDir.length(), apiDir);
    log->info(Logr::Notice, "Copying auth zone file", "file", Logging::Loggable(origName), "to", Logging::Loggable(newName));
    fileCopy(origName, newName, log);
    zone.file = ::rust::String(newName);
    api_add_auth_zone(yamlAPiZonesFile, zone);
  }
  api_add_forward_zones(yamlAPiZonesFile, settings.recursor.forward_zones);
  api_add_forward_zones(yamlAPiZonesFile, settings.recursor.forward_zones_recurse);
  for (const auto& file : forwAndAuthFiles) {
    if (rename(file.c_str(), (file + ".converted").c_str()) != 0) {
      int err = errno;
      log->error(Logr::Error, err, "Rename failed", "file", Logging::Loggable(file), "to", Logging::Loggable(file + ".converted"));
    }
  }
}

void pdns::settings::rec::processAPIDir(const string& includeDirOnCommandLine, pdns::rust::settings::rec::Recursorsettings& settings, Logr::log_t log)
{
  auto apiDir = std::string(settings.webservice.api_dir);
  if (apiDir.empty()) {
    return;
  }
  auto includeDir = std::string(settings.recursor.include_dir);
  if (!includeDirOnCommandLine.empty()) {
    includeDir = includeDirOnCommandLine;
  }
  if (includeDir == apiDir) {
    throw runtime_error("Active YAML settings do not allow include_dir to be equal to api_dir");
  }
  const std::array<std::string, 2> aclFiles = {
    "allow-from",
    "allow-notify-from"};
  for (const auto& file : aclFiles) {
    possiblyConvertACLFile(includeDir, apiDir, file, log);
    auto path = apiDir;
    path.append("/").append(file).append(".yml");
    mergeYamlSubFile(path, settings, true, log);
  }
  possiblyConvertForwardsandAuths(includeDir, apiDir, log);
}

pdns::settings::rec::YamlSettingsStatus pdns::settings::rec::readYamlSettings(const std::string& configname, const std::string& includeDirOnCommandLine, Recursorsettings& settings, std::string& msg, Logr::log_t log)
{
  auto file = ifstream(configname);
  if (!file.is_open()) {
    msg = stringerror(errno);
    return YamlSettingsStatus::CannotOpen;
  }
  SLOG(g_log << Logger::Notice << "Processing main YAML settings from " << configname << endl,
       log->info(Logr::Notice, "Processing main YAML settings", "path", Logging::Loggable(configname)));
  try {
    auto data = string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    auto yamlstruct = pdns::rust::settings::rec::parse_yaml_string(data);
    std::vector<std::string> yamlFiles;
    ::arg().gatherIncludes(!includeDirOnCommandLine.empty() ? includeDirOnCommandLine : string(yamlstruct.recursor.include_dir),
                           ".yml", yamlFiles);
    for (const auto& yamlfile : yamlFiles) {
      mergeYamlSubFile(yamlfile, yamlstruct, false, log);
    }
    yamlstruct.validate();
    settings = std::move(yamlstruct);
    return YamlSettingsStatus::OK;
  }
  catch (const ::rust::Error& ex) {
    msg = ex.what();
    return YamlSettingsStatus::PresentButFailed;
  }
  catch (const std::exception& ex) {
    msg = ex.what();
    return YamlSettingsStatus::PresentButFailed;
  }
  catch (...) {
    msg = "Unexpected exception processing YAML";
    return YamlSettingsStatus::PresentButFailed;
  }
}

void pdns::settings::rec::readYamlAllowFromFile(const std::string& filename, ::rust::Vec<::rust::String>& vec, Logr::log_t log)
{
  SLOG(g_log << Logger::Notice << "Processing allow YAML settings from " << filename << endl,
       log->info(Logr::Notice, "Processing allow YAML settings", "path", Logging::Loggable(filename)));
  auto file = ifstream(filename);
  if (!file.is_open()) {
    throw runtime_error(stringerror(errno));
  }
  auto data = string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  auto yamlvec = pdns::rust::settings::rec::parse_yaml_string_to_allow_from(data);
  pdns::rust::settings::rec::validate_allow_from(filename, yamlvec);
  vec = std::move(yamlvec);
}

void pdns::settings::rec::readYamlForwardZonesFile(const std::string& filename, ::rust::Vec<pdns::rust::settings::rec::ForwardZone>& vec, Logr::log_t log)
{
  SLOG(g_log << Logger::Notice << "Processing forwarding YAML settings from " << filename << endl,
       log->info(Logr::Notice, "Processing forwarding YAML settings", "path", Logging::Loggable(filename)));
  auto file = ifstream(filename);
  if (!file.is_open()) {
    throw runtime_error(stringerror(errno));
  }
  auto data = string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  auto yamlvec = pdns::rust::settings::rec::parse_yaml_string_to_forward_zones(data);
  pdns::rust::settings::rec::validate_forward_zones("forward_zones", yamlvec);
  vec = std::move(yamlvec);
}

void pdns::settings::rec::readYamlAllowNotifyForFile(const std::string& filename, ::rust::Vec<::rust::String>& vec, Logr::log_t log)
{
  SLOG(g_log << Logger::Notice << "Processing allow-notify-for YAML settings from " << filename << endl,
       log->info(Logr::Notice, "Processing allow-notify-for YAML settings", "path", Logging::Loggable(filename)));
  auto file = ifstream(filename);
  if (!file.is_open()) {
    throw runtime_error(stringerror(errno));
  }
  auto data = string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  auto yamlvec = pdns::rust::settings::rec::parse_yaml_string_to_allow_notify_for(data);
  pdns::rust::settings::rec::validate_allow_notify_for("allow-notify-for", yamlvec);
  vec = std::move(yamlvec);
}

std::string pdns::settings::rec::to_arg(const AuthZone& authzone)
{
  std::ostringstream str;
  str << to_arg(authzone.zone) << '=' << to_arg(authzone.file);
  return str.str();
}

std::string pdns::settings::rec::to_arg(const ForwardZone& forwardzone)
{
  std::ostringstream str;
  str << to_arg(forwardzone.zone) << '=';
  const auto& vec = forwardzone.forwarders;
  for (auto iter = vec.begin(); iter != vec.end(); ++iter) {
    if (iter != vec.begin()) {
      str << ';';
    }
    str << to_arg(*iter);
  }
  return str.str();
}

void pdns::settings::rec::setArgsForZoneRelatedSettings(Recursorsettings& settings)
{
  ::arg().set("forward-zones") = to_arg(settings.recursor.forward_zones);
  ::arg().set("forward-zones-file") = to_arg(settings.recursor.forward_zones_file);
  ::arg().set("forward-zones-recurse") = to_arg(settings.recursor.forward_zones_recurse);
  ::arg().set("auth-zones") = to_arg(settings.recursor.auth_zones);
  ::arg().set("allow-notify-for") = to_arg(settings.incoming.allow_notify_for);
  ::arg().set("allow-notify-for-file") = to_arg(settings.incoming.allow_notify_for_file);
  ::arg().set("export-etc-hosts") = to_arg(settings.recursor.export_etc_hosts);
  ::arg().set("serve-rfc1918") = to_arg(settings.recursor.serve_rfc1918);
}

void pdns::settings::rec::setArgsForACLRelatedSettings(Recursorsettings& settings)
{
  ::arg().set("allow-from") = to_arg(settings.incoming.allow_from);
  ::arg().set("allow-from-file") = to_arg(settings.incoming.allow_from_file);
  ::arg().set("allow-notify-from") = to_arg(settings.incoming.allow_notify_from);
  ::arg().set("allow-notify-from-file") = to_arg(settings.incoming.allow_notify_from_file);
}

void pdns::settings::rec::to_yaml(uint64_t& field, const std::string& val)
{
  if (val.empty()) {
    field = 0;
    return;
  }

  checked_stoi_into(field, val, nullptr, 0);
}

void pdns::settings::rec::to_yaml(double& field, const std::string& val)
{
  if (val.empty()) {
    field = 0.0;
    return;
  }

  const auto* cptr_orig = val.c_str();
  char* cptr_ret = nullptr;
  auto retval = strtod(cptr_orig, &cptr_ret);

  field = retval;
}

void pdns::settings::rec::to_yaml(::rust::Vec<AuthZone>& field, const std::string& val)
{
  vector<string> zones;
  stringtok(zones, val, " ,\t\n\r");
  for (const auto& zone : zones) {
    auto headers = splitField(zone, '=');
    boost::trim(headers.first);
    boost::trim(headers.second);
    AuthZone authzone{headers.first, headers.second};
    field.push_back(std::move(authzone));
  }
}

void pdns::settings::rec::to_yaml(::rust::Vec<ForwardZone>& field, const std::string& val, bool recurse)
{
  vector<string> zones;
  stringtok(zones, val, " ,\t\n\r");
  for (const auto& zone : zones) {
    auto headers = splitField(zone, '=');
    boost::trim(headers.first);
    boost::trim(headers.second);
    ::rust::Vec<::rust::String> addresses;
    stringtok(addresses, headers.second, " ;");
    ForwardZone forwardzone{headers.first, std::move(addresses), recurse, false};
    field.push_back(std::move(forwardzone));
  }
}

using FieldMap = std::map<pair<::rust::String, ::rust::String>, pdns::rust::settings::rec::OldStyle>;

static bool simpleRustType(const ::rust::String& rname)
{
  return rname == "bool" || rname == "u64" || rname == "f64" || rname == "String";
}

static void processLine(const std::string& arg, FieldMap& map, bool mainFile)
{
  string var;
  string val;
  string::size_type pos = 0;
  bool incremental = false;

  if (arg.find("--") == 0 && (pos = arg.find("+=")) != string::npos) // this is a --port+=25 case
  {
    var = arg.substr(2, pos - 2);
    val = arg.substr(pos + 2);
    incremental = true;
  }
  else if (arg.find("--") == 0 && (pos = arg.find('=')) != string::npos) // this is a --port=25 case
  {
    var = arg.substr(2, pos - 2);
    val = arg.substr(pos + 1);
  }
  else if (arg.find("--") == 0 && (arg.find('=') == string::npos)) // this is a --daemon case
  {
    var = arg.substr(2);
    val = "";
  }
  else if (arg[0] == '-' && arg.length() > 1) {
    var = arg.substr(1);
    val = "";
  }
  boost::trim(var);
  if (var.empty()) {
    return;
  }
  pos = val.find_first_not_of(" \t"); // strip leading whitespace
  if (pos != 0 && pos != string::npos) {
    val = val.substr(pos);
  }

  ::rust::String section;
  ::rust::String fieldname;
  ::rust::String type_name;
  pdns::rust::settings::rec::Value rustvalue = {false, 0, 0.0, "", {}, {}, {}};
  if (pdns::settings::rec::oldKVToBridgeStruct(var, val, section, fieldname, type_name, rustvalue)) {
    auto overriding = !mainFile && !incremental && !simpleRustType(type_name);
    auto [existing, inserted] = map.emplace(std::pair{std::pair{section, fieldname}, pdns::rust::settings::rec::OldStyle{section, fieldname, var, std::move(type_name), rustvalue, overriding}});
    if (!inserted) {
      // Simple values overwrite always
      existing->second.value.bool_val = rustvalue.bool_val;
      existing->second.value.u64_val = rustvalue.u64_val;
      existing->second.value.f64_val = rustvalue.f64_val;
      existing->second.value.string_val = rustvalue.string_val;
      // List values only if = was used
      if (!incremental) {
        existing->second.value.vec_string_val.clear();
        existing->second.value.vec_forwardzone_val.clear();
        existing->second.value.vec_authzone_val.clear();
      }
      for (const auto& add : rustvalue.vec_string_val) {
        existing->second.value.vec_string_val.emplace_back(add);
      }
      for (const auto& add : rustvalue.vec_forwardzone_val) {
        existing->second.value.vec_forwardzone_val.emplace_back(add);
      }
      for (const auto& add : rustvalue.vec_authzone_val) {
        existing->second.value.vec_authzone_val.emplace_back(add);
      }
    }
  }
}

std::string pdns::settings::rec::oldStyleSettingsFileToYaml(const string& fname, bool mainFile)
{
  string line;
  string pline;

  std::ifstream configFileStream(fname);
  if (!configFileStream) {
    int err = errno;
    throw runtime_error("Cannot read " + fname + ": " + stringerror(err));
  }

  // Read the old-style config file and produce a map with the data, taking into account the
  // difference between = and +=
  FieldMap map;
  while (getline(configFileStream, pline)) {
    boost::trim_right(pline);

    if (!pline.empty() && pline[pline.size() - 1] == '\\') {
      line += pline.substr(0, pline.length() - 1);
      continue;
    }

    line += pline;

    // strip everything after a #
    string::size_type pos = line.find('#');
    if (pos != string::npos) {
      // make sure it's either first char or has whitespace before
      // fixes issue #354
      if (pos == 0 || (std::isspace(line[pos - 1]) != 0)) {
        line = line.substr(0, pos);
      }
    }

    // strip trailing spaces
    boost::trim_right(line);

    // strip leading spaces
    pos = line.find_first_not_of(" \t\r\n");
    if (pos != string::npos) {
      line = line.substr(pos);
    }

    processLine("--" + line, map, mainFile);
    line = "";
  }

  // Convert the map to a vector, as CXX does not have any dictionary like support.
  ::rust::Vec<pdns::rust::settings::rec::OldStyle> vec;
  vec.reserve(map.size());
  for (const auto& entry : map) {
    vec.emplace_back(entry.second);
  }
  return std::string(pdns::rust::settings::rec::map_to_yaml_string(vec));
}

std::string pdns::settings::rec::defaultsToYaml()
{
  // In this function we make use of the fact that we know a little about the formatting of YAML by
  // serde_yaml.  ATM there's no way around that, as serde_yaml itself does not have any support for
  // comments (other than stripping them while parsing). So produced YAML cannot have any comments.

  // First we construct a map of (section, name) to info about the field (oldname, type, value etc)
  FieldMap map;
  for (const auto& var : arg().list()) {
    if (const auto newname = ArgvMap::isDeprecated(var); !newname.empty()) {
      continue;
    }
    ::rust::String section;
    ::rust::String fieldname;
    ::rust::String type_name;
    pdns::rust::settings::rec::Value rustvalue{false, 0, 0.0, "", {}, {}, {}};
    string name = var;
    string val = arg().getDefault(var);
    if (pdns::settings::rec::oldKVToBridgeStruct(name, val, section, fieldname, type_name, rustvalue)) {
      map.emplace(std::pair{std::pair{section, fieldname}, pdns::rust::settings::rec::OldStyle{section, fieldname, name, std::move(type_name), std::move(rustvalue), false}});
    }
  }
  // Convert the map to a vector, as CXX does not have any dictionary like support.
  ::rust::Vec<pdns::rust::settings::rec::OldStyle> vec;
  vec.reserve(map.size());
  for (const auto& entry : map) {
    vec.emplace_back(entry.second);
  }
  const auto defs = std::string(pdns::rust::settings::rec::map_to_yaml_string(vec));

  // We now have a YAML string, with all sections and all default values. Do a litle bit of parsing
  // to insert the help text lines.
  std::vector<std::string> lines;
  stringtok(lines, defs, "\n");
  std::string res;

  // These two RE's know about the formatting generated by serde_yaml
  std::regex sectionRE("^(\\w+):");
  std::regex fieldRE("^  (\\w+):");
  std::string section;
  std::string field;

  for (const auto& line : lines) {
    bool withHelp = false;
    bool sectionChange = false;
    std::smatch matches;
    std::regex_search(line, matches, sectionRE);
    if (!matches.empty()) {
      section = matches[1];
      sectionChange = true;
    }
    std::regex_search(line, matches, fieldRE);
    if (!matches.empty()) {
      field = matches[1];
      withHelp = true;
    }
    if (withHelp) {
      std::string oldname;
      if (auto iter = map.find(make_pair(section, field)); iter != map.end()) {
        oldname = std::string(iter->second.old_name);
      }
      res += "##### ";
      res += arg().getHelp(oldname);
      res += '\n';
    }
    if (sectionChange) {
      res += "\n######### SECTION ";
      res += section;
      res += " #########\n";
      res += line;
    }
    else {
      res += "# ";
      res += line;
    }
    res += '\n';
  }
  return res;
}
