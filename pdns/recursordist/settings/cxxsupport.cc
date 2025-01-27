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
#include "rec-lua-conf.hh"
#include "root-dnssec.hh"
#include "dnsrecords.hh"
#include "base64.hh"
#include "validate-recursor.hh"
#include "threadname.hh"
#include "iputils.hh"
#include "bridge.hh"
#include "settings/rust/web.rs.h"

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
  auto filePtr = pdns::UniqueFilePtr(fopen(file.c_str(), "r"));
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
      vector<string> acls;
      stringtok(acls, val, " ,\t");
      for (const auto& acl : acls) {
        result.emplace_back(acl);
      }
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

template <typename T>
static void addToAllowNotifyFor(Recursorsettings& settings, const rust::Vec<T>& vec)
{
  for (const auto& item : vec) {
    if (item.notify_allowed) {
      settings.incoming.allow_notify_for.emplace_back(item.zone);
    }
  }
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
    // Add the zones with notify_allowed to allow_notify_for. For a forward_zones_file that will be
    // taken care of elsewhere.  One drawback: the zones will be shown in allow_notify_for if you
    // run --config, while they aren't actually there in any config file.
    addToAllowNotifyFor(yamlstruct, yamlstruct.recursor.forward_zones);
    addToAllowNotifyFor(yamlstruct, yamlstruct.recursor.forward_zones_recurse);
    addToAllowNotifyFor(yamlstruct, yamlstruct.recursor.forwarding_catalog_zones);
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
  pdns::rust::settings::rec::Value rustvalue = {false, 0, 0.0, "", {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}};
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
    pdns::rust::settings::rec::Value rustvalue{};
    string name = var;
    string val = arg().getDefault(var);
    if (pdns::settings::rec::oldKVToBridgeStruct(name, val, section, fieldname, type_name, rustvalue)) {
      map.emplace(std::pair{std::pair{section, fieldname}, pdns::rust::settings::rec::OldStyle{section, fieldname, name, std::move(type_name), std::move(rustvalue), false}});
    }
  }

  // Should be generated
  auto def = [&](const string& section, const string& name, const string& type) {
    pdns::rust::settings::rec::Value rustvalue{};
    // Dirty hack: trustanchorfile_interval is the only u64 value, set the right default for it.
    // And for all other values below, the default is either an empty string or an empty vector.
    // Once we get more u64 values below with different default values this hack no longer works.
    rustvalue.u64_val = 24;
    map.emplace(std::pair{std::pair{section, name}, pdns::rust::settings::rec::OldStyle{section, name, name, type, std::move(rustvalue), false}});
  };
  def("dnssec", "trustanchors", "Vec<TrustAnchor>");
  def("dnssec", "negative_trustanchors", "Vec<NegativeTrustAnchor>");
  def("dnssec", "trustanchorfile", "String");
  def("dnssec", "trustanchorfile_interval", "u64");
  def("logging", "protobuf_servers", "Vec<ProtobufServer>");
  def("logging", "outgoing_protobuf_servers", "Vec<ProtobufServer>");
  def("logging", "dnstap_framestream_servers", "Vec<DNSTapFrameStreamServer>");
  def("logging", "dnstap_nod_framestream_servers", "Vec<DNSTapNODFrameStreamServer>");
  def("recursor", "rpzs", "Vec<RPZ>");
  def("recursor", "sortlists", "Vec<SortList>");
  def("recordcache", "zonetocaches", "Vec<ZoneToCache>");
  def("recursor", "allowed_additional_qtypes", "Vec<AllowedAdditionalQType>");
  def("incoming", "proxymappings", "Vec<ProxyMapping>");
  def("recursor", "forwarding_catalog_zones", "Vec<ForwardingCatalogZone>");
  // End of should be generated XXX

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
      auto help = arg().getHelp(oldname);
      if (help.empty()) {
        replace(oldname.begin(), oldname.end(), '_', '-');
        help = arg().getHelp(oldname);
      }
      res += help;
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

namespace
{
void fromLuaToRust(const LuaConfigItems& luaConfig, pdns::rust::settings::rec::Dnssec& dnssec)
{
  dnssec.trustanchorfile = luaConfig.trustAnchorFileInfo.fname;
  dnssec.trustanchorfile_interval = luaConfig.trustAnchorFileInfo.interval;
  dnssec.trustanchors.clear();
  for (const auto& anchors : luaConfig.dsAnchors) {
    ::rust::Vec<::rust::String> dsRecords;
    for (const auto& dsRecord : anchors.second) {
      const auto dsString = dsRecord.getZoneRepresentation();
      if (anchors.first != g_rootdnsname || std::find(rootDSs.begin(), rootDSs.end(), dsString) == rootDSs.end()) {
        dsRecords.emplace_back(dsRecord.getZoneRepresentation());
      }
    }
    if (!dsRecords.empty()) {
      pdns::rust::settings::rec::TrustAnchor trustAnchor{anchors.first.toString(), std::move(dsRecords)};
      dnssec.trustanchors.emplace_back(trustAnchor);
    }
  }
  for (const auto& anchors : luaConfig.negAnchors) {
    pdns::rust::settings::rec::NegativeTrustAnchor negtrustAnchor{anchors.first.toString(), anchors.second};
    dnssec.negative_trustanchors.emplace_back(negtrustAnchor);
  }
}

void fromLuaToRust(const ProtobufExportConfig& pbConfig, pdns::rust::settings::rec::ProtobufServer& pbServer)
{
  for (const auto& server : pbConfig.servers) {
    pbServer.servers.emplace_back(server.toStringWithPort());
  }
  pbServer.timeout = pbConfig.timeout;
  pbServer.maxQueuedEntries = pbConfig.maxQueuedEntries;
  pbServer.reconnectWaitTime = pbConfig.reconnectWaitTime;
  pbServer.taggedOnly = pbConfig.taggedOnly;
  pbServer.asyncConnect = pbConfig.asyncConnect;
  pbServer.logQueries = pbConfig.logQueries;
  pbServer.logResponses = pbConfig.logResponses;
  for (const auto num : pbConfig.exportTypes) {
    pbServer.exportTypes.emplace_back(QType(num).toString());
  }
  pbServer.logMappedFrom = pbConfig.logMappedFrom;
}

void fromLuaToRust(const FrameStreamExportConfig& fsc, pdns::rust::settings::rec::DNSTapFrameStreamServer& dnstap)
{
  for (const auto& server : fsc.servers) {
    dnstap.servers.emplace_back(server);
  }
  dnstap.logQueries = fsc.logQueries;
  dnstap.logResponses = fsc.logResponses;
  dnstap.bufferHint = fsc.bufferHint;
  dnstap.flushTimeout = fsc.flushTimeout;
  dnstap.inputQueueSize = fsc.inputQueueSize;
  dnstap.outputQueueSize = fsc.outputQueueSize;
  dnstap.queueNotifyThreshold = fsc.queueNotifyThreshold;
  dnstap.reopenInterval = fsc.reopenInterval;
}

void fromLuaToRust(const FrameStreamExportConfig& fsc, pdns::rust::settings::rec::DNSTapNODFrameStreamServer& dnstap)
{
  for (const auto& server : fsc.servers) {
    dnstap.servers.emplace_back(server);
  }
  dnstap.logNODs = fsc.logNODs;
  dnstap.logUDRs = fsc.logUDRs;
  dnstap.bufferHint = fsc.bufferHint;
  dnstap.flushTimeout = fsc.flushTimeout;
  dnstap.inputQueueSize = fsc.inputQueueSize;
  dnstap.outputQueueSize = fsc.outputQueueSize;
  dnstap.queueNotifyThreshold = fsc.queueNotifyThreshold;
  dnstap.reopenInterval = fsc.reopenInterval;
}

void assign(pdns::rust::settings::rec::TSIGTriplet& var, const TSIGTriplet& tsig)
{
  var.name = tsig.name.empty() ? "" : tsig.name.toStringNoDot();
  var.algo = tsig.algo.empty() ? "" : tsig.algo.toStringNoDot();
  var.secret = Base64Encode(tsig.secret);
}

void assign(TSIGTriplet& var, const pdns::rust::settings::rec::TSIGTriplet& tsig)
{
  if (!tsig.name.empty()) {
    var.name = DNSName(std::string(tsig.name));
  }
  if (!tsig.algo.empty()) {
    var.algo = DNSName(std::string(tsig.algo));
  }
  B64Decode(std::string(tsig.secret), var.secret);
}

std::string cvt(DNSFilterEngine::PolicyKind kind)
{
  switch (kind) {
  case DNSFilterEngine::PolicyKind::NoAction:
    return "NoAction";
  case DNSFilterEngine::PolicyKind::Drop:
    return "Drop";
  case DNSFilterEngine::PolicyKind::NXDOMAIN:
    return "NXDOMAIN";
  case DNSFilterEngine::PolicyKind::NODATA:
    return "NODATA";
  case DNSFilterEngine::PolicyKind::Truncate:
    return "Truncate";
  case DNSFilterEngine::PolicyKind::Custom:
    return "Custom";
  }
  return "UnknownPolicyKind";
}

void fromLuaToRust(const vector<RPZTrackerParams>& rpzs, pdns::rust::settings::rec::Recursor& rec)
{
  for (const auto& rpz : rpzs) {
    pdns::rust::settings::rec::RPZ rustrpz{
      .name = "",
      .addresses = {},
      .defcontent = "",
      .defpol = "",
      .defpolOverrideLocalData = true,
      .defttl = std::numeric_limits<uint32_t>::max(),
      .extendedErrorCode = std::numeric_limits<uint32_t>::max(),
      .extendedErrorExtra = "",
      .includeSOA = false,
      .ignoreDuplicates = false,
      .maxTTL = std::numeric_limits<uint32_t>::max(),
      .policyName = "",
      .tags = {},
      .overridesGettag = true,
      .zoneSizeHint = 0,
      .tsig = {},
      .refresh = 0,
      .maxReceivedMBytes = 0,
      .localAddress = "",
      .axfrTimeout = 20,
      .dumpFile = "",
      .seedFile = "",
    };

    for (const auto& address : rpz.zoneXFRParams.primaries) {
      rustrpz.addresses.emplace_back(address);
    }
    rustrpz.name = rpz.zoneXFRParams.name;
    rustrpz.defcontent = rpz.defcontent;
    if (rpz.defpol) {
      rustrpz.defpol = cvt(rpz.defpol->d_kind);
      rustrpz.defttl = rpz.defpol->d_ttl;
    }
    rustrpz.defpolOverrideLocalData = rpz.defpolOverrideLocal;
    rustrpz.extendedErrorCode = rpz.extendedErrorCode;
    rustrpz.extendedErrorExtra = rpz.extendedErrorExtra;
    rustrpz.includeSOA = rpz.includeSOA;
    rustrpz.ignoreDuplicates = rpz.ignoreDuplicates;
    rustrpz.maxTTL = rpz.maxTTL;
    rustrpz.policyName = rpz.polName;
    for (const auto& tag : rpz.tags) {
      rustrpz.tags.emplace_back(tag);
    }
    rustrpz.overridesGettag = rpz.defpolOverrideLocal;
    rustrpz.zoneSizeHint = rpz.zoneXFRParams.zoneSizeHint;
    assign(rustrpz.tsig, rpz.zoneXFRParams.tsigtriplet);
    rustrpz.refresh = rpz.zoneXFRParams.refreshFromConf;
    rustrpz.maxReceivedMBytes = rpz.zoneXFRParams.maxReceivedMBytes;
    if (rpz.zoneXFRParams.localAddress != ComboAddress()) {
      rustrpz.localAddress = rpz.zoneXFRParams.localAddress.toString();
    }
    rustrpz.axfrTimeout = rpz.zoneXFRParams.xfrTimeout;
    rustrpz.dumpFile = rpz.dumpZoneFileName;
    rustrpz.seedFile = rpz.seedFileName;

    rec.rpzs.emplace_back(rustrpz);
  }
}

string cvt(pdns::ZoneMD::Config cfg)
{
  switch (cfg) {
  case pdns::ZoneMD::Config::Ignore:
    return "ignore";
  case pdns::ZoneMD::Config::Validate:
    return "validate";
  case pdns::ZoneMD::Config::Require:
    return "require";
  }
  return "UnknownZoneMDConfig";
}

void fromLuaToRust(const map<DNSName, RecZoneToCache::Config>& ztcConfigs, pdns::rust::settings::rec::Recordcache& recordcache)
{
  for (const auto& [_, iter] : ztcConfigs) {
    pdns::rust::settings::rec::ZoneToCache ztc;
    ztc.zone = iter.d_zone;
    ztc.method = iter.d_method;
    for (const auto& src : iter.d_sources) {
      ztc.sources.emplace_back(src);
    }
    ztc.timeout = iter.d_timeout;
    if (!iter.d_tt.name.empty()) {
      ztc.tsig.name = iter.d_tt.name.toString();
      ztc.tsig.algo = iter.d_tt.algo.toString();
      ztc.tsig.secret = Base64Encode(iter.d_tt.secret);
    }
    ztc.refreshPeriod = iter.d_refreshPeriod;
    ztc.retryOnErrorPeriod = iter.d_retryOnError;
    ztc.maxReceivedMBytes = iter.d_maxReceivedBytes;
    if (iter.d_local != ComboAddress()) {
      ztc.localAddress = iter.d_local.toString();
    }
    ztc.zonemd = cvt(iter.d_zonemd);
    ztc.dnssec = cvt(iter.d_dnssec);
    recordcache.zonetocaches.emplace_back(ztc);
  }
}

std::string cvt(AdditionalMode mode)
{
  switch (mode) {
  case AdditionalMode::Ignore:
    return "Ignore";
  case AdditionalMode::CacheOnly:
    return "CacheOnly";
  case AdditionalMode::CacheOnlyRequireAuth:
    return "CacheOnlyRequireAuth";
  case AdditionalMode::ResolveImmediately:
    return "ResolveImmediately";
  case AdditionalMode::ResolveDeferred:
    return "ResolveDeferred";
  }
  return "UnknownAdditionalMode";
}

AdditionalMode cvtAdditional(const std::string& mode)
{
  static const std::map<std::string, AdditionalMode> map = {
    {"Ignore", AdditionalMode::Ignore},
    {"CacheOnly", AdditionalMode::CacheOnly},
    {"CacheOnlyRequireAuth", AdditionalMode::CacheOnlyRequireAuth},
    {"ResolveImmediately", AdditionalMode::ResolveImmediately},
    {"ResolveDeferred", AdditionalMode::ResolveDeferred}};
  if (auto iter = map.find(mode); iter != map.end()) {
    return iter->second;
  }
  throw runtime_error("AdditionalMode '" + mode + "' unknown");
}

pdns::ZoneMD::Config cvtZoneMDConfig(const std::string& mode)
{
  static const std::map<std::string, pdns::ZoneMD::Config> map = {
    {"ignore", pdns::ZoneMD::Config::Ignore},
    {"validate", pdns::ZoneMD::Config::Validate},
    {"require", pdns::ZoneMD::Config::Require},
  };
  if (auto iter = map.find(mode); iter != map.end()) {
    return iter->second;
  }
  throw runtime_error("ZoneMD config '" + mode + "' unknown");
}

void fromLuaToRust(const std::map<QType, std::pair<std::set<QType>, AdditionalMode>>& allowAdditionalQTypes, pdns::rust::settings::rec::Recursor& rec)
{
  for (const auto& [qtype, data] : allowAdditionalQTypes) {
    const auto& [qtypeset, mode] = data;
    pdns::rust::settings::rec::AllowedAdditionalQType add;
    add.qtype = qtype.toString();
    for (const auto& extra : qtypeset) {
      add.targets.emplace_back(extra.toString());
    }
    add.mode = cvt(mode);
    rec.allowed_additional_qtypes.emplace_back(add);
  }
}

void fromLuaToRust(const ProxyMapping& proxyMapping, pdns::rust::settings::rec::Incoming& incoming)
{
  for (const auto& mapping : proxyMapping) {
    pdns::rust::settings::rec::ProxyMapping pmap;
    pmap.subnet = mapping.first.toString();
    pmap.address = mapping.second.address.toString();
    if (mapping.second.suffixMatchNode) {
      for (const auto& domain : mapping.second.suffixMatchNode->d_tree.getNodes()) {
        pmap.domains.emplace_back(domain.toString());
      }
    }
    incoming.proxymappings.emplace_back(pmap);
  }
}

void fromLuaToRust(const SortList& arg, pdns::rust::settings::rec::Recursor& rec)
{
  const auto& sortlist = arg.getTree();
  for (const auto& iter : sortlist) {
    pdns::rust::settings::rec::SortList rsl;
    rsl.key = iter.first.toString();
    const auto& sub = iter.second;
    // Some extra work to present them ordered in the YAML
    std::set<int> indexes;
    std::multimap<int, Netmask> ordered;
    for (auto& order : sub.d_orders) {
      indexes.emplace(order.second);
      ordered.emplace(order.second, order.first);
    }
    for (const auto& index : indexes) {
      const auto& range = ordered.equal_range(index);
      for (auto subnet = range.first; subnet != range.second; ++subnet) {
        pdns::rust::settings::rec::SubnetOrder snorder;
        snorder.order = index;
        snorder.subnet = subnet->second.toString();
        rsl.subnets.emplace_back(snorder);
      }
    }
    rec.sortlists.emplace_back(rsl);
  }
}
} // namespace

void pdns::settings::rec::fromLuaConfigToBridgeStruct(LuaConfigItems& luaConfig, const ProxyMapping& proxyMapping, pdns::rust::settings::rec::Recursorsettings& settings)
{

  fromLuaToRust(luaConfig, settings.dnssec);
  settings.logging.protobuf_mask_v4 = luaConfig.protobufMaskV4;
  settings.logging.protobuf_mask_v6 = luaConfig.protobufMaskV6;
  if (luaConfig.protobufExportConfig.enabled) {
    pdns::rust::settings::rec::ProtobufServer pbServer;
    fromLuaToRust(luaConfig.protobufExportConfig, pbServer);
    settings.logging.protobuf_servers.emplace_back(pbServer);
  }
  if (luaConfig.outgoingProtobufExportConfig.enabled) {
    pdns::rust::settings::rec::ProtobufServer pbServer;
    fromLuaToRust(luaConfig.outgoingProtobufExportConfig, pbServer);
    settings.logging.outgoing_protobuf_servers.emplace_back(pbServer);
  }
  if (luaConfig.frameStreamExportConfig.enabled) {
    pdns::rust::settings::rec::DNSTapFrameStreamServer dnstap;
    fromLuaToRust(luaConfig.frameStreamExportConfig, dnstap);
    settings.logging.dnstap_framestream_servers.emplace_back(dnstap);
  }
  if (luaConfig.nodFrameStreamExportConfig.enabled) {
    pdns::rust::settings::rec::DNSTapNODFrameStreamServer dnstap;
    fromLuaToRust(luaConfig.nodFrameStreamExportConfig, dnstap);
    settings.logging.dnstap_nod_framestream_servers.emplace_back(dnstap);
  }
  fromLuaToRust(luaConfig.rpzs, settings.recursor);
  fromLuaToRust(luaConfig.sortlist, settings.recursor);
  fromLuaToRust(luaConfig.ztcConfigs, settings.recordcache);
  fromLuaToRust(luaConfig.allowAdditionalQTypes, settings.recursor);
  fromLuaToRust(proxyMapping, settings.incoming);
}

namespace
{
void fromRustToLuaConfig(const pdns::rust::settings::rec::Dnssec& dnssec, LuaConfigItems& luaConfig)
{
  // This function fills a luaConfig equivalent to the given YAML config, assuming luaConfig has
  // its default content.  The docs say: "If the sequence contains an entry for the root zone, the
  // default root zone trust anchor is not included."  By default, a newly created luaConfig has the
  // TAs for the root in it.  If the YAML config has an entry for these, clear them from
  // luaConfig. Otherwise the default TA's would remain even if the YAML config is trying to set
  // them.  This code actually clears all of the TAs in luaConfig mentioned in the YAML config, but
  // as the luaConfig only contains the root TAs, this is equivalent (but not *very* efficient).
  for (const auto& trustAnchor : dnssec.trustanchors) {
    auto name = DNSName(std::string(trustAnchor.name));
    luaConfig.dsAnchors.erase(name);
  }
  for (const auto& trustAnchor : dnssec.trustanchors) {
    auto name = DNSName(std::string(trustAnchor.name));
    for (const auto& dsRecord : trustAnchor.dsrecords) {
      auto dsRecContent = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(std::string(dsRecord)));
      luaConfig.dsAnchors[name].emplace(*dsRecContent);
    }
  }
  for (const auto& nta : dnssec.negative_trustanchors) {
    luaConfig.negAnchors[DNSName(std::string(nta.name))] = std::string(nta.reason);
  }
  luaConfig.trustAnchorFileInfo.fname = std::string(dnssec.trustanchorfile);
  luaConfig.trustAnchorFileInfo.interval = dnssec.trustanchorfile_interval;
}

void fromRustToLuaConfig(const pdns::rust::settings::rec::ProtobufServer& pbServer, ProtobufExportConfig& exp)
{
  exp.enabled = true;
  exp.exportTypes.clear();
  for (const auto& type : pbServer.exportTypes) {
    exp.exportTypes.emplace(QType::chartocode(std::string(type).c_str()));
  }
  for (const auto& server : pbServer.servers) {
    exp.servers.emplace_back(std::string(server));
  }
  exp.maxQueuedEntries = pbServer.maxQueuedEntries;
  exp.timeout = pbServer.timeout;
  exp.reconnectWaitTime = pbServer.reconnectWaitTime;
  exp.asyncConnect = pbServer.asyncConnect;
  exp.logQueries = pbServer.logQueries;
  exp.logResponses = pbServer.logResponses;
  exp.taggedOnly = pbServer.taggedOnly;
  exp.logMappedFrom = pbServer.logMappedFrom;
}

void fromRustToLuaConfig(const pdns::rust::settings::rec::DNSTapFrameStreamServer& dnstap, FrameStreamExportConfig& exp)
{
  exp.enabled = true;
  for (const auto& server : dnstap.servers) {
    exp.servers.emplace_back(std::string(server));
  }
  exp.logQueries = dnstap.logQueries;
  exp.logResponses = dnstap.logResponses;
  exp.bufferHint = dnstap.bufferHint;
  exp.flushTimeout = dnstap.flushTimeout;
  exp.inputQueueSize = dnstap.inputQueueSize;
  exp.outputQueueSize = dnstap.outputQueueSize;
  exp.queueNotifyThreshold = dnstap.queueNotifyThreshold;
  exp.reopenInterval = dnstap.reopenInterval;
}

void fromRustToLuaConfig(const pdns::rust::settings::rec::DNSTapNODFrameStreamServer& dnstap, FrameStreamExportConfig& exp)
{
  exp.enabled = true;
  for (const auto& server : dnstap.servers) {
    exp.servers.emplace_back(std::string(server));
  }
  exp.logNODs = dnstap.logNODs;
  exp.logUDRs = dnstap.logUDRs;
  exp.bufferHint = dnstap.bufferHint;
  exp.flushTimeout = dnstap.flushTimeout;
  exp.inputQueueSize = dnstap.inputQueueSize;
  exp.outputQueueSize = dnstap.outputQueueSize;
  exp.queueNotifyThreshold = dnstap.queueNotifyThreshold;
  exp.reopenInterval = dnstap.reopenInterval;
}

DNSFilterEngine::PolicyKind cvtKind(const std::string& kind)
{
  static const std::map<std::string, DNSFilterEngine::PolicyKind> map = {
    {"Custom", DNSFilterEngine::PolicyKind::Custom},
    {"Drop", DNSFilterEngine::PolicyKind::Drop},
    {"NoAction", DNSFilterEngine::PolicyKind::NoAction},
    {"NODATA", DNSFilterEngine::PolicyKind::NODATA},
    {"NXDOMAIN", DNSFilterEngine::PolicyKind::NXDOMAIN},
    {"Truncate", DNSFilterEngine::PolicyKind::Truncate}};
  if (auto iter = map.find(kind); iter != map.end()) {
    return iter->second;
  }
  throw runtime_error("PolicyKind '" + kind + "' unknown");
}

void fromRustToLuaConfig(const rust::Vec<pdns::rust::settings::rec::RPZ>& rpzs, LuaConfigItems& luaConfig)
{
  for (const auto& rpz : rpzs) {
    RPZTrackerParams params;
    for (const auto& address : rpz.addresses) {
      params.zoneXFRParams.primaries.emplace_back(address);
    }
    params.zoneXFRParams.name = std::string(rpz.name);
    params.polName = std::string(rpz.policyName);

    if (!rpz.defpol.empty()) {
      params.defpol = DNSFilterEngine::Policy();
      params.defcontent = std::string(rpz.defcontent);
      params.defpol->d_kind = cvtKind(std::string(rpz.defpol));
      params.defpol->setName(params.polName);
      if (params.defpol->d_kind == DNSFilterEngine::PolicyKind::Custom) {
        if (!params.defpol->d_custom) {
          params.defpol->d_custom = make_unique<DNSFilterEngine::Policy::CustomData>();
        }
        params.defpol->d_custom->push_back(DNSRecordContent::make(QType::CNAME, QClass::IN,
                                                                  std::string(params.defcontent)));

        if (rpz.defttl != std::numeric_limits<uint32_t>::max()) {
          params.defpol->d_ttl = static_cast<int>(rpz.defttl);
        }
        else {
          params.defpol->d_ttl = -1; // get it from the zone
        }
      }
    }
    params.defpolOverrideLocal = rpz.defpolOverrideLocalData;
    params.extendedErrorCode = rpz.extendedErrorCode;
    params.extendedErrorExtra = std::string(rpz.extendedErrorExtra);
    params.includeSOA = rpz.includeSOA;
    params.ignoreDuplicates = rpz.ignoreDuplicates;
    params.maxTTL = rpz.maxTTL;

    for (const auto& tag : rpz.tags) {
      params.tags.emplace(std::string(tag));
    }
    params.defpolOverrideLocal = rpz.overridesGettag;
    params.zoneXFRParams.zoneSizeHint = rpz.zoneSizeHint;
    assign(params.zoneXFRParams.tsigtriplet, rpz.tsig);
    params.zoneXFRParams.refreshFromConf = rpz.refresh;
    params.zoneXFRParams.maxReceivedMBytes = rpz.maxReceivedMBytes;
    if (!rpz.localAddress.empty()) {
      params.zoneXFRParams.localAddress = ComboAddress(std::string(rpz.localAddress));
    }
    params.zoneXFRParams.xfrTimeout = rpz.axfrTimeout;
    params.dumpZoneFileName = std::string(rpz.dumpFile);
    params.seedFileName = std::string(rpz.seedFile);
    luaConfig.rpzs.emplace_back(params);
  }
}

void fromRustToLuaConfig(const rust::Vec<pdns::rust::settings::rec::ZoneToCache>& ztcs, map<DNSName, RecZoneToCache::Config>& lua)
{
  for (const auto& ztc : ztcs) {
    DNSName zone = DNSName(std::string(ztc.zone));
    RecZoneToCache::Config lztc;
    for (const auto& source : ztc.sources) {
      lztc.d_sources.emplace_back(std::string(source));
    }
    lztc.d_zone = std::string(ztc.zone);
    lztc.d_method = std::string(ztc.method);
    if (!ztc.localAddress.empty()) {
      lztc.d_local = ComboAddress(std::string(ztc.localAddress));
    }
    if (!ztc.tsig.name.empty()) {
      lztc.d_tt.name = DNSName(std::string(ztc.tsig.name));
      lztc.d_tt.algo = DNSName(std::string(ztc.tsig.algo));
      B64Decode(std::string(ztc.tsig.secret), lztc.d_tt.secret);
    }
    lztc.d_maxReceivedBytes = ztc.maxReceivedMBytes;
    lztc.d_retryOnError = static_cast<time_t>(ztc.retryOnErrorPeriod);
    lztc.d_refreshPeriod = static_cast<time_t>(ztc.refreshPeriod);
    lztc.d_timeout = ztc.timeout;
    lztc.d_zonemd = cvtZoneMDConfig(std::string(ztc.zonemd));
    lztc.d_dnssec = cvtZoneMDConfig(std::string(ztc.dnssec));
    lua.emplace(zone, lztc);
  }
}

void fromRustToLuaConfig(const rust::Vec<pdns::rust::settings::rec::SortList>& sortlists, SortList& lua)
{
  for (const auto& sortlist : sortlists) {
    for (const auto& entry : sortlist.subnets) {
      lua.addEntry(Netmask(std::string(sortlist.key)), Netmask(std::string(entry.subnet)), static_cast<int>(entry.order));
    }
  }
}

void fromRustToLuaConfig(const rust::Vec<pdns::rust::settings::rec::AllowedAdditionalQType>& alloweds, std::map<QType, std::pair<std::set<QType>, AdditionalMode>>& lua)
{
  for (const auto& allowed : alloweds) {
    QType qtype(QType::chartocode(std::string(allowed.qtype).c_str()));
    std::set<QType> set;
    for (const auto& target : allowed.targets) {
      set.emplace(QType::chartocode(std::string(target).c_str()));
    }
    AdditionalMode mode = AdditionalMode::CacheOnlyRequireAuth;
    mode = cvtAdditional(std::string(allowed.mode));
    lua.emplace(qtype, std::pair{set, mode});
  }
}

void fromRustToLuaConfig(const rust::Vec<pdns::rust::settings::rec::ProxyMapping>& pmaps, ProxyMapping& proxyMapping)
{
  for (const auto& pmap : pmaps) {
    Netmask subnet = Netmask(std::string(pmap.subnet));
    ComboAddress address(std::string(pmap.address));
    boost::optional<SuffixMatchNode> smn;
    if (!pmap.domains.empty()) {
      smn = boost::make_optional(SuffixMatchNode{});
      for (const auto& dom : pmap.domains) {
        smn->add(DNSName(std::string(dom)));
      }
    }
    proxyMapping.insert_or_assign(subnet, {address, smn});
  }
}

void fromRustToLuaConfig(const rust::Vec<pdns::rust::settings::rec::ForwardingCatalogZone>& catzones, std::vector<FWCatalogZone>& lua)
{
  for (const auto& catz : catzones) {
    FWCatalogZone fwcatz;
    for (const auto& def : catz.groups) {
      fwcatz.d_defaults.emplace(def.name, def);
    }
    fwcatz.d_catz = std::make_shared<CatalogZone>();

    for (const auto& address : catz.xfr.addresses) {
      fwcatz.d_params.primaries.emplace_back(address);
    }
    fwcatz.d_params.name = std::string(catz.zone);
    fwcatz.d_params.zoneSizeHint = catz.xfr.zoneSizeHint;
    assign(fwcatz.d_params.tsigtriplet, catz.xfr.tsig);
    fwcatz.d_params.refreshFromConf = catz.xfr.refresh;
    fwcatz.d_params.maxReceivedMBytes = catz.xfr.maxReceivedMBytes;
    if (!catz.xfr.localAddress.empty()) {
      fwcatz.d_params.localAddress = ComboAddress(std::string(catz.xfr.localAddress));
    }
    fwcatz.d_params.xfrTimeout = catz.xfr.axfrTimeout;
    lua.emplace_back(std::move(fwcatz));
  }
}
}

void pdns::settings::rec::fromBridgeStructToLuaConfig(const pdns::rust::settings::rec::Recursorsettings& settings, LuaConfigItems& luaConfig, ProxyMapping& proxyMapping)
{
  fromRustToLuaConfig(settings.dnssec, luaConfig);
  luaConfig.protobufMaskV4 = settings.logging.protobuf_mask_v4;
  luaConfig.protobufMaskV6 = settings.logging.protobuf_mask_v6;
  if (!settings.logging.protobuf_servers.empty()) {
    fromRustToLuaConfig(settings.logging.protobuf_servers.at(0), luaConfig.protobufExportConfig);
  }
  if (!settings.logging.outgoing_protobuf_servers.empty()) {
    fromRustToLuaConfig(settings.logging.outgoing_protobuf_servers.at(0), luaConfig.outgoingProtobufExportConfig);
  }
  if (!settings.logging.dnstap_framestream_servers.empty()) {
    fromRustToLuaConfig(settings.logging.dnstap_framestream_servers.at(0), luaConfig.frameStreamExportConfig);
  }
  if (!settings.logging.dnstap_nod_framestream_servers.empty()) {
    fromRustToLuaConfig(settings.logging.dnstap_nod_framestream_servers.at(0), luaConfig.nodFrameStreamExportConfig);
  }
  fromRustToLuaConfig(settings.recursor.rpzs, luaConfig);
  fromRustToLuaConfig(settings.recursor.sortlists, luaConfig.sortlist);
  fromRustToLuaConfig(settings.recordcache.zonetocaches, luaConfig.ztcConfigs);
  fromRustToLuaConfig(settings.recursor.allowed_additional_qtypes, luaConfig.allowAdditionalQTypes);
  fromRustToLuaConfig(settings.recursor.forwarding_catalog_zones, luaConfig.catalogzones);
  fromRustToLuaConfig(settings.incoming.proxymappings, proxyMapping);
}

// Return true if an item that's (also) a Lua config item is set
bool pdns::settings::rec::luaItemSet(const pdns::rust::settings::rec::Recursorsettings& settings)
{
  bool alldefault = true;
  for (const auto& trustanchor : settings.dnssec.trustanchors) {
    if (trustanchor.name == ".") {
      if (trustanchor.dsrecords.size() != rootDSs.size()) {
        alldefault = false;
        break;
      }
      for (const auto& dsRecord : trustanchor.dsrecords) {
        if (std::find(rootDSs.begin(), rootDSs.end(), std::string(dsRecord)) == rootDSs.end()) {
          alldefault = false;
          break;
        }
      }
    }
    else {
      alldefault = false;
      break;
    }
  }
  alldefault = alldefault && settings.dnssec.negative_trustanchors.empty();
  alldefault = alldefault && settings.dnssec.trustanchorfile.empty();
  alldefault = alldefault && settings.dnssec.trustanchorfile_interval == 24;
  alldefault = alldefault && settings.logging.protobuf_mask_v4 == 32;
  alldefault = alldefault && settings.logging.protobuf_mask_v6 == 128;
  alldefault = alldefault && settings.logging.protobuf_servers.empty();
  alldefault = alldefault && settings.logging.outgoing_protobuf_servers.empty();
  alldefault = alldefault && settings.logging.dnstap_framestream_servers.empty();
  alldefault = alldefault && settings.logging.dnstap_nod_framestream_servers.empty();
  alldefault = alldefault && settings.recursor.sortlists.empty();
  alldefault = alldefault && settings.recursor.rpzs.empty();
  alldefault = alldefault && settings.recursor.forwarding_catalog_zones.empty();
  alldefault = alldefault && settings.recordcache.zonetocaches.empty();
  alldefault = alldefault && settings.recursor.allowed_additional_qtypes.empty();
  alldefault = alldefault && settings.incoming.proxymappings.empty();
  return !alldefault;
}

pdns::settings::rec::YamlSettingsStatus pdns::settings::rec::tryReadYAML(const string& yamlconfigname, bool setGlobals, bool& yamlSettings, bool& luaSettingsInYAML, rust::settings::rec::Recursorsettings& settings, Logr::log_t startupLog)
{
  string msg;
  // TODO: handle include-dir on command line
  auto yamlstatus = pdns::settings::rec::readYamlSettings(yamlconfigname, ::arg()["include-dir"], settings, msg, startupLog);

  switch (yamlstatus) {
  case pdns::settings::rec::YamlSettingsStatus::CannotOpen:
    SLOG(g_log << Logger::Debug << "No YAML config found for configname '" << yamlconfigname << "': " << msg << endl,
         startupLog->error(Logr::Debug, msg, "No YAML config found", "configname", Logging::Loggable(yamlconfigname)));
    break;

  case pdns::settings::rec::YamlSettingsStatus::PresentButFailed:
    SLOG(g_log << Logger::Error << "YAML config found for configname '" << yamlconfigname << "' but error ocurred processing it" << endl,
         startupLog->error(Logr::Error, msg, "YAML config found, but error occurred processing it", "configname", Logging::Loggable(yamlconfigname)));
    break;

  case pdns::settings::rec::YamlSettingsStatus::OK:
    yamlSettings = true;
    SLOG(g_log << Logger::Notice << "YAML config found and processed for configname '" << yamlconfigname << "'" << endl,
         startupLog->info(Logr::Notice, "YAML config found and processed", "configname", Logging::Loggable(yamlconfigname)));
    pdns::settings::rec::processAPIDir(arg()["include-dir"], settings, startupLog);
    luaSettingsInYAML = pdns::settings::rec::luaItemSet(settings);
    if (luaSettingsInYAML && !settings.recursor.lua_config_file.empty()) {
      const std::string err = "YAML settings include values originally in Lua but also sets `recursor.lua_config_file`. This is unsupported";
      SLOG(g_log << Logger::Error << err << endl,
           startupLog->info(Logr::Error, err, "configname", Logging::Loggable(yamlconfigname)));
      yamlstatus = pdns::settings::rec::PresentButFailed;
    }
    else if (!settings.recursor.forwarding_catalog_zones.empty() && settings.webservice.api_dir.empty()) {
      startupLog->info(Logr::Error, "Catalog zones defined, but webservice.api_dir is not set", "configname", Logging::Loggable(yamlconfigname));
      yamlstatus = pdns::settings::rec::PresentButFailed;
    }
    else if (setGlobals) {
      pdns::settings::rec::bridgeStructToOldStyleSettings(settings);
    }
    break;
  }
  return yamlstatus;
}

uint16_t pdns::rust::settings::rec::qTypeStringToCode(::rust::Str str)
{
  std::string tmp(str.data(), str.length());
  return QType::chartocode(tmp.c_str());
}

bool pdns::rust::settings::rec::isValidHostname(::rust::Str str)
{
  try {
    auto name = DNSName(string(str));
    return name.isHostname();
  }
  catch (...) {
    return false;
  }
}

namespace pdns::rust::web::rec
{

template <typename M>
Wrapper<M>::Wrapper(const M& arg) :
  d_ptr(std::make_unique<M>(arg))
{
}

template <typename M>
Wrapper<M>::~Wrapper<M>() = default;

template <typename M>
[[nodiscard]] const M& Wrapper<M>::get() const
{
  return *d_ptr;
}

template class Wrapper<::NetmaskGroup>;
template class Wrapper<::ComboAddress>;
template class Wrapper<std::shared_ptr<::Logr::Logger>>;

std::unique_ptr<ComboAddress> comboaddress(::rust::Str str)
{
  return std::make_unique<ComboAddress>(::ComboAddress(std::string(str)));
}

bool matches(const std::unique_ptr<NetmaskGroup>& nmg, const std::unique_ptr<ComboAddress>& address)
{
  return nmg->get().match(address->get());
}

void log(const std::unique_ptr<Logger>& logger, pdns::rust::web::rec::Priority log_level, ::rust::Str msg, const ::rust::Vec<KeyValue>& values)
{
  auto log = logger->get();
  for (const auto& [key, value] : values) {
    log = log->withValues(std::string(key), Logging::Loggable(std::string(value)));
  }
  log->info(static_cast<Logr::Priority>(log_level), std::string(msg));
}

  void error(const std::unique_ptr<Logger>& logger, pdns::rust::web::rec::Priority log_level, ::rust::Str error, ::rust::Str msg, const ::rust::Vec<KeyValue>& values)
{
  auto log = logger->get();
  for (const auto& [key, value] : values) {
    log = log->withValues(std::string(key), Logging::Loggable(std::string(value)));
  }
  log->error(static_cast<Logr::Priority>(log_level), std::string(error), std::string(msg));
}

std::unique_ptr<Logger> withValue(const std::unique_ptr<Logger>& logger, ::rust::Str key, ::rust::Str val)
{
  auto ret = logger->get()->withValues(std::string(key), Logging::Loggable(std::string(val)));
  return std::make_unique<Logger>(ret);
}

}
