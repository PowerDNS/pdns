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

#include <iostream>
#include <iomanip>
#include <fcntl.h>

#include "pdnsexception.hh"
#include "arguments.hh"
#include "credentials.hh"
#include "namespaces.hh"
#include "rec_channel.hh"
#include "rec-rust-lib/cxxsettings.hh"
#include "logger.hh"
#include "logging.hh"

ArgvMap& arg()
{
  static ArgvMap arg;
  return arg;
}

static void initArguments(int argc, char** argv, Logr::log_t log)
{
  arg().set("config-dir", "Location of configuration directory (recursor.conf)") = SYSCONFDIR;

  arg().set("socket-dir", string("Where the controlsocket will live, ") + LOCALSTATEDIR + "/pdns-recursor when unset and not chrooted") = "";
  arg().set("chroot", "switch to chroot jail") = "";
  arg().set("process", "When controlling multiple recursors, the target process number") = "";
  arg().set("timeout", "Number of seconds to wait for the recursor to respond") = "5";
  arg().set("config-name", "Name of this virtual configuration - will rename the binary image") = "";
  arg().setCmd("help", "Provide this helpful message");
  arg().setCmd("version", "Show the version of this program");

  arg().laxParse(argc, argv);
  if (arg().mustDo("version")) {
    cout << "rec_control version " << VERSION << endl;
    exit(0); // NOLINT(concurrency-mt-unsafe)
  }
  if (arg().mustDo("help") || arg().getCommands().empty()) {
    cout << "syntax: rec_control [options] command, options as below: " << endl
         << endl;
    cout << arg().helpstring(arg()["help"]) << endl;
    cout << "In addition, 'rec_control help' can be used to retrieve a list\nof available commands from PowerDNS" << endl;
    exit(arg().mustDo("help") ? 0 : 99); // NOLINT(concurrency-mt-unsafe)
  }

  string configname = ::arg()["config-dir"] + "/recursor";
  if (!::arg()["config-name"].empty()) {
    configname = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"];
  }

  cleanSlashes(configname);

  string msg;
  pdns::rust::settings::rec::Recursorsettings settings;
  pdns::settings::rec::YamlSettingsStatus yamlstatus{};

  for (const string suffix : {".yml", ".conf"}) {
    const string yamlconfigname = configname + suffix;
    yamlstatus = pdns::settings::rec::readYamlSettings(yamlconfigname, "", settings, msg, g_slog);

    switch (yamlstatus) {
    case pdns::settings::rec::YamlSettingsStatus::CannotOpen:
      break;
    case pdns::settings::rec::YamlSettingsStatus::PresentButFailed:
      if (suffix == ".yml") {
        log->error(Logr::Error, msg, "YAML config found, but error ocurred processing it", "configname", Logging::Loggable(yamlconfigname));
        exit(1); // NOLINT(concurrency-mt-unsafe)
      }
      break;
    case pdns::settings::rec::YamlSettingsStatus::OK:
      log->info(Logr::Notice, "YAML config found and processed", "configname", Logging::Loggable(yamlconfigname));
      pdns::settings::rec::bridgeStructToOldStyleSettings(settings);
      break;
    }
    if (yamlstatus == pdns::settings::rec::YamlSettingsStatus::OK) {
      break;
    }
  }
  if (yamlstatus != pdns::settings::rec::YamlSettingsStatus::OK) {
    configname += ".conf";
    arg().laxFile(configname);
  }
  arg().laxParse(argc, argv); // make sure the commandline wins
  if (::arg()["socket-dir"].empty()) {
    if (::arg()["chroot"].empty()) {
      ::arg().set("socket-dir") = std::string(LOCALSTATEDIR) + "/pdns-recursor";
    }
    else {
      ::arg().set("socket-dir") = ::arg()["chroot"] + "/";
    }
  }
  else if (!::arg()["chroot"].empty()) {
    ::arg().set("socket-dir") = ::arg()["chroot"] + "/" + ::arg()["socket-dir"];
  }
}

static std::string showLuaYAML(const ::rust::string& rfile)
{
  std::string msg;
  if (rfile.empty()) {
    return msg;
  }

  const auto file = string(rfile);
  ProxyMapping proxyMapping;
  LuaConfigItems lci;

  try {
    loadRecursorLuaConfig(file, proxyMapping, lci);
    auto settings = pdns::rust::settings::rec::parse_yaml_string("");
    pdns::settings::rec::fromLuaConfigToBridgeStruct(lci, proxyMapping, settings);
    auto yaml = settings.to_yaml_string();
    msg += "# Start of converted Lua config .yml based on " + file + "\n";
    msg += std::string(yaml);
    msg += "# Validation result: ";
    try {
      // Parse back and validate
      settings.validate();
      msg += "OK";
    }
    catch (const rust::Error& err) {
      msg += err.what();
    }
    msg += "\n# End of converted " + file + "\n#\n";
  }
  catch (PDNSException& e) {
    cerr << "Cannot load Lua configuration: " << e.reason << endl;
  }
  return msg;
}

static std::string showIncludeYAML(::rust::String& rdirname)
{
  std::string msg;
  if (rdirname.empty()) {
    return msg;
  }
  const auto dirname = string(rdirname);

  std::vector<std::string> confFiles;
  ::arg().gatherIncludes(dirname, ".conf", confFiles);
  msg += "# Found " + std::to_string(confFiles.size()) + " .conf file" + addS(confFiles.size()) + " in " + dirname + "\n";
  for (const auto& confFile : confFiles) {
    auto converted = pdns::settings::rec::oldStyleSettingsFileToYaml(confFile, false);
    msg += "# Converted include-dir " + confFile + " to YAML format:\n";
    msg += converted;
    msg += "# Validation result: ";
    try {
      // Parse back and validate
      auto settings = pdns::rust::settings::rec::parse_yaml_string(converted);
      settings.validate();
      msg += "OK";
    }
    catch (const rust::Error& err) {
      msg += err.what();
    }
    msg += "\n# End of converted " + confFile + "\n#\n";
  }
  return msg;
}

static std::string showForwardFileYAML(const ::rust::string& rfilename)
{
  std::string msg;
  if (rfilename.empty() || boost::ends_with(rfilename, ".yml")) {
    return msg;
  }
  const std::string filename = string(rfilename);

  msg += "# Converted " + filename + " to YAML format for recursor.forward_zones_file: \n";
  rust::Vec<pdns::rust::settings::rec::ForwardZone> forwards;
  pdns::settings::rec::oldStyleForwardsFileToBridgeStruct(filename, forwards);
  auto yaml = pdns::rust::settings::rec::forward_zones_to_yaml_string(forwards);
  msg += std::string(yaml);
  msg += "# Validation result: ";
  try {
    pdns::rust::settings::rec::validate_forward_zones("forward_zones", forwards);
    msg += "OK";
  }
  catch (const rust::Error& err) {
    msg += err.what();
  }
  msg += "\n# End of converted " + filename + "\n#\n";
  return msg;
}

static std::string showAllowYAML(const ::rust::String& rfilename, const string& section, const string& key, const std::function<void(const ::rust::String&, const ::rust::Vec<::rust::String>&)>& func)
{
  std::string msg;
  if (rfilename.empty() || boost::ends_with(rfilename, ".yml")) {
    return msg;
  }
  const std::string filename = string(rfilename);

  msg += "# Converted " + filename + " to YAML format for " + section + "." + key + ": \n";
  rust::Vec<::rust::String> allows;
  pdns::settings::rec::oldStyleAllowFileToBridgeStruct(filename, allows);
  auto yaml = pdns::rust::settings::rec::allow_from_to_yaml_string(allows);
  msg += std::string(yaml);
  msg += "# Validation result: ";
  try {
    func(key, allows);
    msg += "OK";
  }
  catch (const rust::Error& err) {
    msg += err.what();
  }
  msg += "\n# End of converted " + filename + "\n#\n";
  return msg;
}

static RecursorControlChannel::Answer showYAML(const std::string& path)
{
  string configName = ::arg()["config-dir"] + "/recursor.conf";
  if (!::arg()["config-name"].empty()) {
    configName = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"] + ".conf";
  }
  if (!path.empty()) {
    configName = path;
  }
  cleanSlashes(configName);

  try {
    std::string msg;
    auto converted = pdns::settings::rec::oldStyleSettingsFileToYaml(configName, true);
    if (converted == "{}\n") {
      msg += "There seems to be no YAML config in " + configName;
      return {1, std::move(msg)};
    }
    msg += "# Start of converted recursor.yml based on " + configName + "\n";
    msg += converted;
    msg += "# Validation result: ";
    pdns::rust::settings::rec::Recursorsettings mainsettings;
    try {
      // Parse back and validate
      mainsettings = pdns::rust::settings::rec::parse_yaml_string(converted);
      mainsettings.validate();
      msg += "OK";
    }
    catch (const rust::Error& err) {
      msg += err.what();
    }
    msg += "\n# End of converted " + configName + "\n#\n";

    msg += showLuaYAML(mainsettings.recursor.lua_config_file);
    msg += showIncludeYAML(mainsettings.recursor.include_dir);
    msg += showForwardFileYAML(mainsettings.recursor.forward_zones_file);
    msg += showAllowYAML(mainsettings.incoming.allow_from_file, "incoming", "allow_from_file", pdns::rust::settings::rec::validate_allow_from);
    msg += showAllowYAML(mainsettings.incoming.allow_notify_from_file, "incoming", "allow_notify_from_file", pdns::rust::settings::rec::validate_allow_from);
    msg += showAllowYAML(mainsettings.incoming.allow_notify_for_file, "incoming", "allow_notify_for_file", pdns::rust::settings::rec::validate_allow_for);
    return {0, std::move(msg)};
  }
  catch (const rust::Error& err) {
    return {1, std::string(err.what())};
  }
  catch (const PDNSException& err) {
    return {1, std::string(err.reason)};
  }
  catch (const std::exception& err) {
    return {1, std::string(err.what())};
  }
}

static void recControlLoggerBackend(const Logging::Entry& entry)
{
  static thread_local std::stringstream buf;

  // First map SL priority to syslog's Urgency
  Logger::Urgency urg = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (urg > Logger::Warning) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Not that lower Urgency means higher number.
    return;
  }
  buf.str("");
  buf << "msg=" << std::quoted(entry.message);
  if (entry.error) {
    buf << " error=" << std::quoted(entry.error.get());
  }

  if (entry.name) {
    buf << " subsystem=" << std::quoted(entry.name.get());
  }
  buf << " level=" << std::quoted(std::to_string(entry.level));
  if (entry.d_priority != 0) {
    buf << " prio=" << std::quoted(Logr::Logger::toString(entry.d_priority));
  }

  std::array<char, 64> timebuf{};
  buf << " ts=" << std::quoted(Logging::toTimestampStringMilli(entry.d_timestamp, timebuf));

  for (auto const& value : entry.values) {
    buf << " ";
    buf << value.first << "=" << std::quoted(value.second);
  }

  cerr << buf.str() << endl;
}

int main(int argc, char** argv)
{
  g_slog = Logging::Logger::create(recControlLoggerBackend);
  auto log = g_slog->withName("config");
  ::arg().setSLog(log);

  const set<string> fileCommands = {
    "dump-cache",
    "dump-edns",
    "dump-ednsstatus",
    "dump-nsspeeds",
    "dump-failedservers",
    "dump-rpz",
    "dump-throttlemap",
    "dump-non-resolving",
    "dump-saved-parent-ns-sets",
    "dump-dot-probe-map",
    "trace-regex",
  };
  try {
    initArguments(argc, argv, log);
    string sockname = "pdns_recursor";

    if (!empty(arg()["config-name"])) {
      sockname += "-" + arg()["config-name"];
    }
    if (!arg()["process"].empty()) {
      sockname += "." + arg()["process"];
    }
    sockname.append(".controlsocket");

    const vector<string>& commands = arg().getCommands();

    if (!commands.empty() && commands.at(0) == "show-yaml") {
      auto [ret, str] = showYAML(commands.size() > 1 ? commands.at(1) : "");
      cout << str << endl;
      return ret;
    }

    if (!commands.empty() && commands.at(0) == "hash-password") {
      uint64_t workFactor = CredentialsHolder::s_defaultWorkFactor;
      if (commands.size() > 1) {
        try {
          pdns::checked_stoi_into(workFactor, commands.at(1));
        }
        catch (const std::exception& e) {
          cerr << "Unable to parse the supplied work factor: " << e.what() << endl;
          return EXIT_FAILURE;
        }
      }

      auto password = CredentialsHolder::readFromTerminal();

      try {
        cout << hashPassword(password.getString(), workFactor, CredentialsHolder::s_defaultParallelFactor, CredentialsHolder::s_defaultBlockSize) << endl;
        return EXIT_SUCCESS;
      }
      catch (const std::exception& e) {
        cerr << "Error while hashing the supplied password: " << e.what() << endl;
        return EXIT_FAILURE;
      }
    }

    string command;
    int fileDesc = -1;
    unsigned int iteration = 0;
    while (iteration < commands.size()) {
      if (iteration > 0) {
        command += " ";
      }
      command += commands[iteration];

      // special case: trace-regex with no arguments is clear regex
      auto traceregexClear = command == "trace-regex" && commands.size() == 1;

      if (fileCommands.count(commands[iteration]) > 0 && !traceregexClear) {
        if (iteration + 1 < commands.size()) {
          // dump-rpz is different, it also has a zonename as argument
          // trace-regex is different, it also has a regexp as argument
          if (commands[iteration] == "dump-rpz" || commands[iteration] == "trace-regex") {
            if (iteration + 2 < commands.size()) {
              ++iteration;
              command += " ";
              command += commands[iteration]; // add rpzname/regex and continue with filename
            }
            else {
              throw PDNSException("Command needs two arguments");
            }
          }
          ++iteration;
          if (commands[iteration] == "-") {
            fileDesc = STDOUT_FILENO;
          }
          else {
            fileDesc = open(commands[iteration].c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
          }
          if (fileDesc == -1) {
            int err = errno;
            throw PDNSException("Error opening dump file for writing: " + stringerror(err));
          }
        }
        else {
          throw PDNSException("Command needs a file argument");
        }
      }
      ++iteration;
    }

    auto timeout = arg().asNum("timeout");
    RecursorControlChannel rccS;
    rccS.connect(arg()["socket-dir"], sockname);
    RecursorControlChannel::send(rccS.getDescriptor(), {0, std::move(command)}, timeout, fileDesc);

    auto receive = RecursorControlChannel::recv(rccS.getDescriptor(), timeout);
    if (receive.d_ret != 0) {
      cerr << receive.d_str;
    }
    else {
      cout << receive.d_str;
    }
    return receive.d_ret;
  }
  catch (PDNSException& ae) {
    log->error(Logr::Error, ae.reason, "Fatal");
    return 1;
  }
}
#include "rec-web-stubs.hh"
