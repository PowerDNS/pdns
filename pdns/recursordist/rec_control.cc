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
#include <fcntl.h>

#include "pdnsexception.hh"
#include "arguments.hh"
#include "credentials.hh"
#include "namespaces.hh"
#include "rec_channel.hh"

ArgvMap& arg()
{
  static ArgvMap arg;
  return arg;
}

static void initArguments(int argc, char** argv)
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
    exit(0);
  }
  if (arg().mustDo("help") || arg().getCommands().empty()) {
    cout << "syntax: rec_control [options] command, options as below: " << endl
         << endl;
    cout << arg().helpstring(arg()["help"]) << endl;
    cout << "In addition, 'rec_control help' can be used to retrieve a list\nof available commands from PowerDNS" << endl;
    exit(arg().mustDo("help") ? 0 : 99);
  }

  string configname = ::arg()["config-dir"] + "/recursor.conf";
  if (::arg()["config-name"] != "")
    configname = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"] + ".conf";

  cleanSlashes(configname);

  arg().laxFile(configname.c_str());

  arg().laxParse(argc, argv); // make sure the commandline wins

  if (::arg()["socket-dir"].empty()) {
    if (::arg()["chroot"].empty())
      ::arg().set("socket-dir") = std::string(LOCALSTATEDIR) + "/pdns-recursor";
    else
      ::arg().set("socket-dir") = ::arg()["chroot"] + "/";
  }
  else if (!::arg()["chroot"].empty()) {
    ::arg().set("socket-dir") = ::arg()["chroot"] + "/" + ::arg()["socket-dir"];
  }
}

int main(int argc, char** argv)
{
  g_slogStructured = false;
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
    initArguments(argc, argv);
    string sockname = "pdns_recursor";

    if (arg()["config-name"] != "")
      sockname += "-" + arg()["config-name"];

    if (!arg()["process"].empty())
      sockname += "." + arg()["process"];

    sockname.append(".controlsocket");

    const vector<string>& commands = arg().getCommands();

    if (commands.size() >= 1 && commands.at(0) == "hash-password") {
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
    int fd = -1;
    unsigned int i = 0;
    while (i < commands.size()) {
      if (i > 0) {
        command += " ";
      }
      command += commands[i];

      // special case: trace-regex with no arguments is clear regex
      auto traceregexClear = command == "trace-regex" && commands.size() == 1;

      if (fileCommands.count(commands[i]) > 0 && !traceregexClear) {
        if (i + 1 < commands.size()) {
          // dump-rpz is different, it also has a zonename as argument
          // trace-regex is different, it also has a regexp as argument
          if (commands[i] == "dump-rpz" || commands[i] == "trace-regex") {
            if (i + 2 < commands.size()) {
              ++i;
              command += " ";
              command += commands[i]; // add rpzname/regex and continue with filename
            }
            else {
              throw PDNSException("Command needs two arguments");
            }
          }
          ++i;
          if (commands[i] == "-") {
            fd = STDOUT_FILENO;
          }
          else {
            fd = open(commands[i].c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
          }
          if (fd == -1) {
            int err = errno;
            throw PDNSException("Error opening dump file for writing: " + stringerror(err));
          }
        }
        else {
          throw PDNSException("Command needs a file argument");
        }
      }
      ++i;
    }

    auto timeout = arg().asNum("timeout");
    RecursorControlChannel rccS;
    rccS.connect(arg()["socket-dir"], sockname);
    rccS.send(rccS.d_fd, {0, command}, timeout, fd);

    auto receive = rccS.recv(rccS.d_fd, timeout);
    if (receive.d_ret != 0) {
      cerr << receive.d_str;
    }
    else {
      cout << receive.d_str;
    }
    return receive.d_ret;
  }
  catch (PDNSException& ae) {
    cerr << "Fatal: " << ae.reason << "\n";
    return 1;
  }
}
