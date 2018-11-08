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
#pragma once

struct ConsoleKeyword {
  std::string name;
  bool function;
  std::string parameters;
  std::string description;
  std::string toString() const
  {
    std::string res(name);
    if (function) {
      res += "(" + parameters + ")";
    }
    res += ": ";
    res += description;
    return res;
  }
};

extern GlobalStateHolder<NetmaskGroup> g_consoleACL;
extern const std::vector<ConsoleKeyword> g_consoleKeywords;
extern std::string g_consoleKey; // in theory needs locking
extern bool g_logConsoleConnections;
extern bool g_consoleEnabled;
extern uint32_t g_consoleOutputMsgMaxSize;

void doClient(ComboAddress server, const std::string& command);
void doConsole();
extern "C" {
char** my_completion( const char * text , int start,  int end);
}
void controlThread(int fd, ComboAddress local);
