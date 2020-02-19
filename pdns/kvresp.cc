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
#include "iputils.hh"
#include "sstuff.hh"
#include "statbag.hh"

/* This tool REALLY wants to be rewritten in Python, by ahu does not speak it very well.
   What it does is provide answers to queries from the Lua generic UDP Question/Answer
   stuff in kv-example-script.lua */

StatBag S;

int main(int argc, char** argv)
try {
  if (argc != 3) {
    cerr << "Syntax: kvresp local-address local-port" << endl;
    exit(EXIT_FAILURE);
  }

  ComboAddress local(argv[1], atoi(argv[2]));
  Socket s(local.sin4.sin_family, SOCK_DGRAM);

  s.bind(local);
  cout << "Bound to " << local.toStringWithPort() << endl;

  char buffer[1500];

  int len;
  ComboAddress rem = local;
  socklen_t socklen = rem.getSocklen();
  for (;;) {
    len = recvfrom(s.getHandle(), buffer, sizeof(buffer), 0, (struct sockaddr*)&rem, &socklen);
    if (len < 0)
      unixDie("recvfrom");
    string query(buffer, len);
    cout << "Had packet: " << query << endl;
    vector<string> parts;
    stringtok(parts, query);
    if (parts.size() < 2)
      continue;
    string response;
    if (parts[0] == "DOMAIN")
      response = (parts[1].find("xxx") != string::npos) ? "1" : "0";
    else if (parts[0] == "IP")
      response = (parts[1] == "127.0.0.1") ? "1" : "0";
    else
      response = "???";

    cout << "Our reply: " << response << endl;
    if (sendto(s.getHandle(), response.c_str(), response.length(), 0, (struct sockaddr*)&rem, socklen) < 0)
      unixDie("sendto");
  }
}
catch (std::exception& e) {
  cerr << "Fatal error: " << e.what() << endl;
  exit(EXIT_FAILURE);
}
