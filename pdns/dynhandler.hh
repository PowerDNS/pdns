/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef PDNS_DYNHANDLER_HH
#define PDNS_DYNHANDLER_HH

#include <vector>
#include <string>
#include <stdlib.h>
#include <sys/types.h>

#ifndef WIN32
# include "config.h"
# include <unistd.h>
#else
# include "pdnsservice.hh"
#endif // WIN32

using namespace std;


bool DLQuitPlease();
string DLQuitHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLRQuitHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLPingHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLShowHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLUptimeHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLSettingsHandler(const vector<string>&parts, Utility::pid_t ppid);
void setStatus(const string &str);
string DLCCHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLStatusHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLNotifyHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLNotifyHostHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLReloadHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLRediscoverHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLVersionHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLPurgeHandler(const vector<string>&parts, Utility::pid_t ppid);
#endif /* PDNS_DYNHANDLER_HH */
