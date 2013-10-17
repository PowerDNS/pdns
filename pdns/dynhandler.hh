/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef PDNS_DYNHANDLER_HH
#define PDNS_DYNHANDLER_HH

#include <vector>
#include <string>
#include <stdlib.h>
#include <sys/types.h>

#include "config.h"
#include <unistd.h>

#include "namespaces.hh"


bool DLQuitPlease();
void setStatus(const string &str);
string DLQuitHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLRQuitHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLPingHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLShowHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLUptimeHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLSettingsHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLRespSizeHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLCCHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLQTypesHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLRSizesHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLRemotesHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLStatusHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLNotifyHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLNotifyHostHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLReloadHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLRediscoverHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLVersionHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLPurgeHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLNotifyRetrieveHandler(const vector<string>&parts, Utility::pid_t ppid);
string DLCurrentConfigHandler(const vector<string>&parts, Utility::pid_t ppid);
#endif /* PDNS_DYNHANDLER_HH */
