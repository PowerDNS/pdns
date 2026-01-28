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
#include <vector>
#include <string>
#include <stdlib.h>
#include <sys/types.h>

#include <unistd.h>

#include "namespaces.hh"


bool DLQuitPlease();
void setStatus(const string &str);
string DLCCHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLCurrentConfigHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLFlushHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLListZones(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLNotifyHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLNotifyHostHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLNotifyRetrieveHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLPingHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLPurgeHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLQTypesHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLQuitHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLRQuitHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLRSizesHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLRediscoverHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLReloadHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLRemotesHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLRespSizeHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLSettingsHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLShowHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLStatusHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLSuckRequests(const vector<string> &parts, Utility::pid_t ppid, Logr::log_t slog);
string DLTokenLogin(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLUptimeHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
string DLVersionHandler(const vector<string>&parts, Utility::pid_t ppid, Logr::log_t slog);
