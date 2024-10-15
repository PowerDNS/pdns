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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <vector>
#include <memory>
#include "syncres.hh"
#include "logger.hh"

bool readHintsIntoCache(time_t now, const std::string& hintfile, std::vector<DNSRecord>& nsvec);
void putDefaultHintsIntoCache(time_t now, std::vector<DNSRecord>& nsvec);

void makeIPToNamesZone(const std::shared_ptr<SyncRes::domainmap_t>& newMap,
                       const vector<string>& parts,
                       Logr::log_t log);

//! A return value `false` means that the line cannot be parsed (e.g. unsupported IPv6).
bool parseEtcHostsLine(std::vector<std::string>& parts, std::string& line);

void makePartialIPZone(SyncRes::domainmap_t& newMap,
                       std::initializer_list<const char*> labels,
                       Logr::log_t log);
void makePartialIP6Zone(SyncRes::domainmap_t& newMap,
                        const std::string& name,
                        Logr::log_t log);

void addForwardAndReverseLookupEntries(SyncRes::domainmap_t& newMap,
                                       const std::string& searchSuffix,
                                       const std::vector<std::string>& parts,
                                       Logr::log_t log);
