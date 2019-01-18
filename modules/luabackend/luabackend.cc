/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 * originally authored by Fredrik Danerklint
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
#include "luabackend.hh"
#include "pdns/logger.hh"

/* SECOND PART */

class LUAFactory : public BackendFactory
{
public:
  LUAFactory() : BackendFactory("lua") {}
  
  void declareArguments(const string &suffix="")
  {
  
    declare(suffix,"filename","Filename of the script for lua backend","powerdns-luabackend.lua");
    declare(suffix,"logging-query","Logging of the LUA Backend","no");

  }
  
  DNSBackend *make(const string &suffix="")
  {
    return new LUABackend(suffix);
  }
  
};

/* THIRD PART */

class LUALoader
{
public:
  LUALoader()
  {
    BackendMakers().report(new LUAFactory);
    
    g_log << Logger::Info << "[luabackend] This is the lua backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }  
};

static LUALoader luaLoader;
