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
 * MERCHANTAPILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "lua2backend.hh"

class Lua2Factory : public BackendFactory
{
public:
  Lua2Factory() : BackendFactory("lua2") {}

  void declareArguments(const string &suffix="")
  {
    declare(suffix,"filename","Filename of the script for lua backend","powerdns-luabackend.lua");
    declare(suffix,"query-logging","Logging of the Lua2 Backend","no");
    declare(suffix,"api","Lua backend API version","2");
  }

  DNSBackend *make(const string &suffix="")
  {
    const std::string apiSet = "lua2" + suffix + "-api";
    const int api = ::arg().asNum(apiSet);
    DNSBackend *be;
    switch(api) {
    case 1:
      throw PDNSException("Use luabackend for api version 1");
    case 2:
      be = new Lua2BackendAPIv2(suffix); break;
    default:
      throw PDNSException("Unsupported ABI version " + ::arg()[apiSet]);
    }
    return be;
  }
};

class Lua2Loader
{
public:
  Lua2Loader()
  {
    BackendMakers().report(new Lua2Factory);

    g_log << Logger::Info << "[lua2backend] This is the lua2 backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};

static Lua2Loader luaLoader;
