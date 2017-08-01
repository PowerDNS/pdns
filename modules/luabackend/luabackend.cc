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
    declare(suffix,"query-logging","Logging of the LUA Backend","no");

    // Allow overriding lua function names.
    declare(suffix,"f_exec_error","lua function name","");
    declare(suffix,"f_rediscover","lua function name","");

    // minimal
    declare(suffix,"f_list","lua function name","");
    declare(suffix,"f_lookup","lua function name","");
    declare(suffix,"f_get","lua function name","");
    declare(suffix,"f_getsoa","lua function name","");

    // master
    declare(suffix,"f_getupdatedmasters","lua function name","");
    declare(suffix,"f_setnotified","lua function name","");

    // slave
    declare(suffix,"f_getdomaininfo","lua function name","");
    declare(suffix,"f_ismaster","lua function name","");
    declare(suffix,"f_getunfreshslaveinfos","lua function name","");
    declare(suffix,"f_setfresh","lua function name","");
    declare(suffix,"f_starttransaction","lua function name","");
    declare(suffix,"f_committransaction","lua function name","");
    declare(suffix,"f_aborttransaction","lua function name","");
    declare(suffix,"f_feedrecord","lua function name","");

    // supermaster
    declare(suffix,"f_supermasterbackend","lua function name","");
    declare(suffix,"f_createslavedomain","lua function name","");

    // dnssec
    declare(suffix,"f_alsonotifies","lua function name","");
    declare(suffix,"f_getdomainmetadata","lua function name","");
    declare(suffix,"f_setdomainmetadata","lua function name","");
    declare(suffix,"f_getdomainkeys","lua function name","");
    declare(suffix,"f_removedomainkey","lua function name","");
    declare(suffix,"f_activatedomainkey","lua function name","");
    declare(suffix,"f_deactivatedomainkey","lua function name","");
    declare(suffix,"f_updatedomainkey","lua function name","");
    declare(suffix,"f_adddomainkey","lua function name","");
    declare(suffix,"f_gettsigkey","lua function name","");
    declare(suffix,"f_getbeforeandafternamesabsolute","lua function name","");
    declare(suffix,"f_updatednssecorderandauthabsolute","lua function name","");
    declare(suffix,"f_updatednssecorderandauth","lua function name","");

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
