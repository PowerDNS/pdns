/*
    Copyright (C) 2011 Fredrik Danerklint

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published 
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

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
    
    L << Logger::Info << "[luabackend] This is the lua backend version " VERSION " reporting" << endl;
  }  
};

static LUALoader luaLoader;
