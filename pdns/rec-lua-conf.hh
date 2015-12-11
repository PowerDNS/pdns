#pragma once
#include "sholder.hh"
#include "sortlist.hh"
#include "filterpo.hh"

class LuaConfigItems 
{
public:
  LuaConfigItems();
  SortList sortlist;
  DNSFilterEngine dfe;
  map<DNSName,DSRecordContent> dsAnchors;
};

extern GlobalStateHolder<LuaConfigItems> g_luaconfs;
void loadRecursorLuaConfig(const std::string& fname);

