#pragma once
#include "sholder.hh"
#include "sortlist.hh"
class LuaConfigItems 
{
public:
  LuaConfigItems();
  SortList sortlist;
};

extern GlobalStateHolder<LuaConfigItems> g_luaconfs;
void loadRecursorLuaConfig(const std::string& fname);

