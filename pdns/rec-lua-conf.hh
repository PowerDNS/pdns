#pragma once
#include "sholder.hh"
#include "sortlist.hh"
#include "filterpo.hh"
#include "remote_logger.hh"
#include "validate.hh"

class LuaConfigItems 
{
public:
  LuaConfigItems();
  SortList sortlist;
  DNSFilterEngine dfe;
  map<DNSName,dsmap_t> dsAnchors;
  map<DNSName,std::string> negAnchors;
  std::shared_ptr<RemoteLogger> protobufServer{nullptr};
  uint8_t protobufMaskV4{32};
  uint8_t protobufMaskV6{128};
};

extern GlobalStateHolder<LuaConfigItems> g_luaconfs;
void loadRecursorLuaConfig(const std::string& fname);

