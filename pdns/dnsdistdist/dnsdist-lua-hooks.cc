
#include "dnsdist-lua-hooks.hh"
#include "dnsdist-lua.hh"
#include "lock.hh"
#include "tcpiohandler.hh"

namespace dnsdist::lua::hooks
{
static LockGuarded<std::vector<MaintenanceCallback>> s_maintenanceHooks;

void runMaintenanceHooks(const LuaContext& context)
{
  (void)context;
  for (const auto& callback : *(s_maintenanceHooks.lock())) {
    callback();
  }
}

void addMaintenanceCallback(const LuaContext& context, MaintenanceCallback callback)
{
  (void)context;
  s_maintenanceHooks.lock()->push_back(std::move(callback));
}

void clearMaintenanceHooks()
{
  s_maintenanceHooks.lock()->clear();
}

void setTicketsKeyAddedHook(const LuaContext& context, const TicketsKeyAddedHook& hook)
{
  TLSCtx::setTicketsKeyAddedHook([hook](const std::string& key) {
    try {
      hook(key.c_str(), key.size());
    }
    catch (const std::exception& exp) {
      warnlog("Error calling the Lua hook after new tickets key has been added", exp.what());
    }
  });
}

void setupLuaHooks(LuaContext& luaCtx)
{
  luaCtx.writeFunction("addMaintenanceCallback", [&luaCtx](const MaintenanceCallback& callback) {
    setLuaSideEffect();
    addMaintenanceCallback(luaCtx, callback);
  });
  luaCtx.writeFunction("setTicketsKeyAddedHook", [&luaCtx](const TicketsKeyAddedHook& hook) {
    setLuaSideEffect();
    setTicketsKeyAddedHook(luaCtx, hook);
  });
}

}
