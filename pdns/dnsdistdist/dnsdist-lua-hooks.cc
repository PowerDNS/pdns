
#include "dnsdist-lua-hooks.hh"
#include "dnsdist-lua.hh"
#include "lock.hh"

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

void setupLuaHooks(LuaContext& luaCtx)
{
  luaCtx.writeFunction("addMaintenanceCallback", [&luaCtx](const MaintenanceCallback& callback) {
    setLuaSideEffect();
    addMaintenanceCallback(luaCtx, callback);
  });
}

}
