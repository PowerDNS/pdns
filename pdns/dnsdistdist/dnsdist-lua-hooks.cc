
#include "dnsdist-lua-hooks.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-opentelemetry.hh"
#include "lock.hh"
#include "tcpiohandler.hh"
#include <memory>

namespace dnsdist::lua::hooks
{
using ExitCallback = std::function<void()>;
using MaintenanceCallback = std::function<void()>;
using TicketsKeyAddedHook = std::function<void(const std::string&, size_t)>;
using ServerStateChangeCallback = std::function<void(const std::string&, bool)>;

static LockGuarded<std::vector<ExitCallback>> s_exitCallbacks;
static LockGuarded<std::vector<std::pair<std::string, MaintenanceCallback>>> s_maintenanceHooks;
static LockGuarded<std::vector<ServerStateChangeCallback>> s_serverStateChangeHooks;

void runMaintenanceHooks(const LuaContext& context, std::shared_ptr<pdns::trace::dnsdist::Tracer>& tracer)
{
  (void)context;
  for (const auto& callback : *(s_maintenanceHooks.lock())) {
    pdns::trace::dnsdist::getCloserForInternalSpan(tracer, callback.first);
    callback.second();
  }
}

static void addMaintenanceCallback(const LuaContext& context, MaintenanceCallback callback, std::string name = "")
{
  (void)context;
  s_maintenanceHooks.lock()->push_back({"maintenanceCallback/" + name, std::move(callback)});
}

void clearMaintenanceHooks()
{
  s_maintenanceHooks.lock()->clear();
}

void runExitCallbacks(const LuaContext& context)
{
  (void)context;
  for (const auto& callback : *(s_exitCallbacks.lock())) {
    callback();
  }
}

static void addExitCallback(const LuaContext& context, ExitCallback callback)
{
  (void)context;
  s_exitCallbacks.lock()->push_back(std::move(callback));
}

void clearExitCallbacks()
{
  s_exitCallbacks.lock()->clear();
}

static void setTicketsKeyAddedHook(const LuaContext& context, const TicketsKeyAddedHook& hook)
{
  (void)context;
  TLSCtx::setTicketsKeyAddedHook([hook](const std::string& key) {
    try {
      auto lua = g_lua.lock();
      hook(key, key.size());
    }
    catch (const std::exception& exp) {
      SLOG(warnlog("Error calling the Lua hook after new tickets key has been added: %s", exp.what()),
           dnsdist::logging::getTopLogger("ticket-keys-hook")->error(Logr::Warning, exp.what(), "Error calling the Lua hook after a new ticket key has been added"));
    }
  });
}

void runServerStateChangeHooks(const LuaContext& context, const std::string& nameWithAddr, bool newState)
{
  (void)context;
  for (const auto& callback : *(s_serverStateChangeHooks.lock())) {
    callback(nameWithAddr, newState);
  }
}

static void addServerStateChangeCallback(const LuaContext& context, ServerStateChangeCallback callback)
{
  (void)context;
  s_serverStateChangeHooks.lock()->push_back(std::move(callback));
}

void clearServerStateChangeCallbacks()
{
  s_serverStateChangeHooks.lock()->clear();
}

void setupLuaHooks(LuaContext& luaCtx)
{
  luaCtx.writeFunction("addMaintenanceCallback", [&luaCtx](const MaintenanceCallback& callback, const std::optional<std::string> name) {
    setLuaSideEffect();
    addMaintenanceCallback(luaCtx, callback, name.value_or("unnamed"));
  });
  luaCtx.writeFunction("addExitCallback", [&luaCtx](const ExitCallback& callback) {
    setLuaSideEffect();
    addExitCallback(luaCtx, callback);
  });
  luaCtx.writeFunction("setTicketsKeyAddedHook", [&luaCtx](const TicketsKeyAddedHook& hook) {
    setLuaSideEffect();
    setTicketsKeyAddedHook(luaCtx, hook);
  });
  luaCtx.writeFunction("addServerStateChangeCallback", [&luaCtx](const ServerStateChangeCallback& hook) {
    setLuaSideEffect();
    addServerStateChangeCallback(luaCtx, hook);
  });
}

}
