#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "mtasker.hh"
#include "syncres.hh"
#include "rec_channel.hh"
#include "iputils.hh"
#include "logger.hh"
#include "logging.hh"
#include "arguments.hh"
#include "lock.hh"

GlobalStateHolder<CarbonConfig> g_carbonConfig;

void doCarbonDump(void*)
{
  auto log = g_slog->withName("carbon");
  try {
    static thread_local auto configHolder = g_carbonConfig.getLocal();

    auto config = *configHolder;
    if (config.servers.empty()) {
      return;
    }

    if (config.namespace_name.empty()) {
      config.namespace_name = "pdns";
    }

    if (config.hostname.empty()) {
      try {
        config.hostname = getCarbonHostName();
      }
      catch (const std::exception& e) {
        throw std::runtime_error(std::string("The 'carbon-ourname' setting has not been set and we are unable to determine the system's hostname: ") + e.what());
      }
    }
    if (config.instance_name.empty()) {
      config.instance_name = "recursor";
    }

    PacketBuffer msg;
    for (const auto& carbonServer : config.servers) {
      ComboAddress remote(carbonServer, 2003);
      Socket s(remote.sin4.sin_family, SOCK_STREAM);
      s.setNonBlocking();
      std::shared_ptr<TLSCtx> tlsCtx{nullptr};
      const struct timeval timeout{
        g_networkTimeoutMsec / 1000, static_cast<suseconds_t>(g_networkTimeoutMsec) % 1000 * 1000};
      auto handler = std::make_shared<TCPIOHandler>("", false, s.releaseHandle(), timeout, tlsCtx);
      handler->tryConnect(SyncRes::s_tcp_fast_open_connect, remote); // we do the connect so the first attempt happens while we gather stats

      if (msg.empty()) {
        auto all = getAllStatsMap(StatComponent::Carbon);

        ostringstream str;
        time_t now = time(0);

        for (const auto& val : all) {
          str << config.namespace_name << '.' << config.hostname << '.' << config.instance_name << '.' << val.first << ' ' << val.second.d_value << ' ' << now << "\r\n";
        }
        const string& x = str.str();
        msg.insert(msg.end(), x.cbegin(), x.cend());
      }

      auto ret = asendtcp(msg, handler); // this will actually do the right thing waiting on the connect
      if (ret == LWResult::Result::Timeout) {
        SLOG(g_log << Logger::Warning << "Timeout connecting/writing carbon data to " << remote.toStringWithPort() << endl,
             log->info(Logr::Warning, "Timeout connecting/writing carbon data", "address", Logging::Loggable(remote)));
      }
      else if (ret != LWResult::Result::Success) {
        int err = errno;
        SLOG(g_log << Logger::Warning << "Error writing carbon data to " << remote.toStringWithPort() << ": " << stringerror(err) << endl,
             log->error(Logr::Warning, err, "Error writing carbon data", "address", Logging::Loggable(remote)));
      }
      handler->close();
    }
  }
  catch (const PDNSException& e) {
    SLOG(g_log << Logger::Error << "Error in carbon thread: " << e.reason << endl,
         log->error(Logr::Error, e.reason, "Error in carbon thread", "exception", Logging::Loggable("PDNSException")));
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "Error in carbon thread: " << e.what() << endl,
         log->error(Logr::Error, e.what(), "Error in carbon thread", "exception", Logging::Loggable("std::exception")));
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "Unknown error in carbon thread" << endl,
         log->info(Logr::Error, "Error in carbon thread"));
  }
}
