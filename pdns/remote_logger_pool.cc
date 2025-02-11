#include <memory>
#include <string>
#include <unistd.h>
#include <sys/un.h>

#include "config.h"
#include "remote_logger_pool.hh"

RemoteLoggerPool::RemoteLoggerPool(std::vector<std::shared_ptr<RemoteLoggerInterface>>&& pool) :
  d_pool(std::move(pool)), d_counter(0)
{
}

[[nodiscard]] std::string RemoteLoggerPool::toString()
{
  auto stats = this->getStats();
  return "Pool of " + std::to_string(d_pool.size()) + " loggers (" + std::to_string(stats.d_queued) + " processed, " + std::to_string(stats.d_pipeFull + stats.d_tooLarge + stats.d_otherError) + " dropped)";
}

RemoteLoggerInterface::Result RemoteLoggerPool::queueData(const std::string& data)
{
  std::shared_ptr<RemoteLoggerInterface> logger = d_pool.at(d_counter++ % d_pool.size());
  return logger->queueData(data);
}
