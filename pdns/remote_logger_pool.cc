#include <memory>
#include <string>
#include <unistd.h>
#include <sys/un.h>

#include "config.h"
#include "lock.hh"
#include "remote_logger_pool.hh"

RemoteLoggerPool::RemoteLoggerPool(std::vector<std::shared_ptr<RemoteLoggerInterface>>&& pool) :
  d_pool(std::move(pool)), d_pool_it(d_pool.begin())
{
}

[[nodiscard]] std::string RemoteLoggerPool::toString()
{
  auto stats = this->getStats();
  std::string loggersDesc;
  for (size_t i = 0; i < this->d_pool.size(); i++) {
    if (i > 0) {
      loggersDesc += ", ";
    }
    loggersDesc += d_pool[i]->toString();
  }
  return "RemoteLoggerPool of " + std::to_string(d_pool.size()) + " loggers (" + std::to_string(stats.d_queued) + " processed, " + std::to_string(stats.d_pipeFull + stats.d_tooLarge + stats.d_otherError) + " dropped)[ " + loggersDesc + "]";
}

RemoteLoggerInterface::Result RemoteLoggerPool::queueData(const std::string& data)
{
  std::shared_ptr<RemoteLoggerInterface> logger;
  {
    auto pool_it = d_pool_it.lock();
    logger = **pool_it;
    (*pool_it)++;
    if (*pool_it == d_pool.end()) {
      *pool_it = d_pool.begin();
    }
  }
  return logger->queueData(data);
}
