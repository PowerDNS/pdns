#pragma once

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include "tcpiohandler-mplexer.hh"
#include "dnsdist-tcp.hh"

template <class T>
class DownstreamConnectionsManager
{
  struct SequencedTag
  {
  };
  struct OrderedTag
  {
  };

  typedef multi_index_container<
    std::shared_ptr<T>,
    indexed_by<
      ordered_unique<tag<OrderedTag>,
                     identity<std::shared_ptr<T>>>,
      /* new elements are added to the front of the sequence */
      sequenced<tag<SequencedTag>>>>
    list_t;
  struct ConnectionLists
  {
    list_t d_actives;
    list_t d_idles;
  };

public:
  static void setMaxIdleConnectionsPerDownstream(size_t max)
  {
    s_maxIdleConnectionsPerDownstream = max;
  }

  static void setCleanupInterval(uint16_t interval)
  {
    s_cleanupInterval = interval;
  }

  static void setMaxIdleTime(uint16_t max)
  {
    s_maxIdleTime = max;
  }

  std::shared_ptr<T> getConnectionToDownstream(std::unique_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& ds, const struct timeval& now, std::string&& proxyProtocolPayload)
  {
    struct timeval freshCutOff = now;
    freshCutOff.tv_sec -= 1;

    auto backendId = ds->getID();

    cleanupClosedConnections(now);

    const bool haveProxyProtocol = ds->d_config.useProxyProtocol || !proxyProtocolPayload.empty();
    if (!haveProxyProtocol) {
      const auto& it = d_downstreamConnections.find(backendId);
      if (it != d_downstreamConnections.end()) {
        /* first scan idle connections, more recent first */
        auto entry = findUsableConnectionInList(freshCutOff, it->second.d_idles, true);
        if (entry) {
          ++ds->tcpReusedConnections;
          it->second.d_actives.insert(entry);
          return entry;
        }

        /* then scan actives ones, more recent first as well */
        entry = findUsableConnectionInList(freshCutOff, it->second.d_actives, false);
        if (entry) {
          ++ds->tcpReusedConnections;
          return entry;
        }
      }
    }

    if (ds->d_config.d_tcpConcurrentConnectionsLimit > 0 && ds->tcpCurrentConnections.load() >= ds->d_config.d_tcpConcurrentConnectionsLimit) {
      ++ds->tcpTooManyConcurrentConnections;
      throw std::runtime_error("Maximum number of TCP connections to " + ds->getNameWithAddr() + " reached, not creating a new one");
    }

    auto newConnection = std::make_shared<T>(ds, mplexer, now, std::move(proxyProtocolPayload));
    // might make sense to check whether max in flight > 0?
    if (!haveProxyProtocol) {
      auto& list = d_downstreamConnections[backendId].d_actives;
      list.template get<SequencedTag>().push_front(newConnection);
    }

    return newConnection;
  }

  void cleanupClosedConnections(const struct timeval& now)
  {
    if (s_cleanupInterval == 0 || (d_nextCleanup != 0 && d_nextCleanup > now.tv_sec)) {
      return;
    }

    d_nextCleanup = now.tv_sec + s_cleanupInterval;

    struct timeval freshCutOff = now;
    freshCutOff.tv_sec -= 1;
    struct timeval idleCutOff = now;
    idleCutOff.tv_sec -= s_maxIdleTime;

    for (auto dsIt = d_downstreamConnections.begin(); dsIt != d_downstreamConnections.end();) {
      cleanUpList(dsIt->second.d_idles, freshCutOff, idleCutOff);
      cleanUpList(dsIt->second.d_actives, freshCutOff, idleCutOff);

      if (dsIt->second.d_idles.empty() && dsIt->second.d_actives.empty()) {
        dsIt = d_downstreamConnections.erase(dsIt);
      }
      else {
        ++dsIt;
      }
    }
  }

  size_t clear()
  {
    size_t count = 0;
    for (const auto& downstream : d_downstreamConnections) {
      count += downstream.second.d_actives.size();
      for (auto& conn : downstream.second.d_actives) {
        conn->stopIO();
      }
      count += downstream.second.d_idles.size();
      for (auto& conn : downstream.second.d_idles) {
        conn->stopIO();
      }
    }

    d_downstreamConnections.clear();
    return count;
  }

  size_t count() const
  {
    return getActiveCount() + getIdleCount();
  }

  size_t getActiveCount() const
  {
    size_t count = 0;
    for (const auto& downstream : d_downstreamConnections) {
      count += downstream.second.d_actives.size();
    }
    return count;
  }

  size_t getIdleCount() const
  {
    size_t count = 0;
    for (const auto& downstream : d_downstreamConnections) {
      count += downstream.second.d_idles.size();
    }
    return count;
  }

  bool removeDownstreamConnection(std::shared_ptr<T>& conn)
  {
    auto backendIt = d_downstreamConnections.find(conn->getDS()->getID());
    if (backendIt == d_downstreamConnections.end()) {
      return false;
    }

    /* idle list first */
    {
      auto it = backendIt->second.d_idles.find(conn);
      if (it != backendIt->second.d_idles.end()) {
        backendIt->second.d_idles.erase(it);
        return true;
      }
    }
    /* then active */
    {
      auto it = backendIt->second.d_actives.find(conn);
      if (it != backendIt->second.d_actives.end()) {
        backendIt->second.d_actives.erase(it);
        return true;
      }
    }

    return false;
  }

  bool moveToIdle(std::shared_ptr<T>& conn)
  {
    auto backendIt = d_downstreamConnections.find(conn->getDS()->getID());
    if (backendIt == d_downstreamConnections.end()) {
      return false;
    }

    auto it = backendIt->second.d_actives.find(conn);
    if (it == backendIt->second.d_actives.end()) {
      return false;
    }

    backendIt->second.d_actives.erase(it);

    if (backendIt->second.d_idles.size() >= s_maxIdleConnectionsPerDownstream) {
      auto old = backendIt->second.d_idles.template get<SequencedTag>().back();
      old->release(false);
      backendIt->second.d_idles.template get<SequencedTag>().pop_back();
    }

    backendIt->second.d_idles.template get<SequencedTag>().push_front(conn);
    return true;
  }

protected:
  void cleanUpList(list_t& list, const struct timeval& freshCutOff, const struct timeval& idleCutOff)
  {
    auto& sidx = list.template get<SequencedTag>();
    for (auto connIt = sidx.begin(); connIt != sidx.end();) {
      if (!(*connIt)) {
        connIt = sidx.erase(connIt);
        continue;
      }

      auto& entry = *connIt;

      /* don't bother checking freshly used connections */
      if (freshCutOff < entry->getLastDataReceivedTime()) {
        ++connIt;
        continue;
      }

      if (entry->isIdle() && entry->getLastDataReceivedTime() < idleCutOff) {
        /* idle for too long */
        (*connIt)->release(false);
        connIt = sidx.erase(connIt);
        continue;
      }

      if (entry->isUsable()) {
        ++connIt;
        continue;
      }

      if (entry->isIdle()) {
        (*connIt)->release(false);
      }
      connIt = sidx.erase(connIt);
    }
  }

  std::shared_ptr<T> findUsableConnectionInList(const struct timeval& freshCutOff, list_t& list, bool removeIfFound)
  {
    auto& sidx = list.template get<SequencedTag>();
    for (auto listIt = sidx.begin(); listIt != sidx.end();) {
      if (!(*listIt)) {
        listIt = sidx.erase(listIt);
        continue;
      }

      auto& entry = *listIt;
      if (isConnectionUsable(entry, freshCutOff)) {
        entry->setReused();
        // make a copy since the iterator will be invalidated after erasing
        auto result = entry;
        if (removeIfFound) {
          sidx.erase(listIt);
        }
        return result;
      }

      if (entry->willBeReusable(false)) {
        ++listIt;
        continue;
      }

      /* that connection will not be usable later, no need to keep it in that list */
      listIt = sidx.erase(listIt);
    }

    return nullptr;
  }

  bool isConnectionUsable(const std::shared_ptr<T>& conn, const struct timeval& freshCutOff)
  {
    if (!conn->canBeReused()) {
      return false;
    }

    /* for connections that have not been used very recently,
       check whether they have been closed in the meantime */
    if (freshCutOff < conn->getLastDataReceivedTime()) {
      /* used recently enough, skip the check */
      return true;
    }

    return conn->isUsable();
  }

  static size_t s_maxIdleConnectionsPerDownstream;
  static uint16_t s_cleanupInterval;
  static uint16_t s_maxIdleTime;

  std::map<boost::uuids::uuid, ConnectionLists> d_downstreamConnections;

  time_t d_nextCleanup{0};
};

template <class T>
size_t DownstreamConnectionsManager<T>::s_maxIdleConnectionsPerDownstream{10};
template <class T>
uint16_t DownstreamConnectionsManager<T>::s_cleanupInterval{60};
template <class T>
uint16_t DownstreamConnectionsManager<T>::s_maxIdleTime{300};

using DownstreamTCPConnectionsManager = DownstreamConnectionsManager<TCPConnectionToBackend>;
extern thread_local DownstreamTCPConnectionsManager t_downstreamTCPConnectionsManager;
