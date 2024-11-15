#pragma once

#include <memory>
#include <string>

struct DNSAction;
struct DNSRule;

#include "rust/cxx.h"

namespace dnsdist::rust::settings
{

struct DNSSelector
{
  std::shared_ptr<DNSRule> d_rule;
  std::string d_name;
};

struct MaxQPSIPSelectorConfiguration;
struct AndSelectorConfig;
struct NetmaskGroupSelectorConfig;
struct TCPSelectorConfig;

std::shared_ptr<DNSSelector> getSelectorByName(const ::rust::String& name);
const std::string& getNameFromSelector(const DNSSelector& selector);

std::shared_ptr<DNSSelector> getMaxIPQPSSelector(const MaxQPSIPSelectorConfiguration& config);
std::shared_ptr<DNSSelector> getAllSelector();
std::shared_ptr<DNSSelector> getTCPSelector(const TCPSelectorConfig& config);
std::shared_ptr<DNSSelector> getAndSelector(const AndSelectorConfig& config);
std::shared_ptr<DNSSelector> getNetmaskGroupSelector(const NetmaskGroupSelectorConfig& config);

struct DNSActionWrapper
{
  std::shared_ptr<DNSAction> d_action;
  std::string d_name;
};

struct PoolActionConfig;

std::shared_ptr<DNSActionWrapper> getActionByName(const ::rust::String& name);
std::shared_ptr<DNSActionWrapper> getPoolAction(const PoolActionConfig& config);
}
