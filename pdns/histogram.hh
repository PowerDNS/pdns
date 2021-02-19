#pragma once

#include <algorithm>
#include <atomic>
#include <vector>
#include <sstream>

namespace pdns {

// By convention, we are using microsecond units
struct Bucket
{
  std::string d_name;
  uint64_t d_boundary;
  uint64_t d_count;
};

inline bool operator<(uint64_t b, const Bucket& bu)
{
  // we are using less-or-equal
  return b <= bu.d_boundary;
}

struct AtomicBucket
{
  // We need the constrcutors in this case, since atomics have a disabled
  // copy constructor.
  AtomicBucket() {}
  AtomicBucket(std::string name, uint64_t boundary, uint64_t val) : d_name(std::move(name)), d_boundary(boundary), d_count(val) {}
  AtomicBucket(const AtomicBucket& rhs) : d_name(rhs.d_name), d_boundary(rhs.d_boundary), d_count(rhs.d_count.load()) {}

  std::string d_name;
  uint64_t d_boundary;
  std::atomic<uint64_t> d_count;
};

inline bool operator<(uint64_t b, const AtomicBucket& bu)
{
  // we are using less-or-equal
  return b <= bu.d_boundary;
}

template<class B>
class BaseHistogram
{
public:
  BaseHistogram(const std::string& prefix, const std::vector<uint64_t>& boundaries)
  {
    if (!std::is_sorted(boundaries.cbegin(), boundaries.cend())) {
      throw std::invalid_argument("boundary array must be sorted");
    }
    if (boundaries.size() == 0) {
      throw std::invalid_argument("boundary array must not be empty");
    }
    if (boundaries[0] == 0) {
      throw std::invalid_argument("boundary array's first element should not be zero");
    }
    d_buckets.reserve(boundaries.size() + 1);
    for (auto b: boundaries) {
      // to_string gives too many .00000's
      std::ostringstream str;
      str << prefix << "le-" << b;
      d_buckets.push_back(B{str.str(), b, 0});
    }
    // everything above last boundary, plus NaN, Inf etc
    d_buckets.push_back(B{prefix + "le-max", std::numeric_limits<uint64_t>::max(), 0});
  }

  const std::vector<B>& getRawData() const
  {
    return d_buckets;
  }

  uint64_t getCount(size_t i) const
  {
    return d_buckets[i].d_count;
  }

  std::vector<B> getCumulativeBuckets() const
  {
    std::vector<B> ret;
    ret.reserve(d_buckets.size());
    uint64_t c{0};
    for (const auto& b : d_buckets) {
      c += b.d_count;
      ret.push_back(B{b.d_name, b.d_boundary, c});
    }
    return ret;
  }

  std::vector<uint64_t> getCumulativeCounts() const
  {
    std::vector<uint64_t> ret;
    ret.reserve(d_buckets.size());
    uint64_t c = 0;
    for (const auto& b : d_buckets) {
      c += b.d_count;
      ret.push_back(c);
    }
    return ret;
  }

  inline void operator()(uint64_t d)
  {
    auto index = std::upper_bound(d_buckets.begin(), d_buckets.end(), d);
    // out index is always valid
    ++index->d_count;
  }

private:
  std::vector<B> d_buckets;
};

template<class T>
using Histogram = BaseHistogram<Bucket>;

template<class T>
using AtomicHistogram = BaseHistogram<AtomicBucket>;

} // namespace pdns
