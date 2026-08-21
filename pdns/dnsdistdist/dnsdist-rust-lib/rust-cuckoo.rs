#[cxx::bridge(namespace = dnsdist::rust::cuckoo)]
#[cfg(feature = "cuckoo")]
mod dnsdist_cuckoo {
    extern "Rust" {
        type CuckooFilter;

        fn new_filter(
            max_entries: usize,
            max_kicks: u32,
            bucket_size: u32,
            fingerprint_bits: u32,
            ttl_enabled: bool,
            ttl: u32,
            ttl_bits: u32,
            lru_enabled: bool,
            lru_bits: u32,
        ) -> Result<Box<CuckooFilter>>;
        fn filter_insert(filter: &mut CuckooFilter, value: String) -> bool;
        fn filter_contains(filter: &mut CuckooFilter, value: String) -> bool;
        fn filter_remove(filter: &mut CuckooFilter, value: String) -> bool;
        fn filter_get_size(filter: &CuckooFilter) -> usize;
        fn filter_get_memory_usage(filter: &CuckooFilter) -> usize;
        fn filter_scan_and_update(filter: &mut CuckooFilter) -> usize;
    }
}

#[cfg(feature = "cuckoo")]
pub struct CuckooFilter {
    inner: cuckoo_clock::CuckooFilter<std::hash::RandomState>,
}

#[cfg(feature = "cuckoo")]
pub fn new_filter(
    max_entries: usize,
    max_kicks: u32,
    bucket_size: u32,
    fingerprint_bits: u32,
    ttl_enabled: bool,
    ttl: u32,
    ttl_bits: u32,
    lru_enabled: bool,
    lru_bits: u32,
) -> Result<Box<CuckooFilter>, Box<dyn std::error::Error>> {
    let mut builder = cuckoo_clock::config::CuckooConfiguration::builder(max_entries)
        .max_kicks(max_kicks as usize)
        .fingerprint_bits((fingerprint_bits as usize).try_into()?)
        .bucket_size((bucket_size as usize).try_into()?);
    if ttl_enabled {
        builder = builder.with_ttl(cuckoo_clock::config::TtlConfig {
            ttl_bits: (ttl_bits as usize).try_into()?,
            ttl: ttl.try_into()?,
        });
    }
    if lru_enabled {
        builder = builder.with_lru(cuckoo_clock::config::LruConfig {
            counter_bits: (lru_bits as usize).try_into()?,
            ..Default::default()
        });
    }
    Ok(Box::new(CuckooFilter {
        inner: cuckoo_clock::CuckooFilter::new_random(builder.build()?),
    }))
}

#[cfg(feature = "cuckoo")]
pub fn filter_insert(filter: &mut CuckooFilter, value: String) -> bool {
    filter.inner.insert_if_not_present(&value).is_none()
}

#[cfg(feature = "cuckoo")]
pub fn filter_contains(filter: &mut CuckooFilter, value: String) -> bool {
    filter.inner.contains(&value)
}

#[cfg(feature = "cuckoo")]
pub fn filter_remove(filter: &mut CuckooFilter, value: String) -> bool {
    filter.inner.remove(&value)
}

#[cfg(feature = "cuckoo")]
pub fn filter_get_size(filter: &CuckooFilter) -> usize {
    filter.inner.get_item_count()
}

#[cfg(feature = "cuckoo")]
pub fn filter_get_memory_usage(filter: &CuckooFilter) -> usize {
    filter.inner.get_memory_usage()
}

#[cfg(feature = "cuckoo")]
pub fn filter_scan_and_update(filter: &mut CuckooFilter) -> usize {
    filter.inner.scan_and_update_full()
}
