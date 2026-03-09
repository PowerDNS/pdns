#[cxx::bridge(namespace = "dnsdist::rust::moka")]
mod rustmoka {
    // Rust types and signatures exposed to C++.
    extern "Rust" {
        type Cache;
        fn clone(&self) -> Box<Cache>;
        fn entry_count(&self) -> u64;
        fn get(&self, key: &[u8]) -> SharedPtr<CacheValue>;
        fn insert(&self, key: Vec<u8>, value: SharedPtr<CacheValue>);

        fn cache_new(capacity: usize, segments: usize) -> Box<Cache>;

        fn vec_u8_extend(data: &mut Vec<u8>, slice: &[u8]);
    }

    // C++ types and signatures exposed to Rust.
    #[namespace = ""]
    unsafe extern "C++" {
        include!("dnsdist-cache.hh");
        type CacheValue;
    }
}

unsafe impl Send for rustmoka::CacheValue {}
unsafe impl Sync for rustmoka::CacheValue {}

fn vec_u8_extend(data: &mut Vec<u8>, slice: &[u8]) {
    data.extend_from_slice(slice);
}

pub struct Cache {
    cache: moka::sync::SegmentedCache<Vec<u8>, cxx::SharedPtr<rustmoka::CacheValue>>,
}

pub fn cache_new(capacity: usize, segments: usize) -> Box<Cache> {
    Box::new(Cache {
        cache: moka::sync::Cache::builder()
            .max_capacity(capacity as u64)
            .segments(segments)
            .build(),
    })
}

impl Cache {
    pub fn clone(&self) -> Box<Cache> {
        Box::new(Cache {
            cache: self.cache.clone(),
        })
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    pub fn get(&self, key: &[u8]) -> cxx::SharedPtr<rustmoka::CacheValue> {
        match self.cache.get(key) {
            Some(value) => value,
            None => cxx::SharedPtr::null(),
        }
    }

    pub fn insert(&self, key: Vec<u8>, value: cxx::SharedPtr<rustmoka::CacheValue>) {
        self.cache.insert(key, value);
    }
}
