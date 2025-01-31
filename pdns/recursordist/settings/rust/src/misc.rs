#[cxx::bridge(namespace = "pdns::rust::misc")]
pub mod rustmisc {

    pub enum LogLevel {
        None,
        Normal,
        Detailed,
    }
    enum Priority {
        Absent = 0,
        Alert = 1,
        Critical = 2,
        Error = 3,
        Warning = 4,
        Notice = 5,
        Info = 6,
        Debug = 7,
    }
    struct KeyValue {
        key: String,
        value: String,
    }

    extern "C++" {
        type NetmaskGroup;
        type ComboAddress;
        type Logger;
    }

    unsafe extern "C++" {
        include!("bridge.hh");
        fn qTypeStringToCode(name: &str) -> u16;
        fn isValidHostname(name: &str) -> bool;
        fn comboaddress(address: &str) -> UniquePtr<ComboAddress>;
        fn matches(nmg: &UniquePtr<NetmaskGroup>, address: &UniquePtr<ComboAddress>) -> bool; // match is a keyword
        fn withValue(logger: &SharedPtr<Logger>, key: &str, val: &str) -> SharedPtr<Logger>;
        fn log(logger: &SharedPtr<Logger>, prio: Priority, msg: &str, values: &Vec<KeyValue>);
        fn error(
            logger: &SharedPtr<Logger>,
            prio: Priority,
            err: &str,
            msg: &str,
            values: &Vec<KeyValue>,
        );
   }
}

