use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_time_millis() -> u128 {
    let now = SystemTime::now();
    let duration_since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let milliseconds = duration_since_epoch.as_millis();
    milliseconds
}
