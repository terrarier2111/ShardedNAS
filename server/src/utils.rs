use std::{fs, io, path::Path, time::{SystemTime, UNIX_EPOCH}};

pub fn current_time_millis() -> u128 {
    let now = SystemTime::now();
    let duration_since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let milliseconds = duration_since_epoch.as_millis();
    milliseconds
}

pub fn clear_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::remove_dir_all(&path)?;
    fs::create_dir(path)?;
    Ok(())
}
