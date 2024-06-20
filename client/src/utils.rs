use std::{mem::size_of, time::{SystemTime, UNIX_EPOCH}};

use ring::aead::{Nonce, NonceSequence, NONCE_LEN};

pub fn current_time_millis() -> u128 {
    let now = SystemTime::now();
    let duration_since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let milliseconds = duration_since_epoch.as_millis();
    milliseconds
}

pub struct BasicNonce {
    cnt: u64,
}

impl BasicNonce {

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            cnt: 2,
        }
    }

}

impl NonceSequence for BasicNonce {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let ret = self.cnt;
        let ret = ret.to_ne_bytes();

        let mut val = [0; NONCE_LEN];
        // FIXME: fill last 4 bytes as well
        for i in 0..size_of::<u64>() {
            val[i] = ret[i];
        }
        Ok(Nonce::assume_unique_for_key(val))
    }
}

