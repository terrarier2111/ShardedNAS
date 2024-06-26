use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Cow;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Write};
use std::mem::transmute;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub const PROTOCOL_VERSION: u16 = 1;

pub(crate) trait RWBytes /*: Sized*/ {
    type Ty;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty>;

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()>;
}

pub(crate) trait RWBytesMut /*: Sized*/ {
    type Ty;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty>;

    fn write(&mut self, dst: &mut BytesMut) -> anyhow::Result<()>;
}

impl RWBytes for u128 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_u128_le())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u128_le(*self);
        Ok(())
    }
}

impl RWBytes for i64 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_i64_le())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_i64_le(*self);
        Ok(())
    }
}

impl RWBytes for i32 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_i32_le())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_i32_le(*self);
        Ok(())
    }
}

impl RWBytes for i16 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_i16_le())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_i16_le(*self);
        Ok(())
    }
}

impl RWBytes for i8 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_i8())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_i8(*self);
        Ok(())
    }
}

impl RWBytes for u64 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_u64_le())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u64_le(*self);
        Ok(())
    }
}

impl RWBytes for u32 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_u32_le())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u32_le(*self);
        Ok(())
    }
}

impl RWBytes for u16 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_u16_le())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u16_le(*self);
        Ok(())
    }
}

impl RWBytes for u8 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Ok(src.get_u8())
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u8(*self);
        Ok(())
    }
}

impl RWBytes for bool {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let val = src.get_u8();
        match val {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(anyhow::Error::from(ErrorBoolConversion(val))),
        }
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u8(*self as u8);
        Ok(())
    }
}

impl RWBytes for f32 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        // SAFETY: this is safe because all possible bit patterns are valid for f32
        Ok(unsafe { transmute(src.get_u32_le()) })
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        // SAFETY: this is safe because all possible bit patterns are valid for u32
        dst.put_u32_le(unsafe { transmute(*self) });
        Ok(())
    }
}

impl RWBytes for f64 {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        // SAFETY: this is safe because all possible bit patterns are valid for f64
        Ok(unsafe { transmute(src.get_u64_le()) })
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        // SAFETY: this is safe because all possible bit patterns are valid for u64
        dst.put_u64_le(unsafe { transmute(*self) });
        Ok(())
    }
}

impl RWBytes for Duration {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let secs = src.get_u64_le();
        let subsec_nanos = src.get_u32_le();
        Ok(Duration::new(secs, subsec_nanos))
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u64_le(self.as_secs());
        dst.put_u32_le(self.subsec_nanos());
        Ok(())
    }
}

impl RWBytes for String {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let len = src.get_u64_le() as usize;
        let result = src.read_slice(len);
        Ok(String::from(String::from_utf8_lossy(result.deref())))
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u64_le(self.len() as u64);
        dst.write_str(self.as_str())?;
        Ok(())
    }
}

impl<T: RWBytes<Ty = V>, V> RWBytes for Vec<T> {
    type Ty = Vec<V>;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let len = src.get_u64_le() as usize;
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            result.push(T::read(src)?);
        }
        Ok(result)
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u64_le(self.len() as u64);
        for val in self.iter() {
            val.write(dst)?;
        }
        Ok(())
    }
}

impl<'a, T: Clone + RWBytes<Ty = V>, V: Clone + 'a> RWBytes for Cow<'a, T> {
    type Ty = Cow<'a, V>;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let val = T::read(src)?;
        Ok(Cow::Owned(val))
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        self.deref().write(dst)
    }
}

impl<'a> RWBytes for Cow<'a, str> {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let len = src.get_u64_le() as usize;
        let result = src.read_slice(len);
        Ok(Cow::Owned(String::from_utf8(result.to_vec())?))
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u64_le(self.len() as u64);
        dst.write_str(self)?;
        Ok(())
    }
}

impl<T: RWBytes<Ty = V>, V> RWBytes for Arc<T> {
    type Ty = Arc<V>;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let val = T::read(src)?;
        Ok(Arc::new(val))
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        // <Self as T>::write(self, dst)
        self.as_ref().write(dst)
    }
}

impl<T: RWBytes<Ty = V>, V> RWBytes for Option<T> {
    type Ty = Option<V>;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        if !bool::read(src)? {
            return Ok(None);
        }
        let val = T::read(src)?;
        Ok(Some(val))
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        // <Self as T>::write(self, dst)
        match self {
            None => bool::write(&false, dst),
            Some(val) => {
                bool::write(&true, dst)?;
                val.write(dst)
            }
        }
    }
}

impl RWBytes for AtomicBool {
    type Ty = bool;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        bool::read(src)
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        // FIXME: is this ordering okay?
        self.load(Ordering::Acquire).write(dst)
    }
}

impl<T: RWBytes<Ty = V>, V> RWBytes for RwLock<T> {
    type Ty = RwLock<V>;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let val = T::read(src)?;
        Ok(RwLock::new(val))
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        self.read().unwrap().write(dst)
    }
}

impl<T: ?Sized + RWBytes<Ty = V>, V> RWBytes for Box<T> {
    type Ty = Box<V>;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let val = T::read(src)?;
        Ok(Box::new(val))
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        self.as_ref().write(dst)
    }
}

impl<I: RWBytes<Ty = V>, V> RWBytesMut for Box<dyn ExactSizeIterator<Item = I>> {
    type Ty = Vec<V>;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        Vec::<I>::read(src)
    }

    fn write(&mut self, dst: &mut BytesMut) -> anyhow::Result<()> {
        dst.put_u64_le(self.len() as u64);

        for _ in 0..self.len() {
            self.next().unwrap().write(dst)?;
        }
        Ok(())
    }
}

impl<T: RWBytes<Ty = V>, V> RWBytes for &T {
    type Ty = V;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        T::read(src)
    }

    fn write(&self, dst: &mut BytesMut) -> anyhow::Result<()> {
        T::write(self, dst)
    }
}

pub struct ErrorEnumVariantNotFound(pub &'static str, pub u8);

impl Debug for ErrorEnumVariantNotFound {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("enum type ")?;
        f.write_str(self.0)?;
        f.write_str(" has no variant with ordinal ")?;
        let num = self.1.to_string();
        f.write_str(num.as_str())
    }
}

impl Display for ErrorEnumVariantNotFound {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

impl Error for ErrorEnumVariantNotFound {}

pub struct ErrorBoolConversion(u8);

impl Debug for ErrorBoolConversion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let num = self.0.to_string();
        f.write_str(num.as_str())?;
        f.write_str(" can not be converted into bool")
    }
}

impl Display for ErrorBoolConversion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

impl Error for ErrorBoolConversion {}

pub trait ReadSlice {
    fn read_slice(&mut self, len: usize) -> Bytes;
}

impl ReadSlice for Bytes {
    fn read_slice(&mut self, len: usize) -> Bytes {
        let offset = self.len() - self.remaining();
        let slice = self.slice(offset..(offset + len));
        self.advance(len);
        slice
    }
}
