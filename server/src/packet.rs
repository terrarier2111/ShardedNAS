use bytes::{Buf, BufMut};
use ordinalizer::Ordinal;

use crate::{protocol::RWBytes, Token};

#[derive(Ordinal)]
#[repr(u8)]
pub enum PacketIn {
    Login {
        token: Token,
    } = 0x0,
    PushResponse {
        accepted: bool,
    } = 0x1,
    PushRequest = 0x2,
    DeliverFrame {
        file_name: String,
        content: Vec<u8>,
    } = 0x3,
}

impl RWBytes for PacketIn {
    type Ty = Self;

    fn read(src: &mut bytes::Bytes) -> anyhow::Result<Self::Ty> {
        let ord = src.get_u8();
        match ord {
            0x0 => Ok(Self::Login { token: Vec::<u8>::read(src)? }),
            0x1 => Ok(Self::PushResponse { accepted: bool::read(src)? }),
            0x2 => Ok(Self::PushRequest),
            0x3 => Ok(Self::DeliverFrame { file_name: String::read(src)?, content: Vec::<u8>::read(src)? }),
            _ => unreachable!("Unknown packet ordinal {ord}"),
        }
    }

    fn write(&self, dst: &mut bytes::BytesMut) -> anyhow::Result<()> {
        dst.put_u8(self.ordinal() as u8);
        match self {
            PacketIn::Login { token } => token.write(dst),
            PacketIn::PushResponse { accepted } => accepted.write(dst),
            PacketIn::PushRequest => Ok(()),
            PacketIn::DeliverFrame { file_name, content } => {
                file_name.write(dst)?;
                content.write(dst)
            },
        }
    }
}

#[repr(usize)]
pub enum PacketOut {
    LoginSuccess = 0x0,
    PushResponse {
        accepted: bool,
    } = 0x1,
    PushRequest = 0x2,
    RequestFrame = 0x3,
}

impl RWBytes for PacketOut {
    type Ty = Self;

    fn read(src: &mut bytes::Bytes) -> anyhow::Result<Self::Ty> {
        todo!()
    }

    fn write(&self, dst: &mut bytes::BytesMut) -> anyhow::Result<()> {
        todo!()
    }
}