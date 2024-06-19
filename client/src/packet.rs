use std::{io::Read, net::TcpStream};

use bytes::{Buf, BufMut, Bytes};
use ordinalizer::Ordinal;

use crate::{protocol::RWBytes, Token};

pub fn read_full_packet(conn: &mut TcpStream) -> anyhow::Result<PacketIn> {
    let mut len_buf = [0; 8];
    conn.read_exact(&mut len_buf).unwrap();
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut packet_buf = vec![0; len];
    conn.read_exact(&mut packet_buf).unwrap();
    let mut packet_buf = Bytes::from(packet_buf);
    Ok(PacketIn::read(&mut packet_buf)?)
}

#[derive(Ordinal)]
#[repr(u8)]
pub enum PacketOut {
    Login { token: Token, version: u16 } = 0x0,
    ChallengeResponse { val: Vec<u8>, } = 0x1,
    KeepAlive = 0x2,
    BackupRequest = 0x3,
    DeliverFrame { file_name: String, content: Vec<u8>, last_frame: bool, } = 0x4,
    FinishedBackup = 0x5,
}

impl RWBytes for PacketOut {
    type Ty = Self;

    fn read(src: &mut bytes::Bytes) -> anyhow::Result<Self::Ty> {
        let ord = src.get_u8();
        match ord {
            0x0 => Ok(Self::Login {
                token: Vec::<u8>::read(src)?,
                version: u16::read(src)?,
            }),
            0x1 => Ok(Self::ChallengeResponse { val: Vec::<u8>::read(src)? }),
            0x2 => Ok(Self::KeepAlive),
            0x3 => Ok(Self::BackupRequest),
            0x4 => Ok(Self::DeliverFrame {
                file_name: String::read(src)?,
                content: Vec::<u8>::read(src)?,
                last_frame: bool::read(src)?,
            }),
            0x5 => Ok(Self::FinishedBackup),
            _ => unreachable!("Unknown packet ordinal {ord}"),
        }
    }

    fn write(&self, dst: &mut bytes::BytesMut) -> anyhow::Result<()> {
        dst.put_u8(self.ordinal() as u8);
        match self {
            Self::Login { token, version } => {
                token.write(dst)?;
                version.write(dst)
            },
            Self::BackupRequest => Ok(()),
            Self::FinishedBackup => Ok(()),
            Self::DeliverFrame { file_name, content, last_frame } => {
                file_name.write(dst)?;
                content.write(dst)?;
                last_frame.write(dst)
            }
            Self::ChallengeResponse { val } => val.write(dst),
            Self::KeepAlive => Ok(()),
        }
    }
}

#[derive(Ordinal)]
#[repr(u8)]
pub enum PacketIn {
    ChallengeRequest { challenge: Vec<u8> } = 0x0,
    LoginSuccess { max_frame_size: u64, } = 0x1,
    KeepAlive = 0x2,
    /// permit the next frame from the client
    FrameRequest = 0x3,
}

impl RWBytes for PacketIn {
    type Ty = Self;

    fn read(src: &mut bytes::Bytes) -> anyhow::Result<Self::Ty> {
        let ord = src.get_u8();
        match ord {
            0x0 => Ok(Self::ChallengeRequest {
                challenge: Vec::<u8>::read(src)?,
            }),
            0x1 => Ok(Self::LoginSuccess { max_frame_size: u64::read(src)? }),
            0x2 => Ok(Self::KeepAlive),
            0x3 => Ok(Self::FrameRequest),
            _ => unreachable!("Unknown packet ordinal {ord}"),
        }
    }

    fn write(&self, dst: &mut bytes::BytesMut) -> anyhow::Result<()> {
        let ord = self.ordinal() as u8;
        dst.put_u8(ord);
        match self {
            Self::LoginSuccess { max_frame_size } => max_frame_size.write(dst),
            Self::FrameRequest => Ok(()),
            Self::ChallengeRequest { challenge } => challenge.write(dst),
            Self::KeepAlive => Ok(()),
        }
    }
}
