use std::{io::Read, net::TcpStream};

use bytes::{Buf, BufMut, Bytes};
use ordinalizer::Ordinal;
use ring::aead::{Aad, OpeningKey};

use crate::{protocol::RWBytes, utils::BasicNonce, Token};

pub fn read_full_packet(
    conn: &mut TcpStream,
    key: &mut OpeningKey<BasicNonce>,
) -> anyhow::Result<PacketIn> {
    let mut len_buf = [0; 8];
    conn.read_exact(&mut len_buf)?;
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut packet_buf = vec![0; len];
    conn.read_exact(&mut packet_buf)?;
    key.open_in_place(Aad::empty(), &mut packet_buf).unwrap();
    let mut packet_buf = Bytes::from(packet_buf);
    Ok(PacketIn::read(&mut packet_buf)?)
}

#[derive(Ordinal)]
#[repr(u8)]
pub enum PacketOut {
    Login {
        version: u16,
        token: Token,
        key: [u8; 32],
    } = 0x0,
    ChallengeResponse {
        val: Vec<u8>,
    } = 0x1,
    KeepAlive = 0x2,
    BackupRequest = 0x3,
    DeliverFrame {
        file_name: String,
        file_hash: u64,
        content: Option<Vec<u8>>,
        remaining_bytes: u64,
    } = 0x4,
    FinishedBackup = 0x5,
}

impl RWBytes for PacketOut {
    type Ty = Self;

    fn read(src: &mut bytes::Bytes) -> anyhow::Result<Self::Ty> {
        let ord = src.get_u8();
        match ord {
            0x0 => Ok(Self::Login {
                version: u16::read(src)?,
                token: Vec::<u8>::read(src)?,
                key: {
                    let mut key = [0; 32];
                    for i in 0..32 {
                        key[i] = u8::read(src)?;
                    }
                    key
                },
            }),
            0x1 => Ok(Self::ChallengeResponse {
                val: Vec::<u8>::read(src)?,
            }),
            0x2 => Ok(Self::KeepAlive),
            0x3 => Ok(Self::BackupRequest),
            0x4 => Ok(Self::DeliverFrame {
                file_name: String::read(src)?,
                file_hash: u64::read(src)?,
                content: Option::<Vec::<u8>>::read(src)?,
                remaining_bytes: u64::read(src)?,
            }),
            0x5 => Ok(Self::FinishedBackup),
            _ => unreachable!("Unknown packet ordinal {ord}"),
        }
    }

    fn write(&self, dst: &mut bytes::BytesMut) -> anyhow::Result<()> {
        dst.put_u8(self.ordinal() as u8);
        match self {
            Self::Login {
                token,
                version,
                key,
            } => {
                version.write(dst)?;
                token.write(dst)?;
                for i in 0..key.len() {
                    key[i].write(dst)?;
                }
                Ok(())
            }
            Self::BackupRequest => Ok(()),
            Self::FinishedBackup => Ok(()),
            Self::DeliverFrame {
                file_name,
                file_hash,
                content,
                remaining_bytes,
            } => {
                file_name.write(dst)?;
                file_hash.write(dst)?;
                content.write(dst)?;
                remaining_bytes.write(dst)
            }
            Self::ChallengeResponse { val } => val.write(dst),
            Self::KeepAlive => Ok(()),
        }
    }
}

#[derive(Ordinal)]
#[repr(u8)]
pub enum PacketIn {
    ChallengeRequest {
        challenge: Vec<u8>,
    } = 0x0,
    LoginSuccess {
        max_frame_size: u64,
    } = 0x1,
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
            0x1 => Ok(Self::LoginSuccess {
                max_frame_size: u64::read(src)?,
            }),
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
