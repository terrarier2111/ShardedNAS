use bytes::{Buf, BufMut, Bytes, BytesMut};
use ordinalizer::Ordinal;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

use crate::{protocol::RWBytes, Token};

pub async fn read_full_packet(conn: &mut TcpStream) -> anyhow::Result<PacketIn> {
    let mut len_buf = [0; 8];
    conn.read_exact(&mut len_buf).await.unwrap();
    let mut id_buf = [0; 1];
    conn.read_exact(&mut id_buf).await.unwrap();
    let len = u64::from_be_bytes(len_buf) as usize;
    let mut packet_buf = vec![0; len];
    conn.read_exact(&mut packet_buf).await.unwrap();
    let mut packet_buf = Bytes::from(packet_buf);
    Ok(PacketIn::read(&mut packet_buf)?)
}

pub async fn write_full_packet(conn: &mut TcpStream, packet: PacketOut) -> anyhow::Result<()> {
    let mut buf = BytesMut::new();
    packet.write(&mut buf)?;
    let mut final_buf = BytesMut::new();
    (buf.len() as u64).write(&mut final_buf)?;
    final_buf.extend_from_slice(&buf);
    conn.write_all(&final_buf).await.unwrap();
    Ok(())
}

#[derive(Ordinal)]
#[repr(u8)]
pub enum PacketIn {
    Login { token: Token, version: u16 } = 0x0,
    ChallengeResponse { val: Vec<u8>, } = 0x1,
    KeepAlive = 0x2,
    PushResponse { response: PushResponse } = 0x3,
    PushRequest = 0x4,
    DeliverFrame { file_name: String, content: Vec<u8> } = 0x5,

}

impl RWBytes for PacketIn {
    type Ty = Self;

    fn read(src: &mut bytes::Bytes) -> anyhow::Result<Self::Ty> {
        let ord = src.get_u8();
        match ord {
            0x0 => Ok(Self::Login {
                token: Vec::<u8>::read(src)?,
                version: u16::read(src)?,
            }),
            0x1 => Ok(Self::PushResponse {
                response: PushResponse::read(src)?,
            }),
            0x2 => Ok(Self::PushRequest),
            0x3 => Ok(Self::DeliverFrame {
                file_name: String::read(src)?,
                content: Vec::<u8>::read(src)?,
            }),
            _ => unreachable!("Unknown packet ordinal {ord}"),
        }
    }

    fn write(&self, dst: &mut bytes::BytesMut) -> anyhow::Result<()> {
        dst.put_u8(self.ordinal() as u8);
        match self {
            PacketIn::Login { token, version } => {
                token.write(dst)?;
                version.write(dst)
            },
            PacketIn::PushResponse { response } => response.write(dst),
            PacketIn::PushRequest => Ok(()),
            PacketIn::DeliverFrame { file_name, content } => {
                file_name.write(dst)?;
                content.write(dst)
            }
            PacketIn::ChallengeResponse { val } => val.write(dst),
            PacketIn::KeepAlive => Ok(()),
        }
    }
}

#[derive(Ordinal)]
#[repr(u8)]
pub enum PushResponse {
    Success = 0x0,
    Wait = 0x1,
    CompletedTransmission = 0x2,
}

impl RWBytes for PushResponse {
    type Ty = Self;

    fn read(src: &mut Bytes) -> anyhow::Result<Self::Ty> {
        let ord = src.get_u8();
        match ord {
            0x0 => Ok(Self::Success),
            0x1 => Ok(Self::Wait),
            0x2 => Ok(Self::CompletedTransmission),
            _ => unreachable!(),
        }
    }

    fn write(&self, dst: &mut bytes::BytesMut) -> anyhow::Result<()> {
        let ord = self.ordinal() as u8;
        dst.put_u8(ord);
        Ok(())
    }
}

#[derive(Ordinal)]
#[repr(u8)]
pub enum PacketOut {
    ChallengeRequest { challenge: Vec<u8> } = 0x0,
    LoginSuccess = 0x1,
    KeepAlive = 0x2,
    /// responds to the clients request to start sending updates
    PushResponse { accepted: bool } = 0x3,
    /// request the next frame from the client
    RequestFrame = 0x4,
}

impl RWBytes for PacketOut {
    type Ty = Self;

    fn read(src: &mut bytes::Bytes) -> anyhow::Result<Self::Ty> {
        let ord = src.get_u8();
        match ord {
            0x0 => Ok(Self::PushResponse {
                accepted: bool::read(src)?,
            }),
            0x1 => Ok(Self::LoginSuccess),
            0x2 => Ok(Self::PushResponse { accepted: bool::read(src)? }),
            0x3 => Ok(Self::RequestFrame),
            _ => unreachable!("Unknown packet ordinal {ord}"),
        }
    }

    fn write(&self, dst: &mut bytes::BytesMut) -> anyhow::Result<()> {
        let ord = self.ordinal() as u8;
        dst.put_u8(ord);
        match self {
            PacketOut::LoginSuccess => Ok(()),
            PacketOut::PushResponse { accepted } => accepted.write(dst),
            PacketOut::ChallengeRequest { challenge } => challenge.write(dst),
            PacketOut::RequestFrame => Ok(()),
            PacketOut::KeepAlive => Ok(()),            
        }
    }
}
