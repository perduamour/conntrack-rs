//! # Connection
//! This module contains the general API for the conntrack library.

use neli::{
    consts::{nl::*, socket::*},
    err::{BuilderError, DeError},
    genl::{Genlmsghdr, GenlmsghdrBuilder},
    nl::{NlPayload, NlmsghdrBuilder},
    socket::asynchronous::NlSocketHandle,
    utils::Groups,
};

use crate::attributes::*;
use crate::decoders::*;
use crate::message::*;
use crate::model::*;
use crate::result::*;

/// The `Conntrack` type is used to connect to a netfilter socket and execute
/// conntrack table specific commands.
pub struct Conntrack {
    socket: NlSocketHandle,
}

impl Conntrack {
    /// This method opens a netfilter socket using a `socket()` syscall, and
    /// returns the `Conntrack` instance on success.
    pub fn connect() -> Result<Self> {
        let socket = NlSocketHandle::connect(NlFamily::Netfilter, Some(0), Groups::empty())?;
        Ok(Self { socket })
    }

    /// The dump call will list all connection tracking for the `Conntrack` table as a
    /// `Vec<Flow>` instances.
    pub async fn dump(&self) -> Result<Vec<Flow>> {
        let genlhdr = GenlmsghdrBuilder::<_, ConntrackAttr, _>::default()
            .cmd(0)
            .version(libc::NFNETLINK_V0 as u8)
            .build()
            .map_err(BuilderError::from)
            .map_err(DeError::from)?;

        let msg = NlmsghdrBuilder::default()
            .nl_type(CtNetlinkMessage::Conntrack)
            .nl_flags(NlmF::REQUEST | NlmF::DUMP)
            .nl_payload(NlPayload::Payload(genlhdr))
            .build()
            .map_err(BuilderError::from)
            .map_err(DeError::from)?;

        self.socket.send(&msg).await?;

        let (msgs, _) = self
            .socket
            .recv::<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>>()
            .await?;

        msgs.filter_map(|res| {
            let msg = res.ok()?;
            if let Some(message) = msg.get_payload() {
                let handle = message.attrs().get_attr_handle();
                Some(Flow::decode(handle))
            } else {
                None
            }
        })
        .collect()
    }
}
