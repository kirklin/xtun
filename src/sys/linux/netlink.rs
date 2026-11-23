//! Interface configuration over rtnetlink: links, addresses and routes.

use std::io;
use std::net::IpAddr;

use ipnet::IpNet;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressHeaderFlags, AddressMessage, AddressScope};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};

use crate::device::Address;

pub(crate) struct Netlink {
    socket: Socket,
    seq: u32,
    buffer: Vec<u8>,
}

impl Netlink {
    pub fn new() -> io::Result<Netlink> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Netlink { socket, seq: 0, buffer: vec![0; 64 * 1024] })
    }

    /// The link's flags and attributes.
    fn link(&mut self, index: u32) -> io::Result<LinkMessage> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        for reply in self.request(RouteNetlinkMessage::GetLink(message), 0)? {
            if let RouteNetlinkMessage::NewLink(link) = reply {
                return Ok(link);
            }
        }
        Err(io::Error::other("the kernel did not report the link"))
    }

    fn set_link(&mut self, index: u32, change: impl FnOnce(&mut LinkMessage)) -> io::Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        change(&mut message);
        self.request(RouteNetlinkMessage::SetLink(message), 0).map(drop)
    }

    pub fn flags(&mut self, index: u32) -> io::Result<LinkFlags> {
        Ok(self.link(index)?.header.flags)
    }

    pub fn set_up(&mut self, index: u32, up: bool) -> io::Result<()> {
        self.set_link(index, |message| {
            message.header.flags = if up { LinkFlags::Up } else { LinkFlags::empty() };
            message.header.change_mask = LinkFlags::Up;
        })
    }

    pub fn set_name(&mut self, index: u32, name: &str) -> io::Result<()> {
        self.set_link(index, |message| message.attributes.push(LinkAttribute::IfName(name.to_owned())))
    }

    pub fn mtu(&mut self, index: u32) -> io::Result<u32> {
        self.link(index)?
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::Mtu(mtu) => Some(*mtu),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("the kernel did not report the MTU"))
    }

    pub fn set_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()> {
        self.set_link(index, |message| message.attributes.push(LinkAttribute::Mtu(mtu)))
    }

    pub fn tx_queue_len(&mut self, index: u32) -> io::Result<u32> {
        self.link(index)?
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::TxQueueLen(length) => Some(*length),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("the kernel did not report the transmit queue length"))
    }

    pub fn set_tx_queue_len(&mut self, index: u32, length: u32) -> io::Result<()> {
        self.set_link(index, |message| message.attributes.push(LinkAttribute::TxQueueLen(length)))
    }

    pub fn mac_address(&mut self, index: u32) -> io::Result<[u8; 6]> {
        self.link(index)?
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::Address(bytes) => <[u8; 6]>::try_from(bytes.as_slice()).ok(),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("the kernel did not report a hardware address"))
    }

    pub fn set_mac_address(&mut self, index: u32, mac: [u8; 6]) -> io::Result<()> {
        self.set_link(index, |message| message.attributes.push(LinkAttribute::Address(mac.to_vec())))
    }

    /// Adds an address; without `prefix_route` the kernel adds no route to its subnet.
    pub fn add_address(&mut self, index: u32, address: Address, prefix_route: bool) -> io::Result<()> {
        let net = address.net;
        let mut message = address_message(index, net);
        message.attributes.push(AddressAttribute::Local(net.addr()));
        message.attributes.push(AddressAttribute::Address(address.peer.unwrap_or(net.addr())));
        if let (IpNet::V4(v4), None) = (net, address.peer)
            && v4.prefix_len() < 31
        {
            message.attributes.push(AddressAttribute::Broadcast(v4.broadcast()));
        }
        let mut flags = AddressFlags::Permanent;
        if net.addr().is_ipv6() {
            flags |= AddressFlags::Nodad;
        }
        if !prefix_route {
            flags |= AddressFlags::Noprefixroute;
        }
        message.attributes.push(AddressAttribute::Flags(flags));
        self.request(RouteNetlinkMessage::NewAddress(message), NLM_F_CREATE | NLM_F_EXCL).map(drop)
    }

    pub fn remove_address(&mut self, index: u32, net: IpNet) -> io::Result<()> {
        let mut message = address_message(index, net);
        message.attributes.push(AddressAttribute::Local(net.addr()));
        self.request(RouteNetlinkMessage::DelAddress(message), 0).map(drop)
    }

    pub fn addresses(&mut self, index: u32) -> io::Result<Vec<IpNet>> {
        let mut nets = Vec::new();
        for reply in self.request(RouteNetlinkMessage::GetAddress(AddressMessage::default()), NLM_F_DUMP)? {
            let RouteNetlinkMessage::NewAddress(message) = reply else {
                continue;
            };
            if message.header.index != index {
                continue;
            }
            let local = message.attributes.iter().find_map(|attribute| match attribute {
                AddressAttribute::Local(ip) => Some(*ip),
                _ => None,
            });
            let address = message.attributes.iter().find_map(|attribute| match attribute {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            });
            if let Some(ip) = local.or(address)
                && let Ok(net) = IpNet::new(ip, message.header.prefix_len)
            {
                nets.push(net);
            }
        }
        Ok(nets)
    }

    pub fn add_route(&mut self, index: u32, net: IpNet, via: Option<IpAddr>) -> io::Result<()> {
        self.request(RouteNetlinkMessage::NewRoute(route_message(index, net, via)), NLM_F_CREATE | NLM_F_EXCL).map(drop)
    }

    pub fn remove_route(&mut self, index: u32, net: IpNet, via: Option<IpAddr>) -> io::Result<()> {
        self.request(RouteNetlinkMessage::DelRoute(route_message(index, net, via)), 0).map(drop)
    }

    /// Sends one request and collects the replies until the kernel acknowledges it, reports an
    /// error, or ends a dump.
    fn request(&mut self, message: RouteNetlinkMessage, flags: u16) -> io::Result<Vec<RouteNetlinkMessage>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        header.sequence_number = seq;
        let mut request = NetlinkMessage::new(header, NetlinkPayload::from(message));
        request.finalize();
        let mut bytes = vec![0; request.buffer_len()];
        request.serialize(&mut bytes);
        self.socket.send(&bytes, 0)?;

        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let mut replies = Vec::new();
        loop {
            let size = self.socket.recv(&mut &mut self.buffer[..], 0)?;
            let mut offset = 0;
            while offset < size {
                let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&self.buffer[offset..size])
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
                let length = reply.header.length as usize;
                if length == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "a netlink message of length zero"));
                }
                offset += length.next_multiple_of(4);
                if reply.header.sequence_number != seq {
                    continue;
                }
                match reply.payload {
                    NetlinkPayload::Error(error) => {
                        if error.code.is_none() {
                            if !dump {
                                return Ok(replies);
                            }
                            continue;
                        }
                        return Err(error.to_io());
                    }
                    NetlinkPayload::Done(_) => return Ok(replies),
                    NetlinkPayload::InnerMessage(message) => replies.push(message),
                    NetlinkPayload::Noop | NetlinkPayload::Overrun(_) => {}
                    _ => {}
                }
            }
        }
    }
}

fn address_message(index: u32, net: IpNet) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.index = index;
    message.header.prefix_len = net.prefix_len();
    message.header.scope = AddressScope::Universe;
    message.header.family = if net.addr().is_ipv4() { AddressFamily::Inet } else { AddressFamily::Inet6 };
    message.header.flags = AddressHeaderFlags::Permanent;
    message
}

fn route_message(index: u32, net: IpNet, via: Option<IpAddr>) -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = if net.addr().is_ipv4() { AddressFamily::Inet } else { AddressFamily::Inet6 };
    message.header.destination_prefix_length = net.prefix_len();
    message.header.table = RouteHeader::RT_TABLE_MAIN;
    message.header.protocol = RouteProtocol::Static;
    message.header.scope = if via.is_some() { RouteScope::Universe } else { RouteScope::Link };
    message.header.kind = RouteType::Unicast;
    message.attributes.push(RouteAttribute::Destination(RouteAddress::from(net.addr())));
    if let Some(via) = via {
        message.attributes.push(RouteAttribute::Gateway(RouteAddress::from(via)));
    }
    message.attributes.push(RouteAttribute::Oif(index));
    message
}
