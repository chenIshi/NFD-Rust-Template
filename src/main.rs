extern crate pnet;
extern crate NFD_RUST_Template;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::collections::{HashMap, BTreeMap, HashSet, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::env;
use NFD_RUST_Template::backend::obj::{PacketField, Variable, PacketInfo, PacketMap};
use NFD_RUST_Template::backend::packet_info;

fn main() {
    /* Setup the default basic environment */
    /* take the second argument as the forwarding node */
    let host_interface_name = env::args().nth(1).unwrap();
    let host_interface_match = | iface: &NetworkInterface | iface.name == host_interface_name;

    let host_interface = datalink::interfaces().into_iter()
                                            .filter(host_interface_match)
                                            .next()
                                            .unwrap();

    /* take the third argument as the receiving node */
    let client_interface_name = env::args().nth(2).unwrap();
    let client_interface_match = | iface: &NetworkInterface | iface.name == client_interface_name;

    let client_interface = datalink::interfaces().into_iter()
                                                .filter(client_interface_match)
                                                .next()
                                                .unwrap();

    let (mut tx, mut rx) = match datalink::channel(&host_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    /* START RECEIVING PACKETS ... */

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethpacket = EthernetPacket::new(packet).unwrap();

                /* init packet info lookup table */

                let mut packet_table = PacketMap::new();
                let init_success = packet_info::extract_packet_info(& ethpacket, &mut packet_table);
                if !init_success {
                    println!("Not a supported packet type, Skip!");
                    continue;
                }

                /* sym_table is for recording the mapping relationship between ID and value */
                let sym_table = packet_info::init_table(packet_table);
            },
            Err(e) => {
                /* If an error occurs, we can handle it here */
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
