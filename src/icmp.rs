/*
This file is part of pingr.

Pingr is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Pingr is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Pingr.  If not, see <http://www.gnu.org/licenses/>.
*/

use std::net::Ipv4Addr;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Option;

pub trait Icmp {
    fn get_icmp_type(&self) -> u8;
    fn get_icmp_code(&self) -> u8;
    fn get_icmp_id(&self) -> u16;
    fn get_icmp_sequence(&self) -> u16;
}

impl<'a> Icmp for Ipv4Packet<'a> {
    fn get_icmp_type(&self) -> u8 {
        self.payload()[0]
    }

    fn get_icmp_code(&self) -> u8 {
        self.payload()[1]
    }

    fn get_icmp_id(&self) -> u16 {
        (self.payload()[4] as u16) << 8 + self.payload()[5]
    }

    fn get_icmp_sequence(&self) -> u16 {
        (self.payload()[6] as u16) << 8 + self.payload()[7]
    }
}

fn payload(icmp_type: u8, icmp_code: u8, id: u16, sequence: u16) -> Vec<u8> {
    // allocate vector
    let mut packet = vec![0u8; 44];
    // fill in values
    packet[0] = icmp_type;
    packet[1] = icmp_code;
    packet[4] = (id >> 8) as u8;
    packet[5] = (id & 0xff) as u8;
    packet[6] = (sequence >> 8) as u8;
    packet[7] = (sequence & 0xff) as u8;
    // calc checksum - std::num::Wrapping be useful here
    let mut checksum: u32 = 0;
    for pair in packet.chunks(2) {
        let mut x: u16 = pair[0] as u16;
        x = (x << 8) + pair[1] as u16;
        checksum = (checksum + !x as u32) % 65535;
    }
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;
    packet
}

pub fn packet<'a>(vec: &'a mut Vec<u8>, addr: Ipv4Addr, id: u16, sequence: u16) -> MutableIpv4Packet<'a> {
    let mut packet = MutableIpv4Packet::new(vec).unwrap();
    let payload = payload(8, 0, id, sequence);
    let options: Vec<Ipv4Option> = vec![];
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_ttl(64);
    packet.set_flags(2);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    packet.set_destination(addr);
    packet.set_options(options);
    packet.set_payload(payload);
    packet.set_total_length(64);
    packet
}

