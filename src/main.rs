#![allow(dead_code)]

use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let query = build_query("metafilter.com");
    {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("failed to bind socket");
        socket
            .connect("8.8.8.8:53")
            .expect("connect function failed");
        socket.send(&query).expect("couldn't send message");
        let mut buf = [0; 1024];
        match socket.recv(&mut buf) {
            Ok(received) => {
                let idx = 12;
                println!("{:x?}", &buf[..received]);
                let header = &buf[..idx];
                let h = DnsHeader::parse(header);
                println!("{h:?}");
                let question = &buf[12..];
                let (idx, q) = DnsQuestion::parse(question);
                println!("{q:x?}");
                let answer = &buf[..received];
                let a = DnsRecord::parse(answer, idx);
                println!("{a:x?}");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
struct DnsHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DnsHeader {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let id = self.id.to_be_bytes();
        let flags = self.flags.to_be_bytes();
        let num_questions = self.num_questions.to_be_bytes();
        let num_answers = self.num_answers.to_be_bytes();
        let num_authorities = self.num_authorities.to_be_bytes();
        let num_additionals = self.num_additionals.to_be_bytes();
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&flags);
        bytes.extend_from_slice(&num_questions);
        bytes.extend_from_slice(&num_answers);
        bytes.extend_from_slice(&num_authorities);
        bytes.extend_from_slice(&num_additionals);
        bytes
    }

    fn parse(data: &[u8]) -> Self {
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let num_questions = u16::from_be_bytes([data[4], data[5]]);
        let num_answers = u16::from_be_bytes([data[6], data[7]]);
        let num_authorities = u16::from_be_bytes([data[8], data[9]]);
        let num_additionals = u16::from_be_bytes([data[10], data[11]]);
        Self {
            id,
            flags,
            num_questions,
            num_answers,
            num_authorities,
            num_additionals,
        }
    }
}

#[derive(Debug)]
struct DnsQuestion {
    name: Vec<u8>,
    type_: u16,
    class_: u16,
}

impl DnsQuestion {
    fn new(name: &str) -> Self {
        let mut name = name
            .split('.')
            .flat_map(|s| [&[(s.len() as u8)], s.as_bytes()].concat())
            .collect::<Vec<_>>();
        name.push(0u8);
        Self {
            name,
            type_: 1,
            class_: 1,
        }
    }

    // TODO: `&[u8]` instead of `Vec<u8>`
    // TODO: Use Serde?
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = self.name.clone();
        let type_ = self.type_.to_be_bytes();
        bytes.extend_from_slice(&type_);
        let class_ = self.class_.to_be_bytes();
        bytes.extend_from_slice(&class_);
        bytes
    }

    fn parse(data: &[u8]) -> (usize, Self) {
        let mut parts = Vec::new();
        let mut length = dbg!(data[0] as usize); //u16::from_be_bytes([data[0], data[1]);
        let mut idx = 0;
        while length != 0 {
            idx += 1;
            parts.extend_from_slice(&data[idx..idx + length]);
            idx += length;
            length = dbg!(data[idx] as usize);
        }
        let type_ = u16::from_be_bytes([data[idx + 1], data[idx + 2]]);
        let class_ = u16::from_be_bytes([data[idx + 3], data[idx + 4]]);
        (
            idx,
            Self {
                name: parts,
                type_,
                class_,
            },
        )
    }
}

// TODO: implement class/record/flags/id
fn build_query(domain_name: &str) -> Vec<u8> {
    let question = DnsQuestion::new(domain_name);
    let id = 65535;
    let recursion_desired = 0x0100;
    let header = DnsHeader {
        id,
        flags: recursion_desired,
        num_questions: 1,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };
    let mut query = header.as_bytes();
    query.append(&mut question.as_bytes());
    query
}

// GOAL: `parse_response` function that parses the DNS Query response into a struct

// A `DnsRecord` has:
// - name: The domain name
// - type_: A/AAAA/MX/NS/TXT/...
// - class_: Assume will always be 1
// - ttl: Time To Live; how long the query ought be cached for
// - data_length: How many octets the data takes up
// - data: the record's content
#[derive(Debug)]
struct DnsRecord {
    name: Vec<u8>,
    type_: u16,
    class_: u16,
    ttl: u32,
    data_length: u16,
    data: std::net::Ipv4Addr,
}

impl DnsRecord {
    fn parse(data: &[u8], idx: usize) -> Self {
        println!("{:x?}", data);
        let length = data[idx + 17];
        dbg!(length);
        if length > 63 {
            let pointer = (length & 0b0011_1111) as usize;
            let data = &data[pointer..];
            let mut parts = Vec::new();
            let mut length = dbg!(data[12] as usize); //u16::from_be_bytes([data[0], data[1]);
            let mut i = 12;
            while length != 0 {
                i += 1;
                parts.extend_from_slice(&data[i..i + length]);
                i += length;
                length = dbg!(data[i] as usize);
            }
            let type_ = u16::from_be_bytes([data[idx + 1 + 18], data[idx + 2 + 18]]);
            let class_ = u16::from_be_bytes([data[idx + 3 + 18], data[idx + 4 + 18]]);
            let ttl = u32::from_be_bytes([
                data[idx + 5 + 18],
                data[idx + 6 + 18],
                data[idx + 7 + 18],
                data[idx + 8 + 18],
            ]);
            let data_length = u16::from_be_bytes([data[idx + 9 + 18], data[idx + 10 + 18]]);
            let data = data[idx + 11 + 18..].to_vec();
            let data = std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            DnsRecord {
                name: parts,
                type_,
                class_,
                ttl,
                data_length,
                data,
            }
        } else {
            panic!()
        }
    }
}
