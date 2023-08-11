use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let query = build_query("example.com");
    {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("failed to bind socket");
        socket
            .connect("8.8.8.8:53")
            .expect("connect function failed");
        socket.send(&query).expect("couldn't send message");
    }
    Ok(())
}

// GOAL: Make a `Query` asking for the IP address for `google.com`
// That is, what information do we need to make the request, and what format does it need to be in?
//
// A `DNS Query` has 2 parts:
// 1. Header
// 2. Question

// A DNS header has:
// - A `Query ID`
// - Some `flags` (we'll ignore for now)
// - 4 `counts`, enumerating the number of records to expect in each section of a `DNS Packet`:
//      1. `num_questions`
//      2. `num_answers`
//      3. `num_authorities`
//      4. `num_additionals`
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
}

// A DNS Question has:
// - A `name`
// - a `type`
// - a `class`
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
