//! Writes element trees and rustid's serialization of each, for an
//! independent XML implementation to build the same trees and compare its
//! serialization. Usage: `oracle_write <file> [count]`. Deterministic.
//! Text CR and attribute TAB are left out: the writer normalizes them on
//! purpose.

use rustid_saml::xml::writer::{XmlElement, write};

/// A small deterministic generator (xorshift).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const NAMESPACES: &[(&str, &str)] = &[
    ("md", "urn:oasis:names:tc:SAML:2.0:metadata"),
    ("ds", "http://www.w3.org/2000/09/xmldsig#"),
    ("saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
    ("", "urn:default"),
    ("", ""),
];
const PIECES: &[&str] = &[
    "a", "Z9", " ", "&", "<", ">", "\"", "'", "\n", "é", "😀", "]]>", "&amp;", "x y", "",
];

fn value(rng: &mut Rng, extra: &[&str]) -> String {
    let n = rng.below(5);
    (0..n)
        .map(|_| {
            if rng.below(6) == 0 {
                rng.pick(extra).to_owned()
            } else {
                rng.pick(PIECES).to_owned()
            }
        })
        .collect()
}

fn tree(rng: &mut Rng, depth: usize) -> XmlElement {
    let (prefix, ns) = NAMESPACES[rng.below(NAMESPACES.len())];
    let mut e = XmlElement::new(prefix, &format!("E{}", rng.below(4)), ns);
    for i in 0..rng.below(3) {
        let v = value(rng, &["\r"]);
        e = e.attr(&format!("a{i}"), v);
    }
    let children = if depth == 0 { 0 } else { rng.below(4) };
    for _ in 0..children {
        if rng.below(3) == 0 {
            let v = value(rng, &["\t"]);
            e = e.text(v);
        } else {
            e = e.child(tree(rng, depth - 1));
        }
    }
    e
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = &args[1];
    let count: usize = args.get(2).map_or(200, |c| c.parse().unwrap());
    let mut rng = Rng(0x5eed_5a3c);
    let cases: Vec<serde_json::Value> = (0..count)
        .map(|_| {
            let t = tree(&mut rng, 3);
            serde_json::json!({ "tree": t, "rust": write(&t) })
        })
        .collect();
    std::fs::write(out, serde_json::to_string_pretty(&cases).unwrap()).unwrap();
}
