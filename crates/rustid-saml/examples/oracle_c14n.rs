//! Writes generated documents and rustid's digests for an external
//! oracle that checks them against its own. Usage: `oracle_c14n <out dir> [count]`. Deterministic.

use std::fmt::Write;

use base64::Engine;
use rustid_saml::xml::c14n::{Options, canonicalize};
use rustid_saml::xml::dom::{Limits, parse};

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

/// Text in the wire form: no character-referenced CR in text or
/// tab in attributes (which some verifiers canonicalize differently; see dsig).
fn text(rng: &mut Rng) -> String {
    let parts = [
        "a", "b", " ", "&amp;", "&lt;", "&gt;", "\"", "'", "é", "€", "😀", "\n", "&#xA;", "x y",
    ];
    (0..rng.below(6)).map(|_| rng.pick(&parts)).collect()
}

fn attr_value(rng: &mut Rng) -> String {
    let parts = [
        "v", "&amp;", "&lt;", "&quot;", "'", "é", " ", "&#xA;", "&#xD;",
    ];
    (0..rng.below(5)).map(|_| rng.pick(&parts)).collect()
}

fn element(rng: &mut Rng, depth: usize, id: Option<&str>, out: &mut String) {
    let name = rng.pick(&["a", "p:b", "q:c", "d"]);
    write!(out, "<{name}").unwrap();
    if let Some(id) = id {
        write!(out, " ID=\"{id}\"").unwrap();
    }
    match rng.below(5) {
        0 => out.push_str(" xmlns=\"urn:d\""),
        1 => out.push_str(" xmlns:p=\"urn:p2\""),
        2 => out.push_str(" xmlns=\"\""),
        _ => {}
    }
    let mut used = Vec::new();
    for _ in 0..rng.below(3) {
        let attr = rng.pick(&["x", "y", "p:z", "q:w"]);
        let local = attr.rsplit(':').next().unwrap();
        if !used.contains(&local) {
            used.push(local);
            write!(out, " {attr}=\"{}\"", attr_value(rng)).unwrap();
        }
    }
    out.push('>');
    let children = if depth == 0 { 0 } else { rng.below(4) };
    for _ in 0..children {
        match rng.below(6) {
            0 => out.push_str(&text(rng)),
            1 => out.push_str("<!-- c -->"),
            2 => out.push_str("<![CDATA[<cd & ata>]]>"),
            3 => out.push_str("<?pi data?>"),
            _ => element(rng, depth - 1, None, out),
        }
    }
    write!(out, "</{name}>").unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = std::path::Path::new(&args[1]);
    let count: usize = args.get(2).map_or(200, |c| c.parse().unwrap());
    std::fs::create_dir_all(out).unwrap();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for n in 0..count {
        let mut xml = String::from("<root ID=\"r\" xmlns:p=\"urn:p\" xmlns:q=\"urn:q\">");
        element(&mut rng, 4, Some("c"), &mut xml);
        for _ in 0..rng.below(3) {
            element(&mut rng, 3, None, &mut xml);
        }
        xml.push_str("</root>");
        let doc = parse(&xml, &Limits::default()).unwrap();
        let mut digests = String::new();
        for id in ["r", "c"] {
            let e = doc
                .root
                .descendants()
                .into_iter()
                .find(|e| e.attr("ID") == Some(id))
                .unwrap();
            let canonical = canonicalize(
                e,
                &Options {
                    comments: false,
                    inclusive: &[],
                    exclude: None,
                    all_namespaces: false,
                },
            );
            let digest = base64::engine::general_purpose::STANDARD.encode(
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes()),
            );
            writeln!(digests, "{id} {digest}").unwrap();
        }
        std::fs::write(out.join(format!("gen-{n:03}.xml")), xml).unwrap();
        std::fs::write(out.join(format!("gen-{n:03}.rust")), digests).unwrap();
    }
    println!("wrote {count} documents to {}", out.display());
}
