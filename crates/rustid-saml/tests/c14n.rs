//! Exclusive canonicalization (with and without comments), byte-identical
//! to an independent implementation on its cases (`fixtures/saml/oracle`).

use std::path::{Path, PathBuf};

use proptest::prelude::*;
use rustid_saml::xml::c14n::{Options, canonicalize, canonicalize_in};
use rustid_saml::xml::dom::{Limits, parse};

fn oracle() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml/oracle")
}

fn options(comments: bool) -> Options<'static> {
    Options {
        comments,
        inclusive: &[],
        exclude: None,
        all_namespaces: false,
    }
}

/// SHA-256 of rustid's canonical form equals the oracle's digest
/// computes for the element through a `#id` reference (`case-*.digests`, one
/// line per element and transform variant).
#[test]
fn every_oracle_case_matches() {
    use base64::Engine;
    let mut checked = 0;
    for entry in std::fs::read_dir(oracle()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !(name.starts_with("case-") && name.ends_with(".xml")) {
            continue;
        }
        let doc = parse(&std::fs::read_to_string(&path).unwrap(), &Limits::default()).unwrap();
        let digests = std::fs::read_to_string(path.with_extension("digests")).unwrap();
        for line in digests.lines() {
            let [id, variant, expected] = line.split(' ').collect::<Vec<_>>()[..] else {
                panic!("{line}");
            };
            let element = doc
                .root
                .descendants()
                .into_iter()
                .find(|e| e.attr("ID") == Some(id))
                .unwrap();
            // A same-document reference ("#id") drops comments before the
            // transforms run (XML-DSig 4.4.3.3), so both modes digest the
            // element without them.
            let out = canonicalize_in(&doc, element, &options(false));
            let digest = base64::engine::general_purpose::STANDARD.encode(
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, out.as_bytes()),
            );
            assert_eq!(digest, expected, "{name} {id} {variant}: {out}");
            checked += 1;
        }
    }
    assert!(checked >= 40, "{checked} digests");
}

#[test]
fn an_excluded_descendant_and_its_subtree_are_left_out() {
    let doc = parse("<r><a/><s><t/></s><b/></r>", &Limits::default()).unwrap();
    let s = doc.root.elements().nth(1).unwrap();
    let out = canonicalize(
        &doc.root,
        &Options {
            comments: true,
            inclusive: &[],
            exclude: Some(s.start),
            all_namespaces: false,
        },
    );
    assert_eq!(out, "<r><a></a><b></b></r>");
}

#[test]
fn listed_prefixes_are_rendered_where_in_scope() {
    let doc = parse(
        "<o xmlns:xs=\"urn:xs\" xmlns:u=\"urn:u\"><c t=\"xs:string\"/></o>",
        &Limits::default(),
    )
    .unwrap();
    let c = doc.root.elements().next().unwrap();
    let listed = ["xs".to_owned(), "absent".to_owned()];
    let out = canonicalize(
        c,
        &Options {
            comments: true,
            inclusive: &listed,
            exclude: None,
            all_namespaces: false,
        },
    );
    assert_eq!(out, "<c xmlns:xs=\"urn:xs\" t=\"xs:string\"></c>");
}

/// A generated document: nested elements over a few namespaces, attributes,
/// text with characters that need escaping, comments and PIs.
fn document() -> impl Strategy<Value = String> {
    let text = "[a-z &<>\"'\t\r\n\u{e9}]{0,8}".prop_map(|t| {
        t.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\r', "&#13;")
    });
    let attr_value = "[a-z &<\"\t\n]{0,6}".prop_map(|v| {
        v.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('"', "&quot;")
            .replace('\t', "&#9;")
            .replace('\n', "&#10;")
    });
    let leaf = (
        prop::sample::select(vec!["a", "p:b", "q:c", "d"]),
        prop::collection::vec(
            (
                prop::sample::select(vec!["x", "y", "p:z", "q:w"]),
                attr_value,
            ),
            0..3,
        ),
        text.clone(),
    )
        .prop_map(|(name, attrs, text)| {
            let mut seen = std::collections::HashSet::new();
            let attrs: String = attrs
                .into_iter()
                .filter(|(n, _)| seen.insert(n.rsplit(':').next().unwrap().to_owned()))
                .map(|(n, v)| format!(" {n}=\"{v}\""))
                .collect();
            format!("<{name}{attrs}>{text}</{name}>")
        });
    leaf.prop_recursive(4, 24, 4, move |inner| {
        (
            prop::sample::select(vec!["a", "p:b", "q:c"]),
            prop::sample::select(vec![
                "",
                " xmlns=\"urn:d\"",
                " xmlns:p=\"urn:p2\"",
                " xmlns=\"\"",
            ]),
            prop::collection::vec(
                prop_oneof![
                    inner,
                    Just("<!-- c -->".to_owned()),
                    Just("<?pi x?>".to_owned()),
                    Just(" \n ".to_owned())
                ],
                0..4,
            ),
        )
            .prop_map(|(name, decl, children)| {
                format!("<{name}{decl}>{}</{name}>", children.concat())
            })
    })
    .prop_map(|body| format!("<root xmlns:p=\"urn:p\" xmlns:q=\"urn:q\">{body}</root>"))
}

proptest! {
    #[test]
    fn canonicalization_is_idempotent(xml in document()) {
        let doc = parse(&xml, &Limits::default()).unwrap();
        for comments in [true, false] {
            let once = canonicalize(&doc.root, &options(comments));
            let again = parse(&once, &Limits::default()).unwrap();
            prop_assert_eq!(canonicalize(&again.root, &options(comments)), once);
        }
    }

    #[test]
    fn the_parser_never_panics(input in ".{0,200}") {
        let _ = parse(&input, &Limits::default());
    }
}
