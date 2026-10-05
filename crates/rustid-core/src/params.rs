//! Request parameters (a name-value collection), and the URL
//! helpers redirect URLs are built with.

use std::collections::HashMap;

use crate::form::Form;

/// Parameters in first-seen key order. Keys match case-insensitively and
/// keep the casing they first arrived with; each key holds its values in
/// arrival order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    entries: Vec<(String, Vec<String>)>,
    /// ASCII-lower-cased key → position in `entries`, so lookups stay
    /// constant time however many keys a hostile query carries.
    index: HashMap<String, usize>,
}

impl Params {
    /// A query's or form's pairs: blank values are
    /// dropped, and a key whose values are all blank is absent.
    pub fn from_pairs<K: AsRef<str>, V: AsRef<str>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        let mut params = Params::default();
        for (key, value) in pairs {
            let value = value.as_ref();
            if !value.trim().is_empty() {
                params.add(key.as_ref(), value);
            }
        }
        params
    }

    /// A query string (without the leading `?`) parsed as the HTTP layer's query
    /// feature does: `+` is a space and `%XX` escapes are decoded. A key
    /// that repeats takes the casing of its second occurrence (the HTTP layer's
    /// query accumulator replaces the key when a second value arrives),
    /// blank values included; then blank values are dropped.
    pub fn parse_query(query: &str) -> Self {
        let mut all = Params::default();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (decode(k), decode(v)),
                None => (decode(pair), String::new()),
            };
            match all.position(&key) {
                Some(i) => {
                    let entry = &mut all.entries[i];
                    if entry.1.len() == 1 {
                        entry.0 = key;
                    }
                    entry.1.push(value);
                }
                None => all.push_entry(key, vec![value]),
            }
        }
        let mut params = Params::default();
        for (key, values) in all.entries {
            for value in values.iter().filter(|v| !v.trim().is_empty()) {
                params.add(&key, value);
            }
        }
        params
    }

    pub fn from_form(form: &Form) -> Self {
        Params::from_pairs(form.pairs())
    }

    fn position(&self, key: &str) -> Option<usize> {
        self.index.get(&key.to_ascii_lowercase()).copied()
    }

    fn push_entry(&mut self, key: String, values: Vec<String>) {
        self.index
            .insert(key.to_ascii_lowercase(), self.entries.len());
        self.entries.push((key, values));
    }

    /// The values joined with commas, `None` when absent.
    pub fn get(&self, key: &str) -> Option<String> {
        self.position(key).map(|i| self.entries[i].1.join(","))
    }

    /// The values; empty when absent.
    pub fn values(&self, key: &str) -> &[String] {
        self.position(key)
            .map(|i| self.entries[i].1.as_slice())
            .unwrap_or(&[])
    }

    pub fn contains(&self, key: &str) -> bool {
        self.position(key).is_some()
    }

    /// Appends to the key's values, or adds the key last.
    pub fn add(&mut self, key: &str, value: &str) {
        match self.position(key) {
            Some(i) => self.entries[i].1.push(value.to_owned()),
            None => self.push_entry(key.to_owned(), vec![value.to_owned()]),
        }
    }

    /// The indexer's setter: replaces the key's values in place, or adds it.
    pub fn set(&mut self, key: &str, value: &str) {
        match self.position(key) {
            Some(i) => self.entries[i].1 = vec![value.to_owned()],
            None => self.push_entry(key.to_owned(), vec![value.to_owned()]),
        }
    }

    pub fn remove(&mut self, key: &str) {
        if let Some(i) = self.index.remove(&key.to_ascii_lowercase()) {
            self.entries.remove(i);
            for position in self.index.values_mut() {
                if *position > i {
                    *position -= 1;
                }
            }
        }
    }

    /// Keys in order, with their values.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// Every value as `key=value` with [`url_encode`],
    /// keys in order; an empty value is written as the bare key.
    pub fn to_query_string(&self) -> String {
        let mut out = String::new();
        for (key, values) in &self.entries {
            for value in values {
                if !out.is_empty() {
                    out.push('&');
                }
                out.push_str(&url_encode(key));
                if !value.is_empty() {
                    out.push('=');
                    out.push_str(&url_encode(value));
                }
            }
        }
        out
    }
}

/// UTF-8 percent-encoding of everything but
/// ASCII letters, digits and `! $ ( ) * , - . ; @ _ ~`.
pub fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut buf = [0u8; 4];
    for c in value.chars() {
        if c.is_ascii_alphanumeric() || "!$()*,-.;@_~".contains(c) {
            out.push(c);
        } else {
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// `url.AddQueryString(query)`: appends with `?`, or `&` when the URL
/// already has a query that doesn't end with `&`.
pub fn add_query_string(url: &str, query: &str) -> String {
    let sep = if !url.contains('?') {
        "?"
    } else if !url.ends_with('&') {
        "&"
    } else {
        ""
    };
    format!("{url}{sep}{query}")
}

/// `url.AddQueryString(name, value)`: the value is [`url_encode`]d.
pub fn add_query_param(url: &str, name: &str, value: &str) -> String {
    add_query_string(url, &format!("{name}={}", url_encode(value)))
}

/// `url.AddHashFragment(query)`: appends after `#`, adding one if missing.
pub fn add_hash_fragment(url: &str, query: &str) -> String {
    if url.contains('#') {
        format!("{url}{query}")
    } else {
        format!("{url}#{query}")
    }
}

/// `/` or `/path` (not `//` or `/\`), or the same after
/// `~`, with no control characters.
pub fn is_local_url(url: &str) -> bool {
    let rest = if let Some(rest) = url.strip_prefix("~/") {
        rest
    } else if let Some(rest) = url.strip_prefix('/') {
        rest
    } else {
        return false;
    };
    !rest.starts_with('/') && !rest.starts_with('\\') && !rest.chars().any(char::is_control)
}

/// Trimmed, split on spaces, empties removed.
pub fn split_spaces(value: &str) -> Vec<String> {
    value
        .trim()
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The length in UTF-16 code units, which input length limits count.
pub fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn decode(raw: &str) -> String {
    Form::decode_component(raw.as_bytes())
}
