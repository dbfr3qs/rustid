//! `application/x-www-form-urlencoded` bodies, read strictly.

/// A parsed form in request order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Form {
    entries: Vec<(String, String)>,
}

/// Form limits: the most values, and the longest key.
pub const MAX_VALUES: usize = 1024;
pub const MAX_KEY_LENGTH: usize = 2048;

/// Why a body isn't an acceptable form. Reading fails
/// `InvalidDataException` for each, which the endpoints turn into
/// `invalid_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FormError {
    #[error("form contains a NUL character")]
    Nul,
    #[error("form has more than {MAX_VALUES} values")]
    TooManyValues,
    #[error("form key is longer than {MAX_KEY_LENGTH} characters")]
    KeyTooLong,
}

impl Form {
    /// Parses a URL-encoded body: `+` is a space, `%XX` escapes are decoded
    /// (invalid ones kept literally), and bytes are read as UTF-8 with
    /// replacement characters. A NUL in any key or value, more than
    /// [`MAX_VALUES`] entries, or a key longer than [`MAX_KEY_LENGTH`] is
    /// rejected.
    pub fn parse(body: &[u8]) -> Result<Form, FormError> {
        let mut entries = Vec::new();
        for pair in body.split(|b| *b == b'&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.iter().position(|b| *b == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &[][..]),
            };
            let (key, value) = (Form::decode_component(key), Form::decode_component(value));
            if key.contains('\0') || value.contains('\0') {
                return Err(FormError::Nul);
            }
            if key.chars().count() > MAX_KEY_LENGTH {
                return Err(FormError::KeyTooLong);
            }
            if entries.len() == MAX_VALUES {
                return Err(FormError::TooManyValues);
            }
            entries.push((key, value));
        }
        Ok(Form { entries })
    }

    pub fn from_pairs(pairs: &[(&str, &str)]) -> Form {
        Form {
            entries: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    /// The first raw value, as `IFormCollection[key].FirstOrDefault()`.
    /// Keys match case-insensitively's form collection.
    pub fn first(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// Blank values dropped, remaining
    /// values joined with commas; `None` when nothing remains.
    pub fn get(&self, key: &str) -> Option<String> {
        let values: Vec<&str> = self.values(key).collect();
        (!values.is_empty()).then(|| values.join(","))
    }

    /// Every entry in request order, blank values included.
    pub fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Decodes one URL-encoded key or value: `+` is a space, `%XX` escapes
    /// are decoded (invalid ones kept literally), bytes are read as UTF-8
    /// with replacement characters.
    pub fn decode_component(raw: &[u8]) -> String {
        decode(raw)
    }

    /// Non-blank values for `key`, in arrival order.
    pub fn values<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |(k, v)| k.eq_ignore_ascii_case(key) && !v.trim().is_empty())
            .map(|(_, v)| v.as_str())
    }
}

fn decode(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => out.push(b' '),
            b'%' if hex(raw.get(i + 1)).is_some() && hex(raw.get(i + 2)).is_some() => {
                out.push(hex(raw.get(i + 1)).unwrap_or(0) * 16 + hex(raw.get(i + 2)).unwrap_or(0));
                i += 3;
                continue;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: Option<&u8>) -> Option<u8> {
    b.and_then(|b| (*b as char).to_digit(16)).map(|d| d as u8)
}
