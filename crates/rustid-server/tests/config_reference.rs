//! `examples/rustid.toml` is the configuration reference: it must mention
//! every setting the server reads. The keys come from the configuration
//! itself: every section rejects unknown fields, and the error lists the
//! ones it expects, so probing each section with an unknown key walks the
//! whole tree.

use figment::Figment;
use figment::providers::{Format, Json};
use serde_json::{Value, json};

const PROBE: &str = "__probe__";

/// The JSON that puts `leaf` at `path` (an element of an array where a
/// segment is `[]`).
fn nest(path: &[String], leaf: Value) -> Value {
    path.iter()
        .rev()
        .fold(leaf, |inner, segment| match segment.as_str() {
            "[]" => Value::Array(vec![inner]),
            key => json!({ key: inner }),
        })
}

/// The error for `value` loaded as the server configuration.
fn error(value: &Value) -> String {
    Figment::from(Json::string(&value.to_string()))
        .extract::<rustid_server::config::ServerConfig>()
        .map(|_| String::new())
        .unwrap_or_else(|e| e.to_string())
}

/// The keys the section at `path` accepts, or `None` when it isn't a
/// section (a value, or a map with free keys).
fn section_keys(path: &[String]) -> Option<Vec<String>> {
    let message = error(&nest(path, json!({ PROBE: 1 })));
    // Only an error about the probe itself lists this section's keys.
    if !message.contains("unknown field")
        || (!message.contains(&format!("found `{PROBE}`"))
            && !message.contains(&format!("unknown field `{PROBE}`")))
    {
        return None;
    }
    let expected = message.split("expected").nth(1)?;
    let expected = expected.split(" for key").next()?;
    let keys: Vec<String> = expected
        .split('`')
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !["one", "of", "or"].contains(t))
        .map(str::to_owned)
        .collect();
    Some(keys)
}

/// Whether the value at `path` is a list (it refuses a map for a sequence).
fn is_list(path: &[String]) -> bool {
    error(&nest(path, json!({ PROBE: 1 }))).contains("expected a sequence")
}

/// Every key path, depth first: sections, lists of sections, and values.
fn walk(path: Vec<String>, out: &mut Vec<Vec<String>>) {
    assert!(path.len() < 8, "the probe went too deep at {path:?}");
    if let Some(keys) = section_keys(&path) {
        for key in keys {
            let mut child = path.clone();
            child.push(key);
            out.push(child.clone());
            walk(child, out);
        }
    } else if !path.is_empty() && is_list(&path) {
        let mut element = path.clone();
        element.push("[]".to_owned());
        if let Some(keys) = section_keys(&element) {
            for key in keys {
                let mut child = element.clone();
                child.push(key);
                out.push(child);
            }
        }
    }
}

/// The example's lines from the header naming `section` (set or commented
/// out, `[...]` or `[[...]]`) up to the next header. The top level is the
/// text before the first header.
fn block<'a>(example: &'a str, section: &str) -> Option<Vec<&'a str>> {
    let header = |line: &str| {
        let t = line.trim_start_matches('#').trim();
        t.starts_with('[').then(|| {
            t.trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or("")
                .to_owned()
        })
    };
    let lines: Vec<&str> = example.lines().collect();
    let start = if section.is_empty() {
        0
    } else {
        lines
            .iter()
            .position(|l| header(l).as_deref() == Some(section))?
            + 1
    };
    let end = lines[start..]
        .iter()
        .position(|l| header(l).is_some())
        .map_or(lines.len(), |i| start + i);
    Some(lines[start..end].to_vec())
}

/// `key = ...` on a line of the block, set or commented out, or inside an
/// inline table.
fn mentions(lines: &[&str], key: &str) -> bool {
    lines.iter().any(|line| {
        let line = line.trim_start_matches('#').trim();
        line.starts_with(&format!("{key} ="))
            || line.contains(&format!("{{ {key} ="))
            || line.contains(&format!(", {key} ="))
    })
}

/// `parent = ...{ key = ...` on one line of the block: a list or table of
/// tables written inline, whose element keys the line shows.
fn inline(lines: &[&str], parent: &str, key: &str) -> bool {
    lines.iter().any(|line| {
        let line = line.trim_start_matches('#').trim();
        line.starts_with(&format!("{parent} ="))
            && (line.contains(&format!("{{ {key} =")) || line.contains(&format!(", {key} =")))
    })
}

/// A header for a section inside `section` (`[[data_protection.keys]]`
/// documents `data_protection`).
fn has_header_under(example: &str, section: &str) -> bool {
    let prefix = format!("{section}.");
    example.lines().any(|line| {
        let t = line.trim_start_matches('#').trim().trim_start_matches('[');
        t.starts_with(&prefix)
    })
}

/// The example documents the settings every hook shares (`timeout`,
/// `failure_policy`, `cache_duration`) once, under `[hooks.profile_claims]`,
/// and says they apply to each hook.
fn hook_setting(example: &str, segments: &[&str]) -> bool {
    matches!(segments, ["hooks", _, key] if block(example, "hooks.profile_claims")
        .is_some_and(|lines| mentions(&lines, key)))
}

#[test]
fn the_example_configuration_mentions_every_setting() {
    let example = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/rustid.toml"
    ))
    .unwrap();
    let mut paths = Vec::new();
    walk(Vec::new(), &mut paths);
    // `[saml]` takes `enabled` and `service_providers_file` out before its
    // options deserialize, so no error lists them: they are named here.
    // Maps with free keys (`hooks.extension_grants`, `telemetry.otlp.headers`,
    // `protocol.discovery.custom_entries`) end the walk; their entries
    // are the operator's own.
    for custom in [["saml", "enabled"], ["saml", "service_providers_file"]] {
        paths.push(custom.iter().map(|s| s.to_string()).collect());
    }
    assert!(
        paths.len() > 100,
        "the probe found only {} keys",
        paths.len()
    );
    let mut missing = Vec::new();
    for path in &paths {
        let segments: Vec<&str> = path
            .iter()
            .map(String::as_str)
            .filter(|s| *s != "[]")
            .collect();
        let (key, parents) = segments.split_last().unwrap();
        let section = parents.join(".");
        let own = if section.is_empty() {
            key.to_string()
        } else {
            format!("{section}.{key}")
        };
        // A section is documented by its header; a value by `key =` in its
        // section, or in an inline table there.
        let documented = block(&example, &own).is_some()
            || has_header_under(&example, &own)
            || hook_setting(&example, &segments)
            || block(&example, &section).is_some_and(|lines| mentions(&lines, key))
            || (!parents.is_empty()
                && block(&example, &parents[..parents.len() - 1].join("."))
                    .is_some_and(|lines| inline(&lines, parents[parents.len() - 1], key)));
        if !documented {
            missing.push(own);
        }
    }
    assert!(
        missing.is_empty(),
        "examples/rustid.toml doesn't mention {} settings:\n{}",
        missing.len(),
        missing.join("\n")
    );
}
