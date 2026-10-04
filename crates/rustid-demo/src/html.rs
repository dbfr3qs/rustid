//! The demo client's pages: plain HTML with every interpolated value
//! escaped.

use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};

/// Escapes text for HTML element content and quoted attribute values.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "\
:root{color-scheme:light dark;--fg:#1d1d1f;--bg:#f5f5f7;--card:#fff;--muted:#6e6e73;--accent:#0a66c2;--bad:#b3261e}\
@media (prefers-color-scheme:dark){:root{--fg:#f5f5f7;--bg:#1d1d1f;--card:#2c2c2e;--muted:#a1a1a6;--accent:#4c9bf0;--bad:#f2b8b5}}\
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg)}\
main{max-width:52rem;margin:6vh auto;padding:0 16px}\
.card{background:var(--card);border-radius:12px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.12)}\
h1{font-size:1.4rem;margin:0 0 4px}p{margin:0 0 16px;color:var(--muted)}\
label{display:block;margin:12px 0 4px;font-weight:600}\
input{width:100%;padding:10px;border:1px solid var(--muted);border-radius:8px;font:inherit;background:transparent;color:inherit}\
button{margin-top:20px;width:100%;padding:10px;border:0;border-radius:8px;font:inherit;font-weight:600;color:#fff;background:var(--accent);cursor:pointer}\
.error{color:var(--bad);font-weight:600}code{font-size:.9em}\
.note{margin-top:16px;font-size:.85rem}\
h2{font-size:1.05rem;margin:24px 0 8px}pre{white-space:pre-wrap;word-break:break-all;font-size:.85rem;margin:0}\
table{border-collapse:collapse;width:100%;font-size:.9rem}td{padding:4px 8px;border-top:1px solid rgba(128,128,128,.25);vertical-align:top;word-break:break-all}td:first-child{font-weight:600;white-space:nowrap;width:1%}\
.ok{color:#1b7f3b;font-weight:600}a.button{display:inline-block;margin:16px 8px 0 0;padding:10px 16px;border-radius:8px;color:#fff;background:var(--accent);text-decoration:none;font-weight:600}\
a.secondary{background:var(--muted)}details{margin-top:8px}";

/// A complete page; `body` is already HTML. Never cached.
pub fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title><style>{STYLE}</style></head>\
         <body><main><div class=\"card\">{body}</div></main></body></html>",
        escape(title)
    );
    (
        status,
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (CACHE_CONTROL, "no-store"),
        ],
        html,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::escape;

    #[test]
    fn markup_and_quotes_are_escaped() {
        assert_eq!(
            escape(r#"<a href="x?a=1&b='2'">"#),
            "&lt;a href=&quot;x?a=1&amp;b=&#39;2&#39;&quot;&gt;"
        );
    }
}
