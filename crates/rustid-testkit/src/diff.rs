use serde::Serialize;
use serde_json::Value;

/// One place where two JSON documents differ. `path` is a JSON pointer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Difference {
    pub path: String,
    pub expected: Option<Value>,
    pub actual: Option<Value>,
}

pub fn json_diff(expected: &Value, actual: &Value) -> Vec<Difference> {
    let mut out = Vec::new();
    walk("", expected, actual, &mut out);
    out
}

fn walk(path: &str, expected: &Value, actual: &Value, out: &mut Vec<Difference>) {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            let mut keys: Vec<&String> = e.keys().chain(a.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child = format!("{path}/{key}");
                match (e.get(key), a.get(key)) {
                    (Some(ev), Some(av)) => walk(&child, ev, av, out),
                    (ev, av) => out.push(Difference {
                        path: child,
                        expected: ev.cloned(),
                        actual: av.cloned(),
                    }),
                }
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            let len = e.len().max(a.len());
            for i in 0..len {
                let child = format!("{path}/{i}");
                match (e.get(i), a.get(i)) {
                    (Some(ev), Some(av)) => walk(&child, ev, av, out),
                    (ev, av) => out.push(Difference {
                        path: child,
                        expected: ev.cloned(),
                        actual: av.cloned(),
                    }),
                }
            }
        }
        (e, a) if e == a => {}
        (e, a) => out.push(Difference {
            path: if path.is_empty() {
                "/".to_owned()
            } else {
                path.to_owned()
            },
            expected: Some(e.clone()),
            actual: Some(a.clone()),
        }),
    }
}
