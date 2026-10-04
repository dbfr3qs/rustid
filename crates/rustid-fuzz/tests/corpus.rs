//! Every fuzz target over its committed seeds and every input that once
//! crashed it (`fuzz/seeds/<target>`, `fuzz/regressions/<target>`): on
//! stable, so CI keeps fixed crashes fixed without nightly.

use std::path::Path;

#[test]
fn every_target_survives_its_seeds_and_regressions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let mut ran = 0;
    for (name, target) in rustid_fuzz::TARGETS {
        let mut seeds = 0;
        for dir in ["seeds", "regressions"] {
            let Ok(entries) = std::fs::read_dir(root.join(dir).join(name)) else {
                continue;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                let data = std::fs::read(&path).unwrap();
                let outcome = std::panic::catch_unwind(|| target(&data));
                assert!(outcome.is_ok(), "{name} panicked on {}", path.display());
                if dir == "seeds" {
                    seeds += 1;
                }
                ran += 1;
            }
        }
        assert!(seeds > 0, "{name} has no seeds in fuzz/seeds/{name}");
    }
    assert!(ran > 0);
}
