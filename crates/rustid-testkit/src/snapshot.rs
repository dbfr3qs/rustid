use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::diff::{Difference, json_diff};
use crate::recorded::Recorded;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub name: String,
    pub recorded: Recorded,
}

/// The normalised responses of one scenario, as recorded from a target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub scenario: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StepDifference {
    pub step: String,
    pub differences: Vec<Difference>,
}

impl Snapshot {
    pub fn path(dir: &Path, scenario: &str) -> PathBuf {
        dir.join(format!("{scenario}.json"))
    }

    pub fn write(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir, &self.scenario);
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))
    }

    pub fn read(dir: &Path, scenario: &str) -> anyhow::Result<Snapshot> {
        let path = Self::path(dir, scenario);
        let json = std::fs::read_to_string(&path)
            .with_context(|| format!("reading snapshot {}", path.display()))?;
        serde_json::from_str(&json).with_context(|| format!("parsing snapshot {}", path.display()))
    }

    pub fn compare(expected: &Snapshot, actual: &Snapshot) -> Vec<StepDifference> {
        let mut out = Vec::new();
        let len = expected.steps.len().max(actual.steps.len());
        for i in 0..len {
            match (expected.steps.get(i), actual.steps.get(i)) {
                (Some(e), Some(a)) => {
                    let ev = serde_json::to_value(&e.recorded).expect("serialisable");
                    let av = serde_json::to_value(&a.recorded).expect("serialisable");
                    let differences = json_diff(&ev, &av);
                    if !differences.is_empty() {
                        out.push(StepDifference {
                            step: e.name.clone(),
                            differences,
                        });
                    }
                }
                (Some(e), None) => out.push(StepDifference {
                    step: e.name.clone(),
                    differences: vec![Difference {
                        path: "/".into(),
                        expected: Some(serde_json::to_value(&e.recorded).expect("serialisable")),
                        actual: None,
                    }],
                }),
                (None, Some(a)) => out.push(StepDifference {
                    step: a.name.clone(),
                    differences: vec![Difference {
                        path: "/".into(),
                        expected: None,
                        actual: Some(serde_json::to_value(&a.recorded).expect("serialisable")),
                    }],
                }),
                (None, None) => {}
            }
        }
        out
    }
}
