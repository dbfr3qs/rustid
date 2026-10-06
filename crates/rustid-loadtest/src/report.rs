//! The Markdown report: a table per flow, and, when a second target named
//! `reference` ran too, rustid's ratio to it at each concurrency level.

use std::fmt::Write;

use crate::{Flow, RunResult, percentile};

pub struct Report {
    /// Markdown before the tables (machine, versions, reading).
    pub header: String,
    pub flows: Vec<FlowReport>,
}

pub struct FlowReport {
    pub flow: Flow,
    pub levels: Vec<LevelReport>,
}

pub struct LevelReport {
    pub concurrency: usize,
    pub targets: Vec<TargetRun>,
}

/// A target's median run (by requests/s) at one level, and the errors over
/// every run.
pub struct TargetRun {
    pub name: String,
    pub median: RunResult,
    pub errors: u64,
    pub runs: usize,
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn cores(sample: Option<crate::Sample>, wall: std::time::Duration) -> String {
    sample.map_or("n/a".to_owned(), |s| {
        format!(
            "{:.2}",
            s.cpu_seconds / wall.as_secs_f64().max(f64::EPSILON)
        )
    })
}

pub fn render(report: &Report) -> String {
    let mut out = report.header.clone();
    for flow in &report.flows {
        let _ = writeln!(out, "\n## {}\n", flow.flow.name());
        let _ = writeln!(out, "One operation: {}.\n", flow.flow.operation());
        out.push_str(
            "| Concurrency | Target | ops/s | p50 ms | p90 ms | p99 ms | errors | server CPU (cores) | harness CPU (cores) | peak RSS MiB |\n",
        );
        out.push_str("|---|---|---|---|---|---|---|---|---|---|\n");
        for level in &flow.levels {
            for t in &level.targets {
                let r = &t.median;
                let _ = writeln!(
                    out,
                    "| {} | {} | {:.0} | {:.1} | {:.1} | {:.1} | {} | {} | {} | {} |",
                    level.concurrency,
                    t.name,
                    r.requests_per_second(),
                    ms(percentile(&r.latencies, 50.0)),
                    ms(percentile(&r.latencies, 90.0)),
                    ms(percentile(&r.latencies, 99.0)),
                    t.errors,
                    cores(r.server, r.wall),
                    cores(r.harness, r.wall),
                    r.server
                        .map_or("n/a".to_owned(), |s| (s.peak_rss_kib / 1024).to_string()),
                );
            }
        }
        out.push('\n');
        for level in &flow.levels {
            let find = |name: &str| level.targets.iter().find(|t| t.name == name);
            if let (Some(rustid), Some(reference)) = (find("rustid"), find("reference")) {
                let rps = rustid.median.requests_per_second()
                    / reference.median.requests_per_second().max(f64::EPSILON);
                let p50 = ms(percentile(&rustid.median.latencies, 50.0))
                    / ms(percentile(&reference.median.latencies, 50.0)).max(f64::EPSILON);
                let marker = if rustid.errors + reference.errors > 0 {
                    " (errors in the runs)"
                } else {
                    ""
                };
                let _ = writeln!(
                    out,
                    "- rustid ÷ reference at {}: {rps:.2}× ops/s, {p50:.2}× p50{marker}",
                    level.concurrency
                );
            }
        }
    }
    out
}
