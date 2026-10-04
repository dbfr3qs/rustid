#![forbid(unsafe_code)]
//! A load harness for rustid: the core flows at fixed concurrency for fixed durations, with latency
//! spec's core flows at fixed concurrency for fixed durations, with latency
//! percentiles and the server's CPU and memory from `/proc`.

pub mod flows;
pub mod report;

use std::sync::Arc;
use std::time::{Duration, Instant};

pub use flows::Flow;

/// CPU time used and peak resident memory of a process.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub cpu_seconds: f64,
    pub peak_rss_kib: u64,
}

/// Linux's `CLK_TCK` on every architecture the report runs on.
const CLOCK_TICKS: f64 = 100.0;

/// `/proc/<pid>` (or `/proc/self`): `utime + stime` and `VmHWM`. `None`
/// where `/proc` isn't there or the process is gone.
pub fn sample(pid: Option<u32>) -> Option<Sample> {
    let dir = match pid {
        Some(pid) => format!("/proc/{pid}"),
        None => "/proc/self".to_owned(),
    };
    let stat = std::fs::read_to_string(format!("{dir}/stat")).ok()?;
    // Fields after the parenthesised command name: state is the first,
    // utime the 12th and stime the 13th.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let ticks: f64 = fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?;
    let status = std::fs::read_to_string(format!("{dir}/status")).ok()?;
    let peak_rss_kib = status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())?;
    Some(Sample {
        cpu_seconds: ticks / CLOCK_TICKS,
        peak_rss_kib,
    })
}

fn delta(before: Option<Sample>, after: Option<Sample>) -> Option<Sample> {
    let (before, after) = (before?, after?);
    Some(Sample {
        cpu_seconds: after.cpu_seconds - before.cpu_seconds,
        peak_rss_kib: after.peak_rss_kib,
    })
}

/// One run of one flow at one concurrency level.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Operations that succeeded.
    pub requests: u64,
    /// Operations that failed (a wrong status, a missing field, a timeout).
    pub errors: u64,
    /// The first error's message, for diagnosis.
    pub first_error: Option<String>,
    /// Every successful operation's latency, sorted.
    pub latencies: Vec<Duration>,
    pub wall: Duration,
    /// The server's CPU over the run and its peak RSS after it.
    pub server: Option<Sample>,
    /// The same for the harness itself.
    pub harness: Option<Sample>,
}

impl RunResult {
    pub fn requests_per_second(&self) -> f64 {
        self.requests as f64 / self.wall.as_secs_f64().max(f64::EPSILON)
    }
}

/// Nearest-rank percentile of sorted latencies; zero for none.
pub fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Runs `flow` against `base` with `concurrency` virtual users for
/// `duration`. Every user's setup (signing in, getting a token) completes
/// before the clock starts.
pub async fn run(
    base: &str,
    flow: Flow,
    concurrency: usize,
    duration: Duration,
    pid: Option<u32>,
) -> anyhow::Result<RunResult> {
    let mut users = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        users.push(flows::User::new(base, flow).await?);
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(concurrency + 1));
    let mut tasks = Vec::with_capacity(concurrency);
    for mut user in users {
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let deadline = Instant::now() + duration;
            let mut latencies = Vec::new();
            let mut errors = 0u64;
            let mut first_error = None;
            while Instant::now() < deadline {
                let started = Instant::now();
                match user.step().await {
                    Ok(()) => latencies.push(started.elapsed()),
                    // A failed operation is neither throughput nor a latency
                    // sample: a target failing fast mustn't look faster.
                    Err(e) => {
                        errors += 1;
                        first_error.get_or_insert_with(|| format!("{e:#}"));
                    }
                }
            }
            (latencies, errors, first_error)
        }));
    }
    let server_before = pid.and_then(|p| sample(Some(p)));
    let harness_before = sample(None);
    barrier.wait().await;
    let started = Instant::now();
    let mut latencies = Vec::new();
    let (mut errors, mut first_error) = (0, None);
    for task in tasks {
        let (l, e, f) = task.await?;
        latencies.extend(l);
        errors += e;
        first_error = first_error.or(f);
    }
    let wall = started.elapsed();
    latencies.sort_unstable();
    Ok(RunResult {
        requests: latencies.len() as u64,
        errors,
        first_error,
        latencies,
        wall,
        server: delta(server_before, pid.and_then(|p| sample(Some(p)))),
        harness: delta(harness_before, sample(None)),
    })
}
