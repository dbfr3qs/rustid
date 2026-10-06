#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use rustid_loadtest::report::{FlowReport, LevelReport, Report, TargetRun, render};
use rustid_loadtest::{Flow, run};

#[derive(Parser, Debug)]
#[command(
    name = "rustid-loadtest",
    about = "Core-flow load runs against rustid (and an optional second target)"
)]
struct Args {
    /// `name=url` or `name=url@pid` (the server's PID, for CPU and memory).
    #[arg(long = "target", required = true)]
    targets: Vec<String>,
    /// Concurrency levels, comma-separated.
    #[arg(long, default_value = "1,16,64", value_delimiter = ',')]
    levels: Vec<usize>,
    /// Seconds per measured run.
    #[arg(long, default_value_t = 10)]
    seconds: u64,
    /// Seconds of discarded warm-up before each level's runs.
    #[arg(long, default_value_t = 2)]
    warmup: u64,
    /// Measured runs per level; the median (by operations a second) is reported.
    #[arg(long, default_value_t = 3)]
    repeats: usize,
    /// `all`, or flow names, comma-separated.
    #[arg(long, default_value = "all", value_delimiter = ',')]
    flows: Vec<String>,
    /// Markdown to put before the tables.
    #[arg(long)]
    header: Option<PathBuf>,
    #[arg(long)]
    out: PathBuf,
}

struct Target {
    name: String,
    url: String,
    pid: Option<u32>,
}

fn parse_target(spec: &str) -> anyhow::Result<Target> {
    let (name, rest) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--target {spec}: expected name=url[@pid]"))?;
    let (url, pid) = match rest.rsplit_once('@') {
        Some((url, pid)) => (url, Some(pid.parse()?)),
        None => (rest, None),
    };
    Ok(Target {
        name: name.to_owned(),
        url: url.to_owned(),
        pid,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let targets = args
        .targets
        .iter()
        .map(|t| parse_target(t))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let flows: Vec<Flow> = if args.flows == ["all"] {
        Flow::ALL.to_vec()
    } else {
        args.flows
            .iter()
            .map(|f| Flow::parse(f))
            .collect::<anyhow::Result<_>>()?
    };
    let mut report = Report {
        header: match &args.header {
            Some(path) => std::fs::read_to_string(path)?,
            None => String::new(),
        },
        flows: Vec::new(),
    };
    for &flow in &flows {
        let mut levels = Vec::new();
        for &concurrency in &args.levels {
            let mut level = LevelReport {
                concurrency,
                targets: Vec::new(),
            };
            for target in &targets {
                let measure = |seconds: u64| {
                    run(
                        &target.url,
                        flow,
                        concurrency,
                        Duration::from_secs(seconds),
                        target.pid,
                    )
                };
                measure(args.warmup).await?;
                let mut runs = Vec::new();
                for _ in 0..args.repeats.max(1) {
                    runs.push(measure(args.seconds).await?);
                }
                let errors = runs.iter().map(|r| r.errors).sum();
                if let Some(e) = runs.iter().find_map(|r| r.first_error.clone()) {
                    eprintln!("{} {} x{concurrency}: {e}", target.name, flow.name());
                }
                runs.sort_by(|a, b| a.requests_per_second().total_cmp(&b.requests_per_second()));
                let count = runs.len();
                let median = runs.swap_remove(count / 2);
                eprintln!(
                    "{:<10} {:<20} x{concurrency:<3} {:>8.0} ops/s, {errors} errors",
                    target.name,
                    flow.name(),
                    median.requests_per_second()
                );
                level.targets.push(TargetRun {
                    name: target.name.clone(),
                    median,
                    errors,
                    runs: count,
                });
            }
            levels.push(level);
        }
        report.flows.push(FlowReport { flow, levels });
    }
    std::fs::write(&args.out, render(&report))?;
    Ok(())
}
