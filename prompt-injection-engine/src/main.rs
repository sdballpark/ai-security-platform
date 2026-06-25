//! `pie` CLI — a thin wrapper over the library so the same detection logic runs
//! in CI, pre-commit hooks, and ad-hoc triage. Exit code is non-zero when input
//! is blocked, so it drops into a pipeline as a gate.

use std::io::Read;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use pie::{Scanner, Severity, SignatureSet, Verdict};

#[derive(Parser)]
#[command(
    name = "pie",
    about = "Detect prompt-injection, jailbreak, and exfiltration patterns in LLM text",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan an input (a file path, or '-' for stdin).
    Scan {
        /// Path to scan, or '-' for stdin.
        input: String,

        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Block threshold: exit non-zero if any detection meets/exceeds this.
        #[arg(long, value_enum, default_value_t = SevArg::High)]
        threshold: SevArg,

        /// Additional signature pack(s), layered on top of the default. Repeatable.
        #[arg(long)]
        signatures: Vec<String>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Copy, Clone, ValueEnum)]
enum SevArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SevArg> for Severity {
    fn from(s: SevArg) -> Self {
        match s {
            SevArg::Info => Severity::Info,
            SevArg::Low => Severity::Low,
            SevArg::Medium => Severity::Medium,
            SevArg::High => Severity::High,
            SevArg::Critical => Severity::Critical,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(blocked) => {
            if blocked {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool> {
    let cli = Cli::parse();
    let Command::Scan {
        input,
        format,
        threshold,
        signatures,
    } = cli.command;

    // Default pack first, then layer any custom packs.
    let mut set = SignatureSet::default_pack().context("loading default signature pack")?;
    for path in &signatures {
        let extra =
            SignatureSet::from_path(path).with_context(|| format!("loading pack {path}"))?;
        set.extend(extra);
    }
    let scanner = Scanner::from_signature_set(set).context("building scanner")?;

    let text = read_input(&input).context("reading input")?;
    let verdict = scanner.scan(&text);
    let threshold: Severity = threshold.into();

    match format {
        Format::Text => print_text(&verdict, threshold),
        Format::Json => print_json(&verdict, threshold)?,
    }

    Ok(verdict.blocked(threshold))
}

fn read_input(input: &str) -> Result<String> {
    if input == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read_to_string(input)?)
    }
}

fn print_text(verdict: &Verdict, threshold: Severity) {
    if verdict.is_clean() {
        println!("CLEAN — no detections");
        return;
    }
    let blocked = verdict.blocked(threshold);
    println!(
        "{} — {} detection(s), max severity {:?}",
        if blocked { "BLOCKED" } else { "FLAGGED" },
        verdict.detections.len(),
        verdict.max_severity().unwrap()
    );
    for d in &verdict.detections {
        let tags = [d.owasp.as_deref(), d.atlas.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" / ");
        let smuggled = if d.via_encoding {
            " [via-encoding]"
        } else {
            ""
        };
        println!(
            "  [{:?}] {}::{}{}  {}\n        {}",
            d.severity, d.detector, d.signature_id, smuggled, tags, d.excerpt
        );
    }
}

fn print_json(verdict: &Verdict, threshold: Severity) -> Result<()> {
    // Wrap the verdict with the block decision so consumers don't re-derive it.
    let out = serde_json::json!({
        "clean": verdict.is_clean(),
        "blocked": verdict.blocked(threshold),
        "max_severity": verdict.max_severity(),
        "detections": verdict.detections,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
