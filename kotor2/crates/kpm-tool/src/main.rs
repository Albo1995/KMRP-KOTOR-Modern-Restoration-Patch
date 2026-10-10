use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use kpm_tool::{find, pack, parse_va, pe::Image, sources, verify};

/// Offline tools for KOTOR Patch Manager patches (32-bit Windows PE).
#[derive(Parser)]
#[command(name = "kpm-tool", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check hooks against an executable: SHA-256 vs target_versions, each
    /// site's original_bytes, instruction boundaries, position-dependent
    /// stolen bytes, KPM's hook rules, and overlaps across all inputs.
    /// Exit status 0 = pass, 1 = a check failed, 2 = could not run.
    Verify {
        /// The game executable (e.g. swkotor2.exe). Only read.
        #[arg(long)]
        exe: PathBuf,
        /// A *hooks.toml, a patch_config.toml, or a .kpatch; repeatable.
        #[arg(long = "hooks", required = true)]
        hooks: Vec<PathBuf>,
        /// Overlaps inside one file are warnings, not failures (for source
        /// tables such as KMRP's kotor1.hooks.toml that hold alternatives).
        #[arg(long)]
        allow_overlap_in_file: bool,
        /// Print every finding, including passes and skipped .kpatch members.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Disassemble instructions at a virtual address.
    Disasm {
        #[arg(long)]
        exe: PathBuf,
        /// Hexadecimal VA, e.g. 0x00401234.
        #[arg(long, value_parser = parse_va)]
        va: u64,
        #[arg(long, default_value_t = 20)]
        count: usize,
    },
    /// Search section bytes for a pattern with ?? wildcards; reports VAs.
    Find {
        #[arg(long)]
        exe: PathBuf,
        /// e.g. "8B 44 24 ?? 85 C0"
        #[arg(long)]
        pattern: String,
        /// Only this section (e.g. .text).
        #[arg(long)]
        section: Option<String>,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// Build a .kpatch as KPM's Patches/create-patch.py lays one out.
    Pack {
        #[arg(long)]
        manifest: PathBuf,
        /// One or more files named *hooks.toml; repeatable.
        #[arg(long = "hooks", required = true)]
        hooks: Vec<PathBuf>,
        /// The module, packed as binaries/windows_x86.dll.
        #[arg(long)]
        dll: Option<PathBuf>,
        /// Extra files for binaries/; repeatable.
        #[arg(long = "binary")]
        binaries: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print an executable's size, SHA-256 and, if KPM knows it, its build.
    Hash {
        #[arg(long)]
        exe: PathBuf,
    },
}

fn read(path: &PathBuf) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Verify {
            exe,
            hooks,
            allow_overlap_in_file,
            verbose,
        } => {
            let mut sets = Vec::new();
            for h in &hooks {
                sets.extend(sources::load(h)?);
            }
            let report = verify::verify(
                &exe.display().to_string(),
                read(&exe)?,
                &sets,
                &verify::Options {
                    allow_overlap_in_file,
                },
            )?;
            print!("{}", report.render(verbose));
            Ok(if report.failed() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::Disasm { exe, va, count } => {
            let image = Image::parse(read(&exe)?)?;
            print!("{}", find::disasm(&image, va, count)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Find {
            exe,
            pattern,
            section,
            max,
        } => {
            let image = Image::parse(read(&exe)?)?;
            let pattern = find::parse_pattern(&pattern)?;
            let hits = find::find(&image, &pattern, section.as_deref(), max);
            print!("{}", find::render_find(&image, &pattern, &hits, max));
            Ok(if hits.is_empty() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::Pack {
            manifest,
            hooks,
            dll,
            binaries,
            out,
        } => {
            let summary = pack::pack(&pack::PackInput {
                manifest,
                hooks,
                dll,
                extra_binaries: binaries,
                out,
            })?;
            for w in &summary.warnings {
                println!("warning: {w}");
            }
            for e in &summary.entries {
                println!("  {e}");
            }
            println!(
                "wrote {} ({} bytes, SHA-256 {}), {} detour hook(s)",
                summary.out.display(),
                summary.bytes,
                summary.sha256,
                summary.detours
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Hash { exe } => {
            let bytes = read(&exe)?;
            let sha = kpm_sdk::process::hex_upper(&kpm_sdk::process::sha256(&bytes));
            println!("{}  {} bytes  {}", sha, bytes.len(), exe.display());
            match kpm_tool::known::lookup(&sha) {
                Some(k) => println!("KPM build: {} ({})", k.key, k.description),
                None => println!("not a build KPM's address databases list"),
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}
