//! Lint DSL source files: one tab per depth, one field per line, no trailing whitespace, etc.
//!
//! Usage:
//!   lint_dsl [OPTIONS] [FILE.dsl ...]
//!   lint_dsl < file.dsl
//!
//! When given file(s), the linter always rewrites them to satisfy lint rules (fix), then reports
//! any remaining issues. So running the linter on a file both fixes its output and lints it.
//!
//! Options:
//!   --fix, -f    With stdin: print fixed source to stdout. With files: same (fix + lint).
//!   --human, -H  Human-readable output
//!
//! If no files are given, reads from stdin (lint only unless --fix).

use aiprotodsl::lint::{lint, lint_fix, LintMessage, LintRule, Severity};
use std::io::{self, Read, Write};
use std::path::Path;

fn rule_id(rule: LintRule) -> &'static str {
    match rule {
        LintRule::IndentationTabsOnly => "indentation-tabs-only",
        LintRule::IndentationDepth => "indentation-depth",
        LintRule::OneFieldPerLine => "one-field-per-line",
        LintRule::ClosingBraceAlone => "closing-brace-alone",
        LintRule::NoTrailingWhitespace => "no-trailing-whitespace",
    }
}

fn print_message(path: &str, m: &LintMessage, style: OutputStyle) {
    let severity_str = match m.severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    };
    match style {
        OutputStyle::Compact => {
            println!(
                "{}:{}:{}: {}: {} [{}]",
                path,
                m.line,
                m.column,
                severity_str,
                m.message,
                rule_id(m.rule)
            );
        }
        OutputStyle::Human => {
            println!(
                "  {} {}:{}: {}",
                path,
                m.line,
                m.column,
                m.message
            );
            println!("    rule: {}", rule_id(m.rule));
        }
    }
}

#[derive(Clone, Copy)]
enum OutputStyle {
    Compact,
    Human,
}

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let fix = if let Some(pos) = args.iter().position(|a| a == "--fix" || a == "-f") {
        args.remove(pos);
        true
    } else {
        false
    };
    let style = if let Some(pos) = args.iter().position(|a| a == "--human" || a == "-H") {
        args.remove(pos);
        OutputStyle::Human
    } else {
        OutputStyle::Compact
    };

    let mut has_error = false;
    let mut total_warnings = 0usize;
    let mut total_errors = 0usize;

    if args.is_empty() {
        let mut src = String::new();
        io::stdin().read_to_string(&mut src)?;
        let src = if fix { lint_fix(&src) } else { src };
        if fix {
            io::stdout().write_all(src.as_bytes())?;
            return Ok(());
        }
        let messages = lint(&src);
        for m in &messages {
            match m.severity {
                Severity::Error => total_errors += 1,
                Severity::Warning => total_warnings += 1,
            }
            print_message("<stdin>", m, style);
        }
        if messages.iter().any(|m| m.severity == Severity::Error) {
            has_error = true;
        }
    } else {
        for path in &args {
            let path = Path::new(path);
            let src = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}: {}", path.display(), e);
                    has_error = true;
                    continue;
                }
            };
            let fixed = lint_fix(&src);
            let did_fix = fixed != src;
            if did_fix {
                if let Err(e) = std::fs::write(path, &fixed) {
                    eprintln!("{}: write failed: {}", path.display(), e);
                    has_error = true;
                    continue;
                }
            }
            let messages = lint(&fixed);
            let display_path = path.display().to_string();
            if did_fix && messages.is_empty() {
                eprintln!("{}: fixed", display_path);
            }
            for m in &messages {
                match m.severity {
                    Severity::Error => total_errors += 1,
                    Severity::Warning => total_warnings += 1,
                }
                print_message(&display_path, m, style);
            }
            if messages.iter().any(|m| m.severity == Severity::Error) {
                has_error = true;
            }
        }
    }

    if total_errors > 0 || total_warnings > 0 {
        eprintln!(
            "lint: {} error(s), {} warning(s)",
            total_errors, total_warnings
        );
    }
    if has_error {
        std::process::exit(1);
    }
    Ok(())
}
