//! Linter for the protocol DSL: enforces style rules.
//!
//! ## Rules
//!
//! - **Indentation**: Use exactly one tab per depth level (no spaces). Depth increases after `{`, decreases after `}`.
//! - **One field per line**: At most one field/statement per line (at most one `;` per line).
//! - **Closing brace alone**: A line containing `}` must not also contain a field (`;`).
//! - **No trailing whitespace**: Lines must not have trailing spaces or tabs.
//!
//! Run the linter via the `lint_dsl` binary: `cargo run --bin lint_dsl -- examples/file.dsl`
//! or pipe: `lint_dsl < file.dsl`. Exit code 1 if any error-level findings.

/// Severity of a lint finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// Identifies which rule produced the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintRule {
    /// Indentation must use tabs only (no spaces).
    IndentationTabsOnly,
    /// Indentation must be exactly N tabs at depth N.
    IndentationDepth,
    /// At most one field/statement per line (one `;` terminator per line).
    OneFieldPerLine,
    /// Closing `}` should be the only non-whitespace on its line.
    ClosingBraceAlone,
    /// Trailing whitespace is not allowed.
    NoTrailingWhitespace,
}

/// A single lint message with location.
#[derive(Debug, Clone)]
pub struct LintMessage {
    pub line: usize,
    pub column: usize,
    pub rule: LintRule,
    pub severity: Severity,
    pub message: String,
}

/// Run all lint rules on DSL source. Returns messages in line order.
pub fn lint(source: &str) -> Vec<LintMessage> {
    let mut out = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut depth: i32 = 0;

    for (i, line) in lines.iter().enumerate() {
        let line_no = i + 1;

        // Trailing whitespace
        if *line != line.trim_end() {
            out.push(LintMessage {
                line: line_no,
                column: line.len().saturating_sub(line.trim_end().len()).max(1),
                rule: LintRule::NoTrailingWhitespace,
                severity: Severity::Warning,
                message: "trailing whitespace not allowed".to_string(),
            });
        }

        let trimmed = line.trim_start();
        let leading = &line[..line.len().saturating_sub(trimmed.len())];

        // Tabs only for indentation
        if leading.contains(' ') && !leading.is_empty() {
            out.push(LintMessage {
                line: line_no,
                column: 1,
                rule: LintRule::IndentationTabsOnly,
                severity: Severity::Error,
                message: "indentation must use tabs only (no spaces)".to_string(),
            });
        }

        // Depth: content lines (non-empty after trim) must have exactly `depth` tabs
        if !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with("/*") {
            let tab_count = leading.chars().filter(|&c| c == '\t').count();
            let expected = depth.max(0) as usize;
            if tab_count != expected {
                out.push(LintMessage {
                    line: line_no,
                    column: 1,
                    rule: LintRule::IndentationDepth,
                    severity: Severity::Error,
                    message: format!(
                        "expected {} tab(s) at depth {} (found {})",
                        expected, depth, tab_count
                    ),
                });
            }
        }

        // One field per line: at most one semicolon that terminates a field/statement
        let content_no_line_comment = if let Some(comment) = trimmed.find("//") {
            trimmed[..comment].trim_end()
        } else {
            trimmed
        };
        let semicolon_count = content_no_line_comment.matches(';').count();
        if semicolon_count > 1 {
            out.push(LintMessage {
                line: line_no,
                column: 1,
                rule: LintRule::OneFieldPerLine,
                severity: Severity::Error,
                message: format!(
                    "one field per line (found {} semicolons)",
                    semicolon_count
                ),
            });
        }

        // Closing brace alone: line containing `}` should not also contain a field (`;`)
        if content_no_line_comment.contains('}') && content_no_line_comment.contains(';') {
            out.push(LintMessage {
                line: line_no,
                column: 1,
                rule: LintRule::ClosingBraceAlone,
                severity: Severity::Warning,
                message: "closing `}` should be the only content on its line".to_string(),
            });
        }

        // Update depth for next line (naive: count all braces, no string/comment awareness)
        for c in content_no_line_comment.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
    }

    out
}

/// Fix DSL source to satisfy lint rules: tabs for indentation (by depth), one field per line, closing brace alone, no trailing whitespace.
pub fn lint_fix(source: &str) -> String {
    let mut depth: i32 = 0;
    let mut out_lines: Vec<String> = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_end();
        let trimmed_start = trimmed.trim_start();
        let content_no_comment = if let Some(i) = trimmed_start.find("//") {
            trimmed_start[..i].trim_end()
        } else {
            trimmed_start
        };

        // One field per line: split at semicolons
        let n_semicolons = content_no_comment.matches(';').count();
        if n_semicolons > 1 {
            let comment_part = if trimmed_start.contains("//") {
                let i = trimmed_start.find("//").unwrap();
                format!("  {}", trimmed_start[i..].trim_start())
            } else {
                String::new()
            };
            let parts: Vec<&str> = content_no_comment.split(';').collect();
            for (j, part) in parts.iter().enumerate() {
                let s = part.trim();
                if s.is_empty() {
                    continue;
                }
                let indent = "\t".repeat(depth.max(0) as usize);
                let is_last = j == parts.len() - 1 || parts[j + 1..].iter().all(|p| p.trim().is_empty());
                let suffix = if is_last && !comment_part.is_empty() {
                    format!(";{}", comment_part)
                } else {
                    ";".to_string()
                };
                out_lines.push(format!("{}{}{}", indent, s, suffix));
                for c in s.chars() {
                    match c {
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
            }
            continue;
        }

        // Closing brace and semicolon on same line: put } on its own line
        if content_no_comment.contains('}') && content_no_comment.contains(';') {
            let indent = "\t".repeat(depth.max(0) as usize);
            if let Some(close) = content_no_comment.find('}') {
                let before = content_no_comment[..close].trim();
                let after = content_no_comment[close..].trim();
                if !before.is_empty() {
                    out_lines.push(format!("{}{};", indent, before));
                }
                out_lines.push(format!("{}{}", indent, after));
                for c in content_no_comment.chars() {
                    match c {
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                continue;
            }
        }

        let expected_tabs = depth.max(0) as usize;
        let indent = "\t".repeat(expected_tabs);
        let content = if trimmed.is_empty() || trimmed_start.is_empty() {
            String::new()
        } else {
            format!("{}{}", indent, content_no_comment)
        };
        out_lines.push(content);
        for c in content_no_comment.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
    }
    out_lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_tabs_only() {
        let src = "transport {\n  x: u8;\n}";
        let msgs = lint(src);
        let tabs_only: Vec<_> = msgs.iter().filter(|m| m.rule == LintRule::IndentationTabsOnly).collect();
        assert!(!tabs_only.is_empty(), "expected IndentationTabsOnly (spaces used)");
    }

    #[test]
    fn lint_one_field_per_line() {
        let src = "message M {\n\tx: u8; y: u8;\n}";
        let msgs = lint(src);
        let one_field: Vec<_> = msgs.iter().filter(|m| m.rule == LintRule::OneFieldPerLine).collect();
        assert!(!one_field.is_empty(), "expected OneFieldPerLine");
    }

    #[test]
    fn lint_clean_tabs_passes() {
        let src = "transport {\n\tx: u8;\n\t}\n";
        let msgs = lint(src);
        let errors: Vec<_> = msgs.iter().filter(|m| m.severity == Severity::Error).collect();
        assert!(errors.is_empty(), "clean tab-indented source should have no errors: {:?}", msgs);
    }
}
