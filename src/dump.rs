//! Format decoded values for display (dump text, tree view). Uses resolved protocol for quantum/units and enum names.

use crate::ast::ResolvedProtocol;
use crate::value::Value;

/// Parse quantum string (e.g. "1/256 NM", "360/65536 °") into (scale, unit).
pub fn parse_quantum(quantum_str: &str) -> Option<(f64, String)> {
    let s = quantum_str.trim();
    let (scale_str, unit) = match s.find(' ') {
        Some(i) => (s[..i].trim(), s[i + 1..].trim().to_string()),
        None => (s, String::new()),
    };
    let scale = parse_scale_expr(scale_str)?;
    Some((scale, unit))
}

fn parse_scale_expr(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Some(slash) = s.find('/') {
        let num_str = s[..slash].trim();
        let denom_str = s[slash + 1..].trim();
        let num: f64 = num_str.parse().ok()?;
        let denom: f64 = if let Some(exp_str) = denom_str.strip_prefix("2^") {
            let exp_str = exp_str.trim_matches(|c| c == '(' || c == ')');
            let exp: i32 = exp_str.parse().ok()?;
            if exp >= 0 {
                (1u64 << exp) as f64
            } else {
                1.0 / (1u64 << (-exp) as u32) as f64
            }
        } else {
            denom_str.parse().ok()?
        };
        return Some(num / denom);
    }
    if let Some(exp_str) = s.strip_prefix("2^") {
        let exp_str = exp_str.trim_matches(|c| c == '(' || c == ')');
        let exp: i32 = exp_str.parse().ok()?;
        return Some(if exp >= 0 {
            (1u64 << exp) as f64
        } else {
            1.0 / (1u64 << (-exp) as u32) as f64
        });
    }
    s.parse::<f64>().ok()
}

/// Format seconds since midnight as HH:MM:SS.
pub fn format_seconds_as_tod(seconds: f64) -> String {
    if seconds < 0.0 || !seconds.is_finite() {
        return format!("{}", seconds);
    }
    let secs = seconds % 86400.0;
    let h = (secs / 3600.0) as u32;
    let m = ((secs % 3600.0) / 60.0) as u32;
    let s_frac = secs % 60.0;
    let s = s_frac as u32;
    let frac = s_frac - (s as f64);
    if frac.abs() > 1e-6 {
        format!("{:02}:{:02}:{:02}.{:03}", h, m, s, (frac * 1000.0) as u32)
    } else {
        format!("{:02}:{:02}:{:02}", h, m, s)
    }
}

/// Format a scalar with optional quantum; TOD (seconds >= 3600) as HH:MM:SS.
pub fn format_scalar_with_quantum(v: &Value, quantum: Option<&str>) -> String {
    let (scale, unit) = match quantum.and_then(parse_quantum) {
        Some((s, u)) => (s, u),
        None => return format_scalar_raw(v),
    };
    let raw = match v {
        Value::U8(x) => *x as f64,
        Value::U16(x) => *x as f64,
        Value::U32(x) => *x as f64,
        Value::U64(x) => *x as f64,
        Value::I8(x) => *x as f64,
        Value::I16(x) => *x as f64,
        Value::I32(x) => *x as f64,
        Value::I64(x) => *x as f64,
        Value::Float(x) => *x as f64,
        Value::Double(x) => *x,
        _ => return format_scalar_raw(v),
    };
    let physical = raw * scale;
    let is_tod_seconds = (unit.eq_ignore_ascii_case("s") || unit.eq_ignore_ascii_case("sec"))
        && physical >= 3600.0
        && physical < 86400.0 * 2.0;
    if is_tod_seconds && physical >= 0.0 {
        format!("{} ({})", format_seconds_as_tod(physical), format_scalar_raw(v))
    } else if unit.is_empty() {
        format!("{} ({})", physical, format_scalar_raw(v))
    } else {
        format!("{} {} ({})", physical, unit, format_scalar_raw(v))
    }
}

/// Raw scalar string (no quantum).
pub fn format_scalar_raw(v: &Value) -> String {
    match v {
        Value::U8(x) => format!("{}", x),
        Value::U16(x) => format!("{}", x),
        Value::U32(x) => format!("{}", x),
        Value::U64(x) => format!("{}", x),
        Value::I8(x) => format!("{}", x),
        Value::I16(x) => format!("{}", x),
        Value::I32(x) => format!("{}", x),
        Value::I64(x) => format!("{}", x),
        Value::Bool(x) => format!("{}", x),
        Value::Float(x) => format!("{}", x),
        Value::Double(x) => format!("{}", x),
        _ => format!("{:?}", v),
    }
}

fn hex_string(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" ")
}

/// Format a value for display (one-line summary for tree leaf, or multi-line for dump).
pub fn value_to_dump(
    resolved: &ResolvedProtocol,
    container_name: &str,
    field_name: &str,
    v: &Value,
    indent: usize,
) -> String {
    let pad = "  ".repeat(indent);
    match v {
        Value::U8(_) | Value::U16(_) | Value::U32(_) | Value::U64(_)
        | Value::I8(_) | Value::I16(_) | Value::I32(_) | Value::I64(_)
        | Value::Bool(_) | Value::Float(_) | Value::Double(_) => {
            let val_i64 = v.as_i64();
            if let Some(n) = val_i64 {
                if resolved.get_enum(container_name).is_some() {
                    if let Some(name) = resolved.enum_variant_name_for_type_and_value(
                        &crate::TypeSpec::StructRef(container_name.to_string()),
                        n,
                    ) {
                        return format!("{}{}", pad, name);
                    }
                }
                if let Some(ts) = resolved.field_type_spec(container_name, field_name) {
                    let ts_for_enum = match ts {
                        crate::TypeSpec::Optional(inner) => inner.as_ref(),
                        _ => ts,
                    };
                    if let Some(name) = resolved.enum_variant_name_for_type_and_value(ts_for_enum, n) {
                        return format!("{}{}", pad, name);
                    }
                }
                if let Some(c) = resolved.field_constraint(container_name, field_name) {
                    if let Some(name) = resolved.enum_variant_name_for_value(c, n) {
                        return format!("{}{}", pad, name);
                    }
                }
            }
            let (quantum, _) = resolved.field_quantum_and_child(container_name, field_name);
            format!("{}{}", pad, format_scalar_with_quantum(v, quantum))
        }
        Value::Bytes(b) => format!("{}hex({})", pad, hex_string(b)),
        Value::Struct(m) => {
            let (_, child_container) = resolved.field_quantum_and_child(container_name, field_name);
            let container = child_container.unwrap_or(container_name);
            let mut lines: Vec<String> = vec![format!("{}struct {{", pad)];
            let mut keys: Vec<_> = m.keys().collect();
            keys.sort();
            for k in keys {
                let val = m.get(k).unwrap();
                if let Value::List(lst) = val {
                    if lst.is_empty() {
                        continue;
                    }
                }
                let sub = value_to_dump(resolved, container, k, val, indent + 1);
                lines.push(format!("  {}: {}", k, sub.trim_start()));
            }
            lines.push(format!("{}}}", pad));
            lines.join("\n")
        }
        Value::List(lst) => {
            let (_, child_container) = resolved.field_quantum_and_child(container_name, field_name);
            let elem_container = child_container.unwrap_or(container_name);
            if lst.is_empty() {
                format!("{}[]", pad)
            } else if lst.len() == 1 {
                value_to_dump(resolved, elem_container, field_name, &lst[0], indent)
            } else {
                let mut lines: Vec<String> = vec![format!("{}[", pad)];
                for (i, item) in lst.iter().enumerate() {
                    let sub = value_to_dump(resolved, elem_container, &format!("[{}]", i), item, indent + 1);
                    lines.push(format!("  [{}] {}", i, sub.trim_start()));
                }
                lines.push(format!("{}]", pad));
                lines.join("\n")
            }
        }
        Value::Padding => format!("{}<padding>", pad),
    }
}

/// First line of value_to_dump (for tree node summary).
pub fn value_summary_line(
    resolved: &ResolvedProtocol,
    container_name: &str,
    field_name: &str,
    v: &Value,
) -> String {
    let full = value_to_dump(resolved, container_name, field_name, v, 0);
    full.lines().next().map(|s| s.trim().to_string()).unwrap_or_default()
}
