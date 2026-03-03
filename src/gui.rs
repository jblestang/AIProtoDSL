//! GUI app for the decode_pcap_gui binary. Load PCAP + DSL and display decoded records in a tree view with @doc tooltips.

#![cfg(feature = "gui")]

use eframe::egui::{self, Widget};
use pcap_parser::Linktype;

pub struct DecodedRecord {
    pub packet_index: u64,
    pub block_offset: usize,
    pub category: u8,
    pub message_name: String,
    pub values: std::collections::HashMap<String, crate::Value>,
    /// Raw ASTERIX data block bytes (cat + len + body).
    pub raw_bytes: Vec<u8>,
    /// Per-field byte spans: (field_name, start, end) relative to body start (offset 3 in raw_bytes).
    pub field_spans: Vec<(String, usize, usize)>,
}

/// Load from in-memory PCAP bytes and DSL text. Used by load_pcap_and_dsl.
fn load_pcap_and_dsl_from_memory(
    pcap_bytes: &[u8],
    dsl_text: &str,
) -> Result<(Vec<DecodedRecord>, crate::ResolvedProtocol), Box<dyn std::error::Error + Send + Sync>> {
    use crate::{parse, Codec, Endianness, ResolvedProtocol};
    use pcap_parser::pcapng::Block as PcapNgBlock;
    use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
    use pcap_parser::{PcapBlockOwned, PcapError};
    use std::io::Read;

    let protocol = parse(dsl_text).map_err(|e| format!("DSL parse: {}", e))?;
    let resolved = ResolvedProtocol::resolve(protocol).map_err(|e| format!("Resolve: {}", e))?;
    let codec = Codec::new(resolved.clone(), Endianness::Big);

    let mut records = Vec::new();
    let mut cursor = std::io::Cursor::new(pcap_bytes);
    let mut probe = [0u8; 4];
    cursor.read_exact(&mut probe)?;
    let is_pcapng = probe == [0x0a, 0x0d, 0x0d, 0x0a];

    let mut pkt_count: u64 = 0;
    let mut linktype = Linktype(1);
    let mut if_linktypes: Vec<Linktype> = vec![];

    if is_pcapng {
        let mut reader = pcap_parser::pcapng::PcapNGReader::new(1 << 20, std::io::Cursor::new(pcap_bytes))
            .map_err(|e| format!("PcapNGReader: {:?}", e))?;
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    if let PcapBlockOwned::NG(b) = block {
                        match &b {
                            PcapNgBlock::InterfaceDescription(idb) => if_linktypes.push(idb.linktype),
                            PcapNgBlock::EnhancedPacket(epb) => {
                                pkt_count += 1;
                                let lt = if_linktypes.get(epb.if_id as usize).copied().unwrap_or(Linktype(1));
                                let frame = epb.packet_data();
                                if let Some(udp_payload) = udp_payload_from_linktype(lt, frame) {
                                    process_udp(&codec, &resolved, udp_payload, pkt_count, &mut records);
                                }
                            }
                            PcapNgBlock::SimplePacket(spb) => {
                                pkt_count += 1;
                                let lt = if_linktypes.first().copied().unwrap_or(Linktype(1));
                                let frame = spb.packet_data();
                                if let Some(udp_payload) = udp_payload_from_linktype(lt, frame) {
                                    process_udp(&codec, &resolved, udp_payload, pkt_count, &mut records);
                                }
                            }
                            _ => {}
                        }
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => reader.refill().map_err(|e| format!("refill: {:?}", e))?,
                Err(e) => return Err(format!("pcapng: {:?}", e).into()),
            }
        }
    } else {
        let mut reader = pcap_parser::pcap::LegacyPcapReader::new(1 << 20, std::io::Cursor::new(pcap_bytes))
            .map_err(|e| format!("LegacyPcapReader: {:?}", e))?;
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(h) => linktype = h.network,
                        PcapBlockOwned::Legacy(b) => {
                            pkt_count += 1;
                            let lt = linktype;
                            if let Some(udp_payload) = udp_payload_from_linktype(lt, b.data) {
                                process_udp(&codec, &resolved, udp_payload, pkt_count, &mut records);
                            }
                        }
                        _ => {}
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => reader.refill().map_err(|e| format!("refill: {:?}", e))?,
                Err(e) => return Err(format!("pcap: {:?}", e).into()),
            }
        }
    }

    Ok((records, resolved))
}

pub fn load_pcap_and_dsl(
    pcap_path: &str,
    dsl_path: &str,
) -> Result<(Vec<DecodedRecord>, crate::ResolvedProtocol), Box<dyn std::error::Error + Send + Sync>> {
    let pcap_bytes = std::fs::read(pcap_path)?;
    let dsl_text = std::fs::read_to_string(dsl_path)?;
    load_pcap_and_dsl_from_memory(&pcap_bytes, &dsl_text)
}

fn process_udp(
    codec: &crate::Codec,
    resolved: &crate::ResolvedProtocol,
    udp_payload: &[u8],
    packet_index: u64,
    records: &mut Vec<DecodedRecord>,
) {
    let mut off = 0usize;
    while off + 3 <= udp_payload.len() {
        let cat = udp_payload[off];
        let block_len = u16::from_be_bytes([udp_payload[off + 1], udp_payload[off + 2]]) as usize;
        if block_len < 3 || off + block_len > udp_payload.len() {
            break;
        }
        let block = &udp_payload[off..off + block_len];
        let raw_bytes = block.to_vec();
        let body = &block[3..];
        if let Ok(transport_values) = codec.decode_transport(block) {
            if let Some(msg_name) = resolved.message_for_transport_values(&transport_values) {
                let mut body_off = 0usize;
                while body_off < body.len() {
                    let (consumed, result) = codec.decode_message_with_spans(msg_name, &body[body_off..]);
                    if consumed == 0 {
                        break;
                    }
                    if let Ok((values, mut spans)) = result {
                        for s in &mut spans {
                            s.1 += body_off;
                            s.2 += body_off;
                        }
                        records.push(DecodedRecord {
                            packet_index,
                            block_offset: off,
                            category: cat,
                            message_name: msg_name.to_string(),
                            values,
                            raw_bytes: raw_bytes.clone(),
                            field_spans: spans,
                        });
                    }
                    body_off += consumed;
                }
            }
        }
        off += block_len;
    }
}

fn udp_payload_from_linktype(linktype: Linktype, frame: &[u8]) -> Option<&[u8]> {
    let l3 = match linktype.0 {
        1 => ethernet_l3(frame)?,
        101 => frame,
        113 => linux_sll_l3(frame)?,
        _ => return None,
    };
    ipv4_udp_payload(l3)
}

fn ethernet_l3(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let mut off = 12usize;
    let mut ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
    off += 2;
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if frame.len() < off + 6 {
            return None;
        }
        off += 4;
        ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
        off += 2;
    }
    match ethertype {
        0x0800 => Some(&frame[off..]),
        _ => None,
    }
}

fn linux_sll_l3(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 16 {
        return None;
    }
    let proto = u16::from_be_bytes([frame[14], frame[15]]);
    match proto {
        0x0800 => Some(&frame[16..]),
        _ => None,
    }
}

fn ipv4_udp_payload(l3: &[u8]) -> Option<&[u8]> {
    if l3.len() < 20 {
        return None;
    }
    let ver_ihl = l3[0];
    let version = ver_ihl >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0f) as usize * 4;
    if ihl < 20 || l3.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([l3[2], l3[3]]) as usize;
    if total_len < ihl {
        return None;
    }
    let l3_trunc = if total_len <= l3.len() { &l3[..total_len] } else { l3 };
    if l3_trunc.len() < ihl + 8 {
        return None;
    }
    if l3_trunc[9] != 17 {
        return None;
    }
    let udp = &l3_trunc[ihl..];
    if udp.len() < 8 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    Some(&udp[8..udp_len])
}

// --- Display filter (Wireshark-style) ---
// Supports: AND, OR, NOT, parentheses, comparison operators (== != < <= > >=),
// .length suffix, array item access (field[0].sub), message-name contains fallback.

/// Filter expression AST.
#[derive(Debug, Clone)]
enum FilterExpr {
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
    Comparison { path: String, op: String, value: String },
    Contains(String),
}

/// Token types for the filter lexer.
#[derive(Debug, Clone, PartialEq)]
enum FilterToken {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Atom(String),
}

/// Tokenize a filter string into tokens.
fn filter_tokenize(input: &str) -> Vec<FilterToken> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        match chars[i] {
            ' ' | '\t' => { i += 1; }
            '(' => { tokens.push(FilterToken::LParen); i += 1; }
            ')' => { tokens.push(FilterToken::RParen); i += 1; }
            _ => {
                let start = i;
                while i < len && chars[i] != ' ' && chars[i] != '\t' && chars[i] != '(' && chars[i] != ')' {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let upper = word.to_uppercase();
                match upper.as_str() {
                    "AND" | "&&" => tokens.push(FilterToken::And),
                    "OR" | "||" => tokens.push(FilterToken::Or),
                    "NOT" | "!" => tokens.push(FilterToken::Not),
                    _ => tokens.push(FilterToken::Atom(word)),
                }
            }
        }
    }
    tokens
}

/// Parse a single atom (e.g. "category==48" or "Cat048") into a FilterExpr.
fn parse_filter_atom(s: &str) -> FilterExpr {
    let s = s.trim();
    for (op, len) in [("==", 2usize), ("!=", 2), ("<=", 2), (">=", 2), ("<", 1), (">", 1)] {
        if let Some(i) = s.find(op) {
            return FilterExpr::Comparison {
                path: s[..i].trim().to_string(),
                op: op.to_string(),
                value: s[i + len..].trim().to_string(),
            };
        }
    }
    if let Some(i) = s.find('=') {
        return FilterExpr::Comparison {
            path: s[..i].trim().to_string(),
            op: "==".to_string(),
            value: s[i + 1..].trim().to_string(),
        };
    }
    FilterExpr::Contains(s.to_string())
}

/// Recursive-descent parser for filter expressions.
/// Grammar:
///   expr     = or_expr
///   or_expr  = and_expr ( OR and_expr )*
///   and_expr = unary ( AND unary )*
///   unary    = NOT unary | primary
///   primary  = '(' expr ')' | atom
struct FilterParser {
    tokens: Vec<FilterToken>,
    pos: usize,
}

impl FilterParser {
    fn new(tokens: Vec<FilterToken>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&FilterToken> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<FilterToken> {
        let t = self.tokens.get(self.pos)?.clone();
        self.pos += 1;
        Some(t)
    }

    fn parse_expr(&mut self) -> Option<FilterExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Option<FilterExpr> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&FilterToken::Or) {
            self.advance();
            let right = self.parse_and()?;
            left = FilterExpr::Or(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn parse_and(&mut self) -> Option<FilterExpr> {
        let mut left = self.parse_unary()?;
        while self.peek() == Some(&FilterToken::And) {
            self.advance();
            let right = self.parse_unary()?;
            left = FilterExpr::And(Box::new(left), Box::new(right));
        }
        Some(left)
    }

    fn parse_unary(&mut self) -> Option<FilterExpr> {
        if self.peek() == Some(&FilterToken::Not) {
            self.advance();
            let inner = self.parse_unary()?;
            return Some(FilterExpr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Option<FilterExpr> {
        match self.peek()? {
            FilterToken::LParen => {
                self.advance();
                let inner = self.parse_expr()?;
                if self.peek() == Some(&FilterToken::RParen) {
                    self.advance();
                }
                Some(inner)
            }
            FilterToken::Atom(_) => {
                if let Some(FilterToken::Atom(s)) = self.advance() {
                    let atom_expr = parse_filter_atom(&s);
                    if matches!(&atom_expr, FilterExpr::Contains(_)) {
                        if let Some(FilterToken::Atom(op_tok)) = self.peek() {
                            let op_str = op_tok.clone();
                            if is_comparison_op(&op_str) {
                                self.advance(); // consume operator
                                if let Some(FilterToken::Atom(val)) = self.peek() {
                                    let val = val.clone();
                                    self.advance(); // consume value
                                    return Some(FilterExpr::Comparison {
                                        path: s,
                                        op: normalize_op(&op_str),
                                        value: val,
                                    });
                                }
                                return Some(FilterExpr::Comparison {
                                    path: s,
                                    op: normalize_op(&op_str),
                                    value: String::new(),
                                });
                            }
                        }
                    }
                    Some(atom_expr)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn is_comparison_op(s: &str) -> bool {
    matches!(s, "==" | "!=" | "<=" | ">=" | "<" | ">" | "=")
}

fn normalize_op(s: &str) -> String {
    if s == "=" { "==".to_string() } else { s.to_string() }
}

fn parse_filter(input: &str) -> Option<FilterExpr> {
    let tokens = filter_tokenize(input);
    if tokens.is_empty() {
        return None;
    }
    let mut parser = FilterParser::new(tokens);
    parser.parse_expr()
}

/// Evaluate a filter expression against a decoded record.
fn eval_filter(expr: &FilterExpr, record: &DecodedRecord) -> bool {
    match expr {
        FilterExpr::And(l, r) => eval_filter(l, record) && eval_filter(r, record),
        FilterExpr::Or(l, r) => eval_filter(l, record) || eval_filter(r, record),
        FilterExpr::Not(inner) => !eval_filter(inner, record),
        FilterExpr::Comparison { path, op, value } => {
            let rhs = value.trim();
            if path == "category" {
                let cat_val: u8 = rhs.parse().unwrap_or(0);
                return value_compare_u8(record.category, op, cat_val);
            }
            let (base_path, use_length) = if path.ends_with(".length") {
                (path[..path.len() - 7].trim(), true)
            } else {
                (path.as_str(), false)
            };
            if use_length {
                if let Some(val) = value_at_path(&record.values, base_path) {
                    let len = value_length(val);
                    if let Ok(r) = rhs.parse::<usize>() {
                        return value_compare_usize(len, op, r);
                    }
                }
                return op == "!=";
            }
            if let Some(val) = value_at_path(&record.values, base_path) {
                return value_compare(val, op, rhs);
            }
            op == "!="
        }
        FilterExpr::Contains(text) => {
            record.message_name.to_lowercase().contains(&text.to_lowercase())
        }
    }
}

/// Check if a decoded record matches the display filter string.
fn record_matches_filter(record: &DecodedRecord, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let filter = filter.trim();
    if filter.is_empty() {
        return true;
    }
    match parse_filter(filter) {
        Some(expr) => eval_filter(&expr, record),
        None => true,
    }
}

/// Get a value from a map by dot-separated path with optional array index (e.g. "i048_010.sac", "i048_130[2].value").
fn value_at_path<'a>(values: &'a std::collections::HashMap<String, crate::Value>, path: &str) -> Option<&'a crate::Value> {
    let mut parts = path.split('.');
    let first = parts.next()?;
    let (key, idx) = parse_path_segment(first);
    let mut current = values.get(key)?;
    if let Some(i) = idx {
        current = current.as_list()?.get(i)?;
    }
    for part in parts {
        let (key, idx) = parse_path_segment(part);
        current = current.as_struct()?.get(key)?;
        if let Some(i) = idx {
            current = current.as_list()?.get(i)?;
        }
    }
    Some(current)
}

/// Parse a path segment like "field" or "field[3]" into (field_name, optional_index).
fn parse_path_segment(s: &str) -> (&str, Option<usize>) {
    if let Some(bracket) = s.find('[') {
        let name = &s[..bracket];
        let rest = &s[bracket + 1..];
        if let Some(end) = rest.find(']') {
            if let Ok(idx) = rest[..end].parse::<usize>() {
                return (name, Some(idx));
            }
        }
        (name, None)
    } else {
        (s, None)
    }
}

/// Length of a value: list count, bytes len, or string representation len.
fn value_length(v: &crate::Value) -> usize {
    use crate::Value;
    match v {
        Value::List(l) => l.len(),
        Value::Bytes(b) => b.len(),
        Value::Struct(m) => m.len(),
        _ => value_to_string(v).len(),
    }
}

fn value_compare(v: &crate::Value, op: &str, rhs: &str) -> bool {
    match op {
        "==" => value_equals(v, rhs),
        "!=" => !value_equals(v, rhs),
        _ => {
            if let (Some(n), Ok(r)) = (v.as_i64(), rhs.parse::<i64>()) {
                return value_compare_i64(n, op, r);
            }
            if let (Some(n), Ok(r)) = (v.as_u64(), rhs.parse::<u64>()) {
                return value_compare_u64(n, op, r);
            }
            let s = value_to_string(v);
            let cmp = s.cmp(&rhs.to_string());
            value_compare_ordering(cmp, op)
        }
    }
}

fn value_equals(v: &crate::Value, rhs: &str) -> bool {
    if let Some(n) = v.as_u64() {
        if let Ok(r) = rhs.parse::<u64>() {
            return n == r;
        }
    }
    if let Some(n) = v.as_i64() {
        if let Ok(r) = rhs.parse::<i64>() {
            return n == r;
        }
    }
    let s = value_to_string(v);
    s == rhs || s.to_lowercase() == rhs.to_lowercase()
}

fn value_compare_u8(l: u8, op: &str, r: u8) -> bool {
    match op {
        "==" => l == r,
        "!=" => l != r,
        "<" => l < r,
        "<=" => l <= r,
        ">" => l > r,
        ">=" => l >= r,
        _ => false,
    }
}

fn value_compare_usize(l: usize, op: &str, r: usize) -> bool {
    match op {
        "==" => l == r,
        "!=" => l != r,
        "<" => l < r,
        "<=" => l <= r,
        ">" => l > r,
        ">=" => l >= r,
        _ => false,
    }
}

fn value_compare_u64(l: u64, op: &str, r: u64) -> bool {
    match op {
        "==" => l == r,
        "!=" => l != r,
        "<" => l < r,
        "<=" => l <= r,
        ">" => l > r,
        ">=" => l >= r,
        _ => false,
    }
}

fn value_compare_i64(l: i64, op: &str, r: i64) -> bool {
    match op {
        "==" => l == r,
        "!=" => l != r,
        "<" => l < r,
        "<=" => l <= r,
        ">" => l > r,
        ">=" => l >= r,
        _ => false,
    }
}

fn value_compare_ordering(cmp: std::cmp::Ordering, op: &str) -> bool {
    use std::cmp::Ordering;
    match op {
        "==" => cmp == Ordering::Equal,
        "!=" => cmp != Ordering::Equal,
        "<" => cmp == Ordering::Less,
        "<=" => cmp != Ordering::Greater,
        ">" => cmp == Ordering::Greater,
        ">=" => cmp != Ordering::Less,
        _ => false,
    }
}

fn value_to_string(v: &crate::Value) -> String {
    use crate::Value;
    match v {
        Value::U8(x) => x.to_string(),
        Value::U16(x) => x.to_string(),
        Value::U32(x) => x.to_string(),
        Value::U64(x) => x.to_string(),
        Value::I8(x) => x.to_string(),
        Value::I16(x) => x.to_string(),
        Value::I32(x) => x.to_string(),
        Value::I64(x) => x.to_string(),
        Value::Bool(x) => x.to_string(),
        Value::Float(x) => x.to_string(),
        Value::Double(x) => x.to_string(),
        Value::Bytes(b) => format!("{:02x?}", b),
        Value::Struct(m) => format!("struct({} fields)", m.len()),
        Value::List(l) => format!("list({} items)", l.len()),
        Value::Padding => "padding".to_string(),
    }
}

// --- Filter autocompletion ---

const MAX_SUGGESTIONS: usize = 12;

/// Return (segment_start, segment_prefix) for the current word being typed in the filter.
/// Handles AND/OR/NOT keywords and parentheses as clause boundaries.
fn filter_segment(filter: &str) -> (usize, &str) {
    let mut start = 0usize;
    // Clause boundaries: parentheses
    if let Some(i) = filter.rfind('(') {
        start = start.max(i + 1);
    }
    if let Some(i) = filter.rfind(')') {
        start = start.max(i + 1);
    }
    // Within the current clause, find the latest operator/space/dot boundary
    let clause = filter.get(start..).unwrap_or("");
    let clause_off = start;
    let mut local = 0usize;
    for (op, len) in [("==", 2), ("!=", 2), ("<=", 2), (">=", 2)] {
        if let Some(i) = clause.rfind(op) {
            local = local.max(i + len);
        }
    }
    if let Some(i) = clause.rfind(' ') {
        local = local.max(i + 1);
    }
    if let Some(i) = clause.rfind('.') {
        local = local.max(i + 1);
    }
    if let Some(i) = clause.rfind('<') {
        local = local.max(i + 1);
    }
    if let Some(i) = clause.rfind('>') {
        local = local.max(i + 1);
    }
    if let Some(i) = clause.rfind('=') {
        local = local.max(i + 1);
    }
    start = clause_off + local;
    let prefix = filter.get(start..).unwrap_or("");
    // Skip past AND/OR/NOT keywords that happen to be at the prefix
    let upper = prefix.to_uppercase();
    if upper == "AND" || upper == "OR" || upper == "NOT" || upper == "&&" || upper == "||" || upper == "!" {
        return (filter.len(), "");
    }
    (start, prefix)
}

/// Parent path (before the last dot) when completing a subfield, or None.
/// Extracts the last path token from the clause (handles AND/OR/paren boundaries).
fn parent_path_before_dot(filter: &str, segment_start: usize) -> Option<&str> {
    if segment_start == 0 {
        return None;
    }
    let before = filter.get(..segment_start - 1)?; // exclude the dot
    let s = clause_last_word(before);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Resolve container type for a dot path (e.g. "i048_010" -> "DataSourceId" in message Cat048Record).
/// Handles array-index notation in path segments (e.g. "i048_130[0]").
fn resolve_path_container<'a>(resolved: &'a crate::ResolvedProtocol, message_name: &'a str, path: &str) -> Option<&'a str> {
    let mut container = message_name;
    for part in path.split('.') {
        let (field_name, _) = parse_path_segment(part);
        let (_, child) = resolved.field_quantum_and_child(container, field_name);
        container = child?;
    }
    Some(container)
}

/// Collect all top-level field names from all messages in the protocol.
fn all_top_level_field_names(resolved: &crate::ResolvedProtocol) -> Vec<String> {
    let mut set = std::collections::HashSet::new();
    for name in resolved.messages_by_name.keys() {
        if let Some(msg) = resolved.get_message(name) {
            for f in &msg.fields {
                set.insert(f.name.clone());
            }
        }
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v
}

/// Subfield names for a type (from type_def).
fn type_def_field_names(resolved: &crate::ResolvedProtocol, type_name: &str) -> Vec<String> {
    resolved
        .get_type_def(type_name)
        .map(|t| t.fields.iter().map(|f| f.name.clone()).collect())
        .unwrap_or_default()
}

/// If the current segment is the RHS of a comparison (after ==, !=, etc.), return the LHS path.
/// Only looks within the current clause (after the last AND/OR/paren boundary).
fn filter_value_lhs_path(filter: &str, segment_start: usize) -> Option<&str> {
    if segment_start == 0 {
        return None;
    }
    let before = filter[..segment_start].trim_end();
    for (op, len) in [("==", 2), ("!=", 2), ("<=", 2), (">=", 2), ("<", 1), (">", 1)] {
        if before.ends_with(op) {
            let lhs_region = before[..before.len().saturating_sub(len)].trim_end();
            let path = clause_last_word(lhs_region);
            return if path.is_empty() { None } else { Some(path) };
        }
    }
    if before.ends_with('=') {
        let lhs_region = before[..before.len().saturating_sub(1)].trim_end();
        let path = clause_last_word(lhs_region);
        return if path.is_empty() { None } else { Some(path) };
    }
    None
}

/// Extract the last word/path from a string, stopping at clause boundaries (space, paren).
fn clause_last_word(s: &str) -> &str {
    let s = s.trim_end();
    let mut start = 0;
    if let Some(i) = s.rfind(|c: char| c == ' ' || c == '(' || c == ')') {
        start = i + 1;
    }
    s.get(start..).unwrap_or("").trim()
}

/// Resolve path to (container_name, field_name) for constraint/type lookup. Message name required for top-level path.
fn path_to_container_and_field<'a, 'b>(
    resolved: &'a crate::ResolvedProtocol,
    message_name: &'a str,
    path: &'b str,
) -> Option<(&'a str, &'b str)> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    if let Some(dot) = path.rfind('.') {
        let parent = path[..dot].trim();
        let field_name = path[dot + 1..].trim();
        if field_name.is_empty() {
            return None;
        }
        let container = resolve_path_container(resolved, message_name, parent)?;
        Some((container, field_name))
    } else {
        Some((message_name, path))
    }
}

/// Enum/constraint value suggestions for a field (for filter RHS completion).
/// Returns Vec<(display_label, insert_value)>.
fn enum_value_suggestions(
    resolved: &crate::ResolvedProtocol,
    container: &str,
    field_name: &str,
    prefix: &str,
) -> Vec<(String, String)> {
    use crate::ast::Constraint;
    use crate::TypeSpec;
    let mut out: Vec<(String, String)> = Vec::new();
    if let Some(c) = resolved.field_constraint_any(container, field_name) {
        if let Constraint::Enum(literals) = c {
            for lit in literals {
                if let Some(v) = lit.as_i64() {
                    let val_str = v.to_string();
                    let label = resolved
                        .enum_variant_name_for_value(c, v)
                        .map(|name| format!("{} ({})", name, &val_str))
                        .unwrap_or_else(|| val_str.clone());
                    let matches = prefix.is_empty()
                        || label.to_lowercase().starts_with(&prefix.to_lowercase())
                        || val_str.starts_with(prefix);
                    if matches {
                        out.push((label, val_str));
                    }
                }
            }
        }
    }
    if let Some(ts) = resolved.field_type_spec(container, field_name) {
        if let TypeSpec::StructRef(name) = ts {
            if let Some(enum_sec) = resolved.get_enum(name) {
                for (variant_name, lit) in &enum_sec.variants {
                    if let Some(v) = lit.as_i64() {
                        let val_str = v.to_string();
                        let label = format!("{} ({})", variant_name, val_str);
                        if prefix.is_empty()
                            || variant_name.to_lowercase().starts_with(&prefix.to_lowercase())
                            || val_str.starts_with(prefix)
                        {
                            out.push((label, val_str));
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Build completion suggestions for the filter. Returns (segment_start, Vec<(display_label, insert_value)>).
fn filter_completion_suggestions(
    resolved: Option<&crate::ResolvedProtocol>,
    filter: &str,
    first_message_name: Option<&str>,
) -> (usize, Vec<(String, String)>) {
    let (start, prefix) = filter_segment(filter);
    let mut suggestions: Vec<(String, String)> = Vec::new();

    let resolved = match resolved {
        Some(r) => r,
        None => return (start, suggestions),
    };

    let default_message = first_message_name
        .or_else(|| resolved.messages_by_name.keys().next().map(String::as_str));

    // Completing the value (RHS of ==, !=, etc.): suggest enum/constraint values
    if let Some(path) = filter_value_lhs_path(filter, start) {
        if path != "category" {
            if let Some(msg) = default_message {
                if let Some((container, field_name)) = path_to_container_and_field(resolved, msg, path) {
                    let suggestions_enum = enum_value_suggestions(resolved, container, field_name, prefix);
                    if !suggestions_enum.is_empty() {
                        let mut out = suggestions_enum;
                        out.truncate(MAX_SUGGESTIONS);
                        return (start, out);
                    }
                }
            }
        }
    }

    // Completing after a dot: subfield names (insert appends "==" so the user can type a value)
    if start > 0 && filter.as_bytes().get(start.wrapping_sub(1)) == Some(&b'.') {
        let parent = match parent_path_before_dot(filter, start) {
            Some(p) => p,
            None => return (start, suggestions),
        };
        let container = default_message.and_then(|msg| resolve_path_container(resolved, msg, parent));
        if let Some(container) = container {
            let subfields = type_def_field_names(resolved, container);
            for name in subfields {
                if prefix.is_empty() || name.starts_with(prefix) {
                    let insert = format!("{}==", name);
                    suggestions.push((name, insert));
                }
            }
        }
        suggestions.truncate(MAX_SUGGESTIONS);
        return (start, suggestions);
    }

    // After a complete comparison (e.g. "category==48 "): suggest AND / OR / NOT
    let trimmed = filter.trim();
    let ends_with_value = !trimmed.is_empty()
        && !trimmed.ends_with('=') && !trimmed.ends_with('<') && !trimmed.ends_with('>')
        && !trimmed.ends_with('(') && !trimmed.ends_with(')')
        && parse_filter(trimmed).is_some()
        && !matches!(parse_filter(trimmed), Some(FilterExpr::Contains(_)));

    if prefix.is_empty() && ends_with_value {
        for kw in ["AND", "OR", "NOT", "("] {
            suggestions.push((kw.to_string(), format!("{} ", kw)));
        }
        return (start, suggestions);
    }
    if !prefix.is_empty() && ends_with_value {
        let upper = prefix.to_uppercase();
        for kw in ["AND", "OR", "NOT"] {
            if kw.starts_with(&upper) {
                suggestions.push((kw.to_string(), format!("{} ", kw)));
            }
        }
        if !suggestions.is_empty() {
            return (start, suggestions);
        }
    }

    // Top-level: "category" and field names (field names insert with "==" appended)
    let all_fields = all_top_level_field_names(resolved);
    if prefix.is_empty() {
        if !trimmed.ends_with('=') && !trimmed.ends_with('<') && !trimmed.ends_with('>') {
            let s = "category".to_string();
            suggestions.push((s.clone(), format!("{}==", s)));
            for op in ["==", "!=", "<", "<=", ">", ">="] {
                suggestions.push((op.to_string(), op.to_string()));
            }
        }
        for name in all_fields {
            let insert = format!("{}==", name);
            suggestions.push((name, insert));
            if suggestions.len() >= MAX_SUGGESTIONS {
                break;
            }
        }
    } else {
        if "category".starts_with(prefix) {
            let s = "category".to_string();
            suggestions.push((s.clone(), format!("{}==", s)));
        }
        for name in all_fields {
            if name.starts_with(prefix) {
                let insert = format!("{}==", name);
                suggestions.push((name, insert));
                if suggestions.len() >= MAX_SUGGESTIONS {
                    break;
                }
            }
        }
    }

    (start, suggestions)
}

// --- GuiApp ---

pub struct GuiApp {
    pub pcap_path: String,
    pub dsl_path: String,
    /// Display filter (Wireshark-style): e.g. "048", "category==48", "i048_010.sac==1"
    pub filter: String,
    pub records: Vec<DecodedRecord>,
    pub resolved: Option<crate::ResolvedProtocol>,
    pub selected_index: Option<usize>,
    /// Currently selected field name (for hex pane highlight).
    pub selected_field: Option<String>,
    pub load_error: Option<String>,
    pub _default_pcap: String,
    pub _default_dsl: String,
}

impl GuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        for (_key, font_id) in style.text_styles.iter_mut() {
            font_id.size = (font_id.size * 1.35).round().max(16.0);
        }
        cc.egui_ctx.set_style(style);

        let default_pcap = std::path::PathBuf::from("assets/cat_034_048.pcap")
            .canonicalize()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "assets/cat_034_048.pcap".to_string());
        let default_dsl = std::path::PathBuf::from("examples/asterix_family.dsl")
            .canonicalize()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "examples/asterix_family.dsl".to_string());

        GuiApp {
            pcap_path: default_pcap.clone(),
            dsl_path: default_dsl.clone(),
            filter: String::new(),
            records: Vec::new(),
            resolved: None,
            selected_index: None,
            selected_field: None,
            load_error: None,
            _default_pcap: default_pcap,
            _default_dsl: default_dsl,
        }
    }

    pub fn load(&mut self) {
        self.load_error = None;
        self.records.clear();
        self.resolved = None;
        self.selected_index = None;

        match load_pcap_and_dsl(&self.pcap_path, &self.dsl_path) {
            Ok((records, resolved)) => {
                self.records = records;
                self.resolved = Some(resolved);
            }
            Err(e) => self.load_error = Some(e.to_string()),
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui: &mut egui::Ui| {
            ui.horizontal(|ui: &mut egui::Ui| {
                ui.label("PCAP:");
                ui.text_edit_singleline(&mut self.pcap_path);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.pcap_path = p.display().to_string();
                    }
                }
                ui.label("DSL:");
                ui.text_edit_singleline(&mut self.dsl_path);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.dsl_path = p.display().to_string();
                    }
                }
                if ui.button("Load").clicked() {
                    self.load();
                }
            });
            let mut filter_replace: Option<(usize, String)> = None;
            ui.horizontal(|ui: &mut egui::Ui| {
                ui.label("Filter:");
                let resp = egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("e.g. category==48 AND i048_010.sac>=1, field[0].sub!=0")
                    .ui(ui);
                let filter_rect = resp.rect;
                let filter_has_focus = resp.has_focus();
                resp.on_hover_text("AND / OR / NOT, parentheses, field[n] array access, .length suffix, == != < <= > >=");
                if ui.button("Clear").clicked() {
                    self.filter.clear();
                }
                // Autocomplete popup for filter only when editing the filter (has focus)
                let (segment_start, suggestions) = if filter_has_focus {
                    let first_message = self.records.first().map(|r| r.message_name.as_str());
                    filter_completion_suggestions(
                        self.resolved.as_ref(),
                        &self.filter,
                        first_message,
                    )
                } else {
                    (0, Vec::new())
                };
                if filter_has_focus && !suggestions.is_empty() {
                    let filter_id = egui::Id::new("filter_completion");
                    let pos = filter_rect.left_bottom() + egui::vec2(0.0, 2.0);
                    egui::Area::new(filter_id)
                        .order(egui::Order::Tooltip)
                        .fixed_pos(pos)
                        .show(ui.ctx(), |ui| {
                            egui::Frame::popup(ui.style()).show(ui, |ui| {
                                ui.set_max_width(280.0);
                                for (display, insert) in &suggestions {
                                    let label = if ["==", "!=", "<", "<=", ">", ">="].contains(&display.as_str()) {
                                        format!("  {}  ", display)
                                    } else {
                                        display.clone()
                                    };
                                    if ui.small_button(&label).clicked() {
                                        filter_replace = Some((segment_start, insert.clone()));
                                    }
                                }
                            });
                        });
                }
            });
            if let Some((segment_start, s)) = filter_replace {
                let end = self.filter.len();
                self.filter = format!("{}{}", &self.filter[..segment_start.min(end)], s);
            }
            if let Some(ref err) = self.load_error {
                ui.colored_label(egui::Color32::RED, err);
            } else if !self.records.is_empty() {
                let filtered_count = self.records.iter().filter(|r| record_matches_filter(r, self.filter.trim())).count();
                if self.filter.trim().is_empty() {
                    ui.label(format!("{} decoded record(s)", self.records.len()));
                } else {
                    ui.label(format!("{} / {} record(s) (filtered)", filtered_count, self.records.len()));
                }
            }
        });

        egui::SidePanel::left("records")
            .resizable(true)
            .default_width(220.0)
            .show(ctx, |ui: &mut egui::Ui| {
                ui.heading("Records");
                ui.separator();
                let filter_str = self.filter.trim();
                let mut by_packet: std::collections::BTreeMap<u64, Vec<usize>> = std::collections::BTreeMap::new();
                for (idx, r) in self.records.iter().enumerate() {
                    if !record_matches_filter(r, filter_str) {
                        continue;
                    }
                    by_packet.entry(r.packet_index).or_default().push(idx);
                }
                egui::ScrollArea::vertical().show(ui, |ui: &mut egui::Ui| {
                    for (pkt, indices) in by_packet {
                        let label = format!("Packet {}", pkt);
                        let id = egui::Id::new(("packet", pkt));
                        egui::CollapsingHeader::new(label)
                            .id_salt(id)
                            .default_open(pkt <= 2)
                            .show(ui, |ui| {
                                for idx in indices {
                                    let r = &self.records[idx];
                                    let label = format!("Cat{:03} #{}", r.category, idx);
                                    let sel = self.selected_index == Some(idx);
                                    if ui.selectable_label(sel, label).clicked() {
                                        self.selected_index = Some(idx);
                                    }
                                }
                            });
                    }
                });
            });

        // Hex pane at the bottom
        if let (Some(idx), Some(_resolved)) = (self.selected_index, self.resolved.as_ref()) {
            if let Some(record) = self.records.get(idx) {
                let raw_bytes = record.raw_bytes.clone();
                let field_spans = record.field_spans.clone();
                let sel_field = self.selected_field.clone();
                egui::TopBottomPanel::bottom("hex_pane")
                    .resizable(true)
                    .default_height(180.0)
                    .show(ctx, |ui| {
                        ui.heading("Hex");
                        ui.separator();
                        let clicked = hex_pane_ui(ui, &raw_bytes, &field_spans, sel_field.as_deref());
                        if let Some(name) = clicked {
                            self.selected_field = Some(name);
                        }
                    });
            }
        }

        egui::CentralPanel::default().show(ctx, |ui: &mut egui::Ui| {
            if let (Some(idx), Some(resolved)) = (self.selected_index, self.resolved.as_ref()) {
                if let Some(record) = self.records.get(idx) {
                    ui.heading(format!(
                        "{} — packet {}, block offset {}",
                        record.message_name, record.packet_index, record.block_offset
                    ));
                    ui.separator();
                    let mut clicked_field: Option<String> = None;
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        tree_ui(ui, &record.message_name, &record.values, resolved,
                            self.selected_field.as_deref(), &mut clicked_field);
                    });
                    if let Some(f) = clicked_field {
                        self.selected_field = Some(f);
                    }
                }
            } else if !self.records.is_empty() {
                ui.label("Select a record from the list.");
            }
        });
    }
}

fn tree_ui(
    ui: &mut egui::Ui,
    container: &str,
    values: &std::collections::HashMap<String, crate::Value>,
    resolved: &crate::ResolvedProtocol,
    selected_field: Option<&str>,
    clicked: &mut Option<String>,
) {
    let mut keys: Vec<_> = values.keys().collect();
    keys.sort();
    for k in keys {
        let v = values.get(k).unwrap();
        if let crate::Value::List(lst) = v {
            if lst.is_empty() {
                continue;
            }
        }
        value_tree_ui(ui, resolved, container, k, v, selected_field, clicked);
    }
}

fn value_tree_ui(
    ui: &mut egui::Ui,
    resolved: &crate::ResolvedProtocol,
    container: &str,
    field_name: &str,
    v: &crate::Value,
    selected_field: Option<&str>,
    clicked: &mut Option<String>,
) {
    use crate::value_summary_line;
    use crate::Value;

    let is_selected = selected_field == Some(field_name);
    let summary = value_summary_line(resolved, container, field_name, v);
    match v {
        Value::Struct(m) => {
            let (_, child_container) = resolved.field_quantum_and_child(container, field_name);
            let child_container = child_container.unwrap_or(container);
            let id = egui::Id::new(("struct", container, field_name));
            let doc = resolved.field_doc(container, field_name);
            let highlight = if is_selected { Some(ui.visuals().selection.bg_fill) } else { None };
            ui.push_id(id, |ui| {
                let header_text = if is_selected {
                    egui::RichText::new(format!("{}: struct", field_name)).strong()
                } else {
                    egui::RichText::new(format!("{}: struct", field_name))
                };
                let resp = egui::CollapsingHeader::new(header_text)
                    .id_salt(id)
                    .default_open(false)
                    .show(ui, |ui| {
                        if let Some(d) = doc {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(d).small().color(ui.visuals().weak_text_color()),
                                )
                                .wrap(),
                            );
                        }
                        let mut keys: Vec<_> = m.keys().collect();
                        keys.sort();
                        for k in keys {
                            let val = m.get(k).unwrap();
                            if let Value::List(lst) = val {
                                if lst.is_empty() {
                                    continue;
                                }
                            }
                            value_tree_ui(ui, resolved, child_container, k, val, selected_field, clicked);
                        }
                    });
                if resp.header_response.clicked() {
                    *clicked = Some(field_name.to_string());
                }
                if let Some(bg) = highlight {
                    ui.painter().rect_filled(resp.header_response.rect, 2.0, bg.linear_multiply(0.25));
                }
                if let Some(d) = doc {
                    resp.header_response.on_hover_text(d);
                }
            });
        }
        Value::List(lst) => {
            if lst.is_empty() {
                return;
            }
            let (_, child_container) = resolved.field_quantum_and_child(container, field_name);
            let elem_container = child_container.unwrap_or(container);
            if lst.len() == 1 {
                value_tree_ui(ui, resolved, elem_container, field_name, &lst[0], selected_field, clicked);
            } else {
                let id = egui::Id::new(("list", container, field_name));
                let doc = resolved.field_doc(container, field_name);
                let highlight = if is_selected { Some(ui.visuals().selection.bg_fill) } else { None };
                ui.push_id(id, |ui| {
                    let header_text = if is_selected {
                        egui::RichText::new(format!("{}: [{} items]", field_name, lst.len())).strong()
                    } else {
                        egui::RichText::new(format!("{}: [{} items]", field_name, lst.len()))
                    };
                    let resp = egui::CollapsingHeader::new(header_text)
                        .id_salt(id)
                        .default_open(false)
                        .show(ui, |ui| {
                            if let Some(d) = doc {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(d).small().color(ui.visuals().weak_text_color()),
                                    )
                                    .wrap(),
                                );
                            }
                            for (i, item) in lst.iter().enumerate() {
                                value_tree_ui(ui, resolved, elem_container, &format!("[{}]", i), item, selected_field, clicked);
                            }
                        });
                    if resp.header_response.clicked() {
                        *clicked = Some(field_name.to_string());
                    }
                    if let Some(bg) = highlight {
                        ui.painter().rect_filled(resp.header_response.rect, 2.0, bg.linear_multiply(0.25));
                    }
                    if let Some(d) = doc {
                        resp.header_response.on_hover_text(d);
                    }
                });
            }
        }
        _ => {
            let doc = resolved.field_doc(container, field_name);
            let inner = ui.horizontal(|ui: &mut egui::Ui| {
                let text = if is_selected {
                    egui::RichText::new(field_name).monospace().strong()
                } else {
                    egui::RichText::new(field_name).monospace()
                };
                if ui.add(egui::Label::new(text).sense(egui::Sense::click())).clicked() {
                    *clicked = Some(field_name.to_string());
                }
                ui.label("→");
                ui.label(&summary);
            });
            if is_selected {
                let bg = ui.visuals().selection.bg_fill;
                ui.painter().rect_filled(inner.response.rect, 2.0, bg.linear_multiply(0.25));
            }
            if let Some(d) = doc {
                inner.response.on_hover_text(d);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(d).small().color(ui.visuals().weak_text_color()),
                    )
                    .wrap(),
                );
            }
        }
    }
}

// --- Hex pane ---

const HEX_BYTES_PER_ROW: usize = 16;

/// A rotating palette of distinct field highlight colors.
const FIELD_COLORS: &[(u8, u8, u8)] = &[
    (66, 133, 244),   // blue
    (52, 168, 83),    // green
    (251, 188, 4),    // yellow
    (234, 67, 53),    // red
    (171, 71, 188),   // purple
    (0, 172, 193),    // teal
    (255, 112, 67),   // deep orange
    (63, 81, 181),    // indigo
    (139, 195, 74),   // light green
    (255, 167, 38),   // orange
];

/// Returns the color index for a field name (stable hash to palette).
fn field_color_index(name: &str) -> usize {
    let mut h: u32 = 5381;
    for b in name.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h as usize % FIELD_COLORS.len()
}

/// Render the hex pane. Returns Some(field_name) if a byte was clicked that belongs to a field.
fn hex_pane_ui(
    ui: &mut egui::Ui,
    raw_bytes: &[u8],
    field_spans: &[(String, usize, usize)],
    selected_field: Option<&str>,
) -> Option<String> {
    let mut clicked_field: Option<String> = None;
    let transport_len = 3usize; // cat(1) + length(2)

    egui::ScrollArea::vertical().id_salt("hex_scroll").show(ui, |ui| {
        for row_start in (0..raw_bytes.len()).step_by(HEX_BYTES_PER_ROW) {
            let row_end = (row_start + HEX_BYTES_PER_ROW).min(raw_bytes.len());
            ui.horizontal(|ui| {
                ui.monospace(format!("{:04x}  ", row_start));

                // Hex bytes
                for i in row_start..row_start + HEX_BYTES_PER_ROW {
                    if i < raw_bytes.len() {
                        let byte_text = format!("{:02x}", raw_bytes[i]);
                        let field = field_for_byte(i, transport_len, field_spans);
                        let (text, bg) = hex_byte_style(ui, &byte_text, i, transport_len, field.as_deref(), selected_field);
                        let label = egui::Label::new(text).sense(egui::Sense::click());
                        let resp = ui.add(label);
                        if let Some(bg_color) = bg {
                            ui.painter().rect_filled(resp.rect, 1.0, bg_color);
                        }
                        if resp.clicked() {
                            if let Some(f) = field {
                                clicked_field = Some(f);
                            }
                        }
                        if let Some(fname) = field_for_byte(i, transport_len, field_spans) {
                            resp.on_hover_text(format!("byte {}: {}", i, fname));
                        }
                    } else {
                        ui.monospace("  ");
                    }
                    if i == row_start + 7 {
                        ui.monospace(" ");
                    }
                }

                ui.monospace("  ");

                // ASCII representation
                let mut ascii = String::with_capacity(HEX_BYTES_PER_ROW);
                for i in row_start..row_end {
                    let b = raw_bytes[i];
                    ascii.push(if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' });
                }
                ui.monospace(&ascii);
            });
        }
    });

    // Legend: show field color mapping
    if !field_spans.is_empty() {
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.monospace("Fields: ");
            // Transport header
            let (tr, tg, tb) = (180, 180, 180);
            let rect = ui.monospace("header").rect;
            ui.painter().rect_filled(rect, 1.0, egui::Color32::from_rgba_premultiplied(tr, tg, tb, 40));
            ui.monospace("  ");
            for (name, _, _) in field_spans {
                let ci = field_color_index(name);
                let (cr, cg, cb) = FIELD_COLORS[ci];
                let is_sel = selected_field == Some(name.as_str());
                let alpha = if is_sel { 80 } else { 40 };
                let text = if is_sel {
                    egui::RichText::new(name).monospace().strong()
                } else {
                    egui::RichText::new(name).monospace()
                };
                let resp = ui.add(egui::Label::new(text).sense(egui::Sense::click()));
                ui.painter().rect_filled(resp.rect, 1.0, egui::Color32::from_rgba_premultiplied(cr, cg, cb, alpha));
                if resp.clicked() {
                    clicked_field = Some(name.clone());
                }
                ui.monospace(" ");
            }
        });
    }

    clicked_field
}

fn field_for_byte(byte_idx: usize, transport_len: usize, field_spans: &[(String, usize, usize)]) -> Option<String> {
    if byte_idx < transport_len {
        return None;
    }
    let body_offset = byte_idx - transport_len;
    for (name, start, end) in field_spans {
        if body_offset >= *start && body_offset < *end {
            return Some(name.clone());
        }
    }
    None
}

fn hex_byte_style(
    _ui: &egui::Ui,
    text: &str,
    byte_idx: usize,
    transport_len: usize,
    field: Option<&str>,
    selected_field: Option<&str>,
) -> (egui::RichText, Option<egui::Color32>) {
    if byte_idx < transport_len {
        let rt = egui::RichText::new(text).monospace().color(egui::Color32::from_rgb(180, 180, 180));
        return (rt, Some(egui::Color32::from_rgba_premultiplied(180, 180, 180, 20)));
    }
    if let Some(fname) = field {
        let ci = field_color_index(fname);
        let (cr, cg, cb) = FIELD_COLORS[ci];
        let is_sel = selected_field == Some(fname);
        let alpha = if is_sel { 100 } else { 35 };
        let rt = if is_sel {
            egui::RichText::new(text).monospace().strong().color(egui::Color32::from_rgb(cr, cg, cb))
        } else {
            egui::RichText::new(text).monospace().color(egui::Color32::from_rgb(cr, cg, cb))
        };
        (rt, Some(egui::Color32::from_rgba_premultiplied(cr, cg, cb, alpha)))
    } else {
        let rt = egui::RichText::new(text).monospace();
        (rt, None)
    }
}

/// Entry point for the native binary.
pub fn run_native() -> eframe::Result<()> {
    eframe::run_native(
        "AIProtoDSL — PCAP + DSL viewer",
        eframe::NativeOptions::default(),
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
}
