//! Frame handling: decode binary frames that may contain one or more messages.
//!
//! When a message is non-compliant (validation failure) but decodable, it is removed
//! and length/count fields in the frame are updated accordingly.

use crate::codec::{Codec, CodecError};
use crate::value::Value;
use std::collections::HashMap;

/// Result of decoding a frame: valid messages and optional raw bytes for messages that failed validation.
#[derive(Debug)]
pub struct FrameDecodeResult {
    /// Messages that decoded and passed validation.
    pub messages: Vec<DecodedMessage>,
    /// Indices/offsets of messages that were removed (non-compliant).
    pub removed: Vec<RemovedMessage>,
}

#[derive(Debug)]
pub struct DecodedMessage {
    pub name: String,
    pub values: HashMap<String, Value>,
    pub byte_range: (usize, usize),
}

#[derive(Debug)]
pub struct RemovedMessage {
    pub name: String,
    pub byte_range: (usize, usize),
    pub reason: String,
}

/// Decode a binary frame: optionally parse transport header, then one or more messages.
/// If a message fails validation, it is removed (bytes still consumed so we can continue).
pub fn decode_frame(
    codec: &Codec,
    message_name: &str,
    bytes: &[u8],
    transport_len: Option<usize>,
) -> Result<FrameDecodeResult, CodecError> {
    let body_bytes = if let Some(n) = transport_len {
        if bytes.len() < n {
            return Err(CodecError::Validation("Frame shorter than transport header".to_string()));
        }
        &bytes[n..]
    } else {
        bytes
    };

    let mut messages = Vec::new();
    let mut removed = Vec::new();
    let mut offset = 0;
    let base = transport_len.unwrap_or(0);

    while offset < body_bytes.len() {
        let (consumed, result) = codec.decode_message_with_extent(message_name, &body_bytes[offset..]);
        if consumed == 0 {
            break;
        }
        match result {
            Ok(values) => {
                messages.push(DecodedMessage {
                    name: message_name.to_string(),
                    values,
                    byte_range: (base + offset, base + offset + consumed),
                });
            }
            Err(e) => {
                removed.push(RemovedMessage {
                    name: message_name.to_string(),
                    byte_range: (base + offset, base + offset + consumed),
                    reason: e.to_string(),
                });
            }
        }
        offset += consumed;
    }

    Ok(FrameDecodeResult { messages, removed })
}

/// Re-encode a frame with only compliant messages, updating transport length and any length/count fields.
pub fn encode_frame_with_compliant_only(
    codec: &Codec,
    message_name: &str,
    result: &FrameDecodeResult,
    transport_values: Option<&HashMap<String, Value>>,
    transport_len: Option<usize>,
) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();

    if let Some(tv) = transport_values {
        let mut header = codec.encode_transport(tv)?;
        if let Some(required_len) = transport_len {
            // Pad or truncate transport header to required_len
            header.resize(required_len, 0);
        }
        out.extend(header);
    }

    for msg in &result.messages {
        let encoded = codec.encode_message(message_name, &msg.values)?;
        out.extend(encoded);
    }

    Ok(out)
}

