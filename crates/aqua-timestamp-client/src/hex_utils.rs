use crate::error::ClientError;

/// Parse a 32-byte hash from a hex string. Accepts optional `0x` prefix and
/// is case-insensitive. Rejects anything that is not exactly 64 hex chars
/// after prefix removal.
#[allow(dead_code)]
pub fn parse_hash32(input: &str) -> Result<[u8; 32], ClientError> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() != 64 {
        return Err(ClientError::Invalid(format!(
            "expected 64 hex chars (optionally 0x-prefixed), got {}",
            trimmed.len()
        )));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(trimmed, &mut out)
        .map_err(|e| ClientError::Invalid(format!("non-hex character: {e}")))?;
    Ok(out)
}

/// Format a 32-byte hash as lowercase hex without a `0x` prefix. This is
/// the on-wire format the server expects for path parameters; the server
/// also accepts `0x`-prefixed bodies but we keep the wire form bare.
pub fn format_hash32_bare(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_hex() {
        let h = parse_hash32(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(h[0], 0x01);
        assert_eq!(h[31], 0xef);
    }

    #[test]
    fn parses_prefixed_hex() {
        let h = parse_hash32(
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(h[0], 0x01);
    }

    #[test]
    fn parses_uppercase() {
        let h = parse_hash32(
            "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        )
        .unwrap();
        assert_eq!(h[0], 0xab);
    }

    #[test]
    fn rejects_short() {
        assert!(parse_hash32("0xabc").is_err());
    }

    #[test]
    fn rejects_long() {
        let s = format!("0x{}ff", "a".repeat(64));
        assert!(parse_hash32(&s).is_err());
    }

    #[test]
    fn rejects_non_hex() {
        let s = "z".repeat(64);
        assert!(parse_hash32(&s).is_err());
    }

    #[test]
    fn round_trips() {
        let bytes = [0xab; 32];
        let s = format_hash32_bare(&bytes);
        assert_eq!(parse_hash32(&s).unwrap(), bytes);
    }
}
