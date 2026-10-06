//! Reading what is written encoded: base64.

/// Standard base64 decoded, or `None`. Padding is optional and not
/// checked: every `=` at the end is dropped, and bits left over after the
/// last whole byte are ignored. Anything outside the standard alphabet
/// (the URL-safe `-` and `_`, whitespace, a `=` before the end) is refused.
pub fn base64_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut bits = 0_u32;
    let mut count = 0;
    let mut bytes = Vec::with_capacity(encoded.len() * 3 / 4);
    for character in encoded.trim_end_matches('=').bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::base64_decode;

    #[test]
    fn standard_base64_is_decoded_with_or_without_padding() {
        let decoded = |text: &str| base64_decode(text);
        assert_eq!(decoded("").as_deref(), Some(&b""[..]));
        assert_eq!(decoded("Zg==").as_deref(), Some(&b"f"[..]));
        assert_eq!(decoded("Zg").as_deref(), Some(&b"f"[..]));
        assert_eq!(decoded("Zm8=").as_deref(), Some(&b"fo"[..]));
        assert_eq!(decoded("Zm9v").as_deref(), Some(&b"foo"[..]));
        assert_eq!(decoded("Zm9vYmFy").as_deref(), Some(&b"foobar"[..]));
        assert_eq!(
            decoded("YW55IGNhcm5hbCBwbGVhcw==").as_deref(),
            Some(&b"any carnal pleas"[..])
        );
        // Every value of a byte, the last two letters of the alphabet too.
        assert_eq!(decoded("+/8A").as_deref(), Some(&[0xfb, 0xff, 0x00][..]));
        // Padding is not counted, and bits short of a byte are dropped.
        assert_eq!(decoded("Zg=====").as_deref(), Some(&b"f"[..]));
        assert_eq!(decoded("Z").as_deref(), Some(&b""[..]));
        assert_eq!(decoded("====").as_deref(), Some(&b""[..]));
    }

    #[test]
    fn what_is_not_standard_base64_is_refused() {
        for text in [
            "Zm9v\n",
            " Zm9v",
            "Zm 9v",
            "Zg==Zg",
            "Zm9v-",
            "Zm9v_",
            "Zm9v.",
            "Zm9\u{e9}",
        ] {
            assert_eq!(base64_decode(text), None, "{text:?}");
        }
    }
}
