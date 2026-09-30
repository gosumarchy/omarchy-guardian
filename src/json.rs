//! A small, strict JSON reader and writer (RFC 8259).
//!
//! Guardian parses hostile input (lockfiles from downloaded source, model
//! output, network responses), so the parser bounds nesting depth, rejects
//! duplicate object keys instead of silently picking one, and keeps numbers as
//! their source text so no precision is lost or invented.

use std::collections::HashSet;
use std::fmt::{self, Write as _};

const MAX_DEPTH: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// The number exactly as written in the source text.
    Number(String),
    String(String),
    Array(Vec<Json>),
    /// Members in source order; keys are unique.
    Object(Vec<(String, Json)>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    offset: usize,
    message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for ParseError {}

impl Json {
    /// Parses exactly one JSON value surrounded by optional whitespace.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut parser = Parser::new(text);
        let value = parser.value()?;
        parser.skip_whitespace();
        if parser.position < parser.bytes.len() {
            return Err(parser.error("trailing characters after JSON value"));
        }
        Ok(value)
    }

    /// Parses a sequence of whitespace-separated JSON values, as produced when
    /// several responses are written back to back.
    pub fn parse_stream(text: &str) -> Result<Vec<Self>, ParseError> {
        let mut parser = Parser::new(text);
        let mut values = Vec::new();
        loop {
            parser.skip_whitespace();
            if parser.position == parser.bytes.len() {
                return Ok(values);
            }
            values.push(parser.value()?);
        }
    }

    /// Builds an object from `(key, value)` pairs.
    pub fn object<'a>(members: impl IntoIterator<Item = (&'a str, Json)>) -> Self {
        Self::Object(
            members
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(member, _)| member == key)
                .map(|(_, value)| value),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            Self::Null | Self::Number(_) | Self::String(_) | Self::Array(_) | Self::Object(_) => {
                None
            }
        }
    }

    /// The value as a non-negative integer, if it is one.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(text) => text.parse().ok(),
            Self::Null | Self::Bool(_) | Self::String(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Object(_) => {
                None
            }
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(members) => Some(members),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => None,
        }
    }
}

impl From<&str> for Json {
    fn from(text: &str) -> Self {
        Self::String(text.to_string())
    }
}

impl From<String> for Json {
    fn from(text: String) -> Self {
        Self::String(text)
    }
}

impl From<bool> for Json {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<u64> for Json {
    fn from(value: u64) -> Self {
        Self::Number(value.to_string())
    }
}

/// Compact serialization.
impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::Number(text) => f.write_str(text),
            Self::String(text) => write_string(f, text),
            Self::Array(items) => {
                f.write_char('[')?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_char(']')
            }
            Self::Object(members) => {
                f.write_char('{')?;
                for (index, (key, value)) in members.iter().enumerate() {
                    if index > 0 {
                        f.write_char(',')?;
                    }
                    write_string(f, key)?;
                    write!(f, ":{value}")?;
                }
                f.write_char('}')
            }
        }
    }
}

fn write_string(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    f.write_char('"')?;
    for character in text.chars() {
        match character {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            control if u32::from(control) < 0x20 => write!(f, "\\u{:04x}", u32::from(control))?,
            other => f.write_char(other)?,
        }
    }
    f.write_char('"')
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            position: 0,
            depth: 0,
        }
    }

    fn error(&self, message: &'static str) -> ParseError {
        ParseError {
            offset: self.position,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn expect_byte(&mut self, expected: u8, message: &'static str) -> Result<(), ParseError> {
        if self.next_byte() == Some(expected) {
            Ok(())
        } else {
            Err(self.error(message))
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn value(&mut self) -> Result<Json, ParseError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.nested(Self::object),
            Some(b'[') => self.nested(Self::array),
            Some(b'"') => self.string().map(Json::String),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("unexpected character")),
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn nested(
        &mut self,
        parse: fn(&mut Self) -> Result<Json, ParseError>,
    ) -> Result<Json, ParseError> {
        if self.depth == MAX_DEPTH {
            return Err(self.error("nesting is too deep"));
        }
        self.depth += 1;
        let value = parse(self);
        self.depth -= 1;
        value
    }

    fn literal(&mut self, word: &'static str, value: Json) -> Result<Json, ParseError> {
        if self.bytes[self.position..].starts_with(word.as_bytes()) {
            self.position += word.len();
            Ok(value)
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn object(&mut self) -> Result<Json, ParseError> {
        self.expect_byte(b'{', "expected '{'")?;
        let mut members: Vec<(String, Json)> = Vec::new();
        // A set, not a scan of `members`: a scan is quadratic in the keys.
        let mut keys: HashSet<String> = HashSet::new();

        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(Json::Object(members));
        }

        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected an object key"));
            }
            let key = self.string()?;
            if !keys.insert(key.clone()) {
                return Err(self.error("duplicate object key"));
            }

            self.skip_whitespace();
            self.expect_byte(b':', "expected ':' after object key")?;
            let value = self.value()?;
            members.push((key, value));

            self.skip_whitespace();
            match self.next_byte() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Object(members)),
                _ => return Err(self.error("expected ',' or '}' in object")),
            }
        }
    }

    fn array(&mut self) -> Result<Json, ParseError> {
        self.expect_byte(b'[', "expected '['")?;
        let mut items = Vec::new();

        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(Json::Array(items));
        }

        loop {
            items.push(self.value()?);
            self.skip_whitespace();
            match self.next_byte() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Array(items)),
                _ => return Err(self.error("expected ',' or ']' in array")),
            }
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect_byte(b'"', "expected '\"'")?;
        let mut output = Vec::new();

        loop {
            let Some(byte) = self.next_byte() else {
                return Err(self.error("unterminated string"));
            };
            match byte {
                b'"' => break,
                b'\\' => {
                    let character = self.escape()?;
                    let mut encoded = [0_u8; 4];
                    output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                }
                0x00..=0x1f => return Err(self.error("control character in string")),
                // The input is a `&str`, so copying bytes keeps it valid UTF-8.
                other => output.push(other),
            }
        }

        String::from_utf8(output).map_err(|_| self.error("invalid UTF-8 in string"))
    }

    fn escape(&mut self) -> Result<char, ParseError> {
        let character = match self.next_byte() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => return self.unicode_escape(),
            _ => return Err(self.error("invalid escape sequence")),
        };
        Ok(character)
    }

    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let first = self.hex4()?;
        let code_point = if (0xd800..0xdc00).contains(&first) {
            if self.next_byte() != Some(b'\\') || self.next_byte() != Some(b'u') {
                return Err(self.error("unpaired surrogate"));
            }
            let second = self.hex4()?;
            if !(0xdc00..0xe000).contains(&second) {
                return Err(self.error("unpaired surrogate"));
            }
            0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
        } else {
            first
        };
        char::from_u32(code_point).ok_or_else(|| self.error("invalid unicode escape"))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut value = 0;
        for _ in 0..4 {
            let digit = self
                .next_byte()
                .and_then(|byte| char::from(byte).to_digit(16))
                .ok_or_else(|| self.error("invalid unicode escape"))?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.position;

        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.next_byte() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.error("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            self.required_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            self.required_digits()?;
        }

        let text = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| self.error("invalid number"))?;
        Ok(Json::Number(text.to_string()))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
    }

    fn required_digits(&mut self) -> Result<(), ParseError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.error("invalid number"));
        }
        self.digits();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Json;

    #[test]
    fn parses_nested_documents() {
        let value =
            Json::parse(r#" {"a": [1, -2.5e3, true, null, "x\"\u00e9\ud83d\ude00"], "b": {}} "#)
                .unwrap();

        let items = value.get("a").and_then(Json::as_array).unwrap();
        assert_eq!(items[0].as_u64(), Some(1));
        assert_eq!(items[1], Json::Number("-2.5e3".to_string()));
        assert_eq!(items[2].as_bool(), Some(true));
        assert_eq!(items[3], Json::Null);
        assert_eq!(items[4].as_str(), Some("x\"\u{e9}\u{1f600}"));
        assert_eq!(value.get("b").and_then(Json::as_object), Some(&[][..]));
    }

    #[test]
    fn rejects_malformed_and_ambiguous_input() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            "\"\u{1}\"",
            "\"\\x\"",
            "\"\\ud800\"",
            "{\"a\":1,\"a\":2}",
            "true false",
            "nul",
        ] {
            assert!(Json::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn bounds_nesting_depth() {
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(Json::parse(&deep).is_err());

        let shallow = format!("{}{}", "[".repeat(100), "]".repeat(100));
        assert!(Json::parse(&shallow).is_ok());
    }

    #[test]
    fn serialization_round_trips() {
        let value = Json::object([
            ("text", Json::from("line\n\"quoted\"\\ \u{1}")),
            ("flag", Json::from(false)),
            ("count", Json::from(7_u64)),
            ("items", Json::Array(vec![Json::Null, Json::from("é")])),
        ]);

        let text = value.to_string();
        assert_eq!(
            text,
            r#"{"text":"line\n\"quoted\"\\ \u0001","flag":false,"count":7,"items":[null,"é"]}"#
        );
        assert_eq!(Json::parse(&text).unwrap(), value);
    }

    #[test]
    fn parses_concatenated_values() {
        let values = Json::parse_stream("{\"id\":\"A\"}\n{\"id\":\"B\"} ").unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[1].get("id").and_then(Json::as_str), Some("B"));
        assert!(Json::parse_stream("{} {").is_err());
    }
}
