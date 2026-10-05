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

/// Characters written as `\uXXXX` although JSON allows most of them raw:
/// the ones that are invisible or reorder text. A reader of the request,
/// the model included, then sees which code point was there, and nothing in
/// a reviewed file can draw what looks like a line of the request around
/// it. Nothing is removed: the escape names the character.
pub const fn is_escaped(character: char) -> bool {
    matches!(
        character,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'
            | '\u{1160}'
            | '\u{17b4}'
            | '\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202f}'
            | '\u{205f}'..='\u{206f}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// The bytes `character` takes inside a JSON string as written here.
pub const fn written_len(character: char) -> usize {
    match character {
        '"' | '\\' | '\n' | '\r' | '\t' => 2,
        // Past the basic plane an escape is a surrogate pair.
        other if is_escaped(other) => {
            if other as u32 > 0xffff {
                12
            } else {
                6
            }
        }
        other => other.len_utf8(),
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
            hidden if is_escaped(hidden) => {
                let mut units = [0_u16; 2];
                for unit in hidden.encode_utf16(&mut units) {
                    write!(f, "\\u{unit:04x}")?;
                }
            }
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
    use std::collections::HashSet;
    use std::fmt::Write as _;

    use super::{Json, MAX_DEPTH};
    use crate::test_support::Rng;

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
    fn invisible_characters_are_written_as_escapes_and_read_back() {
        // One of each kind: a C1 control, a soft hyphen, a bidi override, a
        // zero-width space, a line separator, a variation selector, a
        // byte-order mark, a blank Braille cell, and two past the basic
        // plane (a musical format character and a tag letter).
        let hidden =
            "a\u{9b}\u{ad}\u{202e}\u{200b}\u{2028}\u{fe0f}\u{feff}\u{2800}\u{1d173}\u{e0041}z";
        let text = Json::from(hidden).to_string();
        // The sixteen-bit units in hex, each after a backslash and a `u`.
        let mut escapes = String::new();
        for unit in [
            "009b", "00ad", "202e", "200b", "2028", "fe0f", "feff", "2800", "d834", "dd73", "db40",
            "dc41",
        ] {
            escapes.push('\\');
            escapes.push('u');
            escapes.push_str(unit);
        }
        assert_eq!(text, format!("\"a{escapes}z\""));
        assert!(text.is_ascii());
        assert_eq!(Json::parse(&text).unwrap(), Json::from(hidden));
        // Ordinary text of any script, and emoji, stay as they are.
        let plain = "é 中 ✓ \u{1f600} \u{2026}";
        assert_eq!(Json::from(plain).to_string(), format!("\"{plain}\""));
    }

    #[test]
    fn the_written_length_is_what_is_written() {
        for character in (0..=0x0011_0000_u32).filter_map(char::from_u32) {
            let mut buffer = [0_u8; 4];
            let text = Json::from(&*character.encode_utf8(&mut buffer)).to_string();
            assert_eq!(
                text.len() - 2,
                super::written_len(character),
                "{:x}",
                u32::from(character)
            );
        }
    }

    #[test]
    fn parses_concatenated_values() {
        let values = Json::parse_stream("{\"id\":\"A\"}\n{\"id\":\"B\"} ").unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[1].get("id").and_then(Json::as_str), Some("B"));
        assert!(Json::parse_stream("{} {").is_err());
    }

    /// What JSON is written with, and what a parser trips over.
    const PIECES: &[&str] = &[
        "{",
        "}",
        "[",
        "]",
        ":",
        ",",
        "\"",
        "\\",
        "\\u",
        "\\ud83d",
        "\\ude00",
        "\\udc00",
        "\\n",
        "\\x",
        "/",
        "true",
        "false",
        "null",
        "nul",
        "-",
        "0",
        "1",
        "9",
        ".",
        "e",
        "E",
        "+",
        " ",
        "\n",
        "\t",
        "\r",
        "a",
        "é",
        "\u{1f600}",
        "\u{202e}",
        "\u{0}",
        "\u{1f}",
        "\u{7f}",
        "\u{feff}",
        "\u{d7ff}",
        "\u{e000}",
        "\u{10ffff}",
        "\"a\"",
        "\"a\":",
        "[]",
        "{}",
    ];

    /// Characters for generated strings: plain, escaped by the writer,
    /// escaped by JSON itself, and past the basic plane.
    const CHARACTERS: &[char] = &[
        'a',
        'Z',
        '0',
        ' ',
        '"',
        '\\',
        '/',
        '\n',
        '\r',
        '\t',
        '\u{0}',
        '\u{8}',
        '\u{c}',
        '\u{1f}',
        '\u{7f}',
        '\u{9b}',
        '\u{ad}',
        'é',
        '中',
        '\u{200b}',
        '\u{202e}',
        '\u{2028}',
        '\u{feff}',
        '\u{fffd}',
        '\u{d7ff}',
        '\u{e000}',
        '\u{1f600}',
        '\u{e0041}',
        '\u{10ffff}',
    ];

    fn string(rng: &mut Rng) -> String {
        (0..rng.below(8)).map(|_| *rng.pick(CHARACTERS)).collect()
    }

    fn number(rng: &mut Rng) -> String {
        let digits = |rng: &mut Rng| -> String {
            (0..=rng.below(4))
                .map(|_| *rng.pick(&['0', '1', '7', '9']))
                .collect()
        };
        let mut text = String::new();
        if rng.chance(3) {
            text.push('-');
        }
        // No leading zero before more digits.
        if rng.chance(4) {
            text.push('0');
        } else {
            text.push(*rng.pick(&['1', '5', '9']));
            if rng.chance(2) {
                text.push_str(&digits(rng));
            }
        }
        if rng.chance(3) {
            text.push('.');
            text.push_str(&digits(rng));
        }
        if rng.chance(3) {
            text.push(*rng.pick(&['e', 'E']));
            text.push_str(rng.pick(&["", "+", "-"]));
            text.push_str(&digits(rng));
        }
        text
    }

    /// A value at most `depth` containers deep, with unique keys.
    fn value(rng: &mut Rng, depth: usize) -> Json {
        match rng.below(if depth == 0 { 4 } else { 6 }) {
            0 => Json::Null,
            1 => Json::Bool(rng.chance(2)),
            2 => Json::Number(number(rng)),
            3 => Json::String(string(rng)),
            4 => Json::Array((0..rng.below(4)).map(|_| value(rng, depth - 1)).collect()),
            _ => {
                let mut members: Vec<(String, Json)> = Vec::new();
                for _ in 0..rng.below(4) {
                    let key = string(rng);
                    if !members.iter().any(|(known, _)| *known == key) {
                        members.push((key, value(rng, depth - 1)));
                    }
                }
                Json::Object(members)
            }
        }
    }

    /// How deep the containers of `value` go.
    fn depth_of(value: &Json) -> usize {
        match value {
            Json::Array(items) => 1 + items.iter().map(depth_of).max().unwrap_or(0),
            Json::Object(members) => {
                1 + members
                    .iter()
                    .map(|(_, member)| depth_of(member))
                    .max()
                    .unwrap_or(0)
            }
            Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => 0,
        }
    }

    fn has_duplicate_keys(value: &Json) -> bool {
        match value {
            Json::Array(items) => items.iter().any(has_duplicate_keys),
            Json::Object(members) => {
                let mut keys = HashSet::new();
                members
                    .iter()
                    .any(|(key, member)| !keys.insert(key) || has_duplicate_keys(member))
            }
            Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => false,
        }
    }

    #[test]
    fn what_is_written_is_read_back_as_it_was() {
        let mut rng = Rng::new(1);
        for case in 0..20_000 {
            let value = value(&mut rng, 4);
            let text = value.to_string();
            assert_eq!(
                Json::parse(&text).as_ref(),
                Ok(&value),
                "case {case}: {text}"
            );
            // Whitespace around it changes nothing.
            let padded = format!(" \n\t{text}\r\n ");
            assert_eq!(Json::parse(&padded).as_ref(), Ok(&value), "case {case}");
        }
    }

    #[test]
    fn several_values_written_back_to_back_are_read_as_those_values() {
        let mut rng = Rng::new(2);
        for case in 0..5_000 {
            let values: Vec<Json> = (0..rng.below(5)).map(|_| value(&mut rng, 2)).collect();
            let mut text = String::new();
            for value in &values {
                let _ = writeln!(text, "{value}");
            }
            assert_eq!(
                Json::parse_stream(&text).as_ref(),
                Ok(&values),
                "case {case}: {text}"
            );
        }
    }

    /// Whatever is accepted is within the limits, has no key twice, and is
    /// read back as itself when written out again.
    fn check_accepted(text: &str) {
        if let Ok(value) = Json::parse(text) {
            assert!(depth_of(&value) <= MAX_DEPTH, "{text:?}");
            assert!(!has_duplicate_keys(&value), "{text:?}");
            assert_eq!(Json::parse(&value.to_string()), Ok(value), "{text:?}");
        }
        if let Ok(values) = Json::parse_stream(text) {
            assert!(values.iter().all(|value| depth_of(value) <= MAX_DEPTH));
        }
    }

    #[test]
    fn no_text_makes_the_parser_panic() {
        let mut rng = Rng::new(3);
        let mut accepted = 0;
        for _ in 0..20_000 {
            let text = rng.text(PIECES, 24);
            accepted += usize::from(Json::parse(&text).is_ok());
            check_accepted(&text);
        }
        // The pieces do come together as JSON now and then: the cases
        // reach past the first byte.
        assert!(accepted > 100, "{accepted}");

        // Every prefix of a document, and documents with a few bytes
        // dropped, repeated, moved or swapped for another piece.
        for _ in 0..3_000 {
            let text = value(&mut rng, 3).to_string();
            for end in (0..=text.len()).filter(|end| text.is_char_boundary(*end)) {
                check_accepted(&text[..end]);
            }
            for _ in 0..6 {
                check_accepted(&rng.mutated(&text, PIECES));
            }
        }
    }

    #[test]
    fn a_key_given_twice_is_refused_however_it_is_spelled() {
        // The same key as written, and through escapes that decode to it.
        let spelled = |rng: &mut Rng, key: &str| -> String {
            let mut text = String::from('"');
            for character in key.chars() {
                if rng.chance(2) {
                    let _ = write!(text, "\\u{:04x}", u32::from(character));
                } else {
                    let written = Json::from(character.to_string()).to_string();
                    text.push_str(&written[1..written.len() - 1]);
                }
            }
            text.push('"');
            text
        };
        let mut rng = Rng::new(4);
        for case in 0..4_000 {
            // Three to six members, one of whose keys is given again
            // somewhere after its first use.
            let keys: Vec<String> = (0..3 + rng.below(4))
                .map(|index| format!("k{index}é\"\n"))
                .collect();
            let again = rng.below(keys.len());
            let mut members: Vec<String> = keys
                .iter()
                .map(|key| format!("{}:{}", spelled(&mut rng, key), value(&mut rng, 1)))
                .collect();
            let unique = format!("{{{}}}", members.join(","));
            assert!(Json::parse(&unique).is_ok(), "case {case}: {unique}");
            let at = again + 1 + rng.below(members.len() - again);
            members.insert(at, format!("{}:null", spelled(&mut rng, &keys[again])));
            let twice = format!("{{{}}}", members.join(","));
            assert_eq!(
                Json::parse(&twice).map_err(|error| error.message),
                Err("duplicate object key"),
                "case {case}: {twice}"
            );
            // And inside another value.
            let nested = format!("[1,{{\"outer\":{twice}}}]");
            assert!(Json::parse(&nested).is_err(), "case {case}");
        }
    }

    #[test]
    fn nesting_is_accepted_up_to_the_limit_and_no_further() {
        let mut rng = Rng::new(5);
        // Arrays and objects mixed at random, `depth` deep.
        let nested = |rng: &mut Rng, depth: usize| -> String {
            let mut open = String::new();
            let mut close = String::new();
            for _ in 0..depth {
                if rng.chance(2) {
                    open.push('[');
                    close.insert(0, ']');
                } else {
                    open.push_str("{\"k\":");
                    close.insert(0, '}');
                }
            }
            format!("{open}null{close}")
        };
        for depth in [0, 1, 2, MAX_DEPTH - 1, MAX_DEPTH] {
            for _ in 0..50 {
                let text = nested(&mut rng, depth);
                assert_eq!(Json::parse(&text).map(|value| depth_of(&value)), Ok(depth));
            }
        }
        for depth in [MAX_DEPTH + 1, MAX_DEPTH + 2, 1_000, 100_000] {
            let text = nested(&mut rng, depth);
            assert_eq!(
                Json::parse(&text).map_err(|error| error.message),
                Err("nesting is too deep"),
                "{depth}"
            );
            assert!(Json::parse_stream(&text).is_err(), "{depth}");
        }
        // Never closed, a million deep: refused at the limit, not after
        // the stack ran out.
        assert!(Json::parse(&"[".repeat(1_000_000)).is_err());
        assert!(Json::parse(&"{\"a\":".repeat(1_000_000)).is_err());
        // Depth is how deep, not how many: siblings do not add up.
        let wide = format!("[{}]", vec!["[[]]"; 10_000].join(","));
        assert_eq!(Json::parse(&wide).map(|value| depth_of(&value)), Ok(3));
    }
}
