//! Reads the Omarchy menu's user file the way the menu itself does, to tell
//! which entry is in effect for an item.
//!
//! The menu removes whole-line `//` comments and commas before a closing
//! bracket, then parses the rest as JSON; a file that does not parse is
//! ignored whole. Of an item named twice the later entry wins. A line that
//! merely contains Guardian's path proves none of that.

use crate::json::Json;

/// One item of the file: its id and its value (`None` for a value the
/// menu reads and this strict reader does not: a key set twice inside it).
pub type Item = (String, Option<Json>);

/// `raw` without what the menu strips before parsing.
fn stripped(raw: &str) -> String {
    let lines: String = raw
        .split_inclusive('\n')
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let characters: Vec<char> = lines.chars().collect();
    let mut text = String::with_capacity(lines.len());
    for (index, character) in characters.iter().enumerate() {
        let closes = || {
            characters[index + 1..]
                .iter()
                .find(|next| !next.is_whitespace())
                .is_some_and(|next| matches!(next, '}' | ']'))
        };
        if *character != ',' || !closes() {
            text.push(*character);
        }
    }
    text
}

/// Where the JSON string starting at `start` (a `"`) ends: past its
/// closing quote.
fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

fn skip_space(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

/// The members of the object `text` holds, in order and with repeats, each
/// value as its source text.
fn members(text: &str) -> Result<Vec<(String, &str)>, String> {
    const BROKEN: &str = "it is not one JSON object";
    let bytes = text.as_bytes();
    let mut index = skip_space(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return Err(BROKEN.into());
    }
    index = skip_space(bytes, index + 1);
    let mut found = Vec::new();
    if bytes.get(index) == Some(&b'}') {
        index += 1;
    } else {
        loop {
            if bytes.get(index) != Some(&b'"') {
                return Err(BROKEN.into());
            }
            let key_end = string_end(bytes, index).ok_or(BROKEN)?;
            let key = Json::parse(&text[index..key_end])
                .ok()
                .and_then(|key| key.as_str().map(str::to_string))
                .ok_or(BROKEN)?;
            index = skip_space(bytes, key_end);
            if bytes.get(index) != Some(&b':') {
                return Err(BROKEN.into());
            }
            let value_start = index + 1;
            index = value_start;
            let mut depth = 0_usize;
            // To the comma or brace that ends this member.
            loop {
                match bytes.get(index).ok_or(BROKEN)? {
                    b'"' => {
                        index = string_end(bytes, index).ok_or(BROKEN)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' if depth > 0 => depth -= 1,
                    b',' | b'}' if depth == 0 => break,
                    _ => {}
                }
                index += 1;
            }
            found.push((key, text[value_start..index].trim()));
            let closed = bytes[index] == b'}';
            index = skip_space(bytes, index + 1);
            if closed {
                break;
            }
        }
    }
    if skip_space(bytes, index) == bytes.len() {
        Ok(found)
    } else {
        Err(BROKEN.into())
    }
}

/// The items of the menu file `raw`, in order and with repeats; an error
/// when the menu would ignore the file.
pub fn items(raw: &str) -> Result<Vec<Item>, String> {
    let text = stripped(raw);
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parse = |members: Vec<(String, &str)>| -> Result<Vec<Item>, String> {
        members
            .into_iter()
            .map(|(id, value)| match Json::parse(value) {
                Ok(value) => Ok((id, Some(value))),
                // The menu takes the last of a repeated key; which one that
                // leaves is not worked out here.
                Err(error) if error.to_string().contains("duplicate") => Ok((id, None)),
                Err(error) => Err(format!("the entry {id:?} is not JSON ({error})")),
            })
            .collect()
    };
    let top = members(&text)?;
    // The menu also takes its items from an `items` object.
    let nested = top
        .iter()
        .rev()
        .find(|(id, _)| id == "items")
        .map(|(_, value)| *value)
        .filter(|value| value.starts_with('{'));
    match nested {
        Some(nested) => parse(members(nested)?),
        None => parse(top),
    }
}

/// The `action` in effect for `id`: of its last entry. `None` when the
/// item is not in the file, or its last entry has no readable action.
pub fn action<'a>(items: &'a [Item], id: &str) -> Option<&'a str> {
    items
        .iter()
        .rev()
        .find(|(candidate, _)| candidate == id)
        .and_then(|(_, value)| value.as_ref())
        .and_then(|value| value.get("action"))
        .and_then(Json::as_str)
}

#[cfg(test)]
mod tests {
    use super::{action, items};

    #[test]
    fn the_last_entry_of_an_item_is_the_one_in_effect() {
        let text = "{\n  // a comment\n  \"a\": {\"action\":\"guardian\"},\n  \"b\": {\"label\":\"B\"},\n  \"a\": {\"action\":\"other\"},\n}\n";
        let found = items(text).unwrap();
        assert_eq!(found.len(), 3);
        assert_eq!(action(&found, "a"), Some("other"));
        assert_eq!(action(&found, "b"), None);
        assert_eq!(action(&found, "c"), None);

        // Braces, commas and quotes inside strings end nothing.
        let found =
            items("{\"a\": {\"action\":\"x, y } \\\" z\"}, \"b\": [1, {\"c\": 2}]}").unwrap();
        assert_eq!(action(&found, "a"), Some("x, y } \" z"));
        assert_eq!(found.len(), 2);

        // An `items` object holds the items when there is one.
        let found =
            items("{\"items\": {\"a\": {\"action\":\"x\"}}, \"a\": {\"action\":\"y\"}}").unwrap();
        assert_eq!(action(&found, "a"), Some("x"));

        assert!(items("").unwrap().is_empty());
        assert!(items("{\n}\n").unwrap().is_empty());
    }

    #[test]
    fn a_file_the_menu_would_ignore_is_an_error() {
        for broken in [
            "[]",
            "{\"a\": {\"action\":\"x\"}",
            "{\"a\": {\"action\":\"x\"}} trailing",
            "{\"a\": nonsense}",
            "{a: 1}",
            // A comment after a value is not stripped by the menu.
            "{\n  \"a\": {\"action\":\"x\"}, // mine\n}\n",
        ] {
            assert!(items(broken).is_err(), "{broken}");
        }
        // A key set twice inside an entry: the menu reads it, so the file
        // stands, but what that entry does is not vouched for.
        let found =
            items("{\"a\": {\"action\":\"x\",\"action\":\"y\"}, \"b\": {\"action\":\"z\"}}")
                .unwrap();
        assert_eq!(action(&found, "a"), None);
        assert_eq!(action(&found, "b"), Some("z"));
    }
}
