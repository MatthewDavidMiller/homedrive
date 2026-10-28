//! Strict JSON: a parser for the records this project reads from disk and
//! stdin, and the escaping its writers share.
//!
//! The parser accepts RFC 8259 JSON and nothing looser -- no comments, no
//! trailing commas, no lone surrogates, no invalid UTF-8 -- and additionally
//! refuses a repeated object key at any depth, because a duplicate is how a
//! crafted record makes two readers disagree about one field. Nesting is
//! capped at 128 levels, and the memory a document may occupy at 64 times its
//! length plus 64 KiB.

use std::fmt;

const MAX_DEPTH: usize = 128;
/// What one parsed value costs against the document's budget: the node size
/// of the C implementation this replaced, so 3.0.0 refuses exactly the
/// documents 2.x did.
const NODE_COST: usize = 80;
const SLOT_COST: usize = 8;

/// A JSON number, keeping its lexical class: an integer literal has no
/// fraction or exponent, and a typed reader that wants an integer refuses
/// `1.0`, exactly as serde does.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Number {
    integer: bool,
    negative: bool,
    /// The magnitude of an integer literal, or `None` when it overflows u64.
    magnitude: Option<u64>,
    value: f64,
}

impl Number {
    pub fn as_f64(&self) -> f64 {
        self.value
    }

    pub fn is_integer(&self) -> bool {
        self.integer
    }

    pub fn as_u64(&self) -> Option<u64> {
        if !self.integer {
            return None;
        }
        let m = self.magnitude?;
        if self.negative && m != 0 { None } else { Some(m) }
    }

    pub fn as_i64(&self) -> Option<i64> {
        if !self.integer {
            return None;
        }
        let m = self.magnitude?;
        if self.negative { 0_i64.checked_sub_unsigned(m) } else { i64::try_from(m).ok() }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    /// Members in document order; keys are unique.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member named `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// True when this is an object whose every key is in `allowed` --
    /// serde's `deny_unknown_fields`.
    pub fn only_keys(&self, allowed: &[&str]) -> bool {
        match self {
            Value::Object(members) => members.iter().all(|(k, _)| allowed.contains(&k.as_str())),
            _ => false,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(n.value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// A string with no embedded NUL, which no consumer here can carry.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) if !s.contains('\0') => Some(s),
            _ => None,
        }
    }

    /// A string as parsed, NUL included.
    pub fn as_raw_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Zeroes every string the document holds, for documents that carried
    /// secrets.
    pub fn wipe(&mut self) {
        match self {
            Value::String(s) => crate::buf::wipe_string(s),
            Value::Array(items) => items.iter_mut().for_each(Value::wipe),
            Value::Object(members) => {
                for (k, v) in members.iter_mut() {
                    crate::buf::wipe_string(k);
                    v.wipe();
                }
            }
            _ => {}
        }
    }
}

/// Why a document was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError(&'static str);

impl ParseError {
    pub fn message(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ParseError {}

/// Parses a whole document with the default budget.
pub fn parse(text: &[u8]) -> Result<Value, ParseError> {
    let budget = text.len().saturating_mul(64).saturating_add(65536);
    parse_with_budget(text, budget)
}

/// Parses a whole document that may occupy at most `budget` bytes.
pub fn parse_with_budget(text: &[u8], budget: usize) -> Result<Value, ParseError> {
    if std::str::from_utf8(text).is_err() {
        return Err(ParseError("JSON is not valid UTF-8"));
    }
    let mut p = Parser { s: text, pos: 0, depth: 0, budget };
    let root = p.value()?;
    p.skip_ws();
    if p.pos != text.len() {
        return Err(ParseError("trailing characters after JSON"));
    }
    Ok(root)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    depth: usize,
    budget: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn charge(&mut self, bytes: usize) -> Result<(), ParseError> {
        let rounded = bytes.div_ceil(16).saturating_mul(16);
        self.budget =
            self.budget.checked_sub(rounded).ok_or(ParseError("JSON document too large"))?;
        Ok(())
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), ParseError> {
        if self.s[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(ParseError("invalid JSON literal"))
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let digits =
            self.s.get(self.pos..self.pos + 4).ok_or(ParseError("truncated JSON escape"))?;
        let mut v = 0;
        for &d in digits {
            let n = char::from(d).to_digit(16).ok_or(ParseError("invalid JSON escape"))?;
            v = (v << 4) | n;
        }
        self.pos += 4;
        Ok(v)
    }

    /// Parses a string body; the caller has consumed the opening quote.
    fn string(&mut self) -> Result<String, ParseError> {
        let mut text: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or(ParseError("unterminated JSON string"))?;
            match c {
                b'"' => {
                    self.pos += 1;
                    break;
                }
                0..0x20 => return Err(ParseError("control character in JSON string")),
                b'\\' => {
                    self.pos += 1;
                    let e = self.peek().ok_or(ParseError("truncated JSON escape"))?;
                    self.pos += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode_escape()?,
                        _ => return Err(ParseError("invalid JSON escape")),
                    };
                    let mut utf8 = [0; 4];
                    text.extend_from_slice(ch.encode_utf8(&mut utf8).as_bytes());
                }
                _ => {
                    // The run of plain bytes; UTF-8 validity was checked up
                    // front and the run ends only at ASCII bytes.
                    let start = self.pos;
                    while matches!(self.peek(), Some(d) if d != b'"' && d != b'\\' && d >= 0x20) {
                        self.pos += 1;
                    }
                    text.extend_from_slice(&self.s[start..self.pos]);
                }
            }
        }
        self.charge(text.len() + 1)?;
        String::from_utf8(text).map_err(|_| ParseError("JSON is not valid UTF-8"))
    }

    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let mut cp = self.hex4()?;
        if (0xDC00..=0xDFFF).contains(&cp) {
            return Err(ParseError("lone JSON surrogate"));
        }
        if (0xD800..=0xDBFF).contains(&cp) {
            if !self.s[self.pos..].starts_with(b"\\u") {
                return Err(ParseError("lone JSON surrogate"));
            }
            self.pos += 2;
            let low = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(ParseError("lone JSON surrogate"));
            }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
        }
        char::from_u32(cp).ok_or(ParseError("invalid JSON escape"))
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<Number, ParseError> {
        const INVALID: ParseError = ParseError("invalid JSON number");
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(INVALID);
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(INVALID),
        }
        let int_end = self.pos;
        let mut integer = true;
        if self.peek() == Some(b'.') {
            integer = false;
            self.pos += 1;
            if self.digits() == 0 {
                return Err(INVALID);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integer = false;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(INVALID);
            }
        }
        let digits_start = start + usize::from(negative);
        let magnitude = if integer {
            self.s[digits_start..int_end]
                .iter()
                .try_fold(0_u64, |m, &d| m.checked_mul(10)?.checked_add(u64::from(d - b'0')))
        } else {
            None
        };
        let literal = &self.s[start..self.pos];
        if literal.len() >= 64 {
            // Longer literals are legal JSON but nothing this project reads
            // needs them.
            if integer {
                let value = if negative { f64::NEG_INFINITY } else { f64::INFINITY };
                return Ok(Number { integer, negative, magnitude: None, value });
            }
            return Err(ParseError("JSON number too long"));
        }
        let value =
            std::str::from_utf8(literal).ok().and_then(|t| t.parse::<f64>().ok()).ok_or(INVALID)?;
        if !value.is_finite() && !integer {
            return Err(ParseError("non-finite JSON number"));
        }
        Ok(Number { integer, negative, magnitude, value })
    }

    fn value(&mut self) -> Result<Value, ParseError> {
        self.skip_ws();
        let c = self.peek().ok_or(ParseError("unexpected end of JSON"))?;
        self.charge(NODE_COST)?;
        match c {
            b'n' => self.literal(b"null").map(|()| Value::Null),
            b't' => self.literal(b"true").map(|()| Value::Bool(true)),
            b'f' => self.literal(b"false").map(|()| Value::Bool(false)),
            b'"' => {
                self.pos += 1;
                self.string().map(Value::String)
            }
            b'[' | b'{' => self.container(c == b'{'),
            b'-' | b'0'..=b'9' => self.number().map(Value::Number),
            _ => Err(ParseError("unexpected JSON character")),
        }
    }

    fn container(&mut self, object: bool) -> Result<Value, ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ParseError("JSON nested too deeply"));
        }
        self.pos += 1;
        let close = if object { b'}' } else { b']' };
        let mut items = Vec::new();
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(close) {
            self.pos += 1;
            self.depth -= 1;
            return Ok(if object { Value::Object(members) } else { Value::Array(items) });
        }
        loop {
            self.charge(if object { SLOT_COST * 3 } else { SLOT_COST })?;
            let key = if object {
                self.skip_ws();
                if self.peek() != Some(b'"') {
                    return Err(ParseError("expected JSON object key"));
                }
                self.pos += 1;
                let key = self.string()?;
                if members.iter().any(|(k, _)| *k == key) {
                    return Err(ParseError("duplicate JSON key"));
                }
                self.skip_ws();
                if self.peek() != Some(b':') {
                    return Err(ParseError("expected ':' in JSON object"));
                }
                self.pos += 1;
                Some(key)
            } else {
                None
            };
            let item = self.value()?;
            match key {
                Some(k) => members.push((k, item)),
                None => items.push(item),
            }
            self.skip_ws();
            let sep = self.peek().ok_or(ParseError("unexpected end of JSON"))?;
            self.pos += 1;
            if sep == b',' {
                continue;
            }
            if sep == close {
                break;
            }
            return Err(ParseError("expected ',' in JSON container"));
        }
        self.depth -= 1;
        Ok(if object { Value::Object(members) } else { Value::Array(items) })
    }
}

/// Appends `s` as a quoted JSON string with serde_json's escaping.
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    let mut run = 0;
    for (i, b) in s.bytes().enumerate() {
        let escape: Option<&str> = match b {
            b'"' => Some("\\\""),
            b'\\' => Some("\\\\"),
            0x08 => Some("\\b"),
            0x0c => Some("\\f"),
            b'\n' => Some("\\n"),
            b'\r' => Some("\\r"),
            b'\t' => Some("\\t"),
            0..0x20 => None,
            _ => {
                continue;
            }
        };
        out.push_str(&s[run..i]);
        run = i + 1;
        if let Some(e) = escape {
            out.push_str(e);
        } else {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.push_str("\\u00");
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        }
    }
    out.push_str(&s[run..]);
    out.push('"');
}

/// `s` as a quoted JSON string.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    write_string(&mut out, s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Value {
        parse(text.as_bytes()).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn duplicate_keys_are_rejected_at_every_depth() {
        for bad in [
            "{\"schema\":1,\"schema\":1}",
            "{\"outer\":{\"value\":1,\"value\":2}}",
            "[{\"a\":1,\"a\":1}]",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
        ok("{\"schema\":1}");
    }

    #[test]
    fn strict_grammar() {
        let bad: [&[u8]; 22] = [
            b"",
            b"{",
            b"[1,]",
            b"{\"a\":1,}",
            b"01",
            b"1.",
            b".5",
            b"-",
            b"+1",
            b"\"\\x\"",
            b"\"\x01\"",
            b"\"\\ud800\"",
            b"\"\\udc00\"",
            b"nul",
            b"true false",
            b"{\"a\" 1}",
            b"[1 2]",
            b"\"\xff\"",
            b"\"\xc0\x80\"",
            b"\"\xed\xa0\x80\"",
            b"1e",
            b"NaN",
        ];
        for text in bad {
            assert!(parse(text).is_err(), "accepted {:?}", String::from_utf8_lossy(text));
        }
        let v = ok(" {\"s\":\"a\\u00e9\\ud83d\\ude00\\n\",\"n\":-12,\"f\":1.5e2,\
                     \"b\":true,\"z\":null,\"a\":[]} ");
        assert_eq!(v.get("s").and_then(Value::as_str), Some("a\u{e9}\u{1f600}\n"));
        assert_eq!(v.get("n").and_then(Value::as_i64), Some(-12));
        assert_eq!(v.get("n").and_then(Value::as_u64), None);
        assert_eq!(v.get("f").and_then(Value::as_u64), None);
        assert_eq!(v.get("f").and_then(Value::as_f64), Some(150.0));
        assert_eq!(v.get("b").and_then(Value::as_bool), Some(true));
        assert!(v.get("z").is_some_and(Value::is_null));
        assert!(v.only_keys(&["s", "n", "f", "b", "z", "a"]));
        assert!(!v.only_keys(&["s", "n", "f", "b", "z"]));
        // An embedded NUL is legal JSON but never a usable string here.
        let v = ok("\"a\\u0000b\"");
        assert_eq!(v.as_raw_str().map(str::len), Some(3));
        assert_eq!(v.as_str(), None);
    }

    #[test]
    fn integers_keep_their_range() {
        assert_eq!(ok("-9223372036854775808").as_i64(), Some(i64::MIN));
        assert_eq!(ok("-9223372036854775809").as_i64(), None);
        assert_eq!(ok("18446744073709551615").as_u64(), Some(u64::MAX));
        assert_eq!(ok("18446744073709551616").as_u64(), None);
        assert_eq!(ok("-0").as_u64(), Some(0));
    }

    #[test]
    fn depth_is_bounded() {
        let deep = format!("{}{}", "[".repeat(300), "]".repeat(300));
        assert!(parse(deep.as_bytes()).is_err());
        let fine = format!("{}{}", "[".repeat(100), "]".repeat(100));
        assert!(parse(fine.as_bytes()).is_ok());
    }

    #[test]
    fn write_string_matches_serde() {
        assert_eq!(quote("a\"b\\c\n\x01/\x7f\u{e9}"), "\"a\\\"b\\\\c\\n\\u0001/\x7f\u{e9}\"");
    }
}
