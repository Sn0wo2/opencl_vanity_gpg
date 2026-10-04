use regex_syntax::hir::{self, HirKind, Look};
use std::fmt;

const MAX_PATTERN: usize = 16;
const LINE_LEN: usize = 80;
const LINE_CONST: &[u8; 36] = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Contains = 0,
    Suffix = 1,
    Prefix = 2,
}

#[derive(Debug, Clone)]
pub(super) struct Filter {
    pub(super) masks: [u64; MAX_PATTERN],
    pub(super) len: u32,
    pub(super) mode: Mode,
}

#[derive(Debug)]
pub(super) enum FilterError {
    Unsupported(String),
    NeverMatches(String),
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterError::Unsupported(why) => write!(
                f,
                "regex cannot be prefiltered on the GPU ({why}); \
                 only concatenations of literals and character classes over the \
                 base64 alphabet are supported"
            ),
            FilterError::NeverMatches(why) => {
                write!(f, "regex can never match an authorized_keys line ({why})")
            }
        }
    }
}

impl std::error::Error for FilterError {}

fn b64_index(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn byte_mask(c: u8) -> Result<u64, FilterError> {
    match b64_index(c) {
        Some(i) => Ok(1u64 << i),
        None => Err(FilterError::Unsupported(format!(
            "byte 0x{c:02x} is not in the base64 alphabet"
        ))),
    }
}

fn class_mask(class: &hir::Class) -> Result<u64, FilterError> {
    let mut mask = 0u64;
    match class {
        hir::Class::Unicode(u) => {
            for r in u.ranges() {
                for c in r.start()..=r.end() {
                    let mut buf = [0u8; 4];
                    let s = c.encode_utf8(&mut buf);
                    if s.len() != 1 {
                        return Err(FilterError::Unsupported(format!(
                            "non-ASCII character {c:?} in class"
                        )));
                    }
                    mask |= byte_mask(s.as_bytes()[0])?;
                }
            }
        }
        hir::Class::Bytes(b) => {
            for r in b.ranges() {
                for c in r.start()..=r.end() {
                    mask |= byte_mask(c)?;
                }
            }
        }
    }
    if mask == 0 {
        return Err(FilterError::NeverMatches("empty character class".into()));
    }
    Ok(mask)
}

pub(super) fn compile(pattern: &str) -> Result<Filter, FilterError> {
    let hir = regex_syntax::Parser::new()
        .parse(pattern)
        .map_err(|e| FilterError::Unsupported(format!("unparseable regex: {e}")))?;

    let nodes: Vec<&hir::Hir> = match hir.kind() {
        HirKind::Concat(subs) => subs.iter().collect(),
        _ => vec![&hir],
    };

    let mut anchored_start = false;
    let mut anchored_end = false;
    let mut start = 0;
    let mut end = nodes.len();
    if start < end {
        if let HirKind::Look(Look::Start) = nodes[start].kind() {
            anchored_start = true;
            start += 1;
        }
    }
    if start < end {
        if let HirKind::Look(Look::End) = nodes[end - 1].kind() {
            anchored_end = true;
            end -= 1;
        }
    }

    let mut masks: Vec<u64> = Vec::new();
    for node in &nodes[start..end] {
        match node.kind() {
            HirKind::Literal(hir::Literal(bytes)) => {
                for &b in bytes.iter() {
                    masks.push(byte_mask(b)?);
                }
            }
            HirKind::Class(class) => masks.push(class_mask(class)?),
            kind => {
                return Err(FilterError::Unsupported(format!(
                    "unsupported construct: {kind:?}"
                )))
            }
        }
    }

    let plen = masks.len();
    let mode = match (anchored_start, anchored_end) {
        (true, true) => {
            if plen != LINE_LEN {
                return Err(FilterError::NeverMatches(format!(
                    "a fully anchored pattern must cover all {LINE_LEN} characters, got {plen}"
                )));
            }
            Mode::Prefix
        }
        (true, false) => Mode::Prefix,
        (false, true) => Mode::Suffix,
        (false, false) => Mode::Contains,
    };

    if masks.len() > MAX_PATTERN {
        match mode {
            Mode::Suffix => masks = masks.split_off(masks.len() - MAX_PATTERN),
            _ => masks.truncate(MAX_PATTERN),
        }
    }

    if mode == Mode::Prefix {
        for (i, &m) in masks.iter().enumerate() {
            if i < LINE_CONST.len() {
                match b64_index(LINE_CONST[i]) {
                    Some(idx) if m & (1u64 << idx) != 0 => {}
                    _ => {
                        return Err(FilterError::NeverMatches(format!(
                            "position {i} conflicts with the constant prefix"
                        )))
                    }
                }
            }
        }
    }

    let mut out = [0u64; MAX_PATTERN];
    out[..masks.len()].copy_from_slice(&masks);
    Ok(Filter {
        masks: out,
        len: masks.len() as u32,
        mode,
    })
}
