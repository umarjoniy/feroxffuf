// src/fuzz/input/mod.rs
pub mod sniper;

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{bail, Context, Result};
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};

pub type InputMap = HashMap<String, Vec<u8>>;

/// A wordlist bound to a keyword.
/// `entries` is Arc-wrapped so cloning a WordlistSource (e.g. once per
/// recursion depth) is O(1) instead of deep-copying every word.
#[derive(Debug, Clone)]
pub struct WordlistSource {
    pub keyword: String,
    pub entries: Arc<Vec<String>>,
}
impl WordlistSource {
    pub fn new(k: impl Into<String>, e: Vec<String>) -> Self {
        Self { keyword: k.into(), entries: Arc::new(e) }
    }
    pub fn len(&self)      -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool  { self.entries.is_empty() }
}

pub trait InputProvider: Send + Sync {
    fn next(&mut self) -> bool;
    fn value(&self)    -> InputMap;
    fn total(&self)    -> usize;
    fn reset(&mut self);
    fn keywords(&self) -> Vec<String>;
}

// ── Pitchfork ────────────────────────────────────────────────────────────
pub struct PitchforkProvider {
    sources: Vec<WordlistSource>,
    pos:     Option<usize>,
    total:   usize,
    done:    bool,
}
impl PitchforkProvider {
    pub fn new(sources: Vec<WordlistSource>) -> Self {
        let total = sources.iter().map(|s| s.len()).min().unwrap_or(0);
        Self { sources, pos: None, total, done: total == 0 }
    }
}
impl InputProvider for PitchforkProvider {
    fn next(&mut self) -> bool {
        if self.done { return false; }
        let n = match self.pos { None => 0, Some(p) => p + 1 };
        if n >= self.total { self.done = true; return false; }
        self.pos = Some(n); true
    }
    fn value(&self) -> InputMap {
        let p = self.pos.expect("value() before next()");
        self.sources.iter().map(|s| (s.keyword.clone(), s.entries[p].as_bytes().to_vec())).collect()
    }
    fn total(&self)    -> usize       { self.total }
    fn reset(&mut self)               { self.pos = None; self.done = self.total == 0; }
    fn keywords(&self) -> Vec<String> { self.sources.iter().map(|s| s.keyword.clone()).collect() }
}

// ── ClusterBomb ──────────────────────────────────────────────────────────
pub struct ClusterBombProvider {
    sources:  Vec<WordlistSource>,
    counters: Vec<usize>,
    total:    usize,
    started:  bool,
    done:     bool,
}
impl ClusterBombProvider {
    pub fn new(sources: Vec<WordlistSource>) -> Self {
        let total: usize = sources.iter().map(|s| s.len()).product();
        Self { counters: vec![0; sources.len()], sources, total, started: false, done: false }
    }
}
impl InputProvider for ClusterBombProvider {
    fn next(&mut self) -> bool {
        if self.done { return false; }
        if !self.started {
            self.started = true;
            return !self.sources.iter().any(|s| s.is_empty());
        }
        let mut carry = true;
        for i in (0..self.counters.len()).rev() {
            if carry {
                self.counters[i] += 1;
                if self.counters[i] >= self.sources[i].len() { self.counters[i] = 0; }
                else { carry = false; }
            }
        }
        if carry { self.done = true; return false; }
        true
    }
    fn value(&self) -> InputMap {
        self.sources.iter().enumerate()
            .map(|(i, s)| (s.keyword.clone(), s.entries[self.counters[i]].as_bytes().to_vec()))
            .collect()
    }
    fn total(&self)    -> usize       { self.total }
    fn reset(&mut self)               { self.counters.iter_mut().for_each(|c| *c=0); self.started=false; self.done=false; }
    fn keywords(&self) -> Vec<String> { self.sources.iter().map(|s| s.keyword.clone()).collect() }
}

// ── I/O ──────────────────────────────────────────────────────────────────
/// Parse `-w path/to/file.txt:KEYWORD`. Last colon splits path from keyword.
pub fn parse_wordlist_arg(arg: &str) -> (&str, &str) {
    match arg.rfind(':') {
        Some(pos) if pos < arg.len() - 1 => {
            let kw = &arg[pos + 1..];
            if kw.contains('/') || kw.contains('\\') { (arg, "FUZZ") }
            else { (&arg[..pos], kw) }
        }
        _ => (arg, "FUZZ"),
    }
}

pub async fn load_wordlist(path: &Path) -> Result<Vec<String>> {
    let file = File::open(path).await
        .with_context(|| format!("Cannot open wordlist: {}", path.display()))?;
    let mut out = Vec::new();
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    while let Ok(bytes_read) = reader.read_until(b'\n', &mut buf).await {
        if bytes_read == 0 { break; }
        let line = String::from_utf8_lossy(&buf);
        let t = line.trim().to_string();
        if !t.is_empty() && !t.starts_with('#') { out.push(t); }
        buf.clear();
    }
    if out.is_empty() { bail!("Wordlist {} is empty", path.display()); }
    Ok(out)
}

/// Expand each wordlist entry with configured extensions, mirroring
/// normal-mode's FeroxUrl::formatted_urls (src/url.rs): for word "admin"
/// with extensions ["php", "html"], produces
/// ["admin", "admin.php", "admin.html"] -- the bare word is always kept
/// first, exactly like formatted_urls always pushes the no-extension URL
/// before any extension variants.
///
/// A no-op (returns entries unchanged) when extensions is empty, so
/// callers can apply this unconditionally without a branch.
///
/// This exists because -x is otherwise silently ignored in fuzz mode:
/// normal-mode's extension-appending lives inside scanner::requester::
/// Requester::request(), which FuzzJob never calls (it builds requests
/// directly via prepare()). Without this, `-x php` would work in normal
/// mode and do nothing in fuzz mode -- exactly the kind of behavioral
/// mismatch this project has been hunting throughout.
pub fn expand_with_extensions(entries: &[String], extensions: &[String]) -> Vec<String> {
    if extensions.is_empty() {
        return entries.to_vec();
    }
    let mut out = Vec::with_capacity(entries.len() * (extensions.len() + 1));
    for entry in entries {
        out.push(entry.clone());
        for ext in extensions {
            let ext = ext.trim_start_matches('.');
            out.push(format!("{entry}.{ext}"));
        }
    }
    out
}
