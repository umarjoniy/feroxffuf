// src/fuzz/input/sniper.rs
// Sniper mode: each FUZZ occurrence in the template is a numbered position.
// Active position receives the current word; all others receive empty string.
// No special keyboard characters needed.

use super::{InputMap, InputProvider, WordlistSource};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SniperPos { pub keyword: String }

/// Replace every occurrence of `keyword` in `s` with synthetic keys __S0__, __S1__, ...
/// `offset` continues numbering across multiple fields.
pub fn index_positions(s: &str, keyword: &str, offset: usize) -> (String, Vec<SniperPos>) {
    let mut out  = String::with_capacity(s.len());
    let mut pos  = Vec::new();
    let mut rest = s;
    let kw_upper = keyword.to_uppercase();
    let kw_lower = keyword.to_lowercase();
    while let Some(i) = {
        let i_upper = rest.find(&kw_upper);
        let i_lower = rest.find(&kw_lower);
        match (i_upper, i_lower) {
            (Some(u), Some(l)) => Some(std::cmp::min(u, l)),
            (Some(u), None) => Some(u),
            (None, Some(l)) => Some(l),
            (None, None) => None,
        }
    } {
        out.push_str(&rest[..i]);
        let synth = format!("__S{}__", offset + pos.len());
        out.push_str(&synth);
        pos.push(SniperPos { keyword: synth });
        rest = &rest[i + keyword.len()..];
    }
    out.push_str(rest);
    (out, pos)
}

pub fn index_positions_bytes(s: &[u8], keyword: &[u8], offset: usize) -> (Vec<u8>, Vec<SniperPos>) {
    let mut out  = Vec::with_capacity(s.len());
    let mut pos  = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.windows(keyword.len()).position(|window| window == keyword) {
        out.extend_from_slice(&rest[..i]);
        let synth = format!("__S{}__", offset + pos.len());
        out.extend_from_slice(synth.as_bytes());
        pos.push(SniperPos { keyword: synth });
        rest = &rest[i + keyword.len()..];
    }
    out.extend_from_slice(rest);
    (out, pos)
}

pub struct SniperProvider {
    wordlist:  Arc<Vec<String>>,
    positions: Vec<SniperPos>,
    active:    usize,
    word_idx:  Option<usize>,
    done:      bool,
}
impl SniperProvider {
    pub fn new(source: WordlistSource, positions: Vec<SniperPos>) -> anyhow::Result<Self> {
        if source.is_empty()    { anyhow::bail!("Sniper wordlist is empty"); }
        if positions.is_empty() {
            anyhow::bail!(
                "Sniper: keyword '{}' not found in URL/headers/body. \
                 Place it where you want positions to cycle.",
                source.keyword
            );
        }
        Ok(Self { wordlist: source.entries, positions, active: 0, word_idx: None, done: false })
    }
    pub fn total(&self) -> usize { self.positions.len() * self.wordlist.len() }
}
impl InputProvider for SniperProvider {
    fn next(&mut self) -> bool {
        if self.done { return false; }
        let nw = match self.word_idx { None => 0, Some(w) => w + 1 };
        if nw < self.wordlist.len() { self.word_idx = Some(nw); return true; }
        let np = self.active + 1;
        if np >= self.positions.len() { self.done = true; return false; }
        self.active = np; self.word_idx = Some(0); true
    }
    fn value(&self) -> InputMap {
        let wi   = self.word_idx.expect("value() before next()");
        let word = self.wordlist[wi].as_bytes().to_vec();
        self.positions.iter().enumerate().map(|(i, p)| {
            let v = if i == self.active { word.clone() } else { b"".to_vec() };
            (p.keyword.clone(), v)
        }).collect()
    }
    fn total(&self)    -> usize       { self.total() }
    fn reset(&mut self)               { self.active = 0; self.word_idx = None; self.done = false; }
    fn keywords(&self) -> Vec<String> { self.positions.iter().map(|p| p.keyword.clone()).collect() }
}
