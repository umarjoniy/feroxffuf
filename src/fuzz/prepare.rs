// src/fuzz/prepare.rs — keyword substitution in all request fields.
// Mirrors ffuf runner/simple.go Prepare(): ReplaceAll across Method, URL, Headers, Body.
// Longer keywords replaced first to prevent FUZZ/FUZZ2 substring conflicts.
// Host header extracted to PreparedRequest::host (mirrors ffuf's httpreq.Host).
//
// Body substitution operates on raw bytes (never round-trips through
// String::from_utf8_lossy) so binary payloads -- file uploads, multipart
// bodies, non-UTF8 fuzzing targets -- are not corrupted by lossy
// replacement-character substitution. Method/URL/headers are substituted
// as UTF-8 text, which is correct per HTTP semantics (these fields are
// always text).

use std::collections::HashMap;
use crate::fuzz::input::InputMap;

#[derive(Debug, Clone)]
pub struct RequestTemplate {
    pub method:  String,
    pub url:     String,
    pub headers: HashMap<String, String>,
    pub body:    Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PreparedRequest {
    pub method:  String,
    pub url:     String,
    pub headers: HashMap<String, String>,
    pub body:    Vec<u8>,
    pub host:    Option<String>,
    pub input:   InputMap,
}

pub fn prepare(tmpl: &RequestTemplate, input: &InputMap) -> PreparedRequest {
    let mut subs: Vec<(&String, &Vec<u8>)> = input.iter().collect();
    subs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    let method = sub_str(&tmpl.method, &subs);
    let url    = sub_str(&tmpl.url,    &subs);
    let body   = sub_bytes(&tmpl.body, &subs);
    let mut headers = HashMap::new();
    for (k, v) in &tmpl.headers {
        headers.insert(sub_str(k, &subs), sub_str(v, &subs));
    }
    let host = headers.remove("Host").or_else(|| headers.remove("host"));
    PreparedRequest { method, url, headers, body, host, input: input.clone() }
}

/// Text-field substitution (Method, URL, header names/values).
/// These are always text per HTTP semantics, so a UTF-8 String round-trip
/// is safe and simplest.
fn sub_str(s: &str, subs: &[(&String, &Vec<u8>)]) -> String {
    let mut out = s.to_string();
    for (kw, val) in subs {
        let replacement = String::from_utf8_lossy(val);
        out = out.replace(kw.as_str(), &replacement);
        let kw_lower = kw.to_lowercase();
        if kw_lower != **kw {
            out = out.replace(&kw_lower, &replacement);
        }
    }
    out
}

/// Byte-level substitution for the request body.
/// Never converts through String::from_utf8_lossy, so arbitrary binary
/// content (file uploads, non-UTF8 fuzz targets) round-trips exactly.
/// Keyword patterns themselves are still UTF-8 text (they come from the
/// CLI), so we search for their raw bytes within the body byte stream.
fn sub_bytes(b: &[u8], subs: &[(&String, &Vec<u8>)]) -> Vec<u8> {
    if b.is_empty() { return Vec::new(); }
    let mut out = b.to_vec();
    for (kw, val) in subs {
        out = replace_bytes(&out, kw.as_bytes(), val);
    }
    out
}

/// Naive but correct byte-string find-and-replace-all.
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() { return haystack.to_vec(); }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}
