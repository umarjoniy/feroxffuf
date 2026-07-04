// src/fuzz/wildcard.rs
//
// Wildcard / false-positive detection for fuzz mode.
//
// Mirrors what normal-mode's heuristics.rs does for directory recursion
// (detect_404_like_responses), but scoped to fuzz mode's template+keyword
// model instead of per-directory scans.
//
// Before fuzzing a given template, two probe requests are sent using
// random words (never real wordlist entries) in place of the keyword. If
// both probes come back with an identical (status, content-length,
// word-count, line-count) signature, the target is treating literally
// anything as a hit -- e.g. wildcard DNS routing every subdomain to the
// same catch-all vhost, or a soft-404 page that always returns 200. Left
// unchecked, that would make every single wordlist entry look like a
// "find" -- pure noise rather than signal, and this is a very common
// situation for subdomain/vhost enumeration in particular.
//
// Detected signatures are registered as a real
// crate::filters::WildcardFilter pushed into the SAME shared filter
// chain that -S/-C/-W/-N already flow through (handles.filters.data),
// rather than a hand-rolled parallel check. This means: it is counted in
// the real WildcardsFiltered stat, and --dont-filter disables it with no
// separate code path to keep in sync -- both come for free from reusing
// the real type.

use std::sync::Arc;
use uuid::Uuid;

use crate::{
    event_handlers::Handles,
    filters::WildcardFilter,
    response::FeroxResponse,
    fuzz::input::InputMap,
    fuzz::prepare::{prepare, RequestTemplate},
    config::OutputLevel,
    progress::PROGRESS_PRINTER,
    utils::ferox_print,
};

/// A random word that is astronomically unlikely to exist on the target,
/// for use as a wildcard-detection probe. Uses the same UUIDv4 mechanism
/// as heuristics::Heuristics::unique_string, truncated to 16 characters
/// so it still resembles a plausible path/subdomain segment rather than
/// a 32-character blob.
fn random_probe_word() -> String {
    let full = Uuid::new_v4().as_simple().to_string();
    full[..16].to_string()
}

/// Probe `template` with a couple of random words substituted for
/// `keyword`. If the target answers identically to both -- despite them
/// being guaranteed-nonexistent -- registers a WildcardFilter on
/// `handles` so the real scan doesn't report that same signature as a
/// hit for every subsequent request.
///
/// No-ops (sends no probe requests at all) when --dont-filter is set,
/// matching normal mode's semantics exactly. Also no-ops silently if a
/// probe request fails outright (e.g. target unreachable) -- that's the
/// real scan's problem to surface, not this function's job to guess at.
pub async fn detect_and_register_wildcard(
    handles:      &Arc<Handles>,
    template:     &RequestTemplate,
    placeholders: &[String],
    fuzz_client:  &reqwest::Client,
) {
    if handles.config.dont_filter {
        return;
    }

    let mut signatures: Vec<(u16, u64, usize, usize)> = Vec::with_capacity(2);

    for _ in 0..2 {
        let mut input = InputMap::new();
        for ph in placeholders {
            input.insert(ph.clone(), random_probe_word().into_bytes());
        }
        let req = prepare(template, &input);

        let Ok(method) = reqwest::Method::from_bytes(req.method.as_bytes()) else { return; };
        let mut rb = fuzz_client.request(method, &req.url);
        for (k, v) in &req.headers { rb = rb.header(k, v); }
        if let Some(host) = &req.host { rb = rb.header("Host", host); }
        if !req.body.is_empty() { rb = rb.body(req.body.clone()); }

        let response = match rb.send().await {
            Ok(r) => r,
            Err(_) => return, // can't probe -- let the real scan's own error handling surface it
        };

        let ferox_resp = FeroxResponse::from(
            response, &req.url, &req.method,
            handles.config.output_level, handles.config.response_size_limit,
        ).await;

        signatures.push((
            ferox_resp.status().as_u16(),
            ferox_resp.content_length(),
            ferox_resp.word_count(),
            ferox_resp.line_count(),
        ));
    }

    if !signatures_indicate_wildcard(&signatures) {
        return;
    }

    let (status, size, words, lines) = signatures[0];

    log::warn!(
        "Wildcard-like response detected (status {status}, {size} bytes, \
         {words} words, {lines} lines) -- random probe words all matched. \
         Auto-filtering that signature for this scan. Use --dont-filter \
         to disable this."
    );

    let mut filter = WildcardFilter::new(handles.config.dont_filter);
    filter.status_code    = status;
    filter.content_length = Some(size);
    filter.word_count     = Some(words);
    filter.line_count     = Some(lines);
    filter.method         = template.method.clone();

    if matches!(handles.config.output_level, OutputLevel::Default | OutputLevel::Quiet) {
        ferox_print(&format!("{filter}"), &PROGRESS_PRINTER);
    }

    let _ = handles.filters.data.push(Box::new(filter));
}

/// True if all collected probe signatures are identical -- i.e. the
/// target answered guaranteed-nonexistent requests with the same
/// (status, content-length, word-count, line-count) every time, which
/// is the signature of wildcard/catch-all behaviour rather than real
/// per-word differences. Pulled out as its own pure function so the
/// decision logic is testable without any network I/O, separately from
/// the end-to-end probe-and-register flow (which does need a real or
/// mocked HTTP round trip and is covered by the httpmock tests below).
fn signatures_indicate_wildcard(sigs: &[(u16, u64, usize, usize)]) -> bool {
    sigs.len() == 2 && sigs[0] == sigs[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use httpmock::{Method::GET, MockServer};
    use crate::config::Configuration;

    #[test]
    fn random_probe_word_is_16_chars_and_varies() {
        let a = random_probe_word();
        let b = random_probe_word();
        assert_eq!(a.len(), 16);
        assert_eq!(b.len(), 16);
        assert_ne!(a, b, "two probes must not collide");
    }

    // ── End-to-end: real HTTP round trip against a mock server,
    //    verifying the full detect -> register-filter pipeline ──

    #[tokio::test]
    async fn wildcard_detection_registers_filter_when_probes_match() {
        let srv = MockServer::start();

        // No .path() constraint on `when` -- matches ANY path under GET,
        // simulating a catch-all vhost / soft-404 that answers identically
        // no matter what's requested. The two random probe words will hit
        // two different (nonexistent) paths and both get this same reply.
        let _mock = srv.mock(|when, then| {
            when.method(GET);
            then.status(200).body("nothing here, sorry!");
        });

        let mut config = Configuration::default();
        config.target_url = srv.url("/FUZZ");

        let (handles, _rx) = Handles::for_testing(None, Some(Arc::new(config.clone())));
        let handles = Arc::new(handles);

        let template = RequestTemplate {
            method:  "GET".into(),
            url:     config.target_url.clone(),
            headers: HashMap::new(),
            body:    vec![],
        };

        detect_and_register_wildcard(&handles, &template, &[ "FUZZ".to_string() ], &handles.config.client).await;

        let registered = handles.filters.data.filters.read().unwrap().len();
        assert_eq!(registered, 1, "a wildcard filter should have been registered");
    }

    // ── Pure decision-logic tests (no network I/O) -- these exercise the
    //    exact comparison used by detect_and_register_wildcard, without
    //    depending on any httpmock feature beyond what's already proven
    //    safe above (static status+body matching any request) ──

    #[test]
    fn identical_signatures_indicate_wildcard() {
        let sigs = vec![(200u16, 42u64, 5usize, 2usize), (200u16, 42u64, 5usize, 2usize)];
        assert!(signatures_indicate_wildcard(&sigs));
    }

    #[test]
    fn differing_status_does_not_indicate_wildcard() {
        let sigs = vec![(200u16, 42u64, 5usize, 2usize), (404u16, 42u64, 5usize, 2usize)];
        assert!(!signatures_indicate_wildcard(&sigs));
    }

    #[test]
    fn differing_size_does_not_indicate_wildcard() {
        let sigs = vec![(200u16, 42u64, 5usize, 2usize), (200u16, 99u64, 5usize, 2usize)];
        assert!(!signatures_indicate_wildcard(&sigs));
    }

    #[test]
    fn fewer_than_two_signatures_never_indicates_wildcard() {
        assert!(!signatures_indicate_wildcard(&[]));
        assert!(!signatures_indicate_wildcard(&[(200, 1, 1, 1)]));
    }

    #[tokio::test]
    async fn wildcard_detection_registers_nothing_when_target_unreachable() {
        // Port 1 is reserved/unassigned -- connection fails immediately.
        // A failed probe must bail out quietly rather than register a
        // (bogus) filter based on incomplete data.
        let mut config = Configuration::default();
        config.target_url = "http://127.0.0.1:1/FUZZ".into();

        let (handles, _rx) = Handles::for_testing(None, Some(Arc::new(config.clone())));
        let handles = Arc::new(handles);

        let template = RequestTemplate {
            method:  "GET".into(),
            url:     config.target_url.clone(),
            headers: HashMap::new(),
            body:    vec![],
        };

        detect_and_register_wildcard(&handles, &template, &[ "FUZZ".to_string() ], &handles.config.client).await;

        let registered = handles.filters.data.filters.read().unwrap().len();
        assert_eq!(registered, 0, "an unreachable target must not register a filter");
    }

    #[tokio::test]
    async fn dont_filter_flag_skips_probing_entirely() {
        let srv = MockServer::start();
        let mock = srv.mock(|when, then| {
            when.method(GET);
            then.status(200).body("same every time");
        });

        let mut config = Configuration::default();
        config.target_url  = srv.url("/FUZZ");
        config.dont_filter = true;

        let (handles, _rx) = Handles::for_testing(None, Some(Arc::new(config.clone())));
        let handles = Arc::new(handles);

        let template = RequestTemplate {
            method:  "GET".into(),
            url:     config.target_url.clone(),
            headers: HashMap::new(),
            body:    vec![],
        };

        detect_and_register_wildcard(&handles, &template, &[ "FUZZ".to_string() ], &handles.config.client).await;

        mock.assert_hits(0); // --dont-filter must skip probing, not just skip registering
        let registered = handles.filters.data.filters.read().unwrap().len();
        assert_eq!(registered, 0);
    }
}
