// src/fuzz/tests.rs
//
// Black-box tests for the fuzz module's public surface: input providers,
// keyword substitution, sniper position parsing, fuzz-mode detection,
// and recursion config parsing. Job.rs-internal logic (recursion target
// building, which needs access to private items) is tested directly
// inside job.rs's own #[cfg(test)] mod tests instead.

use crate::fuzz::{
    input::{
        ClusterBombProvider, InputMap, InputProvider, PitchforkProvider,
        WordlistSource, expand_with_extensions, parse_wordlist_arg,
    },
    input::sniper::{SniperProvider, index_positions},
    job::{FuzzMode, RecurseConfig, is_fuzz_mode_config},
    prepare::{RequestTemplate, prepare},
};
use crate::config::Configuration;
use std::collections::HashMap;

// ── Helpers ───────────────────────────────────────────────────────────────

fn src(kw: &str, words: &[&str]) -> WordlistSource {
    WordlistSource::new(kw, words.iter().map(|s| s.to_string()).collect())
}

fn w(map: &InputMap, k: &str) -> String {
    String::from_utf8(map[k].clone()).unwrap()
}

fn tmpl(url: &str) -> RequestTemplate {
    RequestTemplate {
        method: "GET".into(), url: url.into(),
        headers: HashMap::new(), body: vec![],
    }
}

fn tmpl_post(url: &str, body: &str) -> RequestTemplate {
    RequestTemplate {
        method: "POST".into(), url: url.into(),
        headers: HashMap::new(), body: body.as_bytes().to_vec(),
    }
}

fn tmpl_with_header(url: &str, k: &str, v: &str) -> RequestTemplate {
    let mut t = tmpl(url);
    t.headers.insert(k.into(), v.into());
    t
}

fn map(pairs: &[(&str, &str)]) -> InputMap {
    pairs.iter().map(|(k, v)| (k.to_string(), v.as_bytes().to_vec())).collect()
}

// ─────────────────────────────────────────────────────────────────────────
// 1. CLI ARG TYPE SAFETY
//    Regression tests for the usize panic that occurred because
//    update_config_if_present!(... usize) was used instead of
//    update_config_with_num_type_if_present!(... usize).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn cli_fuzz_recurse_depth_stored_as_string_parses_to_usize() {
    let app = clap::Command::new("test")
        .arg(clap::Arg::new("fuzz-recurse-depth")
            .long("fuzz-recurse-depth")
            .default_value("4")
            .num_args(1));

    let m = app.clone().get_matches_from(["test"]);
    let s = m.get_one::<String>("fuzz-recurse-depth").unwrap();
    assert_eq!(s.parse::<usize>().unwrap(), 4, "default depth must be 4");

    let m = app.get_matches_from(["test", "--fuzz-recurse-depth", "10"]);
    let s = m.get_one::<String>("fuzz-recurse-depth").unwrap();
    assert_eq!(s.parse::<usize>().unwrap(), 10);
}

#[test]
#[should_panic]
fn cli_broken_get_one_usize_panics_without_value_parser() {
    let app = clap::Command::new("test")
        .arg(clap::Arg::new("fuzz-recurse-depth")
            .long("fuzz-recurse-depth")
            .default_value("4")
            .num_args(1));

    let m = app.get_matches_from(["test"]);
    let _ = m.get_one::<usize>("fuzz-recurse-depth");
}

#[test]
fn cli_mode_values_are_accepted() {
    let app = clap::Command::new("test")
        .arg(clap::Arg::new("mode")
            .long("mode")
            .value_parser(["clusterbomb", "pitchfork", "sniper"])
            .default_value("clusterbomb")
            .num_args(1));

    for mode in &["clusterbomb", "pitchfork", "sniper"] {
        let m = app.clone().get_matches_from(["test", "--mode", mode]);
        assert_eq!(m.get_one::<String>("mode").map(|s| s.as_str()), Some(*mode));
    }
}

#[test]
fn cli_fuzz_recurse_status_parses_as_string() {
    let app = clap::Command::new("test")
        .arg(clap::Arg::new("fuzz-recurse-status")
            .long("fuzz-recurse-status")
            .num_args(1));

    let m = app.get_matches_from(["test", "--fuzz-recurse-status", "200,301"]);
    let raw = m.get_one::<String>("fuzz-recurse-status").unwrap();
    let codes: Vec<u16> = raw.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    assert_eq!(codes, vec![200u16, 301u16]);
}

// ─────────────────────────────────────────────────────────────────────────
// 2. INPUT PROVIDERS
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn pitchfork_zips_and_stops_at_shortest() {
    let mut p = PitchforkProvider::new(vec![
        src("USER", &["a", "b", "c"]),
        src("PASS", &["1", "2"]),
    ]);
    assert_eq!(p.total(), 2);
    let mut pairs = vec![];
    while p.next() {
        pairs.push((w(&p.value(), "USER"), w(&p.value(), "PASS")));
    }
    assert_eq!(pairs, vec![
        ("a".into(), "1".into()),
        ("b".into(), "2".into()),
    ]);
}

#[test]
fn pitchfork_single_wordlist() {
    let mut p = PitchforkProvider::new(vec![src("FUZZ", &["x", "y", "z"])]);
    assert_eq!(p.total(), 3);
    let mut words = vec![];
    while p.next() { words.push(w(&p.value(), "FUZZ")); }
    assert_eq!(words, vec!["x", "y", "z"]);
}

#[test]
fn clusterbomb_total_is_product() {
    let p = ClusterBombProvider::new(vec![
        src("A", &["a", "b"]),
        src("B", &["1", "2", "3"]),
    ]);
    assert_eq!(p.total(), 6);
}

#[test]
fn clusterbomb_rightmost_ticks_fastest() {
    let mut p = ClusterBombProvider::new(vec![
        src("A", &["a", "b"]),
        src("B", &["1", "2"]),
    ]);
    let mut pairs = vec![];
    while p.next() {
        pairs.push((w(&p.value(), "A"), w(&p.value(), "B")));
    }
    assert_eq!(pairs, vec![
        ("a".into(), "1".into()),
        ("a".into(), "2".into()),
        ("b".into(), "1".into()),
        ("b".into(), "2".into()),
    ]);
}

#[test]
fn providers_reset_correctly() {
    let mut p = PitchforkProvider::new(vec![src("FUZZ", &["a", "b"])]);
    while p.next() {}
    p.reset();
    let mut count = 0;
    while p.next() { count += 1; }
    assert_eq!(count, 2);

    let mut p = ClusterBombProvider::new(vec![src("FUZZ", &["x", "y", "z"])]);
    while p.next() {}
    p.reset();
    let mut count = 0;
    while p.next() { count += 1; }
    assert_eq!(count, 3);
}

#[test]
fn wordlist_source_clone_is_cheap_and_shares_data() {
    // Regression: entries is Arc<Vec<String>> so cloning a WordlistSource
    // (e.g. once per recursion depth in run_single_scan) must not deep-copy
    // the underlying words.
    let original = src("FUZZ", &["a", "b", "c"]);
    let cloned = original.clone();
    assert_eq!(cloned.len(), 3);
    assert!(std::sync::Arc::ptr_eq(&original.entries, &cloned.entries),
        "clone should share the same underlying Arc allocation");
}

// ─────────────────────────────────────────────────────────────────────────
// 3. PREPARE -- keyword substitution
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn prepare_substitutes_in_url() {
    let r = prepare(&tmpl("https://t.io/FUZZ"), &map(&[("FUZZ", "admin")]));
    assert_eq!(r.url, "https://t.io/admin");
}

#[test]
fn prepare_multiple_keywords_in_url() {
    let r = prepare(&tmpl("https://t.io/USER/PASS"),
                    &map(&[("USER", "root"), ("PASS", "secret")]));
    assert_eq!(r.url, "https://t.io/root/secret");
}

#[test]
fn prepare_keyword_in_query_string() {
    let r = prepare(&tmpl("https://t.io/?q=FUZZ"), &map(&[("FUZZ", "hello")]));
    assert_eq!(r.url, "https://t.io/?q=hello");
}

#[test]
fn prepare_keyword_in_post_body() {
    let r = prepare(&tmpl_post("https://t.io/login", "user=admin&pass=FUZZ"),
                    &map(&[("FUZZ", "hunter2")]));
    assert_eq!(r.body, b"user=admin&pass=hunter2");
}

#[test]
fn prepare_keyword_in_json_body() {
    let r = prepare(
        &tmpl_post("https://t.io/api", r#"{"user":"USER","pass":"PASS"}"#),
        &map(&[("USER", "admin"), ("PASS", "s3cr3t")]),
    );
    assert_eq!(String::from_utf8(r.body).unwrap(), r#"{"user":"admin","pass":"s3cr3t"}"#);
}

#[test]
fn prepare_host_header_extracted() {
    let r = prepare(
        &tmpl_with_header("https://10.0.0.1/", "Host", "FUZZ.example.com"),
        &map(&[("FUZZ", "api")]),
    );
    assert_eq!(r.host, Some("api.example.com".into()));
    assert!(!r.headers.contains_key("Host"), "Host must be extracted from headers");
    assert!(!r.headers.contains_key("host"));
}

#[test]
fn prepare_custom_header_substituted() {
    let r = prepare(
        &tmpl_with_header("https://t.io/", "X-Token", "FUZZ"),
        &map(&[("FUZZ", "deadbeef")]),
    );
    assert_eq!(r.headers["X-Token"], "deadbeef");
}

#[test]
fn prepare_longer_keyword_wins_over_substring() {
    let r = prepare(
        &tmpl("https://t.io/FUZZ/FUZZ2"),
        &map(&[("FUZZ", "alpha"), ("FUZZ2", "beta")]),
    );
    assert_eq!(r.url, "https://t.io/alpha/beta");
}

#[test]
fn prepare_empty_body_stays_empty() {
    let r = prepare(&tmpl("https://t.io/FUZZ"), &map(&[("FUZZ", "x")]));
    assert!(r.body.is_empty());
}

#[test]
fn prepare_body_preserves_binary_bytes_not_valid_utf8() {
    // Regression: an earlier version routed the body through
    // String::from_utf8_lossy before and after substitution, which
    // replaces invalid byte sequences with U+FFFD (3 bytes each) and
    // corrupts binary payloads (e.g. file-upload multipart fuzzing).
    let mut body: Vec<u8> = b"before-".to_vec();
    body.extend_from_slice(&[0xFF, 0xFE, 0x00, 0xFF]); // invalid UTF-8
    body.extend_from_slice(b"-FUZZ-after");

    let t = RequestTemplate {
        method: "POST".into(),
        url: "https://t.io/upload".into(),
        headers: HashMap::new(),
        body,
    };
    let r = prepare(&t, &map(&[("FUZZ", "X")]));

    // The invalid bytes must survive byte-for-byte, and the keyword must
    // still be substituted correctly around them.
    assert_eq!(&r.body[0..7], b"before-");
    assert_eq!(&r.body[7..11], &[0xFF, 0xFE, 0x00, 0xFF]);
    assert_eq!(&r.body[11..], b"-X-after");
}

#[test]
fn prepare_body_substitution_still_works_for_text() {
    let r = prepare(
        &tmpl_post("https://t.io/x", "a=FUZZ&b=FUZZ&c=static"),
        &map(&[("FUZZ", "REPL")]),
    );
    assert_eq!(r.body, b"a=REPL&b=REPL&c=static");
}

// ─────────────────────────────────────────────────────────────────────────
// 4. SNIPER -- position parsing and iteration
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn index_positions_replaces_occurrences_with_synthetic_keys() {
    let (tmpl, pos) = index_positions("https://t.io/FUZZ?p=FUZZ", "FUZZ", 0);
    assert_eq!(tmpl, "https://t.io/__S0__?p=__S1__");
    assert_eq!(pos.len(), 2);
    assert_eq!(pos[0].keyword, "__S0__");
    assert_eq!(pos[1].keyword, "__S1__");
}

#[test]
fn index_positions_no_keyword_returns_unchanged() {
    let (tmpl, pos) = index_positions("https://t.io/path", "FUZZ", 0);
    assert_eq!(tmpl, "https://t.io/path");
    assert!(pos.is_empty());
}

#[test]
fn index_positions_offset_continues_numbering() {
    let (_, pos1) = index_positions("FUZZ/FUZZ", "FUZZ", 0);
    let (_, pos2) = index_positions("?q=FUZZ", "FUZZ", pos1.len());
    assert_eq!(pos2[0].keyword, "__S2__");
}

#[test]
fn sniper_total_is_positions_times_words() {
    let (_, pos) = index_positions("https://t.io/FUZZ?p=FUZZ", "FUZZ", 0);
    let p = SniperProvider::new(src("FUZZ", &["a", "b", "c"]), pos).unwrap();
    assert_eq!(p.total(), 6);
}

#[test]
fn sniper_cycles_positions_correctly() {
    let (_, _pos) = index_positions("__S0__/__S1__", "FUZZ", 0); // template already has __S0__/__S1__
    let pos2 = vec![
        crate::fuzz::input::sniper::SniperPos { keyword: "__S0__".into() },
        crate::fuzz::input::sniper::SniperPos { keyword: "__S1__".into() },
    ];
    let mut p = SniperProvider::new(src("FUZZ", &["x", "y"]), pos2).unwrap();

    assert!(p.next());
    assert_eq!(w(&p.value(), "__S0__"), "x");
    assert_eq!(w(&p.value(), "__S1__"), "");

    assert!(p.next());
    assert_eq!(w(&p.value(), "__S0__"), "y");
    assert_eq!(w(&p.value(), "__S1__"), "");

    assert!(p.next());
    assert_eq!(w(&p.value(), "__S0__"), "");
    assert_eq!(w(&p.value(), "__S1__"), "x");

    assert!(p.next());
    assert_eq!(w(&p.value(), "__S1__"), "y");

    assert!(!p.next());
}

#[test]
fn sniper_error_when_no_positions() {
    let result = SniperProvider::new(src("FUZZ", &["a"]), vec![]);
    assert!(result.is_err());
}

// ─────────────────────────────────────────────────────────────────────────
// 5. is_fuzz_mode_config detection
// ─────────────────────────────────────────────────────────────────────────

fn base_config() -> Configuration {
    Configuration::default()
}

#[test]
fn fuzz_mode_detected_by_keyword_in_url() {
    let mut c = base_config();
    c.target_url = "https://target/FUZZ".into();
    assert!(is_fuzz_mode_config(&c));
}

#[test]
fn fuzz_mode_detected_by_keyword_in_host_header() {
    let mut c = base_config();
    c.headers.insert("Host".into(), "FUZZ.example.com".into());
    assert!(is_fuzz_mode_config(&c));
}

#[test]
fn fuzz_mode_detected_by_keyword_in_body() {
    let mut c = base_config();
    c.data = b"user=admin&pass=FUZZ".to_vec();
    assert!(is_fuzz_mode_config(&c));
}

#[test]
fn fuzz_mode_detected_by_colon_keyword_syntax() {
    let mut c = base_config();
    c.fuzz_wordlists = vec!["users.txt:USER".into()];
    assert!(is_fuzz_mode_config(&c));
}

#[test]
fn fuzz_mode_detected_by_multiple_wordlists() {
    let mut c = base_config();
    c.fuzz_wordlists = vec!["u.txt:USER".into(), "p.txt:PASS".into()];
    assert!(is_fuzz_mode_config(&c));
}

#[test]
fn fuzz_mode_detected_by_non_default_mode() {
    let mut c = base_config();
    c.fuzz_mode = "pitchfork".into();
    assert!(is_fuzz_mode_config(&c));
}

#[test]
fn fuzz_mode_not_detected_for_plain_url() {
    let mut c = base_config();
    c.target_url = "https://target/".into();
    assert!(!is_fuzz_mode_config(&c));
}

// ─────────────────────────────────────────────────────────────────────────
// 6. FuzzMode parsing
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn fuzz_mode_from_str_all_variants() {
    assert_eq!(FuzzMode::from_str("clusterbomb").unwrap(), FuzzMode::ClusterBomb);
    assert_eq!(FuzzMode::from_str("pitchfork").unwrap(),   FuzzMode::Pitchfork);
    assert_eq!(FuzzMode::from_str("sniper").unwrap(),      FuzzMode::Sniper);
    assert_eq!(FuzzMode::from_str("").unwrap(),            FuzzMode::ClusterBomb);
}

#[test]
fn fuzz_mode_from_str_rejects_unknown() {
    assert!(FuzzMode::from_str("invalid").is_err());
    assert!(FuzzMode::from_str("burp").is_err());
    assert!(FuzzMode::from_str("fuzz").is_err());
}

#[test]
fn fuzz_mode_from_str_is_case_insensitive_by_design() {
    // from_str lowercases input before matching, so this is intentional
    // behavior, not a bug -- covered explicitly so a future refactor
    // can't silently flip this without a test failing.
    assert_eq!(FuzzMode::from_str("CLUSTERBOMB").unwrap(), FuzzMode::ClusterBomb);
    assert_eq!(FuzzMode::from_str("Sniper").unwrap(), FuzzMode::Sniper);
    assert_eq!(FuzzMode::from_str("PITCH-FORK").unwrap(), FuzzMode::Pitchfork);
}

// ─────────────────────────────────────────────────────────────────────────
// 7. RecurseConfig -- construction and trigger logic
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn recurse_config_defaults() {
    let c = RecurseConfig::default();
    assert!(!c.enabled);
    assert_eq!(c.max_depth, 4);
    assert!(c.status_codes.contains(&200));
    assert!(c.status_codes.contains(&301));
    assert!(!c.vhost);
}

#[test]
fn recurse_config_from_configuration() {
    let mut c = base_config();
    c.fuzz_recurse          = true;
    c.fuzz_recurse_depth    = 2;
    c.fuzz_recurse_status   = vec![301, 302];
    c.fuzz_recurse_vhost    = true;
    c.fuzz_recurse_match    = r"/$".into();

    let rc = RecurseConfig::from_config(&c);
    assert!(rc.enabled);
    assert_eq!(rc.max_depth, 2);
    assert_eq!(rc.status_codes, vec![301u16, 302u16]);
    assert!(rc.vhost);
    assert!(rc.match_pattern.is_some());
}

#[test]
fn recurse_config_empty_match_pattern_is_none() {
    let mut c = base_config();
    c.fuzz_recurse_match = String::new();
    let rc = RecurseConfig::from_config(&c);
    assert!(rc.match_pattern.is_none());
}

#[test]
fn recurse_status_defaults_used_when_config_empty() {
    let c = base_config();
    let rc = RecurseConfig::from_config(&c);
    assert!(rc.status_codes.contains(&200));
    assert!(rc.status_codes.contains(&301));
}

// ─────────────────────────────────────────────────────────────────────────
// 8. parse_wordlist_arg
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn parse_wordlist_arg_with_keyword() {
    assert_eq!(parse_wordlist_arg("list.txt:USER"),   ("list.txt", "USER"));
    assert_eq!(parse_wordlist_arg("list.txt:PASS"),   ("list.txt", "PASS"));
    assert_eq!(parse_wordlist_arg("list.txt:FUZZ2"),  ("list.txt", "FUZZ2"));
}

#[test]
fn parse_wordlist_arg_no_keyword_defaults_to_fuzz() {
    assert_eq!(parse_wordlist_arg("list.txt"),        ("list.txt", "FUZZ"));
    assert_eq!(parse_wordlist_arg("/abs/path.txt"),   ("/abs/path.txt", "FUZZ"));
}

#[test]
fn parse_wordlist_arg_splits_on_last_colon() {
    let (path, kw) = parse_wordlist_arg("/path/to/file.txt:KEYWORD");
    assert_eq!(path, "/path/to/file.txt");
    assert_eq!(kw, "KEYWORD");
}

#[test]
fn parse_wordlist_arg_keyword_with_path_sep_falls_back_to_fuzz() {
    let (path, kw) = parse_wordlist_arg("/path/no/colon");
    assert_eq!(path, "/path/no/colon");
    assert_eq!(kw, "FUZZ");
}

// ─────────────────────────────────────────────────────────────────────────
// 9. expand_with_extensions (-x support)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn expand_with_extensions_no_extensions_is_identity() {
    let entries = vec!["admin".to_string(), "login".to_string()];
    let out = expand_with_extensions(&entries, &[]);
    assert_eq!(out, entries);
}

#[test]
fn expand_with_extensions_appends_bare_word_first() {
    let entries = vec!["admin".to_string()];
    let exts = vec!["php".to_string(), "html".to_string()];
    let out = expand_with_extensions(&entries, &exts);
    assert_eq!(out, vec!["admin", "admin.php", "admin.html"]);
}

#[test]
fn expand_with_extensions_handles_multiple_words() {
    let entries = vec!["admin".to_string(), "login".to_string()];
    let exts = vec!["php".to_string()];
    let out = expand_with_extensions(&entries, &exts);
    assert_eq!(out, vec!["admin", "admin.php", "login", "login.php"]);
}

#[test]
fn expand_with_extensions_strips_leading_dot_if_present() {
    // Some users write -x .php,.html with a leading dot; must not
    // produce a double dot like "admin..php".
    let entries = vec!["admin".to_string()];
    let exts = vec![".php".to_string()];
    let out = expand_with_extensions(&entries, &exts);
    assert_eq!(out, vec!["admin", "admin.php"]);
}
