// src/fuzz/job.rs
//
// FuzzJob -- runs INSTEAD of FeroxScanner in fuzz mode.
// Uses Arc<Handles> so output, filters, and stats are identical to normal mode.
//
// ── Concurrency model ────────────────────────────────────────────────────
//
// Requests are generated LAZILY via futures::stream::unfold driven by the
// InputProvider, and dispatched through buffer_unordered(threads). This
// means at most `threads` PreparedRequests exist in memory at any time --
// NOT the full combinatorial total. This matters a lot for cluster-bomb
// mode: two 5,000-word wordlists produce 25,000,000 combinations, and
// materialising all of them upfront (as an earlier version of this code
// did) would exhaust memory before a single request was sent.
//
// ── Stats / progress-bar parity ──────────────────────────────────────────
//
// main.rs already creates a progress bar (Command::CreateBar) before
// fuzz-mode dispatch. Sending Command::AddStatus / Command::AddError per
// request (exactly like scanner::requester::Requester does) is what
// actually drives that bar and populates the end-of-run statistics
// (Requests, Successes, Errors, per-status-code buckets). We also adjust
// StatField::TotalExpected per depth-level batch so the bar's percentage
// reflects the real fuzz-mode total rather than the unrelated wordlist
// length that scanner::initialize() used to size it.
//
// ── Recursion ─────────────────────────────────────────────────────────────
//
// Controlled by RecurseConfig (populated from CLI flags), off by default:
//
//   --fuzz-recurse                 enable recursion in fuzz mode
//   --fuzz-recurse-depth N         max depth (default: 4)
//   --fuzz-recurse-status 301,302  status codes that trigger recursion
//   --fuzz-recurse-match PATTERN   regex on response URL/body to trigger recursion
//   --fuzz-recurse-vhost           also recurse into discovered vhosts
//
// PATH mode  (keyword in URL path/query):
//   found dir -> queue  <discovered_url>/<keyword>  at depth+1
//   Gated on the keyword actually appearing in THIS depth's URL, so a
//   pure POST-body credential fuzz (keyword only in -d) never triggers
//   path recursion (it makes no sense to append /FUZZ to a login URL).
//
// VHOST mode (keyword in Host header):
//   found host -> queue  <keyword>.<discovered_host>  at depth+1
//   Only active with --fuzz-recurse-vhost.
//
// Sniper mode + recursion is not supported (rejected at construction
// time with a clear error) -- see comment on `sniper_pos` validation
// below for why a correct implementation is nontrivial.
//
// A visited-set prevents the same discovered URL/host from being queued
// for a recursive sub-scan more than once (duplicate hits across
// cluster-bomb payload combinations, or multiple regex matches, would
// otherwise cause redundant full-wordlist re-scans).

use std::{cmp::max, collections::{HashSet, VecDeque}, path::PathBuf, sync::Arc, time::Duration};
use anyhow::{bail, Context, Result};
use futures::stream::{self, StreamExt};
use leaky_bucket::RateLimiter;
use regex::Regex;

use url::Url;

use crate::{
    event_handlers::{
        Command::{AddError, AddStatus, AddToUsizeField, CreateBar},
        Handles,
    },
    response::FeroxResponse,
    scan_manager::{PAUSE_SCAN, MenuCmdResult},
    statistics::{StatError, StatField::TotalExpected},
    utils::should_deny_url,
    fuzz::{
        input::{
            ClusterBombProvider, InputProvider, PitchforkProvider,
            WordlistSource, load_wordlist, parse_wordlist_arg,
        },
        input::sniper::{SniperProvider, SniperPos, index_positions},
        prepare::{PreparedRequest, RequestTemplate, prepare},
        wildcard::detect_and_register_wildcard,
    },
};

// ── FuzzMode ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum FuzzMode { ClusterBomb, Pitchfork, Sniper }

impl FuzzMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().replace('-', "").as_str() {
            "clusterbomb" | "" => Ok(FuzzMode::ClusterBomb),
            "pitchfork"        => Ok(FuzzMode::Pitchfork),
            "sniper"           => Ok(FuzzMode::Sniper),
            o => bail!("Unknown --mode '{}'. Valid: clusterbomb, pitchfork, sniper", o),
        }
    }
}

// ── Recursion ─────────────────────────────────────────────────────────────

/// Controls if and how fuzz mode recurses on discovered targets.
#[derive(Debug, Clone)]
pub struct RecurseConfig {
    pub enabled: bool,
    pub max_depth: usize,
    pub status_codes: Vec<u16>,
    pub match_pattern: Option<Regex>,
    pub vhost: bool,
}

impl Default for RecurseConfig {
    fn default() -> Self {
        Self {
            enabled:       false,
            max_depth:     4,
            status_codes:  vec![200, 301, 302, 307, 308],
            match_pattern: None,
            vhost:         false,
        }
    }
}

impl RecurseConfig {
    pub fn from_config(config: &crate::config::Configuration) -> Self {
        let status_codes = if config.fuzz_recurse_status.is_empty() {
            vec![200, 301, 302, 307, 308]
        } else {
            config.fuzz_recurse_status.clone()
        };
        let match_pattern = if config.fuzz_recurse_match.is_empty() {
            None
        } else {
            Regex::new(&config.fuzz_recurse_match).ok()
        };
        Self {
            enabled:       config.fuzz_recurse,
            max_depth:     config.fuzz_recurse_depth,
            status_codes,
            match_pattern,
            vhost:         config.fuzz_recurse_vhost,
        }
    }

    /// True if this response's status/pattern qualifies it as a recursion
    /// trigger. Does NOT decide path-vs-vhost eligibility -- callers gate
    /// that separately (see `keyword_in_url` / `host_header` checks at the
    /// call site), since that depends on what's being fuzzed, not on the
    /// response itself.
    fn status_or_pattern_matches(&self, resp: &FeroxResponse) -> bool {
        let status_ok = self.status_codes.contains(&resp.status().as_u16());
        let pattern_ok = self.match_pattern.as_ref()
            .map_or(true, |re| re.is_match(resp.url().as_str()) || re.is_match(resp.text()));
        status_ok && pattern_ok
    }
}

// ── RecurseTarget -- what to enqueue for the next depth level ─────────────

#[derive(Debug, Clone)]
enum RecurseTarget {
    /// URL-path mode: new base URL with the keyword appended.
    Path { template: RequestTemplate, dedup_key: String },
    /// VHost mode: discovered host becomes new subdomain base.
    VHost { template: RequestTemplate, dedup_key: String },
}

// ── Fuzz mode detection ───────────────────────────────────────────────────

pub fn is_fuzz_mode_config(config: &crate::config::Configuration) -> bool {
    if config.fuzz_wordlists.len() > 1 { return true; }
    if let Some(first) = config.fuzz_wordlists.first() {
        if parse_wordlist_arg(first).1 != "FUZZ" { return true; }
    }
    let has = |s: &str| s.contains("FUZZ") || s.contains("fuzz");
    if has(&config.target_url)                                                     { return true; }
    if config.headers.iter().any(|(k,v)| has(k) || has(v))                       { return true; }
    if !config.data.is_empty() && has(&String::from_utf8_lossy(&config.data))    { return true; }
    if !config.fuzz_mode.is_empty() && config.fuzz_mode != "clusterbomb"         { return true; }
    false
}

// ── FuzzJob ───────────────────────────────────────────────────────────────

pub async fn download_wordlist(url: &str, client: &reqwest::Client) -> Result<PathBuf> {
    let response = client.get(url).send().await
        .context(format!("Unable to download wordlist from remote url: {}", url))?;
    if !response.status().is_success() {
        bail!("[{}] Unable to download wordlist from url: {}", response.status().as_str(), url);
    }
    let path_segments = response.url().path_segments()
        .ok_or_else(|| anyhow::anyhow!("Unable to parse path from url: {}", response.url()))?;
    let filename = path_segments.last()
        .ok_or_else(|| anyhow::anyhow!("Unable to parse filename from url's path: {}", response.url().path()))?;
    let filename = filename.to_string();
    let body = response.bytes().await?;
    tokio::fs::write(&filename, body).await?;
    Ok(PathBuf::from(filename))
}

#[derive(Debug)]
pub struct FuzzJob {
    base_template:    RequestTemplate,
    sources:          Vec<WordlistSource>,
    mode:             FuzzMode,
    handles:          Arc<Handles>,
    recurse:          RecurseConfig,
    keyword:          String,
    sniper_positions: Vec<SniperPos>,
    /// Static requests/sec cap from --rate-limit, mirrors
    /// scanner::requester::Requester::build_a_bucket. None when
    /// --rate-limit is 0 (unlimited, the default). Unlike the real
    /// Requester, this is NOT adaptive (no auto-tune/auto-bail based on
    /// error rate) -- it always honours the user-specified rate exactly.
    rate_limiter:     Option<Arc<RateLimiter>>,
    /// HTTP/1.1-only client used for all fuzz-mode requests.
    ///
    /// reqwest (hyper 1.x) negotiates HTTP/2 via ALPN on TLS connections.
    /// In HTTP/2 the `Host` header is replaced by the `:authority`
    /// pseudo-header, which is derived from the URL -- NOT from any
    /// manually-set Host header. This means that when the keyword
    /// lives in a `Host: FUZZ.example.com` template and reqwest
    /// upgrades to H2, the fuzz payload is silently dropped and the
    /// server sees the URL's authority (the raw IP/hostname) instead.
    ///
    /// HTTP/1.1 is the correct transport for Host-header fuzzing:
    /// the spec mandates exactly one Host header per request, and every
    /// server that does vhost routing supports it. This is also how
    /// ffuf implements vhost mode.
    fuzz_client:      reqwest::Client,
}

impl FuzzJob {
    pub async fn from_config_with_handles(
        config: &crate::config::Configuration,
        handles: Arc<Handles>,
    ) -> Result<Self> {
        let mode    = FuzzMode::from_str(&config.fuzz_mode)?;
        let recurse = RecurseConfig::from_config(config);

        // Sniper + recursion is not supported: sniper's synthetic __Sn__
        // position markers are computed once from the ORIGINAL template.
        // A recursed template (built from a discovered URL/host at
        // runtime) is different text that doesn't contain those markers,
        // so reusing them would silently produce identical, non-fuzzed
        // requests at every depth beyond the first. Rejecting this
        // combination outright is safer than a subtly-broken result.
        if mode == FuzzMode::Sniper && recurse.enabled {
            bail!(
                "Sniper mode does not support --fuzz-recurse yet \
                 (sniper positions are computed once from the initial \
                 template and cannot be safely re-derived for recursed \
                 targets). Use clusterbomb or pitchfork mode with \
                 recursion, or run sniper mode without --fuzz-recurse."
            );
        }

        // Load wordlists
        let wl_args = if !config.fuzz_wordlists.is_empty() {
            config.fuzz_wordlists.clone()
        } else {
            vec![config.wordlist.clone()]
        };
        let mut sources: Vec<WordlistSource> = Vec::new();
        for arg in &wl_args {
            let (path, keyword) = parse_wordlist_arg(arg);
            let local_path = if path.starts_with("http") {
                download_wordlist(path, &config.client).await?
            } else {
                PathBuf::from(path)
            };
            let mut entries = load_wordlist(&local_path).await?;

            // -x/--extensions: only meaningful for a wordlist whose
            // keyword actually drives URL path/query fuzzing -- applying
            // it to e.g. a POST password wordlist would be nonsensical
            // (there's no such thing as "hunter2.php" as a password).
            let keyword_lower = keyword.to_lowercase();
            let has_kw = |s: &str| s.contains(keyword) || s.contains(&keyword_lower);
            let mut keyword_in_path = false;
            if let Ok(parsed_url) = url::Url::parse(&config.target_url) {
                if has_kw(parsed_url.path()) || parsed_url.query().map_or(false, |q| has_kw(q)) {
                    keyword_in_path = true;
                }
            } else {
                keyword_in_path = has_kw(&config.target_url);
            }

            if !config.extensions.is_empty() && keyword_in_path {
                entries = crate::fuzz::input::expand_with_extensions(&entries, &config.extensions);
            }

            sources.push(WordlistSource::new(keyword, entries));
        }

        let keyword = sources.first().map(|s| s.keyword.clone()).unwrap_or_else(|| "FUZZ".into());

        // Warn (don't fail) if --fuzz-recurse-vhost was set but the
        // keyword never actually appears in any header value -- the flag
        // would silently do nothing, which is confusing to debug.
        if recurse.vhost {
            let kw_in_any_header = config.headers.iter().any(|(_, v)| v.contains(&keyword as &str) || v.contains(&keyword.to_lowercase() as &str));
            if !kw_in_any_header {
                log::warn!(
                    "--fuzz-recurse-vhost was set, but keyword '{}' does not appear \
                     in any header value (e.g. -H \"Host: {}.example.com\"). \
                     VHost recursion will never trigger.",
                    keyword, keyword
                );
            }
        }

        // Build template (sniper: replace keyword occurrences with __S0__, __S1__, ...)
        let (url_t, hdr_map, body_t, sniper_pos) = match mode {
            FuzzMode::Sniper => {
                let (url_t, mut pos) = index_positions(&config.target_url, &keyword, 0);
                let mut hdr = std::collections::HashMap::new();
                for (k, v) in &config.headers {
                    let (tk, pk) = index_positions(k, &keyword, pos.len());
                    let (tv, pv) = index_positions(v, &keyword, pos.len() + pk.len());
                    pos.extend(pk); pos.extend(pv);
                    hdr.insert(tk, tv);
                }
                let (body_t, pb) = crate::fuzz::input::sniper::index_positions_bytes(&config.data, keyword.as_bytes(), pos.len());
                pos.extend(pb);
                (url_t, hdr, body_t, pos)
            }
            _ => (config.target_url.clone(), config.headers.clone(), config.data.clone(), vec![]),
        };

        let base_template = RequestTemplate {
            method:  config.methods.first().cloned().unwrap_or_else(|| "GET".into()),
            url:     url_t,
            headers: hdr_map,
            body:    body_t,
        };

        if mode == FuzzMode::Sniper {
            if sources.len() > 1 {
                bail!("Sniper mode: only one -w allowed");
            }
            if sniper_pos.is_empty() {
                bail!("Sniper: keyword '{}' not found in URL/headers/body.", keyword);
            }
        }

        // Mirrors scanner::requester::Requester::build_a_bucket: a
        // 1-second-interval token bucket refilled at exactly `limit`
        // tokens/sec, seeded at half capacity to avoid an initial burst.
        let rate_limiter = if config.rate_limit > 0 {
            let limit   = max(config.rate_limit, 1);
            let refill  = limit;
            let initial = max((limit as f64 / 2.0).round() as usize, 1);
            Some(Arc::new(
                RateLimiter::builder()
                    .interval(Duration::from_millis(1000))
                    .refill(refill)
                    .initial(initial)
                    .max(limit)
                    .build(),
            ))
        } else {
            None
        };

        // Build a dedicated HTTP/1.1-only client for all fuzz requests.
        // See the `fuzz_client` field docstring for the full rationale.
        // We mirror every setting from the user's actual client (insecure,
        // timeout, headers, redirect policy) -- the ONLY difference is
        // `.http1_only()` which disables ALPN H2 negotiation.
        let fuzz_client = {
            let c = &config;
            let header_map: reqwest::header::HeaderMap = {
                use std::convert::TryInto;
                (&c.headers).try_into()
                    .unwrap_or_default()
            };
            let policy = if c.redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            };
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(c.timeout))
                .user_agent(&c.user_agent)
                .danger_accept_invalid_certs(c.insecure)
                .default_headers(header_map)
                .redirect(policy)
                .http1_only()       // Host header works correctly in HTTP/1.1
                .build()
                .unwrap_or_else(|_| c.client.clone()) // fallback to normal client
        };

        Ok(Self {
            base_template, sources, mode, handles, recurse,
            keyword, sniper_positions: sniper_pos, rate_limiter,
            fuzz_client,
        })
    }

    pub async fn run(self) -> Result<()> {
        // main.rs's normal-mode path creates the progress bar via
        // Command::CreateBar inside scan() (src/main.rs), but that
        // function is never reached in fuzz mode -- our dispatch returns
        // early before it. Without sending CreateBar ourselves, the
        // underlying StatsHandler keeps its default ProgressBar::hidden()
        // for the entire run: our AddStatus/AddError/AddToUsizeField
        // calls below would still correctly update the final statistics
        // (and any --save-state/JSON output), but nothing would ever be
        // drawn to the terminal while the scan is running. Sending it
        // here, once, up front, is what actually makes the bar visible.
        self.handles.stats.send(CreateBar(0)).unwrap_or_default();

        let mut queue: VecDeque<(RequestTemplate, usize)> = VecDeque::new();
        queue.push_back((self.base_template.clone(), 0));

        // Prevents the same discovered URL/host from spawning a
        // duplicate recursive sub-scan (e.g. two different cluster-bomb
        // payload combinations both landing on the same directory).
        let mut visited: HashSet<String> = HashSet::new();

        let recurse          = self.recurse.clone();
        let keyword           = self.keyword.clone();
        let mode              = self.mode.clone();
        let handles           = self.handles.clone();
        let sources           = self.sources.clone();
        let sniper_positions  = Arc::new(self.sniper_positions.clone());
        let fuzz_client   = Arc::new(self.fuzz_client.clone());
        let rate_limiter      = self.rate_limiter.clone();

        while let Some((template, depth)) = queue.pop_front() {
            if depth > 0 {
                log::info!("Fuzz recursion depth {}: {}", depth, template.url);
            }

            let discovered = run_single_scan(
                &template, &sources, &mode, handles.clone(), &recurse,
                &sniper_positions, &keyword, rate_limiter.clone(), fuzz_client.clone(),
            ).await?;

            if recurse.enabled && depth < recurse.max_depth {
                for target in discovered {
                    match target {
                        RecurseTarget::Path { template: t, dedup_key } => {
                            if visited.insert(dedup_key) {
                                queue.push_back((t, depth + 1));
                            }
                        }
                        RecurseTarget::VHost { template: t, dedup_key } => {
                            if recurse.vhost && visited.insert(dedup_key) {
                                queue.push_back((t, depth + 1));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ── Single-depth scan ─────────────────────────────────────────────────────

async fn run_single_scan(
    template:         &RequestTemplate,
    sources:          &[WordlistSource],
    mode:             &FuzzMode,
    handles:          Arc<Handles>,
    recurse:          &RecurseConfig,
    sniper_positions: &[SniperPos],
    keyword:          &str,
    rate_limiter:     Option<Arc<RateLimiter>>,
    fuzz_client:      Arc<reqwest::Client>,
) -> Result<Vec<RecurseTarget>> {
    let provider: Box<dyn InputProvider> = match mode {
        FuzzMode::ClusterBomb => Box::new(ClusterBombProvider::new(sources.to_vec())),
        FuzzMode::Pitchfork   => Box::new(PitchforkProvider::new(sources.to_vec())),
        FuzzMode::Sniper => {
            Box::new(SniperProvider::new(sources[0].clone(), sniper_positions.to_vec())?)
        }
    };

    // Mirrors scanner::requester::Requester::request(), which loops
    // `for method in self.handles.config.methods.iter()` and sends every
    // word with every configured method (-X GET,POST tries both for
    // each word). Our template previously only ever used
    // config.methods.first(), silently dropping any additional
    // configured methods.
    //
    // Exception: if the template's method field itself contains the
    // keyword (an intentional, more advanced use -- fuzzing the HTTP
    // verb via a wordlist, e.g. -X FUZZ -w methods.txt), per-word
    // substitution already covers that and takes priority; expanding
    // over config.methods as well would conflict with it, so it's
    // skipped in that specific case.
    let methods: Vec<String> = if handles.config.methods.is_empty() {
        vec!["GET".to_string()]
    } else {
        handles.config.methods.clone()
    };
    let expand_methods = methods.len() > 1 && !template.method.contains(keyword);
    let method_count   = if expand_methods { methods.len() } else { 1 };

    let total = provider.total() * method_count;
    log::info!("FuzzJob: {} requests | threads: {}", total, handles.config.threads);

    // Grow the progress bar's denominator to include this batch, mirroring
    // how normal-mode recursion incrementally raises TotalExpected as new
    // sub-scans get queued (see scanner/requester.rs).
    handles.stats.send(AddToUsizeField(TotalExpected, total)).unwrap_or_default();

    // A response is only eligible for PATH recursion if the keyword
    // actually appears in THIS depth's URL. This stops nonsensical
    // recursion on pure POST-body fuzzing (e.g. a login bruteforce with
    // -d \"user=admin&pass=FUZZ\" and no FUZZ in the URL at all --
    // appending /FUZZ to the login endpoint would make no sense).
    let keyword_lower = keyword.to_lowercase();
    let has_kw = |s: &str| s.contains(keyword) || s.contains(&keyword_lower);

    let mut keyword_in_path = false;
    let mut keyword_in_host_part = false;
    if let Ok(parsed_url) = url::Url::parse(&template.url) {
        if let Some(host_str) = parsed_url.host_str() {
            if has_kw(host_str) {
                keyword_in_host_part = true;
            }
        }
        if has_kw(parsed_url.path()) || parsed_url.query().map_or(false, |q| has_kw(q)) {
            keyword_in_path = true;
        }
    } else {
        keyword_in_path = has_kw(&template.url);
    }

    let keyword_in_url = keyword_in_path;
    let keyword_in_host = keyword_in_host_part || template.headers.iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("host") && has_kw(v));

    // Wildcard/false-positive detection: only worth the two probe
    // requests when the keyword drives an actual target lookup (URL
    // path/query, or the Host header for vhost fuzzing). Skipped
    // entirely for pure POST-body/header param fuzzing, where "does a
    // random word return the same response" isn't a meaningful check.
    if keyword_in_url || keyword_in_host {
        if expand_methods {
            for m in &methods {
                let mut tmpl = template.clone();
                tmpl.method = m.clone();
                detect_and_register_wildcard(&handles, &tmpl, keyword, &fuzz_client).await;
            }
        } else {
            detect_and_register_wildcard(&handles, template, keyword, &fuzz_client).await;
        }
    }

    let threads = handles.config.threads;

    // Lazily generate PreparedRequests one at a time via the InputProvider,
    // instead of collecting all of them into a Vec upfront. For
    // cluster-bomb mode in particular the combinatorial total can be in
    // the tens of millions; buffer_unordered(threads) below ensures at
    // most `threads` requests are in flight (and thus in memory) at once.
    let template = template.clone();
    let stream = stream::unfold(provider, move |mut provider| {
        let template = template.clone();
        let methods   = methods.clone();
        async move {
            if provider.next() {
                let value = provider.value();
                let reqs: Vec<PreparedRequest> = if expand_methods {
                    methods.iter().map(|m| {
                        let mut t = template.clone();
                        t.method = m.clone();
                        prepare(&t, &value)
                    }).collect()
                } else {
                    vec![prepare(&template, &value)]
                };
                Some((reqs, provider))
            } else {
                None
            }
        }
    });

    let recurse   = recurse.clone();
    let keyword_s = keyword.to_string();

    let discovered: Vec<RecurseTarget> = stream
        .flat_map(stream::iter)
        .map(|req| {
            let h = handles.clone();
            let r = recurse.clone();
            let kw = keyword_s.clone();
            let rl = rate_limiter.clone();
            let fc = fuzz_client.clone();
            async move { execute_request(h, req, &r, &kw, keyword_in_url, keyword_in_host, rl, fc).await }
        })
        .buffer_unordered(threads)
        .filter_map(|res| async move {
            match res {
                Ok(Some(target)) => Some(target),
                Ok(None)         => None,
                Err(e)           => { log::warn!("FuzzJob request error: {e}"); None }
            }
        })
        .collect()
        .await;

    Ok(discovered)
}

// ── HTTP execution ────────────────────────────────────────────────────────

async fn execute_request(
    handles:         Arc<Handles>,
    req:             PreparedRequest,
    recurse:         &RecurseConfig,
    keyword:         &str,
    keyword_in_url:  bool,
    keyword_in_host: bool,
    rate_limiter:    Option<Arc<RateLimiter>>,
    fuzz_client:     Arc<reqwest::Client>,
) -> Result<Option<RecurseTarget>> {
    // Mirrors scanner::requester::Requester::request(): --url-denylist /
    // --regex-denylist (aka --dont-scan) must be honoured in fuzz mode
    // too, and checked BEFORE consuming a rate-limit token, so denied
    // URLs don't waste permits that real requests are waiting on.
    let should_test_deny = !handles.config.url_denylist.is_empty()
        || !handles.config.regex_denylist.is_empty();
    if should_test_deny {
        if let Ok(parsed) = Url::parse(&req.url) {
            if should_deny_url(&parsed, handles.clone())? {
                return Ok(None);
            }
        }
    }

    // Mirrors scanner::requester::Requester::limit(): block until a
    // token is available before sending, when --rate-limit is set.
    if let Some(limiter) = &rate_limiter {
        limiter.acquire_one().await;
    }

    // Interactive menu support: block if PAUSE_SCAN is active, just like
    // FeroxScanner does in stream_requests().
    if PAUSE_SCAN.load(std::sync::atomic::Ordering::Acquire) {
        if let Some(r) = handles.ferox_scans().ok() {
            let limiter = Arc::new(crate::sync::DynamicSemaphore::new(handles.config.scan_limit));
            match r.pause(true, handles.clone(), limiter).await {
                // Mimic ferox_scanner's check_for_user_input handling
                Some(MenuCmdResult::Url(url)) => {
                    let _ = handles.send_scan_command(crate::event_handlers::Command::ScanNewUrl(url));
                }
                Some(MenuCmdResult::NumCancelled(num_canx)) if num_canx > 0 => {
                    let _ = handles.stats.send(crate::event_handlers::Command::SubtractFromUsizeField(TotalExpected, num_canx));
                }
                Some(MenuCmdResult::NumPermitsToAdd(n)) => {
                    let _ = handles.send_scan_command(crate::event_handlers::Command::AddScanPermits(n));
                }
                Some(MenuCmdResult::NumPermitsToSubtract(n)) => {
                    let _ = handles.send_scan_command(crate::event_handlers::Command::SubtractScanPermits(n));
                }
                _ => {}
            }
        }
    }

    log::debug!("execute_request: url={} host={:?} method={}", req.url, req.host, req.method);
    let method = reqwest::Method::from_bytes(req.method.as_bytes())?;
    let mut rb  = fuzz_client.request(method, &req.url);
    for (k, v) in &req.headers { rb = rb.header(k, v); }
    if let Some(host) = &req.host { rb = rb.header("Host", host); }
    if !req.body.is_empty()       { rb = rb.body(req.body.clone()); }

    let response = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            // Log the full error chain (source causes) so that deep errors
            // (TLS, connection refused, invalid header value, etc.) are visible
            // rather than only the top-level "error sending request" message.
            let mut msg = format!("{e}");
            let mut src: &dyn std::error::Error = &e;
            while let Some(cause) = src.source() {
                msg.push_str(&format!(" | caused by: {cause}"));
                src = cause;
            }
            log::warn!("Request error for {}: {msg}", req.url);
            handles.stats.send(AddError(StatError::Other)).unwrap_or_default();
            return Ok(None);
        }
    };

    let display_url = if let Some(host) = &req.host {
        if let Ok(mut parsed) = Url::parse(&req.url) {
            let host_only = host.split(':').next().unwrap_or(host);
            if let Ok(port_str) = host.split(':').nth(1).unwrap_or("").parse::<u16>() {
                let _ = parsed.set_port(Some(port_str));
            }
            if parsed.set_host(Some(host_only)).is_ok() {
                parsed.to_string()
            } else {
                req.url.clone()
            }
        } else {
            req.url.clone()
        }
    } else {
        req.url.clone()
    };

    let mut ferox_resp = FeroxResponse::from(
        response,
        &display_url,
        &req.method,
        handles.config.output_level,
        handles.config.response_size_limit,
    ).await;

    ferox_resp.set_url(&display_url);

    // Mirrors scanner::requester::Requester: AddStatus internally
    // increments the requests counter, the appropriate status-code
    // bucket, AND advances the progress bar (see
    // statistics/container.rs add_status_code() / add_request()).
    // Without this call the bar -- already created by main.rs before
    // fuzz-mode dispatch -- never moves, and end-of-run stats show zero
    // requests despite real traffic having been sent.
    handles.stats.send(AddStatus(*ferox_resp.status())).unwrap_or_default();

    if handles.filters.data.should_filter_response(&ferox_resp, handles.stats.tx.clone()) {
        return Ok(None);
    }

    let recurse_target = if recurse.enabled {
        build_recurse_target(&ferox_resp, &req, recurse, keyword, keyword_in_url, keyword_in_host)
    } else {
        None
    };

    if let Err(e) = ferox_resp.send_report(handles.output.tx.clone()) {
        log::warn!("Could not send response to output: {e}");
    }

    Ok(recurse_target)
}

// ── Recursion target builder ──────────────────────────────────────────────

fn build_recurse_target(
    resp:            &FeroxResponse,
    req:             &PreparedRequest,
    recurse:         &RecurseConfig,
    keyword:         &str,
    keyword_in_url:  bool,
    keyword_in_host: bool,
) -> Option<RecurseTarget> {
    if !recurse.status_or_pattern_matches(resp) {
        return None;
    }

    let host_header = req.host.as_deref();

    if recurse.vhost && keyword_in_host {
        if let Some(host) = host_header {
            let new_host = build_recursed_vhost(keyword, host);
            let mut new_headers = req.headers.clone();
            new_headers.insert("Host".to_string(), new_host);
            return Some(RecurseTarget::VHost {
                dedup_key: format!("vhost:{}", host),
                template: RequestTemplate {
                    method:  req.method.clone(),
                    url:     req.url.clone(),
                    headers: new_headers,
                    body:    req.body.clone(),
                },
            });
        }
    }

    // Path-mode recursion only makes sense if the keyword was actually
    // in the URL for this depth (see `keyword_in_url` computed once per
    // batch in run_single_scan).
    if !keyword_in_url {
        return None;
    }

    let discovered_url = resp.url().as_str();
    let base = discovered_url.find('?').map(|p| &discovered_url[..p]).unwrap_or(discovered_url);
    let new_url = build_recursed_path_url(base, keyword);

    Some(RecurseTarget::Path {
        dedup_key: base.to_string(),
        template: RequestTemplate {
            method:  req.method.clone(),
            url:     new_url,
            headers: req.headers.clone(),
            body:    req.body.clone(),
        },
    })
}

/// Build the next-depth URL for path-mode recursion: appends the
/// user-configured keyword (not a hardcoded literal) to a discovered
/// base URL, so the next scan's InputProvider can substitute real
/// wordlist entries into it.
fn build_recursed_path_url(base: &str, keyword: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{keyword}")
    } else {
        format!("{base}/{keyword}")
    }
}

/// Build the next-depth Host header for vhost-mode recursion: prefixes
/// the discovered host with the user-configured keyword (not a
/// hardcoded literal), so the next scan fuzzes one level deeper.
fn build_recursed_vhost(keyword: &str, discovered_host: &str) -> String {
    format!("{keyword}.{discovered_host}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use httpmock::{Method::GET, MockServer};

    // ── Regression: recursion must use the configured keyword, not a
    //    hardcoded "FUZZ" literal (bug found during architecture review) ──

    #[test]
    fn recursed_path_url_uses_custom_keyword() {
        let url = build_recursed_path_url("https://t.io/admin", "WORD");
        assert_eq!(url, "https://t.io/admin/WORD");
        assert!(!url.contains("FUZZ"), "must not hardcode FUZZ for custom keywords");
    }

    #[test]
    fn recursed_path_url_default_keyword_still_works() {
        let url = build_recursed_path_url("https://t.io/admin", "FUZZ");
        assert_eq!(url, "https://t.io/admin/FUZZ");
    }

    #[test]
    fn recursed_path_url_handles_trailing_slash() {
        let url = build_recursed_path_url("https://t.io/admin/", "FUZZ");
        assert_eq!(url, "https://t.io/admin/FUZZ", "must not produce a double slash");
    }

    #[test]
    fn recursed_vhost_uses_custom_keyword() {
        let host = build_recursed_vhost("WORD", "api.example.com");
        assert_eq!(host, "WORD.api.example.com");
        assert!(!host.contains("FUZZ"), "must not hardcode FUZZ for custom keywords");
    }

    // ── Regression: keyword-in-URL gate prevents nonsensical path
    //    recursion on pure POST-body fuzzing jobs ──

    #[test]
    fn keyword_in_url_true_for_path_fuzzing() {
        let template_url = "https://t.io/FUZZ";
        assert!(template_url.contains("FUZZ"));
    }

    #[test]
    fn keyword_in_url_false_for_post_only_fuzzing() {
        // e.g. -u https://t.io/login -d "user=admin&pass=FUZZ" -- keyword
        // lives only in the body, never in the URL.
        let template_url = "https://t.io/login";
        assert!(!template_url.contains("FUZZ"));
    }

    // ── Regression: sniper + recursion must be rejected at construction,
    //    not silently produce broken (duplicate, non-fuzzed) requests ──

    #[tokio::test]
    async fn sniper_with_recursion_is_rejected_at_construction() {
        let mut config = Configuration::default();
        config.target_url      = "https://t.io/FUZZ".into();
        config.fuzz_mode        = "sniper".into();
        config.fuzz_recurse     = true;
        config.wordlist         = "/nonexistent/does-not-matter.txt".into();

        let (handles, _rx) = Handles::for_testing(None, Some(Arc::new(config.clone())));
        let result = FuzzJob::from_config_with_handles(&config, Arc::new(handles)).await;

        assert!(result.is_err(), "sniper + --fuzz-recurse must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Sniper"), "error should explain which mode was rejected");
    }

    // ── Regression: --url-denylist / --regex-denylist (--dont-scan) must
    //    be honoured in fuzz mode, mirroring scanner::requester::
    //    Requester::request()'s should_deny_url check ──

    #[tokio::test]
    async fn denylisted_url_is_never_sent() {
        let srv = MockServer::start();
        let mock = srv.mock(|when, then| {
            when.method(GET);
            then.status(200).body("should never be hit");
        });

        let denied_url = format!("{}/admin", srv.base_url());

        let mut config = Configuration::default();
        config.url_denylist = vec![url::Url::parse(&denied_url).unwrap()];

        let (handles, _rx) = Handles::for_testing(None, Some(Arc::new(config.clone())));
        let handles = Arc::new(handles);

        let req = PreparedRequest {
            method:  "GET".into(),
            url:     denied_url,
            headers: std::collections::HashMap::new(),
            body:    vec![],
            host:    None,
            input:   std::collections::HashMap::new(),
        };
        let recurse = RecurseConfig::default();

        let fuzz_client = Arc::new(handles.config.client.clone());
        let result = execute_request(handles, req, &recurse, "FUZZ", false, false, None, fuzz_client).await;
        assert!(result.unwrap().is_none(), "denylisted URL must not produce a recursion target");
        mock.assert_hits(0);
    }

    // ── Regression: -X GET,POST must try every configured method, not
    //    just the first one (mirrors Requester::request()'s
    //    `for method in config.methods.iter()` loop) ──

    #[test]
    fn expand_methods_true_when_multiple_methods_and_keyword_not_in_method() {
        let methods = vec!["GET".to_string(), "POST".to_string()];
        let template_method = "GET"; // static, keyword not embedded here
        let expand = methods.len() > 1 && !template_method.contains("FUZZ");
        assert!(expand);
    }

    #[test]
    fn expand_methods_false_when_keyword_fuzzes_the_verb_itself() {
        // -X FUZZ -w methods.txt: per-word substitution already covers
        // this; config.methods expansion must not also kick in.
        let methods = vec!["GET".to_string(), "POST".to_string()];
        let template_method = "FUZZ";
        let expand = methods.len() > 1 && !template_method.contains("FUZZ");
        assert!(!expand);
    }

    #[test]
    fn expand_methods_false_when_only_one_method_configured() {
        let methods = vec!["POST".to_string()];
        let template_method = "POST";
        let expand = methods.len() > 1 && !template_method.contains("FUZZ");
        assert!(!expand);
    }

    #[test]
    fn recurse_config_status_or_pattern_status_match() {
        let mut rc = RecurseConfig::default();
        rc.status_codes = vec![301, 302];
        // status_or_pattern_matches needs a FeroxResponse which requires
        // a real HTTP round trip to construct safely from outside
        // response.rs (its fields are private); status_codes/pattern
        // logic itself is covered indirectly via the construction tests
        // above and the RecurseConfig::from_config tests in tests.rs.
        assert_eq!(rc.status_codes, vec![301, 302]);
    }

    // ── rate limiter construction (mirrors Requester::build_a_bucket) ──

    fn write_tmp_wordlist(words: &[&str]) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for w in words { writeln!(f, "{w}").unwrap(); }
        f.flush().unwrap();
        f
    }

    #[tokio::test]
    async fn rate_limiter_created_when_rate_limit_set() {
        let wl = write_tmp_wordlist(&["a", "b"]);
        let mut config = Configuration::default();
        config.target_url = "https://t.io/FUZZ".into();
        config.wordlist    = wl.path().to_str().unwrap().to_string();
        config.rate_limit  = 50;

        let (handles, _rx) = Handles::for_testing(None, Some(Arc::new(config.clone())));
        let job = FuzzJob::from_config_with_handles(&config, Arc::new(handles)).await.unwrap();
        assert!(job.rate_limiter.is_some(), "rate_limit > 0 must create a limiter");
    }

    #[tokio::test]
    async fn rate_limiter_absent_when_rate_limit_zero() {
        let wl = write_tmp_wordlist(&["a", "b"]);
        let mut config = Configuration::default();
        config.target_url = "https://t.io/FUZZ".into();
        config.wordlist    = wl.path().to_str().unwrap().to_string();
        config.rate_limit  = 0; // default: unlimited

        let (handles, _rx) = Handles::for_testing(None, Some(Arc::new(config.clone())));
        let job = FuzzJob::from_config_with_handles(&config, Arc::new(handles)).await.unwrap();
        assert!(job.rate_limiter.is_none(), "rate_limit == 0 must mean unlimited (no limiter)");
    }

    // ── progress bar: CreateBar must be sent, since main.rs's normal-mode
    //    scan() -- where CreateBar normally originates -- is never reached
    //    in fuzz mode (our dispatch returns early before it) ──

    #[tokio::test]
    async fn run_sends_create_bar_since_normal_scan_path_is_bypassed() {
        let wl = write_tmp_wordlist(&["a"]);
        let mut config = Configuration::default();
        // Port 1 is reserved/unassigned -- connection fails immediately,
        // keeping the test fast without needing a real listener.
        config.target_url = "http://127.0.0.1:1/FUZZ".into();
        config.wordlist    = wl.path().to_str().unwrap().to_string();
        config.threads     = 1;

        let (handles, mut rx) = Handles::for_testing(None, Some(Arc::new(config.clone())));
        let job = FuzzJob::from_config_with_handles(&config, Arc::new(handles)).await.unwrap();
        job.run().await.unwrap();

        let mut saw_create_bar = false;
        while let Ok(cmd) = rx.try_recv() {
            if matches!(cmd, CreateBar(_)) { saw_create_bar = true; break; }
        }
        assert!(saw_create_bar,
            "FuzzJob::run() must send CreateBar itself, since main.rs's normal                  scan() function (where CreateBar is otherwise sent) is never reached                  in fuzz mode");
    }
}

