<h1 align="center">
  <br>
  ⚡ feroxffuf
  <br>
</h1>

<h4 align="center">A high-performance, recursive content discovery and multi-placeholder fuzzing tool written in Rust</h4>

<p align="center">
  <b>feroxffuf</b> is a specialized command-line security tool combining the recursive directory scanning power of <b>feroxbuster</b> with the high-performance, arbitrary HTTP multi-placeholder fuzzing capabilities of <b>ffuf</b>.
</p>

---

## 🚀 Key Features

* **Recursive Fuzzing:** Auto-recurse on discovered paths (directory recursion) or subdomains (virtual host recursion).
* **Multi-Placeholder Fuzzing:** Cycle through multiple wordlists (default keyword: `FUZZ`, customizable, e.g. `-w list.txt:KEYWORD`).
* **Flexible Modes:** Supports `sniper` (cycle one by one), `pitchfork` (cycle lock-step), and `clusterbomb` (cartesian product).
* **Adaptive Rate Limiting & Auto-Tuning:** Automatically throttles connections on HTTP `429`, `403`, or general network errors.
* **Interactive Terminal UI Menu:** Pause, resume, and dynamically adjust thread counts while the scan is running.
* **Robust Wildcard Calibration:** Built-in subdomain-level and path-level wildcard calibration filter to eliminate false positives automatically.
* **Asynchronous Speed:** Fully asynchronous runtime built on `tokio` and `reqwest` for maximum throughput.

---

## 💡 Why feroxffuf?

| Capability | standard tools | **feroxffuf** |
| :--- | :--- | :--- |
| **Recursion** | Appends words strictly to the URL path | **Both URL path & virtual host recursion** |
| **Arbitrary Insertion** | Limited to path scanning | **Placeholder replacement in Method, URL, Headers, and Body** |
| **Adaptive Controls** | Static delay / manual tuning | **Auto-throttles fuzzing rates dynamically** |
| **Memory Safe** | High memory usage on combinatoric lists | **Lazy combinatoric generator (keeps only `threads` requests in memory)** |
| **Wildcard Detection** | Basic path filtering | **Subdomain-level calibration** |

---

## 🛠️ How It Works (Under the Hood)

1. **Placeholder Replacement**
   Dynamically substitutes words from your wordlists into target fields:
   * **URL Path / Authority:** `https://FUZZ.example.com/` or `https://example.com/FUZZ`
   * **Headers:** `-H "Host: FUZZ.example.com"` or `-H "X-Custom: FUZZ"`
   * **Request Method:** `-X FUZZ`
   * **Request Body:** `-d "username=admin&password=FUZZ"`

2. **Lazy Combinatoric Streaming**
   In combinatoric modes (like `Clusterbomb`), `feroxffuf` uses `futures::stream::unfold` to generate combinatorics lazily from the wordlists on demand. This keeps memory consumption minimal, regardless of wordlist sizes.

3. **Connection Routing Fallback**
   To support host header fuzzing, `feroxffuf` routes host-header-fuzzed requests through an HTTP/1.1-only client to prevent HTTP/2 ALPN negotiation from discarding custom headers.

4. **Logical URL Mapping**
   When scanning virtual hosts on a single IP target, `feroxffuf` rewrites response URLs dynamically to their logical domain layout (`https://subdomain.example.com/`), ensuring accurate duplicate filtering and clean terminal stdout logs.

---

## 📖 CLI Usage

```bash
feroxffuf [FLAGS] [OPTIONS] --url <URL> --wordlist <PATH>
```

### Options & Flags

* `-w, --wordlist <PATH:KEYWORD>`: Path to a wordlist, with optional custom keyword override (e.g. `subs.txt:SUB`). Can be specified multiple times.
* `--mode <mode>`: Fuzzing mode: `sniper`, `pitchfork`, or `clusterbomb` (default).
* `--fuzz-recurse`: Enable recursion into discovered paths/subdirectories.
* `--fuzz-recurse-vhost`: Recursively fuzz discovered subdomains under virtual hosts.
* `--fuzz-recurse-depth <N>`: Maximum recursion depth (default: 4).
* `--fuzz-recurse-status <CODES>`: Status codes that trigger recursion (default: `200,301,302,307,308`).
* `--fuzz-recurse-match <REGEX>`: Regular expression matching response URLs to trigger recursion.
* `-t, --threads <N>`: Number of concurrent threads (default: 50).
* `-N, --filter-lines <N>`: Filter out responses with N lines.
* `-W, --filter-words <N>`: Filter out responses with N words.
* `-S, --filter-size <N>`: Filter out responses with N bytes content length.
* `-C, --filter-status <CODES>`: Filter out responses with specific status codes.

---

## 🚀 Examples

### 1. Subdomain Virtual Host Fuzzing (Pinned IP Target)
Enumerate virtual hosts on a single web server IP with recursion:
```bash
feroxffuf -u https://142.250.130.113/ --fuzz-recurse-vhost -H "Host: FUZZ.google.com" --insecure -w wordlist.txt
```

### 2. URL Authority Subdomain Discovery (DNS Resolution)
Fuzz and connect to discovered subdomains via their real DNS IP addresses:
```bash
feroxffuf -u https://FUZZ.innowise.com -w wordlist.txt --insecure
```

### 3. Cartesian-Product Fuzzing (Clusterbomb Mode)
Fuzz username and password combinations:
```bash
feroxffuf -u https://target/login -d "u=USER&p=PASS" --mode clusterbomb -w users.txt:USER -w pass.txt:PASS
```

---

## 🤖 Credits & Disclosures

* **Credits:** Built as an integration fork combining the concepts, code structure, and recursive patterns of **[feroxbuster](https://github.com/epi052/feroxbuster)** (by Ben "epi" Risher) and the fuzzing modes of **[ffuf](https://github.com/ffuf/ffuf)** (by Joona Hoikkala).
* **AI-Assisted Development:** This integration, including its asynchronous concurrency architecture, H2/HTTP1.1 TLS connection routing fixes, and custom URL-rewriting deduplication, was designed, implemented, and refined using Advanced Agentic AI (Google Gemini / Antigravity).
