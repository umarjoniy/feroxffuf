# Project-Scoped Rules for feroxffuf

## CLI Input & Stdin Handling
- **Interactive Keyboard Handlers:** Always ensure that keyboard event loop threads (like `TermInputHandler`) are initialized and active across all dispatch paths, including early-returns, custom subcommands, and alternative running modes (e.g. fuzzing mode). On exit, explicitly set state markers (such as `SCAN_COMPLETE`) so receiver threads terminate gracefully without leaking resources.

## Hostname & Authority Fuzzing
- **Case-Insensitive Target & Keyword Matching:** Hostnames/authorities are automatically converted to lowercase by standard URL parsers. Always match and substitute fuzzing keywords (e.g., `FUZZ` and `fuzz`) case-insensitively inside hostname components.
- **HTTP/1.1 Enforcement for Host Overrides:** When fuzzing virtual hosts (custom `Host` headers), force the client to use HTTP/1.1 (e.g., using `.http1_only()`). Default HTTP/2 connections will negotiate ALPN and silently override manual `Host` headers with the URL authority.

## Custom HTTP Client Configuration
- **Settings Inheritance:** Any custom or auxiliary HTTP client builders (such as specialized fuzz clients) must inherit the proxy settings, timeouts, server/client certificates, and TLS configuration from the user's primary/global client configuration to ensure correct routing and verification in corporate networks.
