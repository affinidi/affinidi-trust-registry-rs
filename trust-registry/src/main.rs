use std::process::ExitCode;

use trust_registry::server::start;

// ─── Allocator ──────────────────────────────────────────────────────────────
//
// Set on the binary only. A library that installs a #[global_allocator] forces
// it on every consumer, so this deliberately does not live in lib.rs.
//
// Why not the system allocator: every request churns short-lived buffers
// (packed/unpacked messages, serialised records, storage-client buffers).
// glibc malloc keeps those arenas rather than returning them, so RSS ratchets
// to the high-water mark and never falls back — indistinguishable from a leak
// on a memory graph.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read by jemalloc itself at startup via this well-known symbol.
///
/// `background_thread:true` runs the purger off the request path.
/// `dirty_decay_ms` / `muzzy_decay_ms` are how long freed pages linger before
/// being returned to the OS; jemalloc's defaults (10s / 10s) are tuned for
/// throughput on allocation-heavy workloads, and hold RSS well above the live
/// heap. 5s keeps the memory graph honest at a negligible cost here, because
/// the registry's hot path is I/O-bound, not allocation-bound.
///
/// Raise these (or drop the `jemalloc` feature) if you are optimising for
/// allocation throughput over resident footprint.
///
/// The symbol must be `_rjem_malloc_conf`, not the `malloc_conf` jemalloc
/// documents: tikv-jemalloc-sys (default features) builds jemalloc with
/// `--with-jemalloc-prefix=_rjem_`, which prefixes every public symbol,
/// including the one it reads its configuration from. An unprefixed
/// `malloc_conf` would compile and link fine and be silently ignored.
///
/// SAFETY: exporting a symbol is unsafe because it could clash with another
/// definition of the same name. `_rjem_malloc_conf` is the (prefixed) name
/// jemalloc reads for exactly this, it is defined once (in the binary, never
/// the library), and the value is the NUL-terminated static string jemalloc
/// expects.
///
/// The type is `&[u8; 63]`, a reference to a fixed-size array: a thin pointer,
/// which is what jemalloc's `const char *malloc_conf` is. A `&[u8]` slice
/// reference is a two-word fat pointer (address + length), which matches
/// `const char *` only by the accident of field order.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[allow(unsafe_code)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8; 63] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000\0";

#[tokio::main]
async fn main() -> ExitCode {
    // `trust-registry setup …` provisions the registry at a VTA and exits;
    // anything else runs the service.
    #[cfg(feature = "vta")]
    if std::env::args_os().nth(1).is_some_and(|a| a == "setup") {
        std::process::exit(trust_registry::setup::run_cli(std::env::args_os().skip(1)).await);
    }
    start().await
}
