//! Background SHA-256 hashing of paths seen in `file_open` events
//! (M10.a). Adds the `hash.sha256` field to outbound `FileEvent`s
//! without blocking the kernel-side drainer.
//!
//! Design summary (full details in `docs/telemetry-roadmap.md`):
//!
//! 1. The eBPF `lsm/file_open` hook (M6.3) stays as-is — pure
//!    observation; it doesn't read the file.
//! 2. The userspace drainer translates each ringbuf event into a
//!    protobuf `FileEvent` with `hash = None`. Before shipping the
//!    event upstream, it consults this module: if the path is a cache
//!    hit, the hash gets stamped in synchronously; if a miss, the
//!    event ships hashless and a background hasher computes the hash
//!    so the *next* event for the same path benefits.
//! 3. Hashing is bounded: 64 MiB max read size, 1k entries LRU,
//!    `nice 19` priority on the worker thread.
//!
//! ## Concurrency
//!
//! Cache is `Arc<Mutex<lru::LruCache<...>>>`. Lookup is O(1). The
//! worker thread reads from a bounded mpsc; back-pressure causes the
//! drainer to drop hash requests rather than block the gRPC stream.
//!
//! ## When the hash is stale
//!
//! Cache entries TTL out after 1 hour, and we keep the file's
//! (mtime, size) alongside the hash. If a later event for the same
//! path has a different (mtime, size), the cache entry is invalidated
//! and the path is re-queued.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
const CACHE_MAX_ENTRIES: usize = 1024;
const CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug)]
struct CacheEntry {
    sha256_hex: String,
    mtime_ns: i128,
    size: u64,
    inserted_at: Instant,
}

/// Public handle. Cheap to clone (Arc).
#[derive(Clone)]
pub struct Hasher {
    cache: Arc<Mutex<HashMap<PathBuf, CacheEntry>>>,
    queue_tx: mpsc::Sender<PathBuf>,
}

impl Hasher {
    pub fn spawn() -> Self {
        let cache: Arc<Mutex<HashMap<PathBuf, CacheEntry>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(CACHE_MAX_ENTRIES)));
        let (tx, mut rx) = mpsc::channel::<PathBuf>(256);

        let worker_cache = cache.clone();
        std::thread::Builder::new()
            .name("edr-hasher".into())
            .spawn(move || {
                // Best-effort lower priority so the hashing doesn't
                // perturb the agent's main paths.
                #[cfg(target_os = "linux")]
                {
                    // SAFETY: setpriority(PRIO_PROCESS, 0, 19) is a
                    // self-targeted call with no preconditions.
                    unsafe {
                        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
                    }
                }
                while let Some(path) = rx.blocking_recv() {
                    let _ = process_one(&path, &worker_cache);
                }
            })
            .expect("spawn edr-hasher thread");

        Self {
            cache,
            queue_tx: tx,
        }
    }

    /// Look up a path in the cache. If hit and fresh → return the
    /// SHA-256 hex string. If miss or stale → enqueue a hash request
    /// and return None. Caller ships the event with no hash; the next
    /// event for the same path will hit the freshly-cached value.
    pub fn lookup_or_enqueue(&self, path: &str) -> Option<String> {
        let path_buf = PathBuf::from(path);

        // Stat once; we'll need it either way.
        let meta = match std::fs::metadata(&path_buf) {
            Ok(m) => m,
            Err(_) => return None,
        };
        let mtime_ns = meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128;
        let size = meta.size();

        // Cache hit?
        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.get(&path_buf) {
                let fresh = entry.inserted_at.elapsed() < CACHE_TTL
                    && entry.mtime_ns == mtime_ns
                    && entry.size == size;
                if fresh {
                    return Some(entry.sha256_hex.clone());
                }
            }
        }

        // Miss → enqueue (drop on backpressure rather than block).
        let _ = self.queue_tx.try_send(path_buf);
        None
    }
}

fn process_one(
    path: &PathBuf,
    cache: &Arc<Mutex<HashMap<PathBuf, CacheEntry>>>,
) -> std::io::Result<()> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Ok(());
    }
    if meta.size() > MAX_READ_BYTES {
        return Ok(()); // Skip huge files; not in our budget.
    }
    let mtime_ns = meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128;
    let size = meta.size();

    // Hash via streaming read so we don't load 64 MiB at once.
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_READ_BYTES {
            return Ok(()); // size grew during read; abort.
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    if let Ok(mut c) = cache.lock() {
        // LRU-ish: cap at CACHE_MAX_ENTRIES. We don't track actual
        // recency; on overflow, drop a random entry (HashMap iteration
        // order). That's good enough for a 1k cache that's mostly hot.
        if c.len() >= CACHE_MAX_ENTRIES {
            if let Some(k) = c.keys().next().cloned() {
                c.remove(&k);
            }
        }
        c.insert(
            path.clone(),
            CacheEntry {
                sha256_hex: hex,
                mtime_ns,
                size,
                inserted_at: Instant::now(),
            },
        );
    }
    Ok(())
}
