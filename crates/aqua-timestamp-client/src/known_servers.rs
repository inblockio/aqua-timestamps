//! Optional `KnownServersFile`: a tiny on-disk record of which server DIDs
//! the caller has previously seen at which base URLs. Modeled on
//! `~/.ssh/known_hosts`, JSON-lines per host.
//!
//! Enabled via the `known-servers-file` feature flag. Callers with their
//! own persistence layer should ignore this and pass prior DIDs through
//! `TimestampClientBuilder::expect_server_did` directly.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    base_url: String,
    did: String,
    first_seen_at: u64,
    last_seen_at: u64,
}

pub struct KnownServersFile {
    path: PathBuf,
    entries: HashMap<String, Entry>,
}

impl KnownServersFile {
    /// Open or create a known-servers file at the given path. Parent
    /// directories are created if missing.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let entries = read_entries(&path)?;
        Ok(Self { path, entries })
    }

    /// Open the XDG-style default path (`$XDG_CONFIG_HOME/aqua/known_servers`,
    /// falling back to `~/.config/aqua/known_servers`).
    pub fn open_default() -> io::Result<Self> {
        Self::open(default_path()?)
    }

    /// Returns the previously recorded DID for the given base URL, if any.
    /// Base URLs are normalised (trailing slash stripped) before comparison.
    pub fn lookup(&self, base_url: &str) -> Option<&str> {
        let key = normalise(base_url);
        self.entries.get(&key).map(|e| e.did.as_str())
    }

    /// Idempotently record a (base_url, did) association. Updates
    /// `last_seen_at` if already present. Overwrites the DID if it differs
    /// (callers wanting rotation detection should compare with `lookup`
    /// before calling `record`).
    pub fn record(&mut self, base_url: &str, did: &str) -> io::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = normalise(base_url);
        self.entries
            .entry(key.clone())
            .and_modify(|e| {
                e.did = did.to_string();
                e.last_seen_at = now;
            })
            .or_insert(Entry {
                base_url: key,
                did: did.to_string(),
                first_seen_at: now,
                last_seen_at: now,
            });
        self.flush()
    }

    fn flush(&self) -> io::Result<()> {
        let mut tmp = self.path.clone();
        tmp.set_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            for entry in self.entries.values() {
                let line = serde_json::to_string(entry)?;
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
            }
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn read_entries(path: &Path) -> io::Result<HashMap<String, Entry>> {
    let mut entries = HashMap::new();
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(entries),
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<Entry>(&line) {
            entries.insert(entry.base_url.clone(), entry);
        }
    }
    Ok(entries)
}

fn normalise(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

fn default_path() -> io::Result<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("aqua").join("known_servers"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home).join(".config").join("aqua").join("known_servers"));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "neither $XDG_CONFIG_HOME nor $HOME is set",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn first_lookup_is_none() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_servers");
        let store = KnownServersFile::open(&path).unwrap();
        assert!(store.lookup("https://timestamp.example").is_none());
    }

    #[test]
    fn record_then_lookup() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_servers");
        let mut store = KnownServersFile::open(&path).unwrap();
        store
            .record("https://timestamp.example/", "did:pkh:eip155:1:0xabc")
            .unwrap();
        assert_eq!(
            store.lookup("https://timestamp.example"),
            Some("did:pkh:eip155:1:0xabc")
        );
    }

    #[test]
    fn persists_across_reopen() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_servers");
        {
            let mut store = KnownServersFile::open(&path).unwrap();
            store
                .record("https://timestamp.example", "did:pkh:eip155:1:0xabc")
                .unwrap();
        }
        let store = KnownServersFile::open(&path).unwrap();
        assert_eq!(
            store.lookup("https://timestamp.example"),
            Some("did:pkh:eip155:1:0xabc")
        );
    }

    #[test]
    fn record_overwrites() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_servers");
        let mut store = KnownServersFile::open(&path).unwrap();
        store
            .record("https://timestamp.example", "did:pkh:eip155:1:0xabc")
            .unwrap();
        store
            .record("https://timestamp.example", "did:pkh:eip155:1:0xdef")
            .unwrap();
        assert_eq!(
            store.lookup("https://timestamp.example"),
            Some("did:pkh:eip155:1:0xdef")
        );
    }

    #[test]
    fn normalises_trailing_slash() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("known_servers");
        let mut store = KnownServersFile::open(&path).unwrap();
        store.record("https://x.example", "did:1").unwrap();
        assert_eq!(store.lookup("https://x.example/"), Some("did:1"));
        assert_eq!(store.lookup("https://x.example"), Some("did:1"));
    }
}
