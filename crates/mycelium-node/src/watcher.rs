use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use mycelium_common::corpus::hash_bytes;

#[derive(Debug)]
pub enum WatchEvent {
    NewSeed { path: PathBuf, hash: String, data: Vec<u8> },
    NewCrash { path: PathBuf, data: Vec<u8> },
}

pub struct DirWatcher {
    seen_hashes: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl DirWatcher {
    pub fn new() -> Self {
        Self {
            seen_hashes: Arc::new(std::sync::Mutex::new(HashSet::new())),
        }
    }

    pub fn watch(
        &self,
        corpus_dir: &Path,
        crash_dir: &Path,
    ) -> Result<mpsc::Receiver<WatchEvent>> {
        let (tx, rx) = mpsc::channel(256);
        let corpus = corpus_dir.to_path_buf();
        let crash = crash_dir.to_path_buf();
        let seen = self.seen_hashes.clone();

        // Scan existing files first
        Self::scan_existing(&corpus, &crash, &seen, &tx)?;

        let tx_clone = tx.clone();
        let seen_clone = seen.clone();
        let corpus_clone = corpus.clone();

        // notify fires both Create and Modify for AFL++'s rename-into-queue pattern,
        // the seen_hashes set deduplicates so we just handle both
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            let Ok(event) = res else { return };
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    for path in event.paths {
                        if !path.is_file() {
                            continue;
                        }
                        let Ok(data) = std::fs::read(&path) else {
                            continue;
                        };
                        if data.is_empty() {
                            continue;
                        }
                        let hash = hash_bytes(&data);
                        {
                            let mut seen = seen_clone.lock().unwrap();
                            if seen.contains(&hash) {
                                continue;
                            }
                            seen.insert(hash.clone());
                        }
                        let is_crash = path.starts_with(&crash);
                        let is_corpus = path.starts_with(&corpus_clone);
                        if is_crash {
                            let _ = tx_clone.blocking_send(WatchEvent::NewCrash {
                                path,
                                data,
                            });
                        } else if is_corpus {
                            let _ = tx_clone.blocking_send(WatchEvent::NewSeed {
                                path,
                                hash,
                                data,
                            });
                        }
                    }
                }
                _ => {}
            }
        })?;

        if corpus_dir.exists() {
            watcher.watch(corpus_dir, RecursiveMode::Recursive)?;
        }
        if crash_dir.exists() {
            watcher.watch(crash_dir, RecursiveMode::Recursive)?;
        }

        // leaked on purpose, circle process owns it until killed
        std::mem::forget(watcher);

        Ok(rx)
    }

    fn scan_existing(
        corpus_dir: &Path,
        crash_dir: &Path,
        seen: &Arc<std::sync::Mutex<HashSet<String>>>,
        tx: &mpsc::Sender<WatchEvent>,
    ) -> Result<()> {
        for dir in [corpus_dir, crash_dir] {
            if !dir.exists() {
                continue;
            }
            let is_crash = dir == crash_dir;
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let data = std::fs::read(&path)?;
                if data.is_empty() {
                    continue;
                }
                let hash = hash_bytes(&data);
                {
                    let mut seen = seen.lock().unwrap();
                    if seen.contains(&hash) {
                        continue;
                    }
                    seen.insert(hash.clone());
                }
                if is_crash {
                    let _ = tx.try_send(WatchEvent::NewCrash { path, data });
                } else {
                    let _ = tx.try_send(WatchEvent::NewSeed { path, hash, data });
                }
            }
        }
        Ok(())
    }

    pub fn mark_seen(&self, hash: &str) {
        self.seen_hashes.lock().unwrap().insert(hash.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn scan_existing_files() {
        let tmp = tempfile::tempdir().unwrap();
        let corpus = tmp.path().join("corpus");
        let crashes = tmp.path().join("crashes");
        fs::create_dir_all(&corpus).unwrap();
        fs::create_dir_all(&crashes).unwrap();
        fs::write(corpus.join("seed1"), b"hello").unwrap();
        fs::write(crashes.join("crash1"), b"boom").unwrap();

        let watcher = DirWatcher::new();
        let mut rx = watcher.watch(&corpus, &crashes).unwrap();

        let mut got_seed = false;
        let mut got_crash = false;

        while let Ok(event) = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            rx.recv(),
        ).await {
            match event {
                Some(WatchEvent::NewSeed { .. }) => got_seed = true,
                Some(WatchEvent::NewCrash { .. }) => got_crash = true,
                None => break,
            }
        }

        assert!(got_seed);
        assert!(got_crash);
    }
}
