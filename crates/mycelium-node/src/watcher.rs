use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use mycelium_common::corpus::hash_bytes;

use crate::profile::{FileRole, FuzzerProfile};

#[derive(Debug)]
pub enum WatchEvent {
    NewSeed { path: PathBuf, hash: String, data: Vec<u8> },
    NewCrash { path: PathBuf, data: Vec<u8> },
}

#[derive(Clone)]
pub struct DirWatcher {
    seen_hashes: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl Default for DirWatcher {
    fn default() -> Self {
        Self::new()
    }
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
        profile: &FuzzerProfile,
    ) -> Result<(notify::RecommendedWatcher, mpsc::UnboundedReceiver<WatchEvent>)> {
        // Unbounded on purpose. A bounded channel dropped the overflow during the
        // startup scan of a large corpus, and its blocking_send stalled notify's
        // callback thread when a fast fuzzer outran the HTTP push. Unbounded never
        // drops and never blocks the watcher; the push loop drains it. The loop
        // keeps the drain moving (short HTTP timeouts) so it does not grow without
        // bound while a coordinator is slow.
        let (tx, rx) = mpsc::unbounded_channel();
        let corpus = corpus_dir.to_path_buf();
        let crash = crash_dir.to_path_buf();
        let seen = self.seen_hashes.clone();

        // Scan the existing corpus on a dedicated thread: it does blocking
        // std::fs reads of every file, and watch() is called from inside the
        // async sync loop, so running it inline would stall the tokio worker (and
        // the heartbeat/pull timers on it) until the whole corpus was read.
        {
            let tx = tx.clone();
            let seen = seen.clone();
            let profile = profile.clone();
            let corpus = corpus.clone();
            let crash = crash.clone();
            std::thread::spawn(move || {
                if let Err(e) = Self::scan_existing(&corpus, &crash, &profile, &seen, &tx) {
                    tracing::warn!(error = %e, "initial corpus scan failed");
                }
            });
        }

        let tx_clone = tx.clone();
        let seen_clone = seen.clone();
        let corpus_clone = corpus.clone();
        let crash_clone = crash.clone();
        let profile = profile.clone();

        // notify fires both Create and Modify for AFL++'s rename-into-queue pattern,
        // the seen_hashes set deduplicates so we just handle both
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            let Ok(event) = res else { return };
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    for path in event.paths {
                        // Only read a real file, never a symlink: the fuzz target
                        // is the one untrusted writer in the watched tree, and a
                        // symlink it drops (queue/x -> /etc/shadow) would otherwise
                        // be read and uploaded as a "seed". symlink_metadata does
                        // not follow the link, so a symlink is skipped outright.
                        match std::fs::symlink_metadata(&path) {
                            Ok(m) if m.is_file() => {}
                            _ => continue,
                        }
                        let role = profile.classify(&path, &corpus_clone, &crash_clone);
                        if role == FileRole::Ignore {
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
                        match role {
                            FileRole::Crash => {
                                let _ = tx_clone.send(WatchEvent::NewCrash { path, data });
                            }
                            FileRole::Seed => {
                                let _ = tx_clone.send(WatchEvent::NewSeed { path, hash, data });
                            }
                            FileRole::Ignore => {}
                        }
                    }
                }
                _ => {}
            }
        })?;

        // Watch the corpus recursively. Watch the crash dir only when it is not
        // already covered: equal to, or nested under, a corpus dir we watched.
        // (A distributed honggfuzz node has crash_dir = output/crashes under
        // corpus_dir = output, so the recursive corpus watch already sees it.)
        let corpus_watched = corpus_dir.exists();
        if corpus_watched {
            watcher.watch(corpus_dir, RecursiveMode::Recursive)?;
        }
        if crash_dir.exists() && !(corpus_watched && crash_dir.starts_with(corpus_dir)) {
            watcher.watch(crash_dir, RecursiveMode::Recursive)?;
        }

        // Hand the watcher back so the caller owns it for the run's lifetime.
        // Dropping it unwatches and frees the inotify FDs and callback thread,
        // which matters in round mode where watch() is called once per round:
        // leaking it (the old std::mem::forget) piled up a live watcher per round
        // until the node hit its FD limit.
        Ok((watcher, rx))
    }

    fn scan_existing(
        corpus_dir: &Path,
        crash_dir: &Path,
        profile: &FuzzerProfile,
        seen: &Arc<std::sync::Mutex<HashSet<String>>>,
        tx: &mpsc::UnboundedSender<WatchEvent>,
    ) -> Result<()> {
        // Walk the dirs recursively, matching the live watcher's recursive mode,
        // so pre-existing files in nested layouts (syzkaller's crashes/<hash>/
        // repro*) are caught on startup, not just flat dirs like AFL's queue.
        // Dedupe the roots so a libFuzzer-style profile (corpus == crash dir) is
        // not walked twice.
        let mut stack = vec![corpus_dir.to_path_buf()];
        if crash_dir != corpus_dir {
            stack.push(crash_dir.to_path_buf());
        }
        while let Some(dir) = stack.pop() {
            if !dir.exists() {
                continue;
            }
            let rd = match std::fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            for entry in rd.flatten() {
                let path = entry.path();
                // DirEntry::file_type does not follow symlinks, so skip a symlink
                // instead of reading its target or walking into a symlinked dir
                // (same exfiltration concern as the live watcher).
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !ft.is_file() {
                    continue;
                }
                let role = profile.classify(&path, corpus_dir, crash_dir);
                if role == FileRole::Ignore {
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
                match role {
                    FileRole::Crash => {
                        let _ = tx.send(WatchEvent::NewCrash { path, data });
                    }
                    FileRole::Seed => {
                        let _ = tx.send(WatchEvent::NewSeed { path, hash, data });
                    }
                    FileRole::Ignore => {}
                }
            }
        }
        Ok(())
    }

    pub fn mark_seen(&self, hash: &str) {
        self.seen_hashes.lock().unwrap().insert(hash.to_string());
    }

    // Forget a hash so the next scan or notify event re-discovers and re-sends
    // it. The loop calls this when an upload fails, so a transient coordinator
    // outage does not permanently drop a seed or crash that was marked seen at
    // discovery time (the dedup set is updated before the upload is attempted).
    pub fn mark_unseen(&self, hash: &str) {
        self.seen_hashes.lock().unwrap().remove(hash);
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
        let (_guard, mut rx) = watcher
            .watch(&corpus, &crashes, &crate::profile::FuzzerProfile::aflpp())
            .unwrap();

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

    #[tokio::test]
    async fn scan_skips_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let corpus = tmp.path().join("corpus");
        let crashes = tmp.path().join("crashes");
        fs::create_dir_all(&corpus).unwrap();
        fs::create_dir_all(&crashes).unwrap();
        // a secret the fuzz target must not be able to exfiltrate via a symlink
        let secret = tmp.path().join("secret");
        fs::write(&secret, b"TOP-SECRET-CONTENTS").unwrap();
        fs::write(corpus.join("real-seed"), b"ordinary seed").unwrap();
        std::os::unix::fs::symlink(&secret, corpus.join("sneaky")).unwrap();

        let watcher = DirWatcher::new();
        let (_guard, mut rx) = watcher
            .watch(&corpus, &crashes, &crate::profile::FuzzerProfile::aflpp())
            .unwrap();

        let mut saw_real = false;
        while let Ok(Some(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
        {
            let data = match event {
                WatchEvent::NewSeed { data, .. } => data,
                WatchEvent::NewCrash { data, .. } => data,
            };
            assert_ne!(data, b"TOP-SECRET-CONTENTS", "symlink target was read and emitted");
            if data == b"ordinary seed" {
                saw_real = true;
            }
        }
        assert!(saw_real, "the real seed should still be picked up");
    }
}
