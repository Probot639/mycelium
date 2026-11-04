use std::path::Path;

/// What a watched file is, according to a fuzzer's on-disk conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRole {
    Seed,
    Crash,
    Ignore,
}

/// How a node interprets a fuzzer's output on disk: which files are new corpus
/// entries, which are crashes, and which are bookkeeping to skip. Built-in
/// presets cover the common fuzzers; a custom profile fills the same fields from
/// config, and a fuzzer that cannot be described by file layout alone uses the
/// script hooks instead (see config `[fuzzer.hooks]`).
#[derive(Debug, Clone)]
pub struct FuzzerProfile {
    pub name: String,
    /// Filename prefixes that mark a crash wherever the file sits (libFuzzer
    /// writes `crash-<sha1>`, `oom-...`, `timeout-...` next to the corpus).
    pub crash_prefixes: Vec<String>,
    /// Exact filenames that are never test cases.
    pub ignore_names: Vec<String>,
    /// Path components (any depth) that are never test cases.
    pub ignore_components: Vec<String>,
    /// AFL++-style output: new corpus lives in `<output>/<instance>/queue` and
    /// crashes in `.../crashes`, where the instance subdir name is learned at
    /// runtime. Other fuzzers write to fixed dirs.
    pub afl_instance_layout: bool,
    /// In distributed mode, whether this fuzzer writes new corpus into the
    /// `{output}` dir (honggfuzz `-o`, libafl, go, syzkaller) rather than back
    /// into the `{corpus}` / `-i` dir (libFuzzer appends new units to its first
    /// positional corpus dir). The node watches the right dir based on this so a
    /// distributed non-AFL node actually syncs its corpus. Unused when
    /// `afl_instance_layout` is set, since AFL has its own output layout.
    pub writes_corpus_to_output: bool,
    /// Default stats parser name (see `mycelium_common::stats::parse_stats`).
    pub stats_parser: String,
}

impl FuzzerProfile {
    /// A built-in preset by name, or None for an unknown name.
    pub fn builtin(name: &str) -> Option<Self> {
        match name {
            "aflpp" | "afl" | "afl++" => Some(Self::aflpp()),
            // these are all libFuzzer underneath
            "libfuzzer" | "cargo-fuzz" | "cargofuzz" | "atheris" | "jazzer" => {
                Some(Self::libfuzzer(name))
            }
            "honggfuzz" => Some(Self::honggfuzz()),
            "libafl" => Some(Self::libafl()),
            "go" | "gofuzz" | "go-fuzz" => Some(Self::go()),
            "syzkaller" | "syz" => Some(Self::syzkaller()),
            _ => None,
        }
    }

    pub fn aflpp() -> Self {
        Self {
            name: "aflpp".into(),
            crash_prefixes: vec![],
            ignore_names: vec![
                "README.txt".into(),
                "fuzzer_stats".into(),
                "fuzzer_setup".into(),
                "plot_data".into(),
                "cmdline".into(),
                ".cur_input".into(),
            ],
            ignore_components: vec![".state".into(), ".synced".into()],
            afl_instance_layout: true,
            writes_corpus_to_output: false,
            stats_parser: "aflpp".into(),
        }
    }

    pub fn libfuzzer(name: &str) -> Self {
        Self {
            name: name.into(),
            crash_prefixes: vec![
                "crash-".into(),
                "oom-".into(),
                "timeout-".into(),
                "leak-".into(),
                "slow-unit-".into(),
            ],
            ignore_names: vec![],
            ignore_components: vec![],
            afl_instance_layout: false,
            writes_corpus_to_output: false,
            stats_parser: "libfuzzer".into(),
        }
    }

    pub fn honggfuzz() -> Self {
        Self {
            name: "honggfuzz".into(),
            crash_prefixes: vec![],
            ignore_names: vec!["HONGGFUZZ.REPORT.TXT".into()],
            ignore_components: vec![],
            afl_instance_layout: false,
            writes_corpus_to_output: true,
            stats_parser: "honggfuzz".into(),
        }
    }

    pub fn libafl() -> Self {
        Self {
            name: "libafl".into(),
            crash_prefixes: vec![],
            ignore_names: vec![".metadata".into()],
            ignore_components: vec![".metadata".into()],
            afl_instance_layout: false,
            writes_corpus_to_output: true,
            stats_parser: "aflpp".into(),
        }
    }

    pub fn go() -> Self {
        Self {
            name: "go".into(),
            crash_prefixes: vec![],
            ignore_names: vec![],
            ignore_components: vec![],
            afl_instance_layout: false,
            writes_corpus_to_output: true,
            stats_parser: "aflpp".into(),
        }
    }

    // syzkaller writes each crash as a dir of files under workdir/crashes: the
    // reproducers are `repro*.prog` / `repro*.cprog`, and everything else
    // (description, log*, report*, machineInfo*) is metadata to skip. Its corpus
    // lives in a single corpus.db, not watchable files, so corpus sync for a
    // syzkaller node goes through the hooks/api path, not the watcher.
    pub fn syzkaller() -> Self {
        Self {
            name: "syzkaller".into(),
            crash_prefixes: vec!["repro".into()],
            ignore_names: vec![],
            ignore_components: vec![],
            afl_instance_layout: false,
            writes_corpus_to_output: true,
            stats_parser: "aflpp".into(),
        }
    }

    /// Decide what a file is. `crash_root` is the dir the fuzzer writes crashes
    /// into (may be the same dir as `corpus_root` for libFuzzer); `corpus_root`
    /// is where new coverage-increasing inputs land.
    pub fn classify(&self, path: &Path, corpus_root: &Path, crash_root: &Path) -> FileRole {
        // bookkeeping first
        if path
            .components()
            .any(|c| self.ignore_components.iter().any(|ig| c.as_os_str() == ig.as_str()))
        {
            return FileRole::Ignore;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => return FileRole::Ignore,
        };
        if self.ignore_names.iter().any(|ig| ig == name) {
            return FileRole::Ignore;
        }
        // a crash by filename prefix wins no matter where it sits
        if self.crash_prefixes.iter().any(|p| name.starts_with(p.as_str())) {
            return FileRole::Crash;
        }
        // a dedicated crash dir, distinct from the corpus dir: for a dir-based
        // fuzzer (no prefixes) its files are crashes. For a prefix-based fuzzer
        // that happens to share no dir, a non-matching file here is just noise.
        if crash_root != corpus_root && path.starts_with(crash_root) {
            return if self.crash_prefixes.is_empty() {
                FileRole::Crash
            } else {
                FileRole::Ignore
            };
        }
        // otherwise anything under the corpus dir is a seed (this also covers
        // libFuzzer, where the corpus and artifact dir are the same path)
        if path.starts_with(corpus_root) {
            return FileRole::Seed;
        }
        FileRole::Ignore
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn aflpp_classification() {
        let p = FuzzerProfile::aflpp();
        let corpus = PathBuf::from("/out/main/queue");
        let crash = PathBuf::from("/out/main/crashes");
        assert_eq!(p.classify(&corpus.join("id:000001"), &corpus, &crash), FileRole::Seed);
        assert_eq!(p.classify(&crash.join("id:000002"), &corpus, &crash), FileRole::Crash);
        assert_eq!(p.classify(&crash.join("README.txt"), &corpus, &crash), FileRole::Ignore);
        assert_eq!(
            p.classify(&corpus.join(".state").join("x"), &corpus, &crash),
            FileRole::Ignore
        );
    }

    #[test]
    fn libfuzzer_classification() {
        let p = FuzzerProfile::libfuzzer("libfuzzer");
        // libFuzzer reuses one dir for corpus and artifacts
        let dir = PathBuf::from("/corpus");
        assert_eq!(p.classify(&dir.join("abc123"), &dir, &dir), FileRole::Seed);
        assert_eq!(p.classify(&dir.join("crash-deadbeef"), &dir, &dir), FileRole::Crash);
        assert_eq!(p.classify(&dir.join("oom-1234"), &dir, &dir), FileRole::Crash);
        assert_eq!(p.classify(&dir.join("timeout-9"), &dir, &dir), FileRole::Crash);
    }

    #[test]
    fn honggfuzz_report_ignored() {
        let p = FuzzerProfile::honggfuzz();
        let corpus = PathBuf::from("/in");
        let crash = PathBuf::from("/crashes");
        assert_eq!(
            p.classify(&crash.join("HONGGFUZZ.REPORT.TXT"), &corpus, &crash),
            FileRole::Ignore
        );
        assert_eq!(p.classify(&crash.join("SIGSEGV.1.fuzz"), &corpus, &crash), FileRole::Crash);
        assert_eq!(p.classify(&corpus.join("seed0"), &corpus, &crash), FileRole::Seed);
    }

    #[test]
    fn syzkaller_repro_vs_metadata() {
        let p = FuzzerProfile::syzkaller();
        let corpus = PathBuf::from("/wk/corpus");
        let crash = PathBuf::from("/wk/crashes/abc123");
        // repro files are the crash reproducers
        assert_eq!(p.classify(&crash.join("repro0.prog"), &corpus, &crash), FileRole::Crash);
        assert_eq!(p.classify(&crash.join("repro0.cprog"), &corpus, &crash), FileRole::Crash);
        // metadata under the crash dir is skipped
        assert_eq!(p.classify(&crash.join("description"), &corpus, &crash), FileRole::Ignore);
        assert_eq!(p.classify(&crash.join("report0"), &corpus, &crash), FileRole::Ignore);
    }

    #[test]
    fn unknown_name_has_no_builtin() {
        assert!(FuzzerProfile::builtin("nonsense").is_none());
        assert!(FuzzerProfile::builtin("libfuzzer").is_some());
    }
}
