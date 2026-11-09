use serde::Deserialize;

use mycelium_common::node::Priority;

use crate::profile::FuzzerProfile;

/// How a node supervises its fuzzer process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzerMode {
    /// Run the fuzzer until it exits, then the node is done. Default.
    Persistent,
    /// The fuzzer exits once per round. The node pulls fresh corpus and
    /// relaunches it after each round.
    Round,
    /// Do not launch a fuzzer at all. Watch the output dirs of a fuzzer managed
    /// elsewhere and only sync corpus and crashes.
    Api,
}

#[derive(Debug, Deserialize)]
pub struct CircleConfig {
    pub node: NodeConfig,
    pub fuzzer: FuzzerConfig,
    pub circle: CircleSettings,
}

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub coordinator: String,
    #[serde(default)]
    pub priority: Priority,
}

#[derive(Debug, Deserialize)]
pub struct FuzzerConfig {
    pub name: String,
    pub command: Vec<String>,
    pub corpus_dir: String,
    pub crash_dir: String,
    #[serde(default)]
    pub stats_file: Option<String>,
    /// Command run on a crashing input to capture a sanitizer trace, with
    /// `{file}` replaced by the input path. Its combined output becomes the
    /// crash's trace and drives the per-bug stack hash. Point this at an
    /// ASAN-instrumented build of the target (for libFuzzer, the fuzzer binary
    /// itself works). With none set, crashes are reported without a trace and
    /// deduped per input.
    #[serde(default)]
    pub triage_cmd: Option<Vec<String>>,
    /// Command template for collecting per-input coverage. `{harness}` is
    /// replaced with the instrumented binary, `{file}` with the input path.
    /// Defaults to the profile's built-in if unset.
    #[serde(default)]
    pub coverage_cmd: Option<Vec<String>>,
    /// Script hooks for a custom fuzzer that file layout alone cannot drive.
    #[serde(default)]
    pub hooks: Hooks,
}

/// Escape hatches for fuzzers that are not purely file-driven. Both are
/// optional: with neither set, the node drops pulled seeds into `inject_dir`
/// and reads stats from `stats_file`, which covers the built-in profiles.
#[derive(Debug, Default, Deserialize)]
pub struct Hooks {
    /// Run once per pulled seed to hand it to the fuzzer. The token `{file}` is
    /// replaced with the path of the seed on disk. Use for a fuzzer that takes
    /// new inputs through its own API or socket rather than a watched dir.
    #[serde(default)]
    pub import_cmd: Option<Vec<String>>,
    /// Run each sync tick; its stdout is parsed by the stats parser. Use for a
    /// fuzzer that reports progress to a command rather than a stats file.
    #[serde(default)]
    pub stats_cmd: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CircleSettings {
    #[serde(default = "default_sync_interval")]
    pub sync_interval: String,
    pub inject_dir: String,
    /// Override the stats parser. Defaults to the one the fuzzer profile implies.
    #[serde(default)]
    pub stats_parser: Option<String>,
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_sync_interval() -> String {
    "30s".into()
}

// Parse "30s" / "2m" / "1h" (or a bare integer, read as seconds) into seconds.
// Returns None for anything that does not parse, so the caller can warn and fall
// back once, rather than silently accepting a typo with an inconsistent default.
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else {
        (s, 1)
    };
    num.trim().parse::<u64>().ok().map(|v| v.saturating_mul(mult))
}

fn default_mode() -> String {
    "persistent".into()
}

impl CircleConfig {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn sync_interval_secs(&self) -> u64 {
        parse_duration_secs(&self.circle.sync_interval).unwrap_or_else(|| {
            tracing::warn!(
                value = %self.circle.sync_interval,
                "unparseable sync_interval, falling back to 30s"
            );
            30
        })
    }

    /// The configured fuzzer supervision mode. Unknown values fall back to
    /// persistent so a typo does not wedge the node.
    pub fn mode(&self) -> FuzzerMode {
        match self.circle.mode.as_str() {
            "round" => FuzzerMode::Round,
            "api" | "external" => FuzzerMode::Api,
            _ => FuzzerMode::Persistent,
        }
    }

    /// The fuzzer profile, selected by `[fuzzer] name`. Governs how the watcher
    /// tells seeds from crashes from bookkeeping. Unknown names fall back to the
    /// AFL++ layout.
    pub fn profile(&self) -> FuzzerProfile {
        let mut p = FuzzerProfile::builtin(&self.fuzzer.name).unwrap_or_else(FuzzerProfile::aflpp);
        if let Some(ref cmd) = self.fuzzer.coverage_cmd {
            p.coverage_cmd = Some(cmd.clone());
        }
        p
    }

    /// Which stats parser to use for heartbeat reporting: the explicit config
    /// value if set, otherwise the one the profile implies.
    pub fn stats_parser(&self) -> String {
        self.circle
            .stats_parser
            .clone()
            .unwrap_or_else(|| self.profile().stats_parser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let toml_str = r#"
[node]
coordinator = "sigil:7100"
priority = "shared"

[fuzzer]
name = "aflpp"
command = ["afl-fuzz", "-i", "{corpus}", "-o", "{output}", "--", "./target"]
corpus_dir = "{output}/default/queue"
crash_dir = "{output}/default/crashes"
stats_file = "{output}/default/fuzzer_stats"

[circle]
sync_interval = "30s"
inject_dir = "{corpus}"
stats_parser = "aflpp"
mode = "persistent"
"#;
        let config: CircleConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.coordinator, "sigil:7100");
        assert_eq!(config.fuzzer.name, "aflpp");
        assert_eq!(config.sync_interval_secs(), 30);
    }

    #[test]
    fn custom_fuzzer_profile_and_hooks() {
        let toml_str = r#"
[node]
coordinator = "x:7100"
[fuzzer]
name = "libfuzzer"
command = ["./fuzz"]
corpus_dir = "./corpus"
crash_dir = "./corpus"
[fuzzer.hooks]
import_cmd = ["myctl", "add", "{file}"]
stats_cmd = ["myctl", "stats"]
[circle]
inject_dir = "./corpus"
"#;
        let cfg: CircleConfig = toml::from_str(toml_str).unwrap();
        // name selects the profile, which implies the stats parser
        assert_eq!(cfg.profile().name, "libfuzzer");
        assert_eq!(cfg.stats_parser(), "libfuzzer");
        assert_eq!(cfg.fuzzer.hooks.import_cmd.as_ref().unwrap(), &["myctl", "add", "{file}"]);
        assert!(cfg.fuzzer.hooks.stats_cmd.is_some());
    }

    #[test]
    fn explicit_stats_parser_overrides_profile() {
        let toml_str = r#"
[node]
coordinator = "x:7100"
[fuzzer]
name = "libfuzzer"
command = ["./fuzz"]
corpus_dir = "./c"
crash_dir = "./c"
[circle]
inject_dir = "./c"
stats_parser = "aflpp"
"#;
        let cfg: CircleConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.stats_parser(), "aflpp");
    }

    #[test]
    fn mode_parses_and_defaults() {
        let base = |mode: &str| {
            format!(
                r#"
[node]
coordinator = "x:7100"
[fuzzer]
name = "aflpp"
command = ["afl-fuzz"]
corpus_dir = "./q"
crash_dir = "./c"
[circle]
inject_dir = "./i"
mode = "{mode}"
"#
            )
        };
        let round: CircleConfig = toml::from_str(&base("round")).unwrap();
        assert_eq!(round.mode(), FuzzerMode::Round);
        let api: CircleConfig = toml::from_str(&base("api")).unwrap();
        assert_eq!(api.mode(), FuzzerMode::Api);
        // unknown or absent -> persistent
        let typo: CircleConfig = toml::from_str(&base("wat")).unwrap();
        assert_eq!(typo.mode(), FuzzerMode::Persistent);
    }

    #[test]
    fn sync_interval_minutes() {
        let toml_str = r#"
[node]
coordinator = "sigil:7100"

[fuzzer]
name = "aflpp"
command = ["afl-fuzz"]
corpus_dir = "./corpus"
crash_dir = "./crashes"

[circle]
inject_dir = "./corpus"
sync_interval = "2m"
"#;
        let config: CircleConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.sync_interval_secs(), 120);
    }

    #[test]
    fn sync_interval_parsing() {
        assert_eq!(super::parse_duration_secs("45s"), Some(45));
        assert_eq!(super::parse_duration_secs("2m"), Some(120));
        assert_eq!(super::parse_duration_secs("1h"), Some(3600));
        assert_eq!(super::parse_duration_secs("90"), Some(90)); // bare int = seconds
        // unparseable values are rejected, not silently coerced
        assert_eq!(super::parse_duration_secs("1.5m"), None);
        assert_eq!(super::parse_duration_secs("soon"), None);
        assert_eq!(super::parse_duration_secs("s"), None);
    }
}
