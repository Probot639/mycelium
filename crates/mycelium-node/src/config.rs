use serde::Deserialize;

use mycelium_common::node::Priority;

#[derive(Debug, Deserialize)]
pub struct CircleConfig {
    pub node: NodeConfig,
    pub fuzzer: FuzzerConfig,
    pub circle: CircleSettings,
}

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub coordinator: String,
    #[serde(default = "default_id")]
    pub id: String,
    #[serde(default)]
    pub priority: Priority,
}

fn default_id() -> String {
    "auto".into()
}

#[derive(Debug, Deserialize)]
pub struct FuzzerConfig {
    pub name: String,
    pub command: Vec<String>,
    pub corpus_dir: String,
    pub crash_dir: String,
    #[serde(default)]
    pub stats_file: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CircleSettings {
    #[serde(default = "default_sync_interval")]
    pub sync_interval: String,
    pub inject_dir: String,
    #[serde(default = "default_stats_parser")]
    pub stats_parser: String,
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_sync_interval() -> String {
    "30s".into()
}

fn default_stats_parser() -> String {
    "aflpp".into()
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
        let s = &self.circle.sync_interval;
        if let Some(n) = s.strip_suffix('s') {
            n.parse().unwrap_or(30)
        } else if let Some(n) = s.strip_suffix('m') {
            n.parse::<u64>().unwrap_or(1) * 60
        } else {
            s.parse().unwrap_or(30)
        }
    }

    pub fn resolve_path(&self, template: &str, corpus: &str, output: &str) -> String {
        template
            .replace("{corpus}", corpus)
            .replace("{output}", output)
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
}
