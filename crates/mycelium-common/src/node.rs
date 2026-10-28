use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Dedicated,
    #[default]
    Shared,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Online,
    Unreachable,
    Offline,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub hostname: String,
    pub campaign: String,
    pub fuzzer: String,
    pub priority: Priority,
    pub status: NodeStatus,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub last_sync: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::Dedicated => write!(f, "dedicated"),
            Priority::Shared => write!(f, "shared"),
            Priority::Idle => write!(f, "idle"),
        }
    }
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::Online => write!(f, "online"),
            NodeStatus::Unreachable => write!(f, "unreachable"),
            NodeStatus::Offline => write!(f, "offline"),
            NodeStatus::Suspended => write!(f, "suspended"),
        }
    }
}
