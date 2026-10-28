use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FuzzerStats {
    pub execs_per_sec: u64,
    pub total_execs: u64,
    pub corpus_size: u64,
    pub crashes_found: u64,
    pub hangs_found: u64,
    pub edges_found: u64,
}

// AFL++ fuzzer_stats is a flat key:value file. The keys changed between 3.x
// and 4.x (e.g. "paths_total" -> "corpus_count") so we just match both where
// they diverge. execs_per_sec is a float for some reason.
pub fn parse_aflpp_stats(raw: &str) -> FuzzerStats {
    let mut stats = FuzzerStats::default();
    for line in raw.lines() {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        match key {
            "execs_per_sec" => {
                stats.execs_per_sec = val.parse::<f64>().unwrap_or(0.0) as u64;
            }
            "execs_done" => stats.total_execs = val.parse().unwrap_or(0),
            "corpus_count" | "paths_total" => {
                stats.corpus_size = val.parse().unwrap_or(0);
            }
            "saved_crashes" | "unique_crashes" => {
                stats.crashes_found = val.parse().unwrap_or(0);
            }
            "saved_hangs" | "unique_hangs" => {
                stats.hangs_found = val.parse().unwrap_or(0);
            }
            "edges_found" => stats.edges_found = val.parse().unwrap_or(0),
            _ => {}
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aflpp_4x_stats_file() {
        let raw = "\
start_time        : 1698765432
last_update       : 1698765500
execs_per_sec     : 1234.56
execs_done        : 500000
corpus_count      : 142
saved_crashes     : 3
saved_hangs       : 1
edges_found       : 2048
";
        let stats = parse_aflpp_stats(raw);
        assert_eq!(stats.execs_per_sec, 1234);
        assert_eq!(stats.total_execs, 500000);
        assert_eq!(stats.corpus_size, 142);
        assert_eq!(stats.crashes_found, 3);
        assert_eq!(stats.hangs_found, 1);
        assert_eq!(stats.edges_found, 2048);
    }

    // AFL++ 3.x used different field names for some of these
    #[test]
    fn parse_aflpp_3x_compat() {
        let raw = "\
execs_per_sec     : 800.0
execs_done        : 100000
paths_total       : 87
unique_crashes    : 1
unique_hangs      : 0
";
        let stats = parse_aflpp_stats(raw);
        assert_eq!(stats.corpus_size, 87);
        assert_eq!(stats.crashes_found, 1);
    }
}
