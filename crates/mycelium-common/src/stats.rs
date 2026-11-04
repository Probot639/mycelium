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

/// Parse a fuzzer's stats output with the named parser. Unknown parser names
/// fall back to the AFL++ parser so a config typo does not zero out the stats.
pub fn parse_stats(parser: &str, raw: &str) -> FuzzerStats {
    match parser {
        "libfuzzer" | "libfuzzer-log" => parse_libfuzzer_log(raw),
        "honggfuzz" => parse_honggfuzz_stats(raw),
        // "aflpp", "afl", "afl++", and anything unrecognized
        _ => parse_aflpp_stats(raw),
    }
}

// honggfuzz prints a periodic "key : value" summary. The exact labels drift
// between versions and numbers can carry thousands separators, so this stays
// best-effort: it reads iterations, speed, and crash count where present.
pub fn parse_honggfuzz_stats(raw: &str) -> FuzzerStats {
    let mut stats = FuzzerStats::default();
    let mut apply = |k: &str, v: &str| {
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().replace(',', "");
        // take the leading number, tolerating a suffix like "4200/sec"
        let lead: String = val.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        let num = lead.parse::<f64>().ok().map(finite_u64).unwrap_or(0);
        if key.starts_with("iterations") {
            stats.total_execs = num;
        } else if key.contains("speed") || key.contains("exec/s") {
            stats.execs_per_sec = num;
        } else if key.starts_with("crashes") {
            stats.crashes_found = num;
        }
    };
    // Two shapes: a spaced one-pair-per-line form ("Speed : 4200/sec"), and the
    // end-of-run summary where pairs are packed onto one line,
    //   Summary iterations:4491810 time:31 speed:144897 crashes_count:0 ...
    // Parse both: the whole-line first colon catches the spaced form, and each
    // whitespace token catches the packed form. Matching is idempotent, so a
    // line that fits both sets the same value twice.
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            apply(k, v);
        }
        for tok in line.split_whitespace() {
            if let Some((k, v)) = tok.split_once(':') {
                apply(k, v);
            }
        }
    }
    stats
}

// libFuzzer prints progress lines to stderr like
//   #1024 NEW    cov: 212 ft: 318 corp: 41 exec/s: 512 ...
// We read the last such line for a rough snapshot. libFuzzer has no persistent
// stats file, so callers point stats_file at a captured log. Note that REDUCE
// lines (corpus minimization) report `exec/s: 0`, so we keep the last *positive*
// rate rather than letting a minimization pass zero the heartbeat.
pub fn parse_libfuzzer_log(raw: &str) -> FuzzerStats {
    let mut stats = FuzzerStats::default();
    for line in raw.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix('#') else {
            continue;
        };
        let mut head = rest.split_whitespace();
        let Some(execs) = head.next().and_then(|n| n.parse::<u64>().ok()) else {
            continue;
        };
        stats.total_execs = execs;
        let toks: Vec<&str> = rest.split_whitespace().collect();
        for pair in toks.windows(2) {
            match pair[0] {
                "cov:" => stats.edges_found = pair[1].parse().unwrap_or(stats.edges_found),
                // libFuzzer prints corp as "count/bytes" (e.g. 37/212b)
                "corp:" => {
                    if let Some(n) = pair[1].split('/').next().and_then(|c| c.parse().ok()) {
                        stats.corpus_size = n;
                    }
                }
                "exec/s:" => {
                    if let Ok(v) = pair[1].parse::<u64>()
                        && v > 0
                    {
                        stats.execs_per_sec = v;
                    }
                }
                _ => {}
            }
        }
    }
    stats
}

// AFL++ fuzzer_stats is a flat key:value file. The keys changed between 3.x
// and 4.x (e.g. "paths_total" -> "corpus_count") so we just match both where
// they diverge. execs_per_sec is a float for some reason.
// AFL writes execs_per_sec as a float, and during calibration it can be a huge
// transient or a non-finite value. A naive `as u64` cast saturates a non-finite
// or astronomically large float to u64::MAX, which then overflows the
// coordinator's signed SQLite column and 500s the heartbeat. Clamp to a finite,
// non-negative value that fits in i64.
fn finite_u64(f: f64) -> u64 {
    if f.is_finite() && f > 0.0 {
        // The float path alone is not enough: i64::MAX as f64 rounds up past
        // i64::MAX, so clamp the resulting integer too.
        (f as u64).min(i64::MAX as u64)
    } else {
        0
    }
}

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
                stats.execs_per_sec = finite_u64(val.parse::<f64>().unwrap_or(0.0));
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

    #[test]
    fn execs_per_sec_never_overflows_i64() {
        // non-finite and negative collapse to 0
        assert_eq!(parse_aflpp_stats("execs_per_sec : inf\n").execs_per_sec, 0);
        assert_eq!(parse_aflpp_stats("execs_per_sec : -5\n").execs_per_sec, 0);
        // astronomically large stays within i64 so the DB bind cannot overflow
        let s = parse_aflpp_stats("execs_per_sec : 1e30\n");
        assert!(s.execs_per_sec <= i64::MAX as u64);
        assert!(s.execs_per_sec > 0);
    }

    #[test]
    fn parse_honggfuzz() {
        let raw = "Iterations : 1,234,567\nSpeed : 4200/sec\nCrashes : 3\n";
        let s = parse_stats("honggfuzz", raw);
        assert_eq!(s.total_execs, 1234567);
        assert_eq!(s.execs_per_sec, 4200);
        assert_eq!(s.crashes_found, 3);
    }

    #[test]
    fn parse_honggfuzz_summary_line() {
        // the real end-of-run line packs the pairs onto one line
        let raw = "Summary iterations:4491810 time:31 speed:144897 crashes_count:0 new_units_added:13\n";
        let s = parse_stats("honggfuzz", raw);
        assert_eq!(s.total_execs, 4491810);
        assert_eq!(s.execs_per_sec, 144897);
        assert_eq!(s.crashes_found, 0);
    }

    #[test]
    fn parse_stats_dispatches_by_name() {
        let afl = "execs_per_sec : 100.0\ncorpus_count : 5\n";
        assert_eq!(parse_stats("aflpp", afl).corpus_size, 5);
        // unknown name falls back to aflpp rather than zeroing out
        assert_eq!(parse_stats("nonsense", afl).corpus_size, 5);

        let lf = "#512 NEW    cov: 212 ft: 318 corp: 41 exec/s: 640 rss: 30Mb\n";
        let s = parse_stats("libfuzzer", lf);
        assert_eq!(s.total_execs, 512);
        assert_eq!(s.edges_found, 212);
        assert_eq!(s.corpus_size, 41);
        assert_eq!(s.execs_per_sec, 640);
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
