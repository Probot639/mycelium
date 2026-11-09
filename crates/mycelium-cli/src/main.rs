use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

use mycelium_node::config::FuzzerMode;

#[derive(Parser)]
#[command(name = "mycelium", about = "Distributed fuzzing framework")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the coordinator
    Spawn {
        #[arg(long, default_value = "0.0.0.0:7100")]
        listen: SocketAddr,
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        db: PathBuf,
    },

    /// Upload a harness and create a campaign
    Inoculate {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        campaign: String,
        #[arg(long)]
        harness: PathBuf,
        #[arg(long, default_value = "aflpp")]
        fuzzer: String,
        /// Optional directory of starting seeds. Uploaded as the campaign's base
        /// corpus so joining nodes begin from real inputs, not an empty corpus.
        #[arg(long)]
        seeds: Option<PathBuf>,
        /// Triage command template for crash dedup. Runs on crashing inputs to
        /// capture sanitizer output for per-bug stack hashing. Use {file} for
        /// the crash input path. Defaults to "{harness} {file}" for libfuzzer
        /// fuzzers, empty for others (dedup by input hash only).
        #[arg(long, value_delimiter = ' ', num_args = 1..)]
        triage_cmd: Option<Vec<String>>,
        /// Fuzzer command template. Use {harness}, {corpus}, {output}, {inject}
        /// as placeholders. For AFL++ distributed mode the command must run a
        /// main instance and import the injected foreign corpus, e.g.
        ///   afl-fuzz -i {corpus} -o {output} -M main -F {inject} -- {harness}
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// Attach a node and start fuzzing
    Join {
        #[arg(long)]
        coordinator: String,
        #[arg(long, default_value = "default")]
        campaign: String,
        /// Local config file (manual mode). Omit to pull harness from coordinator.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Working directory for downloaded harness and fuzzer output (distributed mode)
        #[arg(long)]
        workdir: Option<PathBuf>,
        #[arg(long, default_value = "shared")]
        priority: String,
    },

    /// Show campaign status
    Probe {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        nodes: bool,
        #[arg(long)]
        json: bool,
    },

    /// Detach a node
    Sever {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        node_id: String,
        /// Graceful: stop sending the node new work and suspend it, but keep
        /// its corpus, crashes, and distribution history. Without --drain the
        /// node and its history are removed outright.
        #[arg(long)]
        drain: bool,
    },

    /// Set a campaign's lifecycle state (running, paused, draining, completed)
    Lifecycle {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        campaign: String,
        /// Target state
        state: String,
    },

    /// Query historical metrics snapshots for a campaign
    Metrics {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        campaign: String,
        #[arg(long, default_value = "50")]
        limit: u64,
        #[arg(long)]
        json: bool,
    },

    /// TCP-ping fleet nodes until all respond
    Ping {
        /// Hostnames or IPs to ping
        #[arg(required = true)]
        nodes: Vec<String>,
        /// Port to probe on each node
        #[arg(long, default_value = "22")]
        port: u16,
        /// Seconds between rounds
        #[arg(long, default_value = "3")]
        interval: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mycelium=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Spawn { listen, corpus, db } => {
            mycelium_coordinator::server::run(listen, &db, &corpus).await?;
        }

        Commands::Inoculate {
            coordinator,
            campaign,
            harness,
            fuzzer,
            seeds,
            triage_cmd,
            cmd,
        } => {
            let harness_data = std::fs::read(&harness)?;
            tracing::info!(
                campaign = %campaign,
                harness = %harness.display(),
                bytes = harness_data.len(),
                "creating campaign"
            );

            // Auto-derive triage command for libfuzzer-family fuzzers when none
            // is given. The harness binary re-runs a crashing input when passed
            // it as an argument, so "{harness} {file}" captures the sanitizer
            // trace for per-bug stack hashing on distributed nodes.
            let effective_triage: Option<Vec<String>> = triage_cmd.or_else(|| {
                let profile = mycelium_node::profile::FuzzerProfile::builtin(&fuzzer);
                match profile.as_ref().map(|p| p.name.as_str()) {
                    Some("libfuzzer" | "cargo-fuzz" | "cargofuzz" | "atheris" | "jazzer") => {
                        Some(vec!["{harness}".into(), "{file}".into()])
                    }
                    _ => None,
                }
            });

            mycelium_node::sync::SyncClient::create_campaign(
                &coordinator,
                &campaign,
                &fuzzer,
                &cmd,
                effective_triage.as_deref(),
            )
            .await?;

            mycelium_node::sync::SyncClient::upload_harness(
                &coordinator,
                &campaign,
                harness_data,
            )
            .await?;

            // optional base corpus, so joining nodes do not start from empty.
            // Upload in size-bounded batches so a large corpus is not held in
            // memory or sent as one oversized request.
            if let Some(seeds_dir) = seeds {
                const MAX_BATCH_BYTES: usize = 32 * 1024 * 1024;
                let mut batch: Vec<(String, Vec<u8>)> = Vec::new();
                let mut batch_bytes = 0usize;
                let mut total = 0usize;
                for entry in std::fs::read_dir(&seeds_dir)? {
                    let path = entry?.path();
                    if !path.is_file() {
                        continue;
                    }
                    let data = std::fs::read(&path)?;
                    if data.is_empty() {
                        continue;
                    }
                    batch_bytes += data.len();
                    batch.push((mycelium_common::corpus::hash_bytes(&data), data));
                    if batch_bytes >= MAX_BATCH_BYTES {
                        total += mycelium_node::sync::SyncClient::upload_seeds(
                            &coordinator,
                            &campaign,
                            std::mem::take(&mut batch),
                        )
                        .await?;
                        batch_bytes = 0;
                    }
                }
                if !batch.is_empty() {
                    total +=
                        mycelium_node::sync::SyncClient::upload_seeds(&coordinator, &campaign, batch)
                            .await?;
                }
                if total > 0 {
                    tracing::info!(count = total, "uploaded base corpus");
                }
            }

            tracing::info!("campaign ready, nodes can join with: mycelium join --coordinator {} --campaign {} --workdir <path>", coordinator, campaign);
        }

        Commands::Join {
            coordinator,
            campaign,
            config,
            workdir,
            priority,
        } => {
            let hostname = gethostname();
            let priority_val: mycelium_common::node::Priority =
                serde_json::from_str(&format!("\"{priority}\"")).unwrap_or_default();

            match (config, workdir) {
                // distributed mode: pull harness + config from coordinator
                (None, Some(workdir)) => {
                    tracing::info!(%coordinator, %campaign, %hostname, "joining (distributed)");

                    let camp_info =
                        mycelium_node::sync::SyncClient::get_campaign_info(&coordinator, &campaign)
                            .await?;

                    if camp_info.harness_len == 0 {
                        anyhow::bail!("campaign '{}' has no harness uploaded yet", campaign);
                    }

                    std::fs::create_dir_all(&workdir)?;
                    let harness_path = workdir.join("harness");
                    // -i seed dir (read once at startup), -F foreign dir (imported
                    // while running), and the fuzzer's own output tree.
                    let seeds_dir = workdir.join("seeds");
                    let inject_dir = workdir.join("inject");
                    let output_dir = workdir.join("output");
                    std::fs::create_dir_all(&seeds_dir)?;
                    std::fs::create_dir_all(&inject_dir)?;
                    std::fs::create_dir_all(&output_dir)?;

                    let harness_data =
                        mycelium_node::sync::SyncClient::download_harness(&coordinator, &campaign)
                            .await?;
                    std::fs::write(&harness_path, &harness_data)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            &harness_path,
                            std::fs::Permissions::from_mode(0o755),
                        )?;
                    }
                    tracing::info!(bytes = harness_data.len(), "harness downloaded");

                    let fuzzer_command: Vec<String> = camp_info
                        .fuzzer_command
                        .iter()
                        .map(|arg| {
                            arg.replace("{harness}", &harness_path.to_string_lossy())
                                .replace("{corpus}", &seeds_dir.to_string_lossy())
                                .replace("{output}", &output_dir.to_string_lossy())
                                .replace("{inject}", &inject_dir.to_string_lossy())
                        })
                        .collect();

                    // the campaign's fuzzer name selects the profile
                    let profile = mycelium_node::profile::FuzzerProfile::builtin(&camp_info.fuzzer_name)
                        .unwrap_or_else(mycelium_node::profile::FuzzerProfile::aflpp);

                    // AFL needs the -F inject dir named in the command or pulled
                    // seeds never reach it; other fuzzers rescan their corpus dir.
                    if profile.afl_instance_layout
                        && !fuzzer_command.iter().any(|a| a.contains(&*inject_dir.to_string_lossy()))
                    {
                        tracing::warn!(
                            "fuzzer command has no {{inject}} placeholder; pulled seeds will \
                             not reach the running fuzzer. For AFL++ add: -M main -F {{inject}}"
                        );
                    }

                    // distributed nodes always run the fuzzer in persistent mode,
                    // so a time budget in the command means the node will finish
                    // and suspend on its own
                    let time_limited = command_is_time_limited(&fuzzer_command);
                    let node_id = mycelium_node::sync::SyncClient::register(
                        &coordinator,
                        &hostname,
                        &campaign,
                        &camp_info.fuzzer_name,
                        priority_val,
                        Some(persistent_node_id(&workdir, &hostname)),
                        time_limited,
                    )
                    .await?;
                    tracing::info!(%node_id, "registered");

                    // AFL writes to <output>/<instance>/{queue,crashes} and takes
                    // injected seeds through the -F dir. Other fuzzers vary: new
                    // corpus lands in {output} (honggfuzz -o, libafl, go, syzkaller)
                    // or back in {corpus} (libFuzzer appends to its positional
                    // corpus dir), per the profile. Crashes land under {output}/
                    // crashes by convention (honggfuzz --crashdir, libFuzzer
                    // -artifact_prefix, syzkaller workdir/crashes). Watching the
                    // wrong dir is why a distributed non-AFL node used to sync
                    // nothing. Pulled seeds still go to the -i dir either way.
                    let stats_parser = profile.stats_parser.clone();
                    let fuzzer_log = if profile.afl_instance_layout {
                        None
                    } else {
                        Some(output_dir.join("mycelium-fuzzer.log"))
                    };
                    let (output, live_inject) = if profile.afl_instance_layout {
                        (
                            OutputDirs::AflAuto { output_base: output_dir.clone() },
                            inject_dir.clone(),
                        )
                    } else {
                        let corpus_watch = if profile.writes_corpus_to_output {
                            output_dir.clone()
                        } else {
                            seeds_dir.clone()
                        };
                        (
                            OutputDirs::Explicit {
                                corpus_dir: corpus_watch,
                                crash_dir: output_dir.join("crashes"),
                                // parse progress from the captured fuzzer log
                                stats_file: fuzzer_log.clone(),
                            },
                            seeds_dir.clone(),
                        )
                    };

                    // Pull the campaign's triage command and substitute
                    // {harness} so the node can auto-triage crashes for
                    // per-bug dedup instead of falling back to per-input hash.
                    let dist_triage: Option<Vec<String>> = camp_info.triage_cmd.map(|cmd| {
                        cmd.iter()
                            .map(|a| a.replace("{harness}", &harness_path.to_string_lossy()))
                            .collect()
                    });

                    run_fuzzer_loop(RunParams {
                        coordinator: &coordinator,
                        node_id: &node_id,
                        campaign: &campaign,
                        priority: priority_val,
                        mode: FuzzerMode::Persistent,
                        stats_parser: &stats_parser,
                        profile,
                        fuzzer_command: &fuzzer_command,
                        output,
                        fuzzer_log,
                        initial_seed_dir: &seeds_dir,
                        inject_dir: &live_inject,
                        import_cmd: None,
                        stats_cmd: None,
                        triage_cmd: dist_triage,
                        sync_interval_secs: 30,
                    })
                    .await?;
                }

                // manual mode: use local config file
                (Some(config), _) => {
                    let cfg = mycelium_node::config::CircleConfig::from_file(&config)?;
                    tracing::info!(%coordinator, %hostname, mode = ?cfg.mode(), "joining (manual config)");

                    // persist the id next to the config so a restart reuses it
                    let id_dir = config.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
                    // a round/api node re-spawns the fuzzer and keeps running, so
                    // only a persistent node with a command time budget is bounded
                    let time_limited = matches!(cfg.mode(), FuzzerMode::Persistent)
                        && command_is_time_limited(&cfg.fuzzer.command);
                    let node_id = mycelium_node::sync::SyncClient::register(
                        &coordinator,
                        &hostname,
                        &campaign,
                        &cfg.fuzzer.name,
                        cfg.node.priority,
                        Some(persistent_node_id(&id_dir, &hostname)),
                        time_limited,
                    )
                    .await?;
                    tracing::info!(%node_id, "registered");

                    let stats_file = cfg.fuzzer.stats_file.as_ref().map(PathBuf::from);
                    let inject_dir = PathBuf::from(&cfg.circle.inject_dir);
                    let stats_parser = cfg.stats_parser();
                    let profile = cfg.profile();

                    // Manual-config triage command is already local paths, no
                    // {harness} substitution needed.
                    run_fuzzer_loop(RunParams {
                        coordinator: &coordinator,
                        node_id: &node_id,
                        campaign: &campaign,
                        priority: cfg.node.priority,
                        mode: cfg.mode(),
                        stats_parser: &stats_parser,
                        profile,
                        fuzzer_command: &cfg.fuzzer.command,
                        output: OutputDirs::Explicit {
                            corpus_dir: PathBuf::from(&cfg.fuzzer.corpus_dir),
                            crash_dir: PathBuf::from(&cfg.fuzzer.crash_dir),
                            stats_file,
                        },
                        fuzzer_log: None,
                        initial_seed_dir: &inject_dir,
                        inject_dir: &inject_dir,
                        import_cmd: cfg.fuzzer.hooks.import_cmd.clone(),
                        stats_cmd: cfg.fuzzer.hooks.stats_cmd.clone(),
                        triage_cmd: cfg.fuzzer.triage_cmd.clone(),
                        sync_interval_secs: cfg.sync_interval_secs(),
                    })
                    .await?;
                }

                (None, None) => {
                    anyhow::bail!("join requires either --config (manual) or --workdir (distributed)");
                }
            }
        }

        Commands::Probe {
            coordinator,
            nodes,
            json,
        } => {
            let base = if coordinator.starts_with("http") {
                coordinator
            } else {
                format!("http://{coordinator}")
            };
            let resp: mycelium_common::protocol::ScryResponse = reqwest::get(format!("{base}/scry"))
                .await?
                .json()
                .await?;

            if json {
                println!("{}", serde_json::to_string(&resp)?);
            } else {
                println!("Campaign: {}  [{}]", resp.campaign.name, resp.campaign.lifecycle);
                println!(
                    "  corpus: {}  crashes: {} ({} bugs)  edges: {}  nodes: {}",
                    resp.campaign.total_corpus,
                    resp.campaign.total_crashes,
                    resp.campaign.unique_bugs,
                    resp.campaign.total_edges,
                    resp.campaign.nodes_online
                );

                if nodes || !resp.nodes.is_empty() {
                    println!();
                    println!(
                        "{:<16} {:<12} {:<12} {:<10} {:<12} {:<8} LAST SYNC",
                        "NODE", "HOST", "FUZZER", "PRIORITY", "STATUS", "RUN"
                    );
                    for node in &resp.nodes {
                        // the Priority/NodeStatus Display impls write directly and
                        // so ignore the {:<N} width flag; format to String first so
                        // the columns actually line up
                        println!(
                            "{:<16} {:<12} {:<12} {:<10} {:<12} {:<8} {}",
                            node.id,
                            node.hostname,
                            node.fuzzer,
                            node.priority.to_string(),
                            node.status.to_string(),
                            if node.time_limited { "timed" } else { "persist" },
                            node.last_sync.format("%H:%M:%S"),
                        );
                    }
                }
            }
        }

        Commands::Sever {
            coordinator,
            node_id,
            drain,
        } => {
            let sync = mycelium_node::sync::SyncClient::new(&coordinator, &node_id, "");
            sync.deregister(drain).await?;
            tracing::info!(%node_id, drain, "severed");
        }

        Commands::Lifecycle {
            coordinator,
            campaign,
            state,
        } => {
            let lifecycle: mycelium_common::protocol::CampaignLifecycle =
                serde_json::from_str(&format!("\"{state}\""))
                    .map_err(|_| anyhow::anyhow!(
                        "invalid lifecycle state '{state}': must be running, paused, draining, or completed"
                    ))?;
            let base = if coordinator.starts_with("http") {
                coordinator
            } else {
                format!("http://{coordinator}")
            };
            let client = reqwest::Client::builder().build()?;
            let mut req = client.patch(format!("{base}/api/v1/campaign/{campaign}/lifecycle"));
            if let Some(token) = std::env::var("MYCELIUM_TOKEN").ok().filter(|s| !s.is_empty()) {
                req = req.bearer_auth(token);
            }
            req.json(&mycelium_common::protocol::UpdateCampaignLifecycleRequest { lifecycle })
                .send()
                .await?
                .error_for_status()?;
            tracing::info!(%campaign, %state, "lifecycle updated");
        }

        Commands::Metrics {
            coordinator,
            campaign,
            limit,
            json,
        } => {
            let base = if coordinator.starts_with("http") {
                coordinator
            } else {
                format!("http://{coordinator}")
            };
            let resp: mycelium_common::protocol::MetricsResponse =
                reqwest::get(format!("{base}/api/v1/metrics/{campaign}?limit={limit}"))
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;

            if json {
                println!("{}", serde_json::to_string(&resp)?);
            } else {
                println!("Metrics: {} ({} snapshots)", resp.campaign, resp.snapshots.len());
                if resp.snapshots.is_empty() {
                    println!("  (no snapshots yet)");
                } else {
                    println!(
                        "{:>12} {:>10} {:>8} {:>8} {:>8} {:>8} {:>6}",
                        "TIMESTAMP", "EXEC/S", "CORPUS", "CRASHES", "BUGS", "EDGES", "NODES"
                    );
                    for s in &resp.snapshots {
                        let ts = chrono::DateTime::from_timestamp(s.ts, 0)
                            .map(|d| d.format("%H:%M:%S").to_string())
                            .unwrap_or_else(|| s.ts.to_string());
                        println!(
                            "{:>12} {:>10} {:>8} {:>8} {:>8} {:>8} {:>6}",
                            ts,
                            s.total_execs_per_sec,
                            s.corpus_size,
                            s.crashes,
                            s.unique_bugs,
                            s.edges,
                            s.nodes_online,
                        );
                    }
                }
            }
        }

        Commands::Ping {
            nodes,
            port,
            interval,
        } => {
            loop {
                let mut unreachable: Vec<&str> = Vec::new();
                for host in &nodes {
                    let addr = format!("{host}:{port}");
                    let start = std::time::Instant::now();
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::net::TcpStream::connect(&addr),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            let ms = start.elapsed().as_millis();
                            println!("{host} :: {ms}ms");
                        }
                        Ok(Err(e)) => {
                            println!("{host} :: FAIL {e}");
                            unreachable.push(host);
                        }
                        Err(_) => {
                            println!("{host} :: TIMEOUT");
                            unreachable.push(host);
                        }
                    }
                }

                if unreachable.is_empty() {
                    println!("all {} nodes reachable", nodes.len());
                    break;
                }

                println!(
                    "{}/{} unreachable  retrying in {interval}s...",
                    unreachable.len(),
                    nodes.len(),
                );
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                println!();
            }
        }
    }

    Ok(())
}

// How the fuzzer's output dirs are discovered. Manual mode knows them from the
// config. Distributed mode only learns the AFL++ instance subdir name (default,
// main, or whatever -M was given) after the fuzzer has started, so it probes
// the output tree for it.
enum OutputDirs {
    Explicit {
        corpus_dir: PathBuf,
        crash_dir: PathBuf,
        stats_file: Option<PathBuf>,
    },
    AflAuto {
        output_base: PathBuf,
    },
}

struct RunParams<'a> {
    coordinator: &'a str,
    node_id: &'a str,
    campaign: &'a str,
    priority: mycelium_common::node::Priority,
    mode: FuzzerMode,
    stats_parser: &'a str,
    profile: mycelium_node::profile::FuzzerProfile,
    fuzzer_command: &'a [String],
    output: OutputDirs,
    // where to tee the fuzzer's stdout+stderr, so the heartbeat can read stats
    // from it (distributed non-AFL mode); None leaves the fuzzer's streams alone
    fuzzer_log: Option<PathBuf>,
    initial_seed_dir: &'a Path,
    inject_dir: &'a Path,
    // custom-fuzzer hooks (see config [fuzzer.hooks]); None for the built-ins
    import_cmd: Option<Vec<String>>,
    stats_cmd: Option<Vec<String>>,
    // command that re-runs a crashing input to capture a sanitizer trace
    triage_cmd: Option<Vec<String>>,
    sync_interval_secs: u64,
}

// Priority scales how often a node pulls shared corpus. The configured interval
// is the baseline for a shared node; dedicated boxes (your primary fuzzers) pull
// twice as often to stay in sync, idle boxes half as often to stay out of the
// way on a borrowed machine. The floor of 1s also stops a "0s" config from
// panicking tokio's interval timer.
fn effective_interval_secs(base: u64, priority: mycelium_common::node::Priority) -> u64 {
    use mycelium_common::node::Priority;
    match priority {
        Priority::Dedicated => (base / 2).max(1),
        Priority::Shared => base.max(1),
        Priority::Idle => base.saturating_mul(2).max(1),
    }
}

// True when the command carries an overall time or run budget, so the fuzzer is
// expected to exit on its own. This is what lets the coordinator mark a node
// "finished its bounded run" rather than leaving an ambiguous suspended state.
// The fleet's bounded flags: honggfuzz --run_time, libFuzzer -max_total_time /
// -runs, Go -fuzztime, and AFL++ -V (seconds) / -E (execs). A plain AFL run with
// none of these runs until killed, so an AFL node reports false there.
fn command_is_time_limited(cmd: &[String]) -> bool {
    cmd.iter().any(|a| {
        let a = a.trim_start_matches('-');
        a == "run_time"
            || a.starts_with("run_time=")
            || a.starts_with("max_total_time")
            || a == "runs"
            || a.starts_with("runs=")
            || a.starts_with("fuzztime")
            || a == "V"
            || a == "E"
    })
}

fn spawn_fuzzer(fuzzer_command: &[String], log: Option<&Path>) -> Result<tokio::process::Child> {
    let mut it = fuzzer_command.iter();
    let program = it
        .next()
        .ok_or_else(|| anyhow::anyhow!("fuzzer command is empty"))?;
    let mut cmd = tokio::process::Command::new(program);
    // kill_on_drop so an early return (failed dir resolve, deregister error,
    // round-mode break) takes the fuzzer process tree down with the node instead
    // of orphaning it still writing to the output dirs. env_remove strips the
    // fleet bearer token from the fuzzer's environment, so the target binary
    // (and any same-uid process reading /proc/<pid>/environ) cannot read it.
    cmd.args(it).kill_on_drop(true).env_remove("MYCELIUM_TOKEN");
    // In distributed mode we capture the fuzzer's stdout+stderr to a log so the
    // heartbeat can parse progress from it (libFuzzer and honggfuzz print their
    // stats there); without this a distributed non-AFL node reports 0 forever.
    if let Some(log) = log {
        let out = std::fs::File::create(log)?;
        let err = out.try_clone()?;
        cmd.stdout(std::process::Stdio::from(out));
        cmd.stderr(std::process::Stdio::from(err));
    }
    let child = cmd.spawn()?;
    tracing::info!(%program, "fuzzer started");
    Ok(child)
}

// Find the AFL++ instance output subdir (contains a `queue` dir). Returns
// (corpus_dir, crash_dir, stats_file).
async fn resolve_afl_dirs(output_base: &Path) -> (PathBuf, PathBuf, Option<PathBuf>) {
    // Probe for the instance subdir (contains `queue`) for up to 30s, since a
    // slow box can take a while to create it. Falling back to `default/` would
    // watch the wrong path for a `-M main` (or any custom -M) instance.
    for _ in 0..300 {
        if let Ok(rd) = std::fs::read_dir(output_base) {
            // Collect every instance dir (one holding a `queue`) and pick
            // deterministically: prefer the one named `main` (AFL's -M main),
            // else the lexicographically first. readdir order is arbitrary, so
            // without this a `-M main -S sec` layout could latch onto a secondary
            // or a stale instance and watch the wrong queue across restarts.
            let mut instances: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.join("queue").is_dir())
                .collect();
            instances.sort();
            let chosen = instances
                .iter()
                .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("main"))
                .or_else(|| instances.first());
            if let Some(p) = chosen {
                return (
                    p.join("queue"),
                    p.join("crashes"),
                    Some(p.join("fuzzer_stats")),
                );
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    tracing::error!(
        output = %output_base.display(),
        "no AFL++ instance dir appeared after 30s; guessing default/ (seeds may not sync)"
    );
    let inst = output_base.join("default");
    (
        inst.join("queue"),
        inst.join("crashes"),
        Some(inst.join("fuzzer_stats")),
    )
}

// Resolve (corpus_dir, crash_dir, stats_file) from the output spec, waiting for
// the dirs to appear and creating them if absent. Reused on round-mode respawn.
async fn resolve_output_dirs(output: &OutputDirs) -> Result<(PathBuf, PathBuf, Option<PathBuf>)> {
    let (corpus_dir, crash_dir, stats_file) = match output {
        OutputDirs::Explicit { corpus_dir, crash_dir, stats_file } => {
            for _ in 0..100 {
                if corpus_dir.exists() && crash_dir.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            (corpus_dir.clone(), crash_dir.clone(), stats_file.clone())
        }
        OutputDirs::AflAuto { output_base } => resolve_afl_dirs(output_base).await,
    };
    if !corpus_dir.exists() || !crash_dir.exists() {
        tracing::warn!(corpus = %corpus_dir.display(), crash = %crash_dir.display(),
            "fuzzer output dirs not present yet, creating and watching anyway");
        std::fs::create_dir_all(&corpus_dir)?;
        std::fs::create_dir_all(&crash_dir)?;
    }
    Ok((corpus_dir, crash_dir, stats_file))
}

// Await an optional child's exit, or never resolve if there is no child (api
// mode, where mycelium only syncs dirs for a fuzzer it does not manage).
async fn wait_opt(child: &mut Option<tokio::process::Child>) -> std::io::Result<std::process::ExitStatus> {
    match child {
        Some(c) => c.wait().await,
        None => std::future::pending().await,
    }
}

async fn run_fuzzer_loop(p: RunParams<'_>) -> Result<()> {
    let sync = mycelium_node::sync::SyncClient::new(p.coordinator, p.node_id, p.campaign);

    // Pull the current corpus into the -i seed dir so the fuzzer has something
    // to start from. A fresh campaign with nothing to pull still needs a
    // non-empty -i, so drop a minimal starter seed in that case.
    let initial_seeds = sync.pull_seeds().await?;
    std::fs::create_dir_all(p.initial_seed_dir)?;
    for seed in &initial_seeds {
        // tolerate a single bad seed (e.g. a rejected hash) rather than aborting
        // startup over it
        if let Err(e) = sync.inject_seed(p.initial_seed_dir, seed) {
            tracing::warn!(error = %e, "skipped initial seed");
        }
    }
    // Track the starter seed's hash (if written) so it is marked seen and never
    // pushed back as real corpus once the fuzzer copies it into its queue.
    let mut starter_hash: Option<String> = None;
    if initial_seeds.is_empty() && matches!(p.output, OutputDirs::AflAuto { .. }) {
        let starter = p.initial_seed_dir.join("mycelium-starter");
        if std::fs::read_dir(p.initial_seed_dir).map(|mut d| d.next().is_none()).unwrap_or(true) {
            let content = b"\n";
            std::fs::write(&starter, content)?;
            starter_hash = Some(mycelium_common::corpus::hash_bytes(content));
            tracing::warn!("no base corpus to pull, wrote a minimal starter seed so the fuzzer can start");
        }
    }
    tracing::info!(count = initial_seeds.len(), "pulled initial corpus");

    // Create the explicit output dirs before launching: some fuzzers check them
    // at startup and bail if missing (libFuzzer aborts when its -artifact_prefix
    // dir does not exist), and the node otherwise only makes them after spawn.
    if let OutputDirs::Explicit { corpus_dir, crash_dir, .. } = &p.output {
        std::fs::create_dir_all(corpus_dir)?;
        std::fs::create_dir_all(crash_dir)?;
    }

    // api mode: do not spawn a fuzzer, just watch and sync existing dirs.
    let mut child = if p.mode == FuzzerMode::Api {
        tracing::info!("api mode: not launching a fuzzer, syncing existing output dirs");
        None
    } else {
        Some(spawn_fuzzer(p.fuzzer_command, p.fuzzer_log.as_deref())?)
    };

    // Resolve the dirs the fuzzer actually writes to.
    let (corpus_dir, crash_dir, mut stats_file) = resolve_output_dirs(&p.output).await?;
    tracing::info!(corpus = %corpus_dir.display(), crash = %crash_dir.display(), "watching fuzzer output");

    let watcher = mycelium_node::watcher::DirWatcher::new();
    for seed in &initial_seeds {
        watcher.mark_seen(&seed.hash);
    }
    if let Some(h) = &starter_hash {
        watcher.mark_seen(h);
    }
    // keep the watcher guard alive for the run; dropping it (on round respawn,
    // where it is reassigned) unwatches and frees the inotify FDs.
    let (mut _watch_guard, mut rx) = watcher.watch(&corpus_dir, &crash_dir, &p.profile)?;

    // Cap concurrent crash triage+report so a crash storm cannot spawn unbounded
    // subprocesses and tasks; the JoinSet lets shutdown wait for in-flight
    // reports so the fuzzer's last crashes are not lost when the node severs.
    let crash_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let mut crash_tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    let interval = effective_interval_secs(p.sync_interval_secs, p.priority);
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));

    loop {
        // reap finished crash-report tasks so the JoinSet does not grow
        while crash_tasks.try_join_next().is_some() {}
        tokio::select! {
            Some(event) = rx.recv() => {
                let events = drain_burst(event, &mut rx);
                handle_events(&sync, &watcher, events, p.triage_cmd.as_deref(), &mut crash_tasks, &crash_sem).await;
            }
            _ = tick.tick() => {
                pull_and_inject(&sync, &watcher, p.inject_dir, p.import_cmd.as_deref()).await;
                // reading stats may shell out (stats_cmd), so keep it off the loop thread
                let parser = p.stats_parser.to_string();
                let scmd = p.stats_cmd.clone();
                let sfile = stats_file.clone();
                let stats = tokio::task::spawn_blocking(move || {
                    read_stats(&parser, scmd.as_deref(), sfile.as_deref())
                })
                .await
                .unwrap_or_default();
                if let Err(e) = sync.heartbeat(stats.execs_per_sec, stats.corpus_size, stats.crashes_found, stats.edges_found).await {
                    tracing::warn!(error = %e, "heartbeat failed");
                }
            }
            status = wait_opt(&mut child) => {
                match status {
                    Ok(s) => tracing::warn!(%s, "fuzzer exited"),
                    Err(e) => tracing::error!(error = %e, "fuzzer wait error"),
                }
                // drain whatever the fuzzer wrote before exiting
                let mut leftover = Vec::new();
                while let Ok(event) = rx.try_recv() {
                    leftover.push(event);
                }
                handle_events(&sync, &watcher, leftover, p.triage_cmd.as_deref(), &mut crash_tasks, &crash_sem).await;
                if p.mode == FuzzerMode::Round {
                    // round fuzzers exit per round; pull fresh corpus into the
                    // -i dir and run the next round.
                    tracing::info!("round complete, pulling corpus and restarting fuzzer");
                    pull_and_inject(&sync, &watcher, p.initial_seed_dir, p.import_cmd.as_deref()).await;
                    match spawn_fuzzer(p.fuzzer_command, p.fuzzer_log.as_deref()) {
                        Ok(c) => {
                            child = Some(c);
                            // the relaunched fuzzer recreates its output dirs, so
                            // re-resolve and re-establish the watch on the new
                            // inodes, otherwise nothing syncs from this round on.
                            // Reassigning _watch_guard drops the old watcher and
                            // frees its inotify FDs (no per-round leak).
                            match resolve_output_dirs(&p.output).await {
                                Ok((cd, crd, sf)) => {
                                    stats_file = sf;
                                    match watcher.watch(&cd, &crd, &p.profile) {
                                        Ok((g, new_rx)) => { _watch_guard = g; rx = new_rx; }
                                        Err(e) => {
                                            tracing::error!(error = %e, "failed to re-watch after round");
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "failed to resolve dirs after round");
                                    break;
                                }
                            }
                            continue;
                        }
                        Err(e) => { tracing::error!(error = %e, "failed to restart fuzzer"); break; }
                    }
                }
                break;
            }
        }
    }

    // Finish reporting any in-flight crashes before severing, so the fuzzer's
    // last crashes reach the coordinator. Bounded so a hung triage subprocess
    // cannot block shutdown forever.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while crash_tasks.join_next().await.is_some() {}
    })
    .await;

    // One last stats read before severing: some fuzzers (honggfuzz) only print a
    // parseable throughput summary at exit, so a mid-run heartbeat never saw it.
    {
        let parser = p.stats_parser.to_string();
        let scmd = p.stats_cmd.clone();
        let sfile = stats_file.clone();
        let stats = tokio::task::spawn_blocking(move || {
            read_stats(&parser, scmd.as_deref(), sfile.as_deref())
        })
        .await
        .unwrap_or_default();
        if let Err(e) = sync
            .heartbeat(stats.execs_per_sec, stats.corpus_size, stats.crashes_found, stats.edges_found)
            .await
        {
            tracing::warn!(error = %e, "final heartbeat failed");
        }
    }

    tracing::info!("severing");
    sync.deregister(true).await?;
    Ok(())
}

// Handle a burst of watch events: seeds go up in one batch, crashes are triaged
// and reported on bounded-concurrency tasks tracked for shutdown.
async fn handle_events(
    sync: &mycelium_node::sync::SyncClient,
    watcher: &mycelium_node::watcher::DirWatcher,
    events: Vec<mycelium_node::watcher::WatchEvent>,
    triage_cmd: Option<&[String]>,
    crash_tasks: &mut tokio::task::JoinSet<()>,
    crash_sem: &std::sync::Arc<tokio::sync::Semaphore>,
) {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    for event in events {
        match event {
            mycelium_node::watcher::WatchEvent::NewSeed { hash, data, .. } => {
                seeds.push((hash, data));
            }
            mycelium_node::watcher::WatchEvent::NewCrash { path, data } => {
                // Triage re-runs the crashing input, which can be slow, so do it
                // on a task: the triage subprocess goes to a blocking thread and
                // the sync loop is never stalled (which would lapse heartbeats
                // and get the node reaped). The semaphore caps how many run at
                // once so a crash storm cannot spawn unbounded subprocesses; the
                // JoinSet lets shutdown wait for the reports to finish.
                let sync = sync.clone();
                let watcher = watcher.clone();
                let sem = crash_sem.clone();
                let triage = triage_cmd.map(|c| c.to_vec());
                crash_tasks.spawn(async move {
                    let _permit = sem.acquire_owned().await;
                    let trace = match triage {
                        Some(cmd) => {
                            let file = path.to_string_lossy().into_owned();
                            tokio::task::spawn_blocking(move || run_triage(&cmd, &file))
                                .await
                                .unwrap_or_default()
                        }
                        None => String::new(),
                    };
                    // recompute the input hash so a failed report can be un-marked
                    // and retried on a later discovery rather than lost
                    let hash = mycelium_common::corpus::hash_bytes(&data);
                    if let Err(e) = sync.report_crash(data, &trace).await {
                        tracing::error!(error = %e, "failed to report crash");
                        watcher.mark_unseen(&hash);
                    }
                });
            }
        }
    }
    let n = seeds.len();
    if n > 0 {
        // keep the hashes so a failed push can be un-marked for retry
        let hashes: Vec<String> = seeds.iter().map(|(h, _)| h.clone()).collect();
        if let Err(e) = sync.push_seeds_batch(seeds).await {
            tracing::error!(error = %e, count = n, "failed to push seed batch");
            for h in &hashes {
                watcher.mark_unseen(h);
            }
        }
    }
}

// Drain the event already received plus any immediately available, up to a cap.
fn drain_burst(
    first: mycelium_node::watcher::WatchEvent,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<mycelium_node::watcher::WatchEvent>,
) -> Vec<mycelium_node::watcher::WatchEvent> {
    let mut events = vec![first];
    while let Ok(e) = rx.try_recv() {
        events.push(e);
        if events.len() >= 512 {
            break;
        }
    }
    events
}

const TRIAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// Re-run a crashing input under the triage command and capture its combined
// output (sanitizers print to stderr). {file} is replaced with the input path.
// Kills the child after TRIAGE_TIMEOUT so a hanging input can't block the
// crash-report pipeline.
fn run_triage(cmd: &[String], file: &str) -> String {
    let Some((program, args)) = cmd.split_first() else {
        return String::new();
    };
    let args: Vec<String> = args.iter().map(|a| a.replace("{file}", file)).collect();

    // Spawn the child with piped stdio, then drain stderr/stdout on
    // dedicated threads so large ASAN traces don't fill the pipe buffer
    // and deadlock. The main thread polls try_wait with a timeout.
    let mut child = match std::process::Command::new(program)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, %program, "triage command failed to run");
            return String::new();
        }
    };

    let mut stderr_pipe = child.stderr.take().unwrap();
    let mut stdout_pipe = child.stdout.take().unwrap();
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stderr_pipe, &mut buf);
        buf
    });
    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout_pipe, &mut buf);
        buf
    });

    let deadline = std::time::Instant::now() + TRIAGE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    tracing::warn!(%program, %file, "triage timed out, killing child");
                    let _ = child.kill();
                    let _ = child.wait();
                    return "[triage timeout]".to_string();
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                tracing::warn!(error = %e, %program, "triage wait failed");
                let _ = child.kill();
                let _ = child.wait();
                return String::new();
            }
        }
    };

    let stderr = t_err.join().unwrap_or_default();
    let stdout = t_out.join().unwrap_or_default();

    let mut s = String::from_utf8_lossy(&stderr).into_owned();
    if s.is_empty() {
        s = String::from_utf8_lossy(&stdout).into_owned();
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            let name = match sig {
                libc::SIGSEGV => "SIGSEGV",
                libc::SIGABRT => "SIGABRT",
                libc::SIGBUS => "SIGBUS",
                libc::SIGFPE => "SIGFPE",
                libc::SIGILL => "SIGILL",
                _ => "",
            };
            if !name.is_empty() {
                if !s.is_empty() && !s.ends_with('\n') {
                    s.push('\n');
                }
                s.push_str(&format!("[signal: {}]", name));
            }
        }
    }
    s
}

async fn pull_and_inject(
    sync: &mycelium_node::sync::SyncClient,
    watcher: &mycelium_node::watcher::DirWatcher,
    inject_dir: &Path,
    import_cmd: Option<&[String]>,
) {
    match sync.pull_seeds().await {
        Ok(seeds) => {
            for seed in &seeds {
                watcher.mark_seen(&seed.hash);
                if let Err(e) = sync.inject_seed(inject_dir, seed) {
                    tracing::error!(error = %e, "failed to inject seed");
                    continue;
                }
                // custom-fuzzer import hook: hand the seed file to the fuzzer's
                // own intake, with {file} substituted. Runs on a blocking thread.
                if let Some(cmd) = import_cmd {
                    let cmd = cmd.to_vec();
                    let file = inject_dir.join(&seed.hash).to_string_lossy().into_owned();
                    let _ = tokio::task::spawn_blocking(move || run_hook(&cmd, &file)).await;
                }
            }
            if !seeds.is_empty() {
                tracing::info!(count = seeds.len(), "pulled seeds");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "seed pull failed");
        }
    }
}

// Run a hook command with {file} substituted. Fire-and-forget: a hook failure
// is logged but does not stop the loop.
fn run_hook(cmd: &[String], file: &str) {
    let Some((program, args)) = cmd.split_first() else {
        return;
    };
    let args: Vec<String> = args.iter().map(|a| a.replace("{file}", file)).collect();
    match std::process::Command::new(program).args(&args).status() {
        Ok(s) if !s.success() => tracing::warn!(%program, "import hook exited nonzero"),
        Err(e) => tracing::warn!(error = %e, %program, "import hook failed to run"),
        _ => {}
    }
}

// Read fuzzer stats: from the stats command's stdout if configured, else from
// the stats file. Either way the configured parser interprets the text.
fn read_stats(
    parser: &str,
    stats_cmd: Option<&[String]>,
    stats_file: Option<&Path>,
) -> mycelium_common::stats::FuzzerStats {
    if let Some(cmd) = stats_cmd {
        if let Some((program, args)) = cmd.split_first()
            && let Ok(out) = std::process::Command::new(program).args(args).output()
        {
            let raw = String::from_utf8_lossy(&out.stdout);
            return mycelium_common::stats::parse_stats(parser, &raw);
        }
        return Default::default();
    }
    match stats_file {
        Some(sf) if sf.exists() => {
            let raw = std::fs::read_to_string(sf).unwrap_or_default();
            mycelium_common::stats::parse_stats(parser, &raw)
        }
        _ => Default::default(),
    }
}

// Read or create a stable node id under `dir`, so a restarted node keeps the
// same id and the coordinator does not re-send it the whole corpus. Shaped like
// the coordinator's own hostname-xxxx so probe output stays readable.
fn persistent_node_id(dir: &std::path::Path, hostname: &str) -> String {
    let path = dir.join(".mycelium-node-id");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if !s.is_empty() {
            return s.to_string();
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // 8 hex chars (32 bits) plus the pid, not 4 (16 bits) off hostname+nanos:
    // on hosts with no /etc/hostname every node's hostname is "unknown", so the
    // old 4-char tail collided far too easily and two nodes shared one id (and,
    // via INSERT OR REPLACE on the coordinator, one row and one history).
    let pid = std::process::id();
    let seed = format!("{hostname}-{nanos}-{pid}");
    let short = &mycelium_common::corpus::hash_bytes(seed.as_bytes())[..8];
    let id = format!("{hostname}-{short}");
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(&path, &id);
    id
}

// gethostname(2) would be cleaner but nix is heavy for one syscall
fn gethostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::command_is_time_limited;

    fn cmd(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bounded_fuzzer_commands_are_time_limited() {
        // honggfuzz passes the budget as a separate arg
        assert!(command_is_time_limited(&cmd(&["honggfuzz", "--run_time", "120", "--", "./h"])));
        // libFuzzer uses =-joined flags
        assert!(command_is_time_limited(&cmd(&["./h", "corpus", "-max_total_time=120"])));
        assert!(command_is_time_limited(&cmd(&["./h", "corpus", "-runs=100000"])));
        // Go's native fuzzer
        assert!(command_is_time_limited(&cmd(&["go", "test", "-fuzz=Fuzz", "-fuzztime=30s"])));
        // AFL++ -V bounds a run by wall-clock seconds
        assert!(command_is_time_limited(&cmd(&["afl-fuzz", "-i", "s", "-o", "o", "-V", "120", "--", "./h"])));
    }

    #[test]
    fn persistent_fuzzer_commands_are_not_time_limited() {
        // AFL++ has no overall time budget
        assert!(!command_is_time_limited(&cmd(&[
            "afl-fuzz", "-i", "seeds", "-o", "out", "-M", "main", "-t", "2000+", "--", "./h"
        ])));
        // a bare libFuzzer run with no budget
        assert!(!command_is_time_limited(&cmd(&["./h", "corpus"])));
    }
}
