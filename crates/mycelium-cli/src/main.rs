use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
        /// Fuzzer command template. Use {harness}, {corpus}, {output} as placeholders.
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
        #[arg(long)]
        drain: bool,
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
            cmd,
        } => {
            let harness_data = std::fs::read(&harness)?;
            tracing::info!(
                campaign = %campaign,
                harness = %harness.display(),
                bytes = harness_data.len(),
                "creating campaign"
            );

            mycelium_node::sync::SyncClient::create_campaign(
                &coordinator,
                &campaign,
                &fuzzer,
                &cmd,
            )
            .await?;

            mycelium_node::sync::SyncClient::upload_harness(
                &coordinator,
                &campaign,
                harness_data,
            )
            .await?;

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
                    let corpus_dir = workdir.join("corpus");
                    let output_dir = workdir.join("output");
                    std::fs::create_dir_all(&corpus_dir)?;
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
                                .replace("{corpus}", &corpus_dir.to_string_lossy())
                                .replace("{output}", &output_dir.to_string_lossy())
                        })
                        .collect();

                    let node_id = mycelium_node::sync::SyncClient::register(
                        &coordinator,
                        &hostname,
                        &campaign,
                        &camp_info.fuzzer_name,
                        priority_val,
                    )
                    .await?;
                    tracing::info!(%node_id, "registered");

                    // stats file depends on fuzzer. aflpp puts it here.
                    let stats_file = output_dir.join("default/fuzzer_stats");

                    run_fuzzer_loop(
                        &coordinator,
                        &node_id,
                        &campaign,
                        &fuzzer_command,
                        &corpus_dir,
                        &output_dir.join("default/crashes"),
                        &corpus_dir,
                        Some(&stats_file),
                        30,
                    )
                    .await?;
                }

                // manual mode: use local config file
                (Some(config), _) => {
                    let cfg = mycelium_node::config::CircleConfig::from_file(&config)?;
                    tracing::info!(%coordinator, %hostname, "joining (manual config)");

                    let node_id = mycelium_node::sync::SyncClient::register(
                        &coordinator,
                        &hostname,
                        &campaign,
                        &cfg.fuzzer.name,
                        cfg.node.priority,
                    )
                    .await?;
                    tracing::info!(%node_id, "registered");

                    let stats_file = cfg.fuzzer.stats_file.as_ref().map(PathBuf::from);

                    run_fuzzer_loop(
                        &coordinator,
                        &node_id,
                        &campaign,
                        &cfg.fuzzer.command,
                        &PathBuf::from(&cfg.fuzzer.corpus_dir),
                        &PathBuf::from(&cfg.fuzzer.crash_dir),
                        &PathBuf::from(&cfg.circle.inject_dir),
                        stats_file.as_deref(),
                        cfg.sync_interval_secs(),
                    )
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
                println!("Campaign: {}", resp.campaign.name);
                println!(
                    "  corpus: {}  crashes: {}  nodes: {}",
                    resp.campaign.total_corpus,
                    resp.campaign.total_crashes,
                    resp.campaign.nodes_online
                );

                if nodes || !resp.nodes.is_empty() {
                    println!();
                    println!(
                        "{:<16} {:<12} {:<12} {:<12} {}",
                        "NODE", "HOST", "FUZZER", "STATUS", "LAST SYNC"
                    );
                    for node in &resp.nodes {
                        println!(
                            "{:<16} {:<12} {:<12} {:<12} {}",
                            node.id,
                            node.hostname,
                            node.fuzzer,
                            node.status,
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
            tracing::info!(%node_id, "severed");
        }
    }

    Ok(())
}

async fn run_fuzzer_loop(
    coordinator: &str,
    node_id: &str,
    campaign: &str,
    fuzzer_command: &[String],
    corpus_dir: &std::path::Path,
    crash_dir: &std::path::Path,
    inject_dir: &std::path::Path,
    stats_file: Option<&std::path::Path>,
    sync_interval_secs: u64,
) -> Result<()> {
    let sync = mycelium_node::sync::SyncClient::new(coordinator, node_id, campaign);

    let initial_seeds = sync.pull_seeds().await?;
    std::fs::create_dir_all(inject_dir)?;
    for seed in &initial_seeds {
        sync.inject_seed(inject_dir, seed)?;
    }
    tracing::info!(count = initial_seeds.len(), "pulled initial corpus");

    std::fs::create_dir_all(corpus_dir)?;
    std::fs::create_dir_all(crash_dir)?;

    let watcher = mycelium_node::watcher::DirWatcher::new();
    for seed in &initial_seeds {
        watcher.mark_seen(&seed.hash);
    }
    let mut rx = watcher.watch(corpus_dir, crash_dir)?;

    let mut cmd_iter = fuzzer_command.iter();
    let program = cmd_iter.next().expect("fuzzer command is empty");
    let mut child = tokio::process::Command::new(program)
        .args(cmd_iter)
        .spawn()?;
    tracing::info!(%program, "fuzzer started");

    let mut tick = tokio::time::interval(std::time::Duration::from_secs(sync_interval_secs));

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                match event {
                    mycelium_node::watcher::WatchEvent::NewSeed { hash, data, .. } => {
                        if let Err(e) = sync.push_seed(hash, data).await {
                            tracing::error!(error = %e, "failed to push seed");
                        }
                    }
                    mycelium_node::watcher::WatchEvent::NewCrash { data, .. } => {
                        if let Err(e) = sync.report_crash(data, "").await {
                            tracing::error!(error = %e, "failed to report crash");
                        }
                    }
                }
            }
            _ = tick.tick() => {
                match sync.pull_seeds().await {
                    Ok(seeds) => {
                        for seed in &seeds {
                            watcher.mark_seen(&seed.hash);
                            if let Err(e) = sync.inject_seed(inject_dir, seed) {
                                tracing::error!(error = %e, "failed to inject seed");
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

                let stats = match stats_file {
                    Some(sf) if sf.exists() => {
                        let raw = std::fs::read_to_string(sf).unwrap_or_default();
                        mycelium_common::stats::parse_aflpp_stats(&raw)
                    }
                    _ => Default::default(),
                };

                if let Err(e) = sync.heartbeat(
                    stats.execs_per_sec,
                    stats.corpus_size,
                    stats.crashes_found,
                ).await {
                    tracing::warn!(error = %e, "heartbeat failed");
                }
            }
            status = child.wait() => {
                match status {
                    Ok(s) => tracing::warn!(%s, "fuzzer exited"),
                    Err(e) => tracing::error!(error = %e, "fuzzer wait error"),
                }
                while let Ok(event) = rx.try_recv() {
                    match event {
                        mycelium_node::watcher::WatchEvent::NewSeed { hash, data, .. } => {
                            let _ = sync.push_seed(hash, data).await;
                        }
                        mycelium_node::watcher::WatchEvent::NewCrash { data, .. } => {
                            let _ = sync.report_crash(data, "").await;
                        }
                    }
                }
                break;
            }
        }
    }

    tracing::info!("severing");
    sync.deregister(true).await?;
    Ok(())
}

// gethostname(2) would be cleaner but nix is heavy for one syscall
fn gethostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}
