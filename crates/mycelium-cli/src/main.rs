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

    /// Attach a node and start fuzzing
    Join {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "default")]
        campaign: String,
    },

    /// Show campaign status
    Probe {
        #[arg(long)]
        coordinator: String,
        #[arg(long)]
        nodes: bool,
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

        Commands::Join {
            coordinator,
            config,
            campaign,
        } => {
            let cfg = mycelium_node::config::CircleConfig::from_file(&config)?;
            let hostname = gethostname();

            tracing::info!(%coordinator, %hostname, "joining network");

            let node_id = mycelium_node::sync::SyncClient::register(
                &coordinator,
                &hostname,
                &campaign,
                &cfg.fuzzer.name,
                cfg.node.priority,
            )
            .await?;

            tracing::info!(%node_id, "registered");

            let sync = mycelium_node::sync::SyncClient::new(&coordinator, &node_id, &campaign);

            let initial_seeds = sync.pull_seeds().await?;
            let inject_dir = PathBuf::from(&cfg.circle.inject_dir);
            std::fs::create_dir_all(&inject_dir)?;
            for seed in &initial_seeds {
                sync.inject_seed(&inject_dir, seed)?;
            }
            tracing::info!(count = initial_seeds.len(), "pulled initial corpus");

            let corpus_dir = PathBuf::from(&cfg.fuzzer.corpus_dir);
            let crash_dir = PathBuf::from(&cfg.fuzzer.crash_dir);
            std::fs::create_dir_all(&corpus_dir)?;
            std::fs::create_dir_all(&crash_dir)?;

            let watcher = mycelium_node::watcher::DirWatcher::new();
            for seed in &initial_seeds {
                watcher.mark_seen(&seed.hash);
            }
            let mut rx = watcher.watch(&corpus_dir, &crash_dir)?;

            let mut cmd_iter = cfg.fuzzer.command.iter();
            let program = cmd_iter.next().expect("fuzzer command is empty");
            let mut child = tokio::process::Command::new(program)
                .args(cmd_iter)
                .spawn()?;
            tracing::info!(%program, "fuzzer started");

            let sync_interval = cfg.sync_interval_secs();
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(sync_interval));

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
                                    if let Err(e) = sync.inject_seed(&inject_dir, seed) {
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

                        let stats = match cfg.fuzzer.stats_file {
                            Some(ref sf) if PathBuf::from(sf).exists() => {
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
                        // flush anything the fuzzer wrote before dying
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
        }

        Commands::Probe { coordinator, nodes } => {
            let base = if coordinator.starts_with("http") {
                coordinator
            } else {
                format!("http://{coordinator}")
            };
            let resp: mycelium_common::protocol::ScryResponse = reqwest::get(format!("{base}/scry"))
                .await?
                .json()
                .await?;

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

// gethostname(2) would be cleaner but nix is heavy for one syscall
fn gethostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}
