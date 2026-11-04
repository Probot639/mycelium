use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use axum::routing::{get, post};
use axum::Router;

use crate::routes;
use crate::state::CoordinatorState;

pub async fn run(listen: SocketAddr, db_path: &Path, corpus_dir: &Path) -> Result<()> {
    let token = std::env::var("MYCELIUM_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    if token.is_none() {
        tracing::warn!(
            "coordinator running without auth: set MYCELIUM_TOKEN to require a bearer token \
             on the write and harness endpoints"
        );
    }
    let state = Arc::new(CoordinatorState::new(db_path, corpus_dir)?.with_auth_token(token));

    // Reap nodes that stopped heartbeating, so a crashed node does not count as
    // online forever. 90s is three missed 30s heartbeats.
    let reaper = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            match reaper.reap_stale(90) {
                Ok(n) if n > 0 => tracing::info!(count = n, "marked stale nodes unreachable"),
                Err(e) => tracing::warn!(error = %e, "node reaper failed"),
                _ => {}
            }
        }
    });

    let app = build_router(state);

    tracing::info!(%listen, "coordinator starting");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn build_router(state: Arc<CoordinatorState>) -> Router {
    use axum::extract::DefaultBodyLimit;

    // Read-only surface: the dashboard and its /scry feed stay open so a browser
    // can load them. Everything that writes, registers, or moves the harness is
    // behind the token.
    let open = Router::new()
        .route("/", get(routes::dashboard))
        .route("/ui", get(routes::dashboard))
        .route("/scry", get(routes::scry));

    let gated = Router::new()
        .route("/register", post(routes::register))
        .route("/seed/push", post(routes::push_seed))
        .route("/seed/push/batch", post(routes::push_seed_batch))
        .route("/seed/pull", post(routes::pull_seeds))
        .route("/crash", post(routes::report_crash))
        .route("/heartbeat", post(routes::heartbeat))
        .route("/deregister", post(routes::deregister))
        .route("/campaign", post(routes::create_campaign))
        .route("/campaign/{name}", get(routes::get_campaign))
        .route(
            "/campaign/{name}/harness",
            get(routes::download_harness)
                .put(routes::upload_harness)
                .layer(DefaultBodyLimit::max(512 * 1024 * 1024)),
        )
        // seed batches, crashes, and base-corpus uploads routinely exceed axum's
        // 2 MB default body limit, so lift it for the whole gated surface
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            routes::require_auth,
        ));

    Router::new().merge(open).merge(gated).with_state(state)
}
