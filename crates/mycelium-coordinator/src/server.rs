use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use axum::routing::{get, patch, post};
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
    let state = {
        #[cfg(feature = "postgres")]
        if let Some(pg_url) = std::env::var("MYCELIUM_PG_URL").ok().filter(|s| !s.is_empty()) {
            tracing::info!("using postgres backend");
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .connect(&pg_url)
                .await?;
            Arc::new(CoordinatorState::new_pg(pool, corpus_dir)?.with_auth_token(token))
        } else {
            #[cfg(feature = "sqlite")]
            { Arc::new(CoordinatorState::new(db_path, corpus_dir)?.with_auth_token(token)) }
            #[cfg(not(feature = "sqlite"))]
            { anyhow::bail!("set MYCELIUM_PG_URL: no sqlite backend compiled in") }
        }
        #[cfg(not(feature = "postgres"))]
        Arc::new(CoordinatorState::new(db_path, corpus_dir)?.with_auth_token(token))
    };

    // Reap stale nodes and snapshot metrics every 30s.
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
            if let Err(e) = reaper.snapshot_metrics() {
                tracing::warn!(error = %e, "metrics snapshot failed");
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

    let open = Router::new()
        .route("/", get(routes::dashboard))
        .route("/ui", get(routes::dashboard))
        .route("/scry", get(routes::scry))
        // versioned read-only API
        .route("/api/v1/metrics/{name}", get(routes::get_metrics))
        .route("/api/v1/corpus/{name}", get(routes::list_corpus))
        .route("/api/v1/crashes/{name}", get(routes::list_crashes));

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
        // versioned write API
        .route(
            "/api/v1/campaign/{name}/lifecycle",
            patch(routes::update_campaign_lifecycle),
        )
        .route(
            "/api/v1/corpus/{name}/inject",
            post(routes::inject_seeds),
        )
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            routes::require_auth,
        ));

    Router::new().merge(open).merge(gated).with_state(state)
}
