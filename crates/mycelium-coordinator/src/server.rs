use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use axum::routing::{get, post};
use axum::Router;

use crate::routes;
use crate::state::CoordinatorState;

pub async fn run(listen: SocketAddr, db_path: &Path, corpus_dir: &Path) -> Result<()> {
    let state = Arc::new(CoordinatorState::new(db_path, corpus_dir)?);
    let app = build_router(state);

    tracing::info!(%listen, "coordinator starting");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn build_router(state: Arc<CoordinatorState>) -> Router {
    use axum::extract::DefaultBodyLimit;

    Router::new()
        .route("/register", post(routes::register))
        .route("/seed/push", post(routes::push_seed))
        .route("/seed/pull", post(routes::pull_seeds))
        .route("/crash", post(routes::report_crash))
        .route("/heartbeat", post(routes::heartbeat))
        .route("/scry", get(routes::scry))
        .route("/deregister", post(routes::deregister))
        .route("/campaign", post(routes::create_campaign))
        .route("/campaign/{name}", get(routes::get_campaign))
        .route(
            "/campaign/{name}/harness",
            get(routes::download_harness)
                .put(routes::upload_harness)
                .layer(DefaultBodyLimit::max(512 * 1024 * 1024)),
        )
        .with_state(state)
}
