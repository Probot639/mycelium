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

    let app = Router::new()
        .route("/register", post(routes::register))
        .route("/seed/push", post(routes::push_seed))
        .route("/seed/pull", post(routes::pull_seeds))
        .route("/crash", post(routes::report_crash))
        .route("/heartbeat", post(routes::heartbeat))
        .route("/scry", get(routes::scry))
        .route("/deregister", post(routes::deregister))
        .with_state(state);

    tracing::info!(%listen, "coordinator starting");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn build_router(state: Arc<CoordinatorState>) -> Router {
    Router::new()
        .route("/register", post(routes::register))
        .route("/seed/push", post(routes::push_seed))
        .route("/seed/pull", post(routes::pull_seeds))
        .route("/crash", post(routes::report_crash))
        .route("/heartbeat", post(routes::heartbeat))
        .route("/scry", get(routes::scry))
        .route("/deregister", post(routes::deregister))
        .with_state(state)
}
