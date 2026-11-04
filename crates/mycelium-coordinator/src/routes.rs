use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;

use mycelium_common::node::{NodeInfo, NodeStatus};
use mycelium_common::protocol::*;
use mycelium_common::validate;

use crate::state::CoordinatorState;

type AppState = Arc<CoordinatorState>;

// Bearer-token gate for the write and harness endpoints. When the coordinator
// has no token set it lets everything through, which is the old open behavior.
pub async fn require_auth(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(expected) = &state.auth_token {
        let provided = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));
        let ok = provided.map(|p| ct_eq(p, expected)).unwrap_or(false);
        if !ok {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    next.run(req).await
}

// Constant-time string compare, so token validation does not leak the matching
// prefix length through response timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // reuse the node's persisted id when it sent a valid one, so a restart keeps
    // its distribution history; otherwise mint a fresh hostname-xxxx
    let node_id = match req.requested_id.as_deref() {
        Some(id) if validate::is_valid_campaign(id) => id.to_string(),
        _ => {
            let short = &uuid::Uuid::new_v4().to_string()[..4];
            format!("{}-{short}", req.hostname)
        }
    };
    let info = NodeInfo {
        id: node_id.clone(),
        hostname: req.hostname,
        campaign: req.campaign,
        fuzzer: req.fuzzer,
        priority: req.priority,
        status: NodeStatus::Online,
        time_limited: req.time_limited,
        last_sync: chrono::Utc::now(),
    };
    match state.register_node(&info) {
        Ok(()) => {
            tracing::info!(%node_id, "node joined");
            (StatusCode::OK, Json(RegisterResponse { node_id })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "registration failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn push_seed(
    State(state): State<AppState>,
    Json(req): Json<PushSeedRequest>,
) -> StatusCode {
    // the hash becomes a path component on disk, so reject anything that is not
    // a clean content hash before it gets there
    if !validate::is_valid_hash(&req.seed.hash) {
        tracing::warn!(from = %req.node_id, "rejected seed with invalid hash");
        return StatusCode::BAD_REQUEST;
    }
    match state.ingest_seed(&req.seed) {
        Ok(true) => {
            tracing::debug!(hash = %req.seed.hash, from = %req.node_id, "new seed");
            StatusCode::OK
        }
        Ok(false) => StatusCode::OK,
        Err(e) => {
            tracing::error!(error = %e, "seed ingest failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub async fn push_seed_batch(
    State(state): State<AppState>,
    Json(req): Json<PushSeedBatchRequest>,
) -> StatusCode {
    let mut new = 0u64;
    for seed in &req.seeds {
        // the state layer validates the hash; a bad seed is skipped, not fatal
        // to the batch
        match state.ingest_seed(seed) {
            Ok(true) => new += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, from = %req.node_id, "skipped bad seed in batch"),
        }
    }
    if new > 0 {
        tracing::debug!(count = req.seeds.len(), new, from = %req.node_id, "seed batch");
    }
    StatusCode::OK
}

pub async fn pull_seeds(
    State(state): State<AppState>,
    Json(req): Json<PullSeedsRequest>,
) -> impl IntoResponse {
    // Bind the pull to the node's registered campaign, not the campaign in the
    // request, so a node cannot read a campaign it did not join.
    let campaign = match state.node_campaign(&req.node_id) {
        Ok(Some(c)) => c,
        _ => {
            return (StatusCode::NOT_FOUND, Json(PullSeedsResponse { seeds: vec![] })).into_response();
        }
    };
    match state.get_seeds_for_node(&req.node_id, &campaign) {
        Ok(seeds) => {
            if !seeds.is_empty() {
                tracing::debug!(count = seeds.len(), to = %req.node_id, "distributing seeds");
            }
            (StatusCode::OK, Json(PullSeedsResponse { seeds })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "pull failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PullSeedsResponse { seeds: vec![] }),
            )
                .into_response()
        }
    }
}

pub async fn report_crash(
    State(state): State<AppState>,
    Json(req): Json<ReportCrashRequest>,
) -> StatusCode {
    // stack_hash becomes a directory name on disk; both hashes must be clean
    if !validate::is_valid_hash(&req.crash.stack_hash) || !validate::is_valid_hash(&req.crash.input_hash) {
        tracing::warn!(from = %req.node_id, "rejected crash with invalid hash");
        return StatusCode::BAD_REQUEST;
    }
    match state.ingest_crash(&req.crash) {
        Ok(is_new) => {
            if is_new {
                tracing::warn!(
                    stack_hash = %req.crash.stack_hash,
                    from = %req.node_id,
                    "new crash 💀"
                );
            }
            StatusCode::OK
        }
        Err(e) => {
            tracing::error!(error = %e, "crash ingest failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// heartbeat errors are non-fatal on the circle side so we don't bother
// with structured error bodies here
pub async fn heartbeat(
    State(state): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> StatusCode {
    if let Err(e) = state.heartbeat(
        &req.node_id,
        req.execs_per_sec,
        req.corpus_size,
        req.crashes_found,
    ) {
        tracing::warn!(error = %e, node = %req.node_id, "heartbeat write failed");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}

// Built-in dashboard. It is deliberately a thin client of /scry so the API, not
// this page, is the real surface. Everything a frontend needs is one GET:
//   GET /scry -> { nodes: [...], campaign: {...} }   (see protocol.rs)
// TODO: when a second frontend shows up, move the read side behind a versioned
// /api/v1/scry and add CORS so it can live on another origin. An SSE or websocket
// push would beat the 3s poll, but poll is fine for a tailnet this size.
pub async fn dashboard() -> Html<&'static str> {
    Html(include_str!("ui/dashboard.html"))
}

pub async fn scry(State(state): State<AppState>) -> Json<ScryResponse> {
    let nodes = state.list_nodes(None).unwrap_or_default();
    let campaign_name = nodes.first().map(|n| n.campaign.as_str()).unwrap_or("none");
    let campaign = state
        .campaign_status(campaign_name)
        .unwrap_or(CampaignStatus {
            name: campaign_name.to_string(),
            total_corpus: 0,
            total_crashes: 0,
            unique_bugs: 0,
            total_execs_per_sec: 0,
            nodes_online: 0,
        });
    Json(ScryResponse { nodes, campaign })
}

pub async fn deregister(
    State(state): State<AppState>,
    Json(req): Json<DeregisterRequest>,
) -> StatusCode {
    // Graceful drain suspends the node but keeps its corpus, crashes, and
    // distribution history, so it does not re-pull everything if it comes back.
    // A hard deregister removes the node and its distribution rows outright.
    let result = if req.drain {
        state.set_node_status(&req.node_id, mycelium_common::node::NodeStatus::Suspended)
    } else {
        state.deregister_node(&req.node_id)
    };
    match result {
        Ok(()) => {
            tracing::info!(node_id = %req.node_id, drain = req.drain, "node left");
            StatusCode::OK
        }
        Err(e) => {
            tracing::error!(error = %e, "deregister failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub async fn create_campaign(
    State(state): State<AppState>,
    Json(req): Json<CreateCampaignRequest>,
) -> impl IntoResponse {
    if !validate::is_valid_campaign(&req.name) || req.fuzzer_command.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.create_campaign(&req.name, &req.fuzzer_name, &req.fuzzer_command) {
        Ok(()) => {
            tracing::info!(campaign = %req.name, "campaign created");
            StatusCode::CREATED.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "campaign create failed");
            StatusCode::CONFLICT.into_response()
        }
    }
}

pub async fn get_campaign(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if !validate::is_valid_campaign(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.get_campaign(&name) {
        Ok(Some(info)) => (StatusCode::OK, Json(info)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "campaign lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn upload_harness(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Bytes,
) -> StatusCode {
    if body.is_empty() || !validate::is_valid_campaign(&name) {
        return StatusCode::BAD_REQUEST;
    }
    // campaign must exist before you can upload a harness for it
    match state.get_campaign(&name) {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    }
    match state.store_harness(&name, &body) {
        Ok(()) => {
            tracing::info!(campaign = %name, bytes = body.len(), "harness uploaded");
            StatusCode::OK
        }
        Err(e) => {
            tracing::error!(error = %e, "harness store failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub async fn download_harness(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if !validate::is_valid_campaign(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.get_harness(&name) {
        Ok(Some(data)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "harness read failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
