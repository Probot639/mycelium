use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;

use mycelium_common::node::{NodeInfo, NodeStatus};
use mycelium_common::protocol::*;
use mycelium_common::validate;

use crate::state::CoordinatorState;

type AppState = Arc<CoordinatorState>;

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
                    "new crash"
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

pub async fn heartbeat(
    State(state): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> StatusCode {
    if let Err(e) = state.heartbeat(
        &req.node_id,
        req.execs_per_sec,
        req.corpus_size,
        req.crashes_found,
        req.edges_found,
    ) {
        tracing::warn!(error = %e, node = %req.node_id, "heartbeat write failed");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}

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
            total_edges: 0,
            nodes_online: 0,
            lifecycle: CampaignLifecycle::Running,
        });
    Json(ScryResponse { nodes, campaign })
}

pub async fn deregister(
    State(state): State<AppState>,
    Json(req): Json<DeregisterRequest>,
) -> StatusCode {
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
    match state.create_campaign(
        &req.name,
        &req.fuzzer_name,
        &req.fuzzer_command,
        req.triage_cmd.as_deref(),
    ) {
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

// --- API v1 ---

pub async fn update_campaign_lifecycle(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<UpdateCampaignLifecycleRequest>,
) -> impl IntoResponse {
    if !validate::is_valid_campaign(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.update_campaign_lifecycle(&name, req.lifecycle) {
        Ok(true) => {
            tracing::info!(campaign = %name, lifecycle = %req.lifecycle, "lifecycle updated");
            StatusCode::OK.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "lifecycle update failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct MetricsQuery {
    #[serde(default = "default_limit")]
    pub limit: u64,
}
fn default_limit() -> u64 {
    500
}

pub async fn get_metrics(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<MetricsQuery>,
) -> impl IntoResponse {
    if !validate::is_valid_campaign(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.get_metrics(&name, q.limit) {
        Ok(snapshots) => (
            StatusCode::OK,
            Json(MetricsResponse {
                campaign: name,
                snapshots,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "metrics query failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn list_corpus(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if !validate::is_valid_campaign(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.list_seed_hashes(&name) {
        Ok(hashes) => {
            let total = hashes.len() as u64;
            (
                StatusCode::OK,
                Json(CorpusListResponse {
                    campaign: name,
                    hashes,
                    total,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "corpus list failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn inject_seeds(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<InjectSeedsRequest>,
) -> impl IntoResponse {
    if !validate::is_valid_campaign(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let mut ingested = 0u64;
    for mut seed in req.seeds {
        seed.campaign = name.clone();
        if seed.source_node.is_empty() {
            seed.source_node = "api-inject".into();
        }
        match state.ingest_seed(&seed) {
            Ok(true) => ingested += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, "skipped bad seed in inject"),
        }
    }
    (StatusCode::OK, Json(serde_json::json!({"ingested": ingested}))).into_response()
}

pub async fn list_crashes(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<MetricsQuery>,
) -> impl IntoResponse {
    if !validate::is_valid_campaign(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.list_crashes(&name, q.limit) {
        Ok(crashes) => (StatusCode::OK, Json(PullCrashesResponse { crashes })).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "crash list failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
