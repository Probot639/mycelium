use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use mycelium_common::node::{NodeInfo, NodeStatus};
use mycelium_common::protocol::*;

use crate::state::CoordinatorState;

type AppState = Arc<CoordinatorState>;

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // 4 hex chars from uuid4 gives us ~65k unique IDs per hostname, good enough
    let short = &uuid::Uuid::new_v4().to_string()[..4];
    let node_id = format!("{}-{short}", req.hostname);
    let info = NodeInfo {
        id: node_id.clone(),
        hostname: req.hostname,
        campaign: req.campaign,
        fuzzer: req.fuzzer,
        priority: req.priority,
        status: NodeStatus::Online,
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

pub async fn pull_seeds(
    State(state): State<AppState>,
    Json(req): Json<PullSeedsRequest>,
) -> impl IntoResponse {
    // TODO: the circle should just send its campaign in the request instead
    // of us looking it up from the node table every time
    let campaign = {
        let nodes = state.list_nodes(None).unwrap_or_default();
        nodes
            .iter()
            .find(|n| n.id == req.node_id)
            .map(|n| n.campaign.clone())
            .unwrap_or_default()
    };
    if campaign.is_empty() {
        return (StatusCode::NOT_FOUND, Json(PullSeedsResponse { seeds: vec![] })).into_response();
    }
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

pub async fn scry(State(state): State<AppState>) -> Json<ScryResponse> {
    let nodes = state.list_nodes(None).unwrap_or_default();
    let campaign_name = nodes.first().map(|n| n.campaign.as_str()).unwrap_or("none");
    let campaign = state
        .campaign_status(campaign_name)
        .unwrap_or(CampaignStatus {
            name: campaign_name.to_string(),
            total_corpus: 0,
            total_crashes: 0,
            total_execs_per_sec: 0,
            nodes_online: 0,
        });
    Json(ScryResponse { nodes, campaign })
}

pub async fn deregister(
    State(state): State<AppState>,
    Json(req): Json<DeregisterRequest>,
) -> StatusCode {
    match state.deregister_node(&req.node_id) {
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
    if req.name.is_empty() || req.fuzzer_command.is_empty() {
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
    if body.is_empty() {
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
