use std::sync::Arc;

use mycelium_node::sync::SyncClient;
use mycelium_common::node::Priority;
use mycelium_coordinator::server::build_router;
use mycelium_coordinator::state::CoordinatorState;

async fn start_server() -> (String, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let corpus_dir = tmp.path().join("corpus");
    let state = Arc::new(CoordinatorState::new_in_memory(&corpus_dir).unwrap());
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), tmp)
}

async fn start_server_with_token(token: &str) -> (String, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let corpus_dir = tmp.path().join("corpus");
    let state = Arc::new(
        CoordinatorState::new_in_memory(&corpus_dir)
            .unwrap()
            .with_auth_token(Some(token.to_string())),
    );
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), tmp)
}

#[tokio::test]
async fn auth_token_gates_writes_but_not_scry() {
    let (url, _tmp) = start_server_with_token("sekret").await;
    let client = reqwest::Client::new();
    let reg = mycelium_common::protocol::RegisterRequest {
        hostname: "h".into(),
        campaign: "c".into(),
        fuzzer: "aflpp".into(),
        priority: Priority::Shared,
        requested_id: None,
        time_limited: false,
    };

    // gated endpoint without a token is rejected
    let resp = client
        .post(format!("{url}/register"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // the read-only dashboard feed stays open
    let resp = reqwest::get(format!("{url}/scry")).await.unwrap();
    assert_eq!(resp.status(), 200);

    // the right token gets through
    let resp = client
        .post(format!("{url}/register"))
        .bearer_auth("sekret")
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // a wrong token is rejected
    let resp = client
        .post(format!("{url}/register"))
        .bearer_auth("nope")
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn register_push_pull_cycle() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "testhost", "campaign-1", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    assert!(node_id.starts_with("testhost-"));

    let sync = SyncClient::new(&url, &node_id, "campaign-1");

    // Push a seed
    let data = b"fuzz input one".to_vec();
    let hash = mycelium_common::corpus::hash_bytes(&data);
    sync.push_seed(hash.clone(), data.clone()).await.unwrap();

    // Register a second node and pull -- it should see the seed
    let node2_id =
        SyncClient::register(&url, "testhost2", "campaign-1", "aflpp", Priority::Shared, None, false)
            .await
            .unwrap();
    let sync2 = SyncClient::new(&url, &node2_id, "campaign-1");
    let seeds = sync2.pull_seeds().await.unwrap();
    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0].hash, hash);
    assert_eq!(seeds[0].data, data);

    // Pulling again should return nothing (already sent)
    let seeds2 = sync2.pull_seeds().await.unwrap();
    assert!(seeds2.is_empty());
}

// A node that sends a stable requested_id keeps it across re-registers, so it
// is one row, not a new node each restart.
#[tokio::test]
async fn stable_id_preserved_across_reregister() {
    let (url, _tmp) = start_server().await;
    let id1 = SyncClient::register(&url, "host", "camp-id", "aflpp", Priority::Shared, Some("host-stable".into()), false)
        .await
        .unwrap();
    assert_eq!(id1, "host-stable");
    let id2 = SyncClient::register(&url, "host", "camp-id", "aflpp", Priority::Shared, Some("host-stable".into()), false)
        .await
        .unwrap();
    assert_eq!(id2, "host-stable");

    let resp: mycelium_common::protocol::ScryResponse =
        reqwest::get(format!("{url}/scry")).await.unwrap().json().await.unwrap();
    assert_eq!(resp.nodes.len(), 1);
}

// Base corpus uploaded at inoculate time reaches a node that joins afterward.
#[tokio::test]
async fn base_corpus_upload_reaches_nodes() {
    let (url, _tmp) = start_server().await;
    SyncClient::upload_seeds(
        &url,
        "camp-base",
        vec![
            (mycelium_common::corpus::hash_bytes(b"s1"), b"s1".to_vec()),
            (mycelium_common::corpus::hash_bytes(b"s2"), b"s2".to_vec()),
        ],
    )
    .await
    .unwrap();

    let id = SyncClient::register(&url, "n", "camp-base", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &id, "camp-base");
    let seeds = sync.pull_seeds().await.unwrap();
    assert_eq!(seeds.len(), 2);
}

// A node must only pull its own campaign's corpus, even if it claims another
// campaign in the request.
#[tokio::test]
async fn pull_seeds_bound_to_registered_campaign() {
    let (url, _tmp) = start_server().await;
    let a = SyncClient::register(&url, "a", "camp-a", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    let b = SyncClient::register(&url, "b", "camp-b", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    // node B contributes a secret seed to camp-b
    let sb = SyncClient::new(&url, &b, "camp-b");
    sb.push_seed(mycelium_common::corpus::hash_bytes(b"secret"), b"secret".to_vec())
        .await
        .unwrap();

    // node A (camp-a) tries to pull camp-b by claiming campaign=camp-b
    let client = reqwest::Client::new();
    let resp: mycelium_common::protocol::PullSeedsResponse = client
        .post(format!("{url}/seed/pull"))
        .json(&serde_json::json!({"node_id": a, "campaign": "camp-b"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(resp.seeds.is_empty(), "node A must not receive camp-b's corpus");
}

#[tokio::test]
async fn crash_dedup_same_input() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "crasher", "campaign-2", "aflpp", Priority::Dedicated, None, false)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &node_id, "campaign-2");

    sync.report_crash(b"bad input".to_vec(), "ASAN: heap-buffer-overflow\n#0 0xdead\n#1 0xbeef")
        .await
        .unwrap();

    // same input twice should dedup to one crash
    sync.report_crash(b"bad input".to_vec(), "ASAN: heap-buffer-overflow\n#0 0xdead\n#1 0xbeef")
        .await
        .unwrap();

    let resp: mycelium_common::protocol::ScryResponse =
        reqwest::get(format!("{url}/scry")).await.unwrap().json().await.unwrap();
    assert_eq!(resp.campaign.total_crashes, 1);
}

// Different inputs that hit the same bug count as one bug but distinct crashes,
// and both reproducers are kept on disk under the bug's dir.
#[tokio::test]
async fn crashes_dedup_by_bug_keep_reproducers() {
    let (url, tmp) = start_server().await;
    let node_id = SyncClient::register(&url, "c", "camp-bug", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &node_id, "camp-bug");

    let trace_a = "==1==ERROR: AddressSanitizer: heap-use-after-free\n    #0 0x1 in foo /a.c:1\n    #1 0x2 in bar /b.c:2\n";
    // two different inputs, same bug
    sync.report_crash(b"input-one".to_vec(), trace_a).await.unwrap();
    sync.report_crash(b"input-two".to_vec(), trace_a).await.unwrap();
    // a third input, a different bug
    let trace_b = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0x1 in baz /c.c:3\n";
    sync.report_crash(b"input-three".to_vec(), trace_b).await.unwrap();

    let resp: mycelium_common::protocol::ScryResponse =
        reqwest::get(format!("{url}/scry")).await.unwrap().json().await.unwrap();
    assert_eq!(resp.campaign.total_crashes, 3); // 3 unique inputs
    assert_eq!(resp.campaign.unique_bugs, 2); // 2 distinct bugs

    // both reproducers of bug A are on disk under its stack-hash dir
    let sh = mycelium_common::triage::stack_hash(trace_a).unwrap();
    let bug_dir = tmp.path().join("corpus").join("crashes").join(&sh);
    let bins = std::fs::read_dir(&bug_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "bin").unwrap_or(false))
        .count();
    assert_eq!(bins, 2);
}

#[tokio::test]
async fn heartbeat_and_scry() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "worker", "campaign-3", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &node_id, "campaign-3");

    sync.heartbeat(5000, 42, 0).await.unwrap();

    let resp: mycelium_common::protocol::ScryResponse =
        reqwest::get(format!("{url}/scry")).await.unwrap().json().await.unwrap();
    assert_eq!(resp.campaign.nodes_online, 1);
    assert_eq!(resp.nodes.len(), 1);
    assert_eq!(resp.nodes[0].hostname, "worker");
}

// Graceful drain keeps the node row (suspended) so it does not re-pull the
// whole corpus if it comes back. It just stops counting as online.
#[tokio::test]
async fn deregister_drains() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "ephemeral", "campaign-4", "aflpp", Priority::Idle, None, false)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &node_id, "campaign-4");

    sync.deregister(true).await.unwrap();

    let resp: mycelium_common::protocol::ScryResponse =
        reqwest::get(format!("{url}/scry")).await.unwrap().json().await.unwrap();
    assert_eq!(resp.campaign.nodes_online, 0);
    // the row is kept, just suspended
    assert_eq!(resp.nodes.len(), 1);
    assert_eq!(resp.nodes[0].status, mycelium_common::node::NodeStatus::Suspended);
}

// A hard deregister (no drain) removes the node outright.
#[tokio::test]
async fn hard_deregister_removes_node() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "gone", "campaign-4b", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &node_id, "campaign-4b");

    sync.deregister(false).await.unwrap();

    let resp: mycelium_common::protocol::ScryResponse =
        reqwest::get(format!("{url}/scry")).await.unwrap().json().await.unwrap();
    assert_eq!(resp.nodes.len(), 0);
}

// A huge execs_per_sec (AFL calibration can report one) must not overflow the
// signed SQLite column and 500 the heartbeat.
#[tokio::test]
async fn heartbeat_clamps_huge_execs() {
    let (url, _tmp) = start_server().await;
    let node_id = SyncClient::register(&url, "fast", "campaign-hb", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &node_id, "campaign-hb");
    // u64::MAX exceeds i64::MAX; before the clamp this returned 500
    sync.heartbeat(u64::MAX, 10, 0).await.unwrap();

    let resp: mycelium_common::protocol::ScryResponse =
        reqwest::get(format!("{url}/scry")).await.unwrap().json().await.unwrap();
    assert_eq!(resp.campaign.nodes_online, 1);
}

#[tokio::test]
async fn campaign_create_and_harness_roundtrip() {
    let (url, _tmp) = start_server().await;

    // create campaign
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/campaign"))
        .json(&mycelium_common::protocol::CreateCampaignRequest {
            name: "fuzz-libpng".into(),
            fuzzer_name: "aflpp".into(),
            fuzzer_command: vec![
                "afl-fuzz".into(),
                "-i".into(),
                "{corpus}".into(),
                "-o".into(),
                "{output}".into(),
                "--".into(),
                "{harness}".into(),
            ],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // check it exists
    let info: mycelium_common::protocol::CampaignInfo = client
        .get(format!("{url}/campaign/fuzz-libpng"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info.name, "fuzz-libpng");
    assert_eq!(info.harness_len, 0);

    // upload harness
    let fake_binary = vec![0xEFu8; 1024];
    let resp = client
        .put(format!("{url}/campaign/fuzz-libpng/harness"))
        .body(fake_binary.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // download it back
    let downloaded = reqwest::get(format!("{url}/campaign/fuzz-libpng/harness"))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(downloaded.len(), 1024);
    assert_eq!(&downloaded[..], &fake_binary[..]);

    // campaign should now show harness_len
    let info: mycelium_common::protocol::CampaignInfo = client
        .get(format!("{url}/campaign/fuzz-libpng"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info.harness_len, 1024);
}

#[tokio::test]
async fn campaign_not_found() {
    let (url, _tmp) = start_server().await;
    let resp = reqwest::get(format!("{url}/campaign/nonexistent"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn harness_upload_requires_campaign() {
    let (url, _tmp) = start_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{url}/campaign/nonexistent/harness"))
        .body(vec![0u8; 64])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// A seed whose hash is a path-traversal string must be rejected before it
// reaches the filesystem, not written under the corpus dir.
#[tokio::test]
async fn rejects_path_traversal_seed_hash() {
    let (url, _tmp) = start_server().await;
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "node_id": "evil",
        "seed": {
            "hash": "../../../../tmp/mycelium-pwned",
            "data": [1, 2, 3],
            "source_node": "evil",
            "campaign": "x",
            "found_at": 0
        }
    });
    let resp = client
        .post(format!("{url}/seed/push"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(!std::path::Path::new("/tmp/mycelium-pwned").exists());
}

#[tokio::test]
async fn rejects_traversal_campaign_name() {
    let (url, _tmp) = start_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/campaign"))
        .json(&mycelium_common::protocol::CreateCampaignRequest {
            name: "../../etc/cron.d/x".into(),
            fuzzer_name: "aflpp".into(),
            fuzzer_command: vec!["afl-fuzz".into()],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn source_node_does_not_receive_own_seeds() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "solo", "campaign-5", "aflpp", Priority::Shared, None, false)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &node_id, "campaign-5");

    let data = b"my own seed".to_vec();
    let hash = mycelium_common::corpus::hash_bytes(&data);
    sync.push_seed(hash, data).await.unwrap();

    // The node that pushed should not get its own seed back
    let seeds = sync.pull_seeds().await.unwrap();
    assert!(seeds.is_empty());
}
