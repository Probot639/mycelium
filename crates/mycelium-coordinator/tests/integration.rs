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

#[tokio::test]
async fn register_push_pull_cycle() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "testhost", "campaign-1", "aflpp", Priority::Shared)
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
        SyncClient::register(&url, "testhost2", "campaign-1", "aflpp", Priority::Shared)
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

#[tokio::test]
async fn crash_dedup_same_input() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "crasher", "campaign-2", "aflpp", Priority::Dedicated)
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

#[tokio::test]
async fn heartbeat_and_scry() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "worker", "campaign-3", "aflpp", Priority::Shared)
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

#[tokio::test]
async fn deregister_drains() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "ephemeral", "campaign-4", "aflpp", Priority::Idle)
        .await
        .unwrap();
    let sync = SyncClient::new(&url, &node_id, "campaign-4");

    sync.deregister(true).await.unwrap();

    let resp: mycelium_common::protocol::ScryResponse =
        reqwest::get(format!("{url}/scry")).await.unwrap().json().await.unwrap();
    assert_eq!(resp.campaign.nodes_online, 0);
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

#[tokio::test]
async fn source_node_does_not_receive_own_seeds() {
    let (url, _tmp) = start_server().await;

    let node_id = SyncClient::register(&url, "solo", "campaign-5", "aflpp", Priority::Shared)
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
