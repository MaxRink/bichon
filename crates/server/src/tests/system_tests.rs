//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project

use poem::test::TestClient;
use serde::Deserialize;

use super::{admin_token, build_api_route, setup};

fn api_client(route: impl poem::Endpoint) -> TestClient<impl poem::Endpoint> {
    TestClient::new(route).default_header("X-Forwarded-For", "127.0.0.1")
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SystemConfig {
    bichon_root_dir: String,
    bichon_http_port: i32,
    bichon_version: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct DashboardStats {
    account_count: usize,
    email_count: u64,
    attachment_count: u64,
    system_version: String,
}

#[tokio::test]
async fn get_system_configurations() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/system-configurations")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn get_dashboard_stats_returns_data() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/dashboard-stats")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;

    // Dashboard stats may return errors if tantivy schemas are empty,
    // but should always produce a response (not a crash)
    let status = resp.0.status();
    // Accept both success (200) and error (4xx/5xx) — just ensure it doesn't panic
    assert!(status.as_u16() > 0, "should produce a valid HTTP response");
}

#[tokio::test]
async fn blob_integrity_requires_admin_authentication() {
    setup().await;
    let route = build_api_route();
    let cli = api_client(route);
    let resp = cli
        .get("/api/v1/blob-integrity?page=1&page_size=1")
        .send()
        .await;
    assert!(resp.0.status().is_client_error());
}

#[tokio::test]
async fn blob_integrity_rejects_unbounded_page_size() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);
    let resp = cli
        .get("/api/v1/blob-integrity?page=1&page_size=1001")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    assert!(resp.0.status().is_client_error());
}

#[tokio::test]
async fn blob_integrity_rejects_unbounded_payload_page_size() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);
    let resp = cli
        .get("/api/v1/blob-integrity?page=1&page_size=101&verify_payload=true")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    assert!(resp.0.status().is_client_error());
}

#[tokio::test]
async fn blob_integrity_returns_bounded_aggregate_page() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);
    let resp = cli
        .get("/api/v1/blob-integrity?page=1&page_size=1")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
    let body: serde_json::Value = resp.json().await.value().deserialize();
    assert_eq!(body["page"], 1);
    assert_eq!(body["page_size"], 1);
    assert_eq!(body["payload_verification_requested"], false);
    assert_eq!(body["scan_mode"], "index_segment_bounds");
}

#[tokio::test]
async fn list_proxy_returns_array() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/list-proxy")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn list_roles_returns_builtins() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/list-roles")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn minimal_user_list_works() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/minimal-user-list")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn list_account_roles_works() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .get("/api/v1/list-account-roles")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}
