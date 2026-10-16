//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project

use poem::test::TestClient;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use bichon_core::{
    database::{delete_impl, insert_impl, manager::DB_MANAGER},
    users::UserModel,
};

use super::{admin_token, build_api_route, setup};

fn api_client(route: impl poem::Endpoint) -> TestClient<impl poem::Endpoint> {
    TestClient::new(route).default_header("X-Forwarded-For", "127.0.0.1")
}

#[derive(Debug, Serialize)]
struct CreateUserPayload {
    username: String,
    email: String,
    password: String,
    global_roles: Vec<u64>,
    account_access_map: std::collections::BTreeMap<u64, u64>,
}

#[derive(Debug, Deserialize)]
struct UserView {
    id: u64,
    username: String,
    #[allow(dead_code)] // present in the API response, not asserted here
    email: String,
}

#[derive(Debug, Serialize)]
struct UpdateUserPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct OidcReconcilePayload {
    source_user_id: u64,
    provider: String,
    subject: String,
}

const ADMIN_ROLE_ID: u64 = 100_000_000_000_000;

#[tokio::test]
async fn user_crud() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    // Create
    let create_payload = CreateUserPayload {
        username: "testuser1".into(),
        email: "testuser1@example.com".into(),
        password: "testpass123".into(),
        global_roles: vec![ADMIN_ROLE_ID],
        account_access_map: Default::default(),
    };
    let resp = cli
        .post("/api/v1/users")
        .header("Authorization", &format!("Bearer {}", token))
        .body_json(&create_payload)
        .send()
        .await;
    resp.assert_status_is_ok();
    let user: UserView = resp.json().await.value().deserialize();
    assert_eq!(user.username, "testuser1");
    let user_id = user.id;

    // List users
    let resp = cli
        .get("/api/v1/list-users")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();

    // Get current user
    let resp = cli
        .get("/api/v1/current-user")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();

    // Update
    let update = UpdateUserPayload {
        description: Some("Test description".into()),
    };
    let resp = cli
        .post(&format!("/api/v1/users/{}", user_id))
        .header("Authorization", &format!("Bearer {}", token))
        .body_json(&update)
        .send()
        .await;
    resp.assert_status_is_ok();

    // Delete
    let resp = cli
        .delete(&format!("/api/v1/users/{}", user_id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn create_user_with_invalid_data_fails() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    // Username too short (min 3)
    let payload = CreateUserPayload {
        username: "ab".into(),
        email: "valid@example.com".into(),
        password: "testpass123".into(),
        global_roles: vec![ADMIN_ROLE_ID],
        account_access_map: Default::default(),
    };
    let resp = cli
        .post("/api/v1/users")
        .header("Authorization", &format!("Bearer {}", token))
        .body_json(&payload)
        .send()
        .await;
    assert!(resp.0.status().is_client_error(), "short username should fail");

    // Password too short (min 8)
    let payload = CreateUserPayload {
        username: "validuser".into(),
        email: "valid@example.com".into(),
        password: "short".into(),
        global_roles: vec![ADMIN_ROLE_ID],
        account_access_map: Default::default(),
    };
    let resp = cli
        .post("/api/v1/users")
        .header("Authorization", &format!("Bearer {}", token))
        .body_json(&payload)
        .send()
        .await;
    assert!(resp.0.status().is_client_error(), "short password should fail");
}

#[tokio::test]
async fn oidc_reconciliation_endpoint_validates_identity_and_requires_authentication() {
    setup().await;
    let route = build_api_route();
    let cli = api_client(route);
    let payload = OidcReconcilePayload {
        source_user_id: 123,
        provider: "   ".into(),
        subject: "subject".into(),
    };

    let response = cli
        .post("/api/v1/users/456/oidc-reconcile")
        .body_json(&payload)
        .send()
        .await;
    assert!(response.0.status().is_client_error());

    let token = admin_token().await;
    let response = cli
        .post("/api/v1/users/456/oidc-reconcile")
        .header("Authorization", &format!("Bearer {token}"))
        .body_json(&payload)
        .send()
        .await;
    assert!(response.0.status().is_client_error());
}

#[tokio::test]
async fn oidc_reconciliation_endpoint_moves_synthetic_identity_and_preserves_data() {
    setup().await;
    let source = UserModel {
        id: 9_910_001,
        username: "canary-oidc-source".into(),
        email: "canary-source@example.test".into(),
        sso_provider: Some("oidc-canary".into()),
        sso_id: Some("canary-subject".into()),
        description: Some("source data".into()),
        global_roles: vec![7],
        ..Default::default()
    };
    let target = UserModel {
        id: 9_910_002,
        username: "canary-native-target".into(),
        email: "canary-target@example.test".into(),
        description: Some("native data".into()),
        global_roles: vec![100_000_000_000_000],
        account_access_map: BTreeMap::from([(123, 456)]),
        ..Default::default()
    };
    insert_impl(DB_MANAGER.db(), source.clone()).unwrap();
    insert_impl(DB_MANAGER.db(), target.clone()).unwrap();

    let token = admin_token().await;
    let cli = api_client(build_api_route());
    let response = cli
        .post(&format!("/api/v1/users/{}/oidc-reconcile", target.id))
        .header("Authorization", &format!("Bearer {token}"))
        .body_json(&OidcReconcilePayload {
            source_user_id: source.id,
            provider: "oidc-canary".into(),
            subject: "canary-subject".into(),
        })
        .send()
        .await;
    response.assert_status_is_ok();

    let source_after = UserModel::find(source.id).unwrap().unwrap();
    let target_after = UserModel::find(target.id).unwrap().unwrap();
    assert_eq!(source_after.sso_provider, None);
    assert_eq!(source_after.sso_id, None);
    assert_eq!(source_after.description, source.description);
    assert_eq!(target_after.sso_provider.as_deref(), Some("oidc-canary"));
    assert_eq!(target_after.sso_id.as_deref(), Some("canary-subject"));
    assert_eq!(target_after.description, target.description);
    assert_eq!(target_after.global_roles, target.global_roles);
    assert_eq!(target_after.account_access_map, target.account_access_map);

    delete_impl::<UserModel>(bichon_core::database::manager::DB_MANAGER.db(), &source.id.to_string())
        .unwrap();
    delete_impl::<UserModel>(bichon_core::database::manager::DB_MANAGER.db(), &target.id.to_string())
        .unwrap();
}

#[tokio::test]
async fn cannot_delete_default_admin() {
    setup().await;
    let token = admin_token().await;
    let route = build_api_route();
    let cli = api_client(route);

    let resp = cli
        .delete("/api/v1/users/100000000000000")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await;
    assert!(resp.0.status().is_client_error(), "deleting admin should fail");
}
